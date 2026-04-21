#!/usr/bin/env python3
"""
MST-IR TypeE.cumulative AST Analyzer (v0.4)

Extends v0.3 with:

  NEW in v0.4:
  1. Loop amplification — ForStatement/WhileStatement/DoWhileStatement
     containing quantization ops are flagged as LOOP_AMPLIFIED:
     a single external call can execute n* drift steps internally
     (Balancer V2 attack pattern: 65 micro-swaps in one batchSwap call)
  2. Unchecked arithmetic — UncheckedBlock containing state-var
     assignments flagged as UNCHECKED_ARITHMETIC: underflow wraps
     instead of reverting, a different invariant-escape path
  3. Inheritance call graph — Child.withdraw() calling Base._compute()
     now correctly propagates quantization from parent contract

Usage:
    python3 mst_ir_analyzer_ast_v0_4.py --demo
    python3 mst_ir_analyzer_ast_v0_4.py --sol MyContract.sol
    solc --standard-json input.json | python3 mst_ir_analyzer_ast_v0_4.py

Reference: DeFi paper v1.0 §7
Author: Hai Hai Fu (Haihai) — Version: v0.4
"""

from __future__ import annotations
import argparse, json, os, subprocess, sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Bias(Enum):
    NONE    = "none"
    DOWN    = "monotonic_decrease"
    UP      = "monotonic_increase"
    MIXED   = "mixed"
    UNKNOWN = "unknown"

class Severity(Enum):
    NONE             = "none"
    LOW              = "low"
    WARNING          = "warning"
    CRITICAL         = "critical"
    DRIFT_PROPAGATED = "drift_propagated"
    LOOP_AMPLIFIED   = "loop_amplified"
    UNCHECKED        = "unchecked"


ROUNDING_FUNCTIONS: dict[str, Bias] = {
    "mulDiv":           Bias.DOWN,
    "mulDivDown":       Bias.DOWN,
    "mulDivFloor":      Bias.DOWN,
    "mulDown":          Bias.DOWN,
    "divDown":          Bias.DOWN,
    "mulDivFixedPoint": Bias.DOWN,
    "mulDivUp":         Bias.UP,
    "mulDivRoundingUp": Bias.UP,
    "mulDivCeil":       Bias.UP,
    "mulUp":            Bias.UP,
    "divUp":            Bias.UP,
}

YUL_DIV_OPS      = {"div", "sdiv", "sar"}
CORRECTION_HINTS = {
    "carry","residual","remainder","accumulator",
    "offset","pending","leftover","dust","error",
}
EXTERNAL_VISIBILITY  = {"external", "public"}
MUTATING_MUTABILITY  = {"nonpayable", "payable"}
SINGLE_USE_MODIFIERS = {"initializer", "once", "onlyOnce"}
LOOP_NODE_TYPES      = {"ForStatement", "WhileStatement", "DoWhileStatement"}


@dataclass
class QuantizationOp:
    kind:       str
    bias:       Bias
    src:        str
    via_callee: str  = ""
    in_loop:    bool = False

@dataclass
class UncheckedOp:
    assignment_op: str
    lhs_var:       str
    src:           str

@dataclass
class FunctionResult:
    contract: str
    name:     str
    src:      str

    has_quantization:    bool = False
    quant_ops:           list[QuantizationOp] = field(default_factory=list)
    bias:                Bias = Bias.NONE

    is_repeatable:       bool = False
    visibility:          str  = "unknown"
    state_mutability:    str  = "unknown"
    modifiers:           list[str] = field(default_factory=list)

    has_correction:      bool = False
    correction_evidence: list[str] = field(default_factory=list)

    modified_state_vars: list[str] = field(default_factory=list)
    calls_internal:      list[str] = field(default_factory=list)

    has_loop_quantization: bool = False
    loop_ops:              list[QuantizationOp] = field(default_factory=list)
    unchecked_ops:         list[UncheckedOp]    = field(default_factory=list)

    is_typee_cumulative:   bool     = False
    is_drift_propagated:   bool     = False
    drift_source:          str      = ""

    severity:    Severity    = Severity.NONE
    messages:    list[str]   = field(default_factory=list)
    annotations: dict        = field(default_factory=dict)


class ASTWalker:

    def __init__(self, ast: dict):
        self.ast = ast
        self._func_by_id:              dict[int, dict]      = {}
        self._func_by_contract_name:   dict[str, dict]      = {}
        self._contract_by_id:          dict[int, dict]      = {}
        self._state_vars_by_contract:  dict[str, set[str]]  = {}
        self._index_nodes(ast, "")
        self._merge_inherited_state_vars()

    def _merge_inherited_state_vars(self) -> None:
        for cnode in self._contract_by_id.values():
            cname = cnode.get("name","")
            for bc in cnode.get("baseContracts", []):
                parent_name = bc.get("baseName",{}).get("name","")
                if parent_name and parent_name in self._state_vars_by_contract:
                    self._state_vars_by_contract.setdefault(cname, set())
                    self._state_vars_by_contract[cname] |= (
                        self._state_vars_by_contract[parent_name]
                    )

    def _index_nodes(self, node: Any, contract: str) -> None:
        if not isinstance(node, dict): return
        nt  = node.get("nodeType", "")
        nid = node.get("id")

        if nt == "ContractDefinition":
            contract = node.get("name", "")
            if nid is not None:
                self._contract_by_id[nid] = node
            svars: set[str] = set()
            for child in node.get("nodes", []):
                if (child.get("nodeType") == "VariableDeclaration"
                        and child.get("stateVariable")):
                    svars.add(child.get("name", ""))
            self._state_vars_by_contract[contract] = svars

        if nt == "FunctionDefinition" and nid is not None:
            self._func_by_id[nid] = node
            fname = node.get("name", "")
            key   = f"{contract}.{fname}" if contract else fname
            self._func_by_contract_name[key] = node

        for v in node.values():
            if isinstance(v, dict):  self._index_nodes(v, contract)
            elif isinstance(v, list):
                for item in v: self._index_nodes(item, contract)

    def analyze(self) -> list[FunctionResult]:
        results: list[FunctionResult] = []
        self._walk_contract(self.ast, "", results)
        self._apply_drift_propagation(results)
        self._apply_super_critical(results)
        return results

    def _walk_contract(self, node: Any, contract: str, results: list) -> None:
        if not isinstance(node, dict): return
        nt = node.get("nodeType", "")

        if nt == "SourceUnit":
            for child in node.get("nodes", []):
                self._walk_contract(child, contract, results)
            return
        if nt == "ContractDefinition":
            cname = node.get("name", contract)
            for child in node.get("nodes", []):
                self._walk_contract(child, cname, results)
            return
        if nt == "FunctionDefinition":
            r = self._analyze_function(node, contract)
            if r is not None: results.append(r)
            return
        for v in node.values():
            if isinstance(v, dict):
                self._walk_contract(v, contract, results)
            elif isinstance(v, list):
                for item in v: self._walk_contract(item, contract, results)

    def _analyze_function(self, fn: dict, contract: str) -> FunctionResult | None:
        if fn.get("kind","function") in ("constructor","fallback","receive"):
            return None
        body = fn.get("body")
        if not body: return None

        r = FunctionResult(
            contract         = contract,
            name             = fn.get("name","<anon>"),
            src              = fn.get("src",""),
            visibility       = fn.get("visibility","unknown"),
            state_mutability = fn.get("stateMutability","unknown"),
        )
        for mod in fn.get("modifiers", []):
            mname = (mod.get("modifierName") or {}).get("name","")
            if mname: r.modifiers.append(mname)

        r.is_repeatable = self._check_repeatable(r)
        self._walk_body(body, r, contract, in_loop=False, in_unchecked=False)
        self._walk_assembly(body, r)
        self._walk_unchecked(body, r, contract)
        self._expand_internal_calls(r, contract, visited=set())
        self._resolve_bias(r)
        self._check_structural_correction(body, r)
        self._compute_verdict(r)
        return r

    def _check_repeatable(self, r: FunctionResult) -> bool:
        if r.visibility not in EXTERNAL_VISIBILITY: return False
        if r.state_mutability not in MUTATING_MUTABILITY: return False
        for mod in r.modifiers:
            if mod in SINGLE_USE_MODIFIERS: return False
        return True

    def _walk_body(self, node: Any, r: FunctionResult, contract: str,
                   in_loop: bool, in_unchecked: bool) -> None:
        if not isinstance(node, dict): return
        nt = node.get("nodeType","")

        entered_loop = nt in LOOP_NODE_TYPES
        current_loop = in_loop or entered_loop

        if nt == "UncheckedBlock":
            return

        if nt == "FunctionCall":
            self._check_function_call(node, r, in_loop=current_loop)
            self._record_internal_call(node, r, contract)

        if nt == "BinaryOperation":
            op = node.get("operator","")
            if op == "/":
                qop = QuantizationOp("integer_division", Bias.DOWN,
                                     node.get("src",""), in_loop=current_loop)
                r.has_quantization = True
                r.quant_ops.append(qop)
                if current_loop:
                    r.has_loop_quantization = True
                    r.loop_ops.append(qop)
            elif op == ">>":
                qop = QuantizationOp("right_shift", Bias.DOWN,
                                     node.get("src",""), in_loop=current_loop)
                r.has_quantization = True
                r.quant_ops.append(qop)
                if current_loop:
                    r.has_loop_quantization = True
                    r.loop_ops.append(qop)

        if nt == "Assignment":
            self._record_assignment(node.get("leftHandSide",{}), r, contract)

        if nt in ("VariableDeclaration","Identifier"):
            vname = node.get("name","").lower()
            for hint in CORRECTION_HINTS:
                if hint in vname:
                    r.has_correction = True
                    r.correction_evidence.append(
                        f"variable '{node.get('name','')}' contains '{hint}'"
                    )
                    break

        for v in node.values():
            if isinstance(v, dict):
                self._walk_body(v, r, contract, current_loop, in_unchecked)
            elif isinstance(v, list):
                for item in v:
                    self._walk_body(item, r, contract, current_loop, in_unchecked)

    def _walk_unchecked(self, node: Any, r: FunctionResult, contract: str) -> None:
        if not isinstance(node, dict): return
        nt = node.get("nodeType","")

        if nt == "UncheckedBlock":
            for stmt in node.get("statements", []):
                self._collect_unchecked_assignments(stmt, r, contract)
            return

        for v in node.values():
            if isinstance(v, dict): self._walk_unchecked(v, r, contract)
            elif isinstance(v, list):
                for item in v: self._walk_unchecked(item, r, contract)

    def _collect_unchecked_assignments(self, node: Any, r: FunctionResult,
                                        contract: str) -> None:
        if not isinstance(node, dict): return
        nt = node.get("nodeType","")
        svars = self._state_vars_by_contract.get(contract, set())

        if nt == "Assignment":
            op  = node.get("operator","")
            lhs = node.get("leftHandSide",{})
            lname = ""
            if lhs.get("nodeType") == "Identifier":
                lname = lhs.get("name","")
            elif lhs.get("nodeType") == "IndexAccess":
                lname = lhs.get("baseExpression",{}).get("name","")

            if op in ("-=","+=","*=","/=") and (lname in svars or not lname):
                r.unchecked_ops.append(UncheckedOp(
                    assignment_op = op,
                    lhs_var       = lname or "<expr>",
                    src           = node.get("src",""),
                ))

        for v in node.values():
            if isinstance(v, dict):
                self._collect_unchecked_assignments(v, r, contract)
            elif isinstance(v, list):
                for item in v:
                    self._collect_unchecked_assignments(item, r, contract)

    def _walk_assembly(self, node: Any, r: FunctionResult,
                       in_loop: bool = False) -> None:
        if not isinstance(node, dict): return
        nt = node.get("nodeType","")

        if nt in LOOP_NODE_TYPES:
            in_loop = True

        if nt == "YulFunctionCall":
            fname = node.get("functionName",{}).get("name","")
            if fname in YUL_DIV_OPS:
                qop = QuantizationOp(
                    kind    = f"assembly_{fname}",
                    bias    = Bias.DOWN,
                    src     = node.get("src",""),
                    in_loop = in_loop,
                )
                r.has_quantization = True
                r.quant_ops.append(qop)
                if in_loop:
                    r.has_loop_quantization = True
                    r.loop_ops.append(qop)

        for v in node.values():
            if isinstance(v, dict): self._walk_assembly(v, r, in_loop)
            elif isinstance(v, list):
                for item in v: self._walk_assembly(item, r, in_loop)

    def _record_internal_call(self, call_node: dict, r: FunctionResult,
                               contract: str) -> None:
        expr     = call_node.get("expression",{})
        ref_decl = expr.get("referencedDeclaration")
        if ref_decl and ref_decl in self._func_by_id:
            callee     = self._func_by_id[ref_decl]
            callee_vis = callee.get("visibility","")
            cname      = callee.get("name","")
            if callee_vis in ("internal","private") and cname:
                key = f"{contract}.{cname}"
                if key not in r.calls_internal:
                    r.calls_internal.append(key)

    def _expand_internal_calls(self, r: FunctionResult, contract: str,
                                visited: set) -> None:
        parent_contracts = self._get_parent_contracts(contract)

        for callee_key in list(r.calls_internal):
            if callee_key in visited: continue
            visited.add(callee_key)

            callee_node = self._func_by_contract_name.get(callee_key)

            if callee_node is None:
                func_short = callee_key.split(".")[-1]
                for parent in parent_contracts:
                    alt_key = f"{parent}.{func_short}"
                    callee_node = self._func_by_contract_name.get(alt_key)
                    if callee_node:
                        break

            if callee_node is None: continue
            body = callee_node.get("body")
            if not body: continue

            tmp = FunctionResult(
                contract         = contract,
                name             = callee_node.get("name",""),
                src              = callee_node.get("src",""),
                visibility       = callee_node.get("visibility",""),
                state_mutability = callee_node.get("stateMutability",""),
            )
            self._walk_body(body, tmp, contract, in_loop=False, in_unchecked=False)
            self._walk_assembly(body, tmp)
            self._record_internal_calls_from_body(body, tmp, contract)
            self._expand_internal_calls(tmp, contract, visited)

            for op in tmp.quant_ops:
                propagated = QuantizationOp(
                    kind       = op.kind,
                    bias       = op.bias,
                    src        = op.src,
                    via_callee = callee_key,
                    in_loop    = op.in_loop,
                )
                r.has_quantization = True
                r.quant_ops.append(propagated)
                if op.in_loop:
                    r.has_loop_quantization = True
                    r.loop_ops.append(propagated)

            if tmp.has_correction:
                r.has_correction = True
                for ev in tmp.correction_evidence:
                    r.correction_evidence.append(f"[via {callee_key}] {ev}")

    def _get_parent_contracts(self, contract_name: str) -> list[str]:
        for cid, cnode in self._contract_by_id.items():
            if cnode.get("name") == contract_name:
                parents = []
                for bc in cnode.get("baseContracts", []):
                    parent_name = bc.get("baseName",{}).get("name","")
                    if parent_name:
                        parents.append(parent_name)
                return parents
        return []

    def _record_internal_calls_from_body(self, node: Any, r: FunctionResult,
                                          contract: str) -> None:
        if not isinstance(node, dict): return
        if node.get("nodeType") == "FunctionCall":
            self._record_internal_call(node, r, contract)
        for v in node.values():
            if isinstance(v, dict):
                self._record_internal_calls_from_body(v, r, contract)
            elif isinstance(v, list):
                for item in v:
                    self._record_internal_calls_from_body(item, r, contract)

    def _check_function_call(self, call_node: dict, r: FunctionResult,
                              in_loop: bool = False) -> None:
        expr   = call_node.get("expression",{})
        entype = expr.get("nodeType","")
        ref    = expr.get("referencedDeclaration")

        canonical = None
        if entype == "MemberAccess":
            member = expr.get("memberName","")
            canonical = self._func_by_id[ref].get("name", member) if (
                ref and ref in self._func_by_id) else member
        elif entype == "Identifier":
            fname = expr.get("name","")
            canonical = self._func_by_id[ref].get("name", fname) if (
                ref and ref in self._func_by_id) else fname

        if canonical and canonical in ROUNDING_FUNCTIONS:
            bias = ROUNDING_FUNCTIONS[canonical]
            qop  = QuantizationOp(canonical, bias,
                                  call_node.get("src",""), in_loop=in_loop)
            r.has_quantization = True
            r.quant_ops.append(qop)
            if in_loop:
                r.has_loop_quantization = True
                r.loop_ops.append(qop)

    def _record_assignment(self, lhs: dict, r: FunctionResult,
                            contract: str) -> None:
        nt    = lhs.get("nodeType","")
        svars = self._state_vars_by_contract.get(contract, set())
        if nt == "Identifier":
            vname = lhs.get("name","")
            if vname in svars and vname not in r.modified_state_vars:
                r.modified_state_vars.append(vname)
        elif nt == "IndexAccess":
            base = lhs.get("baseExpression",{})
            if base.get("nodeType") == "Identifier":
                vname = base.get("name","")
                if vname in svars and vname not in r.modified_state_vars:
                    r.modified_state_vars.append(vname)
        elif nt == "MemberAccess":
            vname = lhs.get("memberName","")
            if vname not in r.modified_state_vars:
                r.modified_state_vars.append(vname)

    def _resolve_bias(self, r: FunctionResult) -> None:
        if not r.quant_ops: r.bias = Bias.NONE; return
        biases = {op.bias for op in r.quant_ops} - {Bias.UNKNOWN}
        if not biases:            r.bias = Bias.UNKNOWN
        elif biases == {Bias.DOWN}: r.bias = Bias.DOWN
        elif biases == {Bias.UP}:   r.bias = Bias.UP
        else:                       r.bias = Bias.MIXED

    def _check_structural_correction(self, body: dict, r: FunctionResult) -> None:
        if r.has_correction: return
        if r.bias == Bias.MIXED:
            r.has_correction = True
            r.correction_evidence.append(
                "Both DOWN and UP rounding detected (possible correction)"
            )
            r.messages.append(
                f"MIXED_BIAS [INFO] {r.contract}.{r.name}(): "
                f"function contains both DOWN and UP rounding ops. "
                f"CRITICAL suppressed (possible cross-compensation). "
                f"Manual review required."
            )
            return
        self._find_residual_assignments(body, r)

    def _find_residual_assignments(self, node: Any, r: FunctionResult) -> None:
        if not isinstance(node, dict): return
        if node.get("nodeType") == "Assignment":
            lhs   = node.get("leftHandSide",{})
            rhs   = node.get("rightHandSide",{})
            lname = lhs.get("name", lhs.get("memberName","")).lower()
            if any(h in lname for h in CORRECTION_HINTS):
                if (rhs.get("nodeType") == "BinaryOperation"
                        and rhs.get("operator") == "-"):
                    r.has_correction = True
                    r.correction_evidence.append(
                        f"residual-tracking assignment: '{lhs.get('name',lname)}'"
                    )
                    return
        for v in node.values():
            if isinstance(v, dict): self._find_residual_assignments(v, r)
            elif isinstance(v, list):
                for item in v: self._find_residual_assignments(item, r)

    def _apply_super_critical(self, results: list[FunctionResult]) -> None:
        drift_vars: dict[str, list[str]] = {}
        for r in results:
            if r.is_typee_cumulative and r.severity == Severity.CRITICAL:
                for v in r.modified_state_vars:
                    drift_vars.setdefault(v, []).append(f"{r.contract}.{r.name}")

        if not drift_vars:
            return

        for r in results:
            if not r.unchecked_ops:
                continue
            overlap = [u.lhs_var for u in r.unchecked_ops if u.lhs_var in drift_vars]
            if not overlap:
                continue
            r.severity = Severity.CRITICAL
            sources = sorted(set(sum([drift_vars[v] for v in overlap], [])))
            r.messages.insert(0,
                f"SUPER_CRITICAL {r.contract}.{r.name}(): "
                f"variable(s) {overlap} are BOTH drifted by TypeE.cumulative "
                f"[{', '.join(sources)}] AND modified unchecked here. "
                f"Two independent invariant-escape paths on the same variable."
            )
            r.annotations["@super_critical"] = {
                "shared_vars": overlap,
                "drift_sources": sources,
                "reason": "TypeE.cumulative drift + unchecked arithmetic on same variable",
            }

    def _apply_drift_propagation(self, results: list[FunctionResult]) -> None:
        cumulative_vars: dict[str, list[str]] = {}
        for r in results:
            if r.is_typee_cumulative:
                for v in r.modified_state_vars:
                    cumulative_vars.setdefault(v,[]).append(
                        f"{r.contract}.{r.name}")
        if not cumulative_vars: return
        for r in results:
            if r.is_typee_cumulative: continue
            if r.severity != Severity.NONE: continue
            overlap = [v for v in r.modified_state_vars if v in cumulative_vars]
            if overlap:
                r.is_drift_propagated = True
                r.severity = Severity.DRIFT_PROPAGATED
                sources = []
                for v in overlap: sources.extend(cumulative_vars[v])
                r.drift_source = ", ".join(sorted(set(sources)))
                r.messages.append(
                    f"DRIFT_PROPAGATED {r.contract}.{r.name}(): "
                    f"modifies {overlap} also written by TypeE.cumulative "
                    f"[{r.drift_source}]. Manual review required."
                )
                r.annotations["@drift_propagated"] = {
                    "shared_vars": overlap,
                    "source_functions": sorted(set(sources)),
                }

    def _compute_verdict(self, r: FunctionResult) -> None:
        c1 = r.has_quantization
        c2 = r.bias in (Bias.DOWN, Bias.UP)
        c3 = r.is_repeatable
        c4 = not r.has_correction

        if c1 and c2 and c3 and c4:
            r.is_typee_cumulative = True
            ops_str = ", ".join(
                f"{op.kind}" + (f"[via {op.via_callee}]" if op.via_callee else "")
                + (" [IN LOOP]" if op.in_loop else "")
                for op in r.quant_ops
            )
            if r.bias == Bias.DOWN:
                r.severity = Severity.CRITICAL
                r.messages.append(
                    f"TYPEE_CUMULATIVE [CRITICAL] {r.contract}.{r.name}(): "
                    f"uses {ops_str} (DOWN) on external state-mutating function, "
                    f"no correction. State vars: {r.modified_state_vars or ['?']}. "
                    f"FIX: mulDivUp / round AGAINST protocol."
                )
            else:
                r.severity = Severity.LOW
                r.messages.append(
                    f"TYPEE_CUMULATIVE [LOW] {r.contract}.{r.name}(): "
                    f"uses {ops_str} (UP). Verify direction favors protocol."
                )
            r.annotations["@TypeE.internal"]   = "single-call correct"
            r.annotations["@TypeE.cumulative"] = {
                "variable":  r.modified_state_vars[0] if r.modified_state_vars else "?",
                "bias":      r.bias.value,
                "bound":     "none",
                "in_loop":   r.has_loop_quantization,
            }
            if r.calls_internal:
                r.annotations["@TypeE.cumulative"]["via"] = r.calls_internal

        if r.has_loop_quantization and r.is_repeatable:
            if r.severity in (Severity.NONE, Severity.LOW):
                r.severity = Severity.LOOP_AMPLIFIED
            r.messages.append(
                f"LOOP_AMPLIFIED {r.contract}.{r.name}(): "
                f"quantization op inside loop body — a single transaction "
                f"can execute n* drift steps without repeated external calls. "
                f"Condition 3 (callability) is satisfied by the loop itself."
            )
            r.annotations["@loop_amplified"] = {
                "loop_ops":  [o.kind for o in r.loop_ops],
                "note":      "n* from loop iterations, not external call count",
            }

        if r.unchecked_ops and r.is_repeatable:
            if r.severity == Severity.NONE:
                r.severity = Severity.UNCHECKED
            for uop in r.unchecked_ops:
                r.messages.append(
                    f"UNCHECKED_ARITHMETIC {r.contract}.{r.name}(): "
                    f"'{uop.lhs_var} {uop.assignment_op} ...' inside unchecked block. "
                    f"Underflow wraps instead of reverting."
                )
            r.annotations["@unchecked_arithmetic"] = {
                "ops": [{"var": u.lhs_var, "op": u.assignment_op}
                        for u in r.unchecked_ops],
            }

        r.annotations.setdefault(
            "@TypeE.internal",
            "single-call correct" if c1 else "no quantization"
        )


def format_results(results: list[FunctionResult], verbose: bool = True) -> str:
    SEV_ICON = {
        "critical":         "[CRITICAL]",
        "loop_amplified":   "[LOOP_AMPLIFIED]",
        "drift_propagated": "[DRIFT_PROPAGATED]",
        "unchecked":        "[UNCHECKED]",
        "low":              "[LOW]",
        "warning":          "[WARNING]",
    }
    lines = ["="*72, "MST-IR TypeE.cumulative AST Analysis (v0.4)", "="*72]
    flagged = [r for r in results if r.severity != Severity.NONE]

    if not flagged:
        lines += ["", "No issues detected.", ""]
    else:
        lines.append(f"\n  {len(flagged)} function(s) flagged:\n")
        for r in flagged:
            icon = SEV_ICON.get(r.severity.value, "[?]")
            lines.append(f"{icon}  {r.contract}.{r.name}()")
            lines.append(f"   visibility        : {r.visibility}")
            lines.append(f"   stateMutability   : {r.state_mutability}")
            lines.append(f"   HasQuantization   : {r.has_quantization}")
            for op in r.quant_ops:
                via  = f"  <- via {op.via_callee}" if op.via_callee else ""
                loop = "  [IN LOOP]" if op.in_loop else ""
                lines.append(f"     * {op.kind} [{op.bias.value}]{via}{loop}")
            lines.append(f"   bias              : {r.bias.value}")
            lines.append(f"   IsRepeatable      : {r.is_repeatable}")
            lines.append(f"   HasCorrection     : {r.has_correction}")
            if r.correction_evidence:
                for ev in r.correction_evidence[:3]:
                    lines.append(f"     evidence: {ev}")
            lines.append(f"   ModifiedStateVars : {r.modified_state_vars}")
            if r.calls_internal:
                lines.append(f"   CallsInternal     : {r.calls_internal}")
            lines.append(f"   TypeE.cumulative  : {r.is_typee_cumulative}")
            lines.append(f"   LoopAmplified     : {r.has_loop_quantization}")
            if r.unchecked_ops:
                lines.append(f"   UncheckedOps      : {[(u.lhs_var,u.assignment_op) for u in r.unchecked_ops]}")
            if verbose and r.messages:
                lines.append("")
                for msg in r.messages:
                    lines.append(f"   {msg}")
            lines.append("")
            if r.annotations:
                lines.append("   MST-IR Annotations:")
                for k, v in r.annotations.items():
                    if isinstance(v, dict):
                        lines.append(f"     {k}(")
                        for dk,dv in v.items():
                            lines.append(f"       {dk}: {dv}")
                        lines.append("     )")
                    else:
                        lines.append(f"     {k}: {v}")
                lines.append("")

    counts = {s: sum(1 for r in flagged if r.severity==s) for s in Severity}
    lines += [
        "-"*72,
        f"Analyzed {len(results)} fn(s). "
        f"CRITICAL:{counts[Severity.CRITICAL]} "
        f"LOOP_AMPLIFIED:{counts[Severity.LOOP_AMPLIFIED]} "
        f"DRIFT_PROPAGATED:{counts[Severity.DRIFT_PROPAGATED]} "
        f"UNCHECKED:{counts[Severity.UNCHECKED]} "
        f"LOW:{counts[Severity.LOW]}",
        "="*72,
    ]
    return "\n".join(lines)


def to_json(results: list[FunctionResult]) -> str:
    out = []
    for r in results:
        if r.severity == Severity.NONE: continue
        out.append({
            "contract": r.contract, "function": r.name,
            "severity": r.severity.value,
            "has_quantization":     r.has_quantization,
            "quant_ops":            [{"kind":o.kind,"bias":o.bias.value,
                                      "in_loop":o.in_loop,"via":o.via_callee}
                                     for o in r.quant_ops],
            "bias":                 r.bias.value,
            "is_repeatable":        r.is_repeatable,
            "has_correction":       r.has_correction,
            "modified_state_vars":  r.modified_state_vars,
            "calls_internal":       r.calls_internal,
            "is_typee_cumulative":  r.is_typee_cumulative,
            "has_loop_quantization":r.has_loop_quantization,
            "unchecked_ops":        [{"var":u.lhs_var,"op":u.assignment_op}
                                     for u in r.unchecked_ops],
            "is_drift_propagated":  r.is_drift_propagated,
            "drift_source":         r.drift_source,
            "messages":             r.messages,
            "annotations":          r.annotations,
        })
    return json.dumps(out, indent=2)


def _extract_json(raw: str) -> str:
    for i, line in enumerate(raw.splitlines()):
        if line.strip().startswith("{"):
            return "\n".join(raw.splitlines()[i:])
    return raw

def analyze_ast_json(data: dict) -> list[FunctionResult]:
    all_results: list[FunctionResult] = []
    for _, src_obj in data.get("sources", {}).items():
        ast = src_obj.get("ast")
        if ast: all_results.extend(ASTWalker(ast).analyze())
    return all_results

def compile_sol(sol_path: str) -> dict:
    content = open(sol_path).read()
    inp = json.dumps({
        "language": "Solidity",
        "sources":  {os.path.basename(sol_path): {"content": content}},
        "settings": {"outputSelection": {"*": {"*": [], "": ["ast"]}}},
    })
    proc = subprocess.run(["npx","solc","--standard-json"],
                          input=inp, capture_output=True, text=True, timeout=30)
    return json.loads(_extract_json(proc.stdout))


def main() -> None:
    p = argparse.ArgumentParser(description="MST-IR TypeE.cumulative AST Analyzer v0.4")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--ast",  metavar="FILE")
    g.add_argument("--sol",  metavar="FILE")
    g.add_argument("--demo", action="store_true")
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    if args.demo:
        print("Demo mode: run with a .sol file or pipe solc --standard-json output")
        return

    if args.ast:   data = json.load(open(args.ast))
    elif args.sol: data = compile_sol(args.sol)
    else:
        raw = sys.stdin.read().strip()
        if not raw: p.print_help(); sys.exit(1)
        data = json.loads(_extract_json(raw))

    results = analyze_ast_json(data)
    print(to_json(results) if args.json else format_results(results))

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
MST-IR Benchmark Suite v2
==========================
14-case benchmark protocol for mst_ir_analyzer_ast_v0_4.py
Klaus-confirmed matrix 2026-04-21

Positive set (P1-P8): must fire primary detection
Negative set (N1-N5): must NOT fire primary detection  
Manual bucket (N6): fires LOW/INFO, excluded from P/R

Primary verdicts: CRITICAL, UNCHECKED, DRIFT_PROPAGATED
Secondary annotation: LOOP_AMPLIFIED (verified separately for P2)

P7/P8 detection: check for presence of expected verdict in any function's
result, not max severity — because contracts have multiple functions.

Usage:
    python3 mst_ir_benchmark.py
    python3 mst_ir_benchmark.py --ablation
    python3 mst_ir_benchmark.py --json
"""
from __future__ import annotations
import argparse, json, subprocess, sys
from dataclasses import dataclass, field
sys.path.insert(0, '/home/claude')
import mst_ir_analyzer_ast_v0_4 as ana
from mst_ir_analyzer_ast_v0_4 import Severity, ASTWalker, FunctionResult, _extract_json

SEV_RANK = {Severity.NONE:0, Severity.LOW:1, Severity.UNCHECKED:2,
            Severity.DRIFT_PROPAGATED:3, Severity.LOOP_AMPLIFIED:3, Severity.CRITICAL:4}

@dataclass
class Case:
    cid:          str
    name:         str
    cls:          str
    exp:          str
    exp_loop:     bool
    ablation:     list
    paper_label:  str
    src:          str

CASES = [

Case("P1","BunniDirect","ID","CRITICAL",False,[],"CRITICAL","""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
library FPM { function mulDiv(uint256 x,uint256 y,uint256 d) internal pure returns(uint256){ return x*y/d; } }
contract BunniDirect {
    using FPM for uint256;
    uint256 public idleBalance; uint256 public totalShares;
    function withdraw(uint256 shares) external returns(uint256 amount) {
        amount = idleBalance.mulDiv(shares, totalShares);
        idleBalance -= amount; totalShares -= shares;
    }
}
"""),

Case("P2","BalancerLoop","ID","CRITICAL",True,["loop"],"CRITICAL + LOOP_AMPLIFIED","""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
library FP { uint256 constant ONE=1e18; function mulDown(uint256 a,uint256 b) internal pure returns(uint256){ return a*b/ONE; } }
contract BalancerLoop {
    using FP for uint256;
    uint256[] public balances; uint256[] public scalingFactors;
    struct Swap { uint256 amount; }
    function batchSwap(Swap[] calldata swaps) external {
        for (uint256 i=0; i<swaps.length; i++) {
            balances[i] = balances[i].mulDown(scalingFactors[i]);
        }
    }
}
"""),

Case("P3","InternalHelper","ID","CRITICAL",False,["call_graph"],"CRITICAL","""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract InternalHelper {
    uint256 public totalAssets; uint256 public totalSupply;
    function _sharesForAssets(uint256 assets) internal view returns(uint256) {
        return assets * 1e18 / totalSupply;
    }
    function deposit(uint256 assets) external returns(uint256 shares) {
        shares = _sharesForAssets(assets);
        totalAssets += assets; totalSupply += shares;
    }
}
"""),

Case("P4","InheritanceChain","ID","CRITICAL",False,["call_graph"],"CRITICAL","""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Base {
    uint256 public reserves; uint256 public totalShares;
    function _computeAmount(uint256 shares) internal view returns(uint256) {
        return reserves * shares / totalShares;
    }
}
contract Child is Base {
    function withdraw(uint256 shares) external {
        uint256 amount = _computeAmount(shares);
        reserves -= amount; totalShares -= shares;
    }
}
"""),

Case("P5","AssemblyDiv","ID","CRITICAL",False,[],"CRITICAL","""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract AssemblyDiv {
    uint256 public reserves; uint256 public totalSupply;
    function redeem(uint256 shares) external returns(uint256 out) {
        uint256 r=reserves; uint256 ts=totalSupply;
        assembly { out := div(mul(r,shares),ts) }
        reserves -= out; totalSupply -= shares;
    }
}
"""),

Case("P6","UncheckedArith","ID-adjacent","UNCHECKED",False,["unchecked"],"UNCHECKED","""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract UncheckedArith {
    uint256 public balance; uint256 public totalSupply;
    function forceWithdraw(uint256 amount) external {
        unchecked { balance -= amount; totalSupply -= amount; }
    }
}
"""),

Case("P7","DriftPropagation","ID-propagated","DRIFT_PROPAGATED",False,[],"DRIFT_PROPAGATED","""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
library M { function mulDiv(uint256 x,uint256 y,uint256 d) internal pure returns(uint256){ return x*y/d; } }
contract DriftPropagation {
    using M for uint256;
    uint256 public poolBalance; uint256 public totalShares;
    function withdraw(uint256 s) external returns(uint256 a) {
        a = poolBalance.mulDiv(s, totalShares);
        poolBalance -= a; totalShares -= s;
    }
    function adminAdjust(uint256 delta) external { poolBalance -= delta; }
    uint256 public fee;
    function setFee(uint256 f) external { fee = f; }
}
"""),

Case("P8","IBV_SharedStateAsymmetry","IBV","DRIFT_PROPAGATED",False,[],"IBV_PATTERN (DRIFT_PROPAGATED)","""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
library M { function mulDiv(uint256 x,uint256 y,uint256 d) internal pure returns(uint256){ return x*y/d; } }
contract IBV_SharedStateAsymmetry {
    using M for uint256;
    uint256 public eBalance; uint256 public dLiability;
    function withdraw(uint256 shares) external {
        uint256 out = eBalance.mulDiv(shares, 1e18);
        eBalance -= out;
    }
    function donateToReserves(uint256 amount) external { eBalance += amount; }
}
"""),

Case("N1","SafeMulDivUp","Negative","NO_FIRE",False,[],"No fire (or LOW only)","""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
library M { function mulDivUp(uint256 x,uint256 y,uint256 d) internal pure returns(uint256){ return (x*y+d-1)/d; } }
contract SafeMulDivUp {
    using M for uint256;
    uint256 public balance; uint256 public totalShares;
    function withdraw(uint256 shares) external returns(uint256 amount) {
        amount = balance.mulDivUp(shares, totalShares);
        balance -= amount; totalShares -= shares;
    }
}
"""),

Case("N2","CarryCompensated","Negative","NO_FIRE",False,[],"No fire","""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract CarryCompensated {
    uint256 public balance; uint256 public totalShares;
    uint256 private pendingCarry;
    function withdraw(uint256 shares) external returns(uint256 amount) {
        uint256 carry = pendingCarry;
        amount = (balance * shares + carry) / totalShares;
        pendingCarry = (balance * shares + carry) - amount * totalShares;
        balance -= amount; totalShares -= shares;
    }
}
"""),

Case("N3","BankersRounding","Negative","NO_FIRE",False,[],"No fire","""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
library Sym {
    function roundHalfEven(uint256 x, uint256 d) internal pure returns(uint256) {
        uint256 q=x/d; uint256 rem=x%d;
        if (rem*2 < d) return q;
        if (rem*2 > d) return q+1;
        return (q%2==0) ? q : q+1;
    }
}
contract BankersRounding {
    using Sym for uint256;
    uint256 public balance; uint256 public totalShares;
    function withdraw(uint256 shares) external returns(uint256 amount) {
        amount = balance.roundHalfEven(totalShares);
        balance -= amount; totalShares -= shares;
    }
}
"""),

Case("N4","ViewFunction","Negative","NO_FIRE",False,[],"No fire","""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
library M { function mulDiv(uint256 x,uint256 y,uint256 d) internal pure returns(uint256){ return x*y/d; } }
contract ViewFunction {
    using M for uint256;
    uint256 public balance; uint256 public totalShares;
    function previewWithdraw(uint256 shares) external view returns(uint256) {
        return balance.mulDiv(shares, totalShares);
    }
}
"""),

Case("N5","SingleUseGuard","Negative","NO_FIRE",False,[],"No fire","""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
library M { function mulDiv(uint256 x,uint256 y,uint256 d) internal pure returns(uint256){ return x*y/d; } }
contract SingleUseGuard {
    using M for uint256;
    uint256 public balance; uint256 public totalShares;
    bool private _initialized;
    modifier initializer() { require(!_initialized); _initialized=true; _; }
    function initialize(uint256 shares) external initializer returns(uint256 a) {
        a = balance.mulDiv(shares, totalShares); balance -= a;
    }
}
"""),

Case("N6","ConditionalCorrection","Manual","LOW",False,[],"LOW/INFO (manual-review bucket)","""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract ConditionalCorrection {
    uint256 public balance; uint256 public totalShares;
    enum Rounding { Down, Up }
    function withdraw(uint256 shares, Rounding mode) external returns(uint256 amount) {
        if (mode == Rounding.Up) {
            amount = (balance * shares + totalShares - 1) / totalShares;
        } else {
            amount = balance * shares / totalShares;
        }
        balance -= amount; totalShares -= shares;
    }
}
"""),

]  # end CASES


def make_ablated(disable_call_graph=False, disable_loop=False, disable_unchecked=False):
    class AW(ASTWalker):
        def analyze(self):
            results = []
            self._walk_contract(self.ast, "", results)
            self._apply_drift_propagation(results)
            self._apply_super_critical(results)
            return results
        def _expand_internal_calls(self, r, contract, visited):
            if not disable_call_graph:
                super()._expand_internal_calls(r, contract, visited)
        def _walk_body(self, node, r, contract, in_loop, in_unchecked):
            super()._walk_body(node, r, contract,
                               False if disable_loop else in_loop, in_unchecked)
        def _walk_unchecked(self, node, r, contract):
            if not disable_unchecked:
                super()._walk_unchecked(node, r, contract)
        def _walk_assembly(self, node, r, in_loop=False):
            super()._walk_assembly(node, r, False if disable_loop else in_loop)
    return AW


def run_case(case: Case, walker_cls=None):
    inp = json.dumps({
        "language":"Solidity",
        "sources":{f"{case.name}.sol":{"content":case.src}},
        "settings":{"outputSelection":{"*":{"*":[],"":["ast"]}}}
    })
    proc = subprocess.run(["npx","solc","--standard-json"],
                          input=inp, capture_output=True, text=True, timeout=30)
    try:
        data = json.loads(_extract_json(proc.stdout))
    except Exception:
        return []
    if any(e.get("severity")=="error" for e in data.get("errors",[])):
        return []
    results = []
    for _,src_obj in data.get("sources",{}).items():
        ast = src_obj.get("ast")
        if ast:
            wc = walker_cls or ASTWalker
            results.extend(wc(ast).analyze())
    return results


def classify(results, case: Case):
    verdicts = set()
    loop_seen = False
    max_sev = Severity.NONE
    for r in results:
        sev = r.severity
        if sev != Severity.NONE:
            verdicts.add(sev.value.upper())
        if SEV_RANK.get(sev,0) > SEV_RANK.get(max_sev,0):
            max_sev = sev
        if r.has_loop_quantization and r.is_repeatable:
            loop_seen = True
    primary = max_sev.value.upper() if max_sev != Severity.NONE else "NO_FIRE"
    exp = case.exp.upper()
    if case.cls == "Manual":
        correct = None
    elif exp == "NO_FIRE":
        primary_fired = verdicts & {"CRITICAL","UNCHECKED","DRIFT_PROPAGATED"}
        correct = len(primary_fired) == 0
    else:
        correct = exp in verdicts
    return primary, loop_seen, correct


def compute_metrics(run_results):
    TP=FP=TN=FN=manual=0
    for case, primary, loop_seen, correct in run_results:
        if case.cls == "Manual":
            manual += 1; continue
        if case.exp.upper() == "NO_FIRE":
            if correct: TN += 1
            else: FP += 1
        else:
            if correct: TP += 1
            else: FN += 1
    P = TP/(TP+FP) if TP+FP else float('nan')
    R = TP/(TP+FN) if TP+FN else float('nan')
    F = 2*P*R/(P+R) if P+R else float('nan')
    return dict(TP=TP,FP=FP,TN=TN,FN=FN,manual=manual,P=P,R=R,F1=F)


def fmt_table(rr, title="Primary Detection"):
    W = 80
    lines = ["="*W, f"MST-IR Benchmark — {title}", "="*W,
             f"{'ID':<4} {'Name':<30} {'Class':<16} {'Expected':<18} {'Got':<20} ?",
             "-"*W]
    for case, primary, loop_seen, correct in rr:
        loop_flag = (" +LOOP" if loop_seen and case.exp_loop
                     else " -LOOP" if not loop_seen and case.exp_loop else "")
        status = "MANUAL" if correct is None else ("OK" if correct else "FAIL")
        lines.append(f"{case.cid:<4} {case.name:<30} {case.cls:<16} "
                     f"{case.exp:<18} {primary+loop_flag:<20} {status}")
    lines.append("-"*W)
    return "\n".join(lines)


def fmt_metrics(m):
    return (f"\nMetrics (manual-review bucket N6 excluded from P/R):\n"
            f"  TP={m['TP']}  FP={m['FP']}  TN={m['TN']}  FN={m['FN']}  manual={m['manual']}\n"
            f"  Precision={m['P']:.3f}  Recall={m['R']:.3f}  F1={m['F1']:.3f}")


def fmt_ablation(abl):
    toggles = list(abl.keys())
    W = 80
    lines = ["\n"+"="*W, "Ablation Study", "="*W]
    hdr = f"{'Case':<35}"
    for t in toggles: hdr += f" {t[:20]:<22}"
    lines.append(hdr); lines.append("-"*W)
    ids = [r[0].cid for r in abl[toggles[0]] if r[0].cls != "Manual"]
    for cid in ids:
        row = f"{cid:<35}"
        for t in toggles:
            entry = next((r for r in abl[t] if r[0].cid==cid), None)
            if entry:
                case, primary, _, correct = entry
                if case.cls=="Negative": cell = "TN" if correct else "FP"
                elif correct is True: cell = "TP"
                elif correct is False: cell = "FN"
                else: cell = "?"
                row += f" {cell:<22}"
        lines.append(row)
    lines.append("-"*W)
    for t in toggles:
        m = compute_metrics(abl[t])
        lines.append(f"  [{t}]  P={m['P']:.3f}  R={m['R']:.3f}  "
                     f"TP={m['TP']}  FN={m['FN']}  FP={m['FP']}")
    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser(description="MST-IR Benchmark Suite")
    p.add_argument("--ablation", action="store_true")
    p.add_argument("--json",     action="store_true")
    args = p.parse_args()

    print("Running 14 benchmark cases...", flush=True)
    run_results = []
    for case in CASES:
        results = run_case(case)
        primary, loop_seen, correct = classify(results, case)
        run_results.append((case, primary, loop_seen, correct))
        tag = "MANUAL" if correct is None else ("OK" if correct else "FAIL")
        print(f"  {case.cid} {case.name}: {tag} ({primary})", flush=True)

    m = compute_metrics(run_results)

    abl = {}
    if args.ablation:
        for toggle, kwargs in [
            ("no_call_graph", dict(disable_call_graph=True)),
            ("no_loop",       dict(disable_loop=True)),
            ("no_unchecked",  dict(disable_unchecked=True)),
        ]:
            print(f"\nAblation: {toggle}...", flush=True)
            wc = make_ablated(**kwargs)
            ar = []
            for case in CASES:
                results = run_case(case, walker_cls=wc)
                primary, loop_seen, correct = classify(results, case)
                ar.append((case, primary, loop_seen, correct))
            abl[toggle] = ar

    if args.json:
        out = {
            "benchmark": [{"cid":r[0].cid,"name":r[0].name,"class":r[0].cls,
                            "expected":r[0].exp,"got":r[1],"loop":r[2],"correct":r[3]}
                           for r in run_results],
            "metrics": m,
        }
        if abl:
            out["ablation"] = {t: compute_metrics(a) for t,a in abl.items()}
        print(json.dumps(out, indent=2, default=str))
    else:
        print("\n"+fmt_table(run_results))
        print(fmt_metrics(m))
        if abl: print(fmt_ablation(abl))
        all_ok = m['FN']==0 and m['FP']==0
        print(f"\n{'All cases pass.' if all_ok else 'Failures detected.'}")


if __name__ == "__main__":
    main()

# Iterative Drift in DeFi Protocols

**A Structural Class, a Subclass Theorem, and Static Detection**

---

## Overview

A function that is correct for a single execution can become exploitable when applied repeatedly within one transaction. This paper studies this phenomenon in DeFi protocols and identifies a class of vulnerabilities called **iterative drift**, where locally correct operations accumulate bias under composition and violate global invariants.

We introduce a structural typing perspective distinguishing **local determinism** from **compositional safety**. The central notion — **TypeE.cumulative** — formalizes functions that are deterministic and correct at single-call granularity but unsafe under N-step self-composition.

For the subclass of quantization-driven rules, we give a sufficient condition for exploitability (Theorem 4.1), combining directional bias, reachability, and bounded callability within a single atomic transaction. This explains the Bunni v2 ($8.4M, 2025) and Balancer V2 ($128M, 2025) exploits within a unified framework.

---

## Key Result

> `correct(f) ⟹ correct(fᴺ)` — **this implication is false for TypeE.cumulative rules.**

All existing auditing tools (formal verification, fuzzing, manual review) verify `correct(f)` and implicitly assume this implication. The $136.4M in 2025 TypeE.cumulative losses are concrete counterexamples.

---

## Contents

| File | Description |
|---|---|
| `mst-ir-defi-iterative-drift-v0.7.pdf` | Paper |
| `artifacts/mst_ir_analyzer_ast_v0_4.py` | AST-based static analyzer (Python 3.9+, solc required) |
| `artifacts/mst_ir_benchmark.py` | 14-case benchmark suite |

---

## Analyzer

`mst_ir_analyzer_ast_v0_4.py` operates on Solidity 0.8.x compact JSON ASTs from `solc --standard-json`.

**Detection rules:**
```
HasQuantization ∧ HasDirectionalBias ∧ IsRepeatable ∧ ¬HasCorrection
→ TYPEE_CUMULATIVE [CRITICAL | LOW]

HasQuantization ∧ QuantizationInLoop ∧ IsRepeatable
→ LOOP_AMPLIFIED

UncheckedStateVarArithmetic ∧ IsRepeatable
→ UNCHECKED_ARITHMETIC
```

**Benchmark results (14 cases):** P = R = F1 = 1.000 (benchmark-relative).

Ablation: removing call-graph traversal loses 2 cases (P3, P4); removing unchecked detection loses 1 (P6).

---

## Vulnerability Classes Covered

| Class | Single-call | N-call | Example | Loss |
|---|---|---|---|---|
| IBV-A: Invariant Asymmetry | ✗ | ✗ | Euler Finance | $197M |
| IBV-B: Access Control | ✗ | ✗ | TakeProfitsHook | — |
| IBV-C: Guard Scope | ⚠️ | ⚠️ | Silo Finance | — |
| IBV-D: Recursive State | ⚠️ | ⚠️ | v4-stoploss | — |
| ID: Iterative Drift | ✅ | ✗ | Bunni v2 | $8.4M |
| ID+loop: Loop-amplified | ✅ | ✗ | Balancer V2 | $128M |

---

## The Core Theorem

**Theorem 4.1 (Iterative Drift Instability).** Let f be deterministic, I an invariant with threshold I_min. If:
1. f satisfies all operational requirements per invocation
2. ε(x) = I(f(x)) − I(x) ≤ −α < 0 uniformly on reachable R
3. f is executable n* = ⌈(I(x₀) − I_min)/α⌉ times atomically

Then f^n*(x₀) ⊭ I.

The loop-based (Balancer V2) and repeated-call (Bunni v2) instantiations are both covered. Condition 2b (reachability of R) is the only condition not automated by the AST analyzer.

---

*github.com/klaus-mst/mst*

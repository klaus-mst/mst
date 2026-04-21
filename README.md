# MST-IR: Invariant Boundary Violations and Iterative Drift in DeFi Protocols

**Authors**: Hai Hai Fu  
**Status**: v0.7 — submission-ready draft

---

## Overview

This repository contains the paper and reference implementation for MST-IR, a structural typing approach to detecting two classes of DeFi vulnerabilities that are systematically missed by existing single-call auditing tools:

- **Invariant Boundary Violations (IBV)**: exploits where a rule modifies shared state in a way that violates a downstream rule's invariant assumption
- **Iterative Drift (ID)**: locally correct operations that become exploitable when chained N times (TypeE.cumulative)

The $136.4M in TypeE.cumulative losses in 2025 (Bunni v2: $8.4M, Balancer V2: $128M) provide direct empirical confirmation that this class was outside the security community's existing conceptual framework.

---

## Contents

| File | Description |
|---|---|
| `mst (8).pdf` | Paper draft v0.7 (submission-ready) |
| `artifacts/mst_ir_analyzer_ast_v0_4.py` | v0.1.x reference implementation (AST-based) |
| `artifacts/mst_ir_benchmark.py` | Benchmark harness |

---

## Tool Positioning

v0.1.x is a **scout-layer for quantization-driven DeFi hazards, not a verifier**.

Five behavioral classes observed across 24 protocols:

| Class | Meaning |
|---|---|
| True-positive candidate | Actionable — inspect for exploitability |
| Bidirectional silence | Correct — protocol rounds safely |
| GT-6 FP | Structural — `/` in non-drift formula |
| FP-1 | Artifact — string-literal `/` match |
| Vocabulary silence | Unknown — tool cannot see the idiom |

---

## Key Result

> *The calibration bounds the behavior of the current implementation; it does not constitute a statistical validation of Theorem 4.4.2.*

All observed behaviors across 24 diverse protocols fall within the closed boundary classification of §8. No new behavioral bucket appeared.

---

*Repository: github.com/klaus-mst/mst*

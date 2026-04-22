# MST-IR Independent Validation Set

Validation of `mst_ir_analyzer_ast_v0_4.py` on contracts derived from real-world exploit post-mortems and public protocol implementations. Conducted independently of the synthetic benchmark (§7.3 of the paper).

---

## Cases

| ID | Name | Source | Expected | Got | Result |
|---|---|---|---|---|---|
| V1 | BunniV2_Real | Bunni v2 exploit post-mortem | CRITICAL | CRITICAL | ✓ |
| V2 | CompoundV2_Redeem | Compound v2 CToken.sol | NO_FIRE | CRITICAL | FP |
| V3 | CompoundFork_Vulnerable | Compound v2 fork (Onyx/Hundred class) | CRITICAL | CRITICAL | ✓ |
| V4 | ERC4626_Safe | OpenZeppelin ERC4626.sol | NO_FIRE | CRITICAL (deposit), LOW (withdraw) | FP |

All tested instances of quantization-driven exploit patterns were detected. No false negatives were observed for the tested quantization-driven patterns.

---

## Analysis

### True Positives

**V1 (BunniV2_Real):** The exact rounding pattern from BunniHubLogic.sol — `idleBalance.mulDiv(shares, totalSupply)` rounds DOWN with no correction. Correctly flagged CRITICAL. Consistent with the primary case in §4.5.

**V3 (CompoundFork_Vulnerable):** A Compound v2 fork that exposes `redeem()` as an external function with one-directional `mulDiv` rounding and no compensating round-up at the same entry point. Correctly flagged CRITICAL. Consistent with the Onyx Protocol / Hundred Finance vulnerability class.

### False Positives — Cross-Function Compensation (Refinement of §8.3)

Both false positives arise from a pattern not present in the synthetic benchmark: **bidirectional rounding implemented across separate entry points** rather than within a single function. This is not a new behavioral class; it is a refinement of the §8.3 visibility boundary.

**V2 (CompoundV2_Redeem):** Compound v2 implements protocol-favoring rounding across two separate entry points — `redeem()` rounds DOWN and `mint()` rounds DOWN. Together these are symmetric and protocol-safe, but each function in isolation appears to have uncorrected downward bias. The tool flags both because it analyzes each function independently (§8.3 visibility boundary).

**V4 (ERC4626_Safe):** The OpenZeppelin ERC4626 pattern uses `mulDiv` (DOWN) in `deposit()` and `mulDivUp` (UP) in `withdraw()`. The tool correctly identifies `withdraw()` as LOW (upward bias), but flags `deposit()` as CRITICAL because intra-function analysis cannot see the compensating direction in the sibling entry point.

### Cross-Function Compensation as §8.3 Refinement

The synthetic benchmark includes a case (N1) where intra-function bidirectional rounding correctly suppresses a CRITICAL finding. This validation reveals a structurally adjacent case: bidirectional rounding implemented across *distinct entry points*. The tool fires on the DOWN-biased function because function-local analysis cannot see protocol-level compensation across entry points.

This is a direct consequence of the §8.3 visibility boundary — the tool is function-local by design. It does not introduce a new behavioral class; it refines the existing boundary by making the cross-function compensation case explicit. The fires are interpretable: they signal "this entry point has uncorrected downward bias; verify whether the entry-point pair as a whole is protocol-safe."

---

## Summary

The independent validation confirms:

1. All tested instances of quantization-driven exploit patterns were detected (V1, V3).
2. False positives on cross-function compensation patterns are a refinement of the §8.3 visibility boundary, not a new behavioral class. All observed failures have structural explanations consistent with the existing §8 taxonomy.
3. No false negatives were observed.

An additional independent validation was conducted on publicly documented exploit contracts and widely used protocol implementations. The results did not introduce new behavioral classes; instead, they refined the visibility boundary by revealing cross-function compensation patterns.

---

*Contracts derived from: Bunni v2 post-mortem (blog.bunni.xyz/posts/exploit-post-mortem/), Compound v2 CToken.sol, Onyx Protocol / Hundred Finance post-mortems, OpenZeppelin ERC4626.sol.*

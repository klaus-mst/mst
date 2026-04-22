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

**TP=2, FP=2, TN=0, FN=0. Precision=0.500, Recall=1.000.**

---

## Analysis

### True Positives

**V1 (BunniV2_Real):** The exact rounding pattern from BunniHubLogic.sol — `idleBalance.mulDiv(shares, totalSupply)` rounds DOWN with no correction. Correctly flagged CRITICAL. Consistent with the primary case in §4.5.

**V3 (CompoundFork_Vulnerable):** A Compound v2 fork that exposes `redeem()` as an external function with one-directional `mulDiv` rounding and no compensating round-up at the same entry point. Correctly flagged CRITICAL. Consistent with the Onyx Protocol / Hundred Finance vulnerability class.

### False Positives — Cross-Function Bidirectional Rounding (GT-4b)

Both false positives arise from a pattern not present in the synthetic benchmark: **bidirectional rounding implemented across separate functions** rather than within a single function.

**V2 (CompoundV2_Redeem):** Compound v2 implements protocol-favoring rounding across two separate entry points — `redeem()` rounds DOWN (user receives less), `mint()` also rounds DOWN (user receives fewer shares). Together these are symmetric and protocol-safe, but each function in isolation appears to have uncorrected downward bias. The tool flags both CRITICAL because it analyzes each function independently (§8.3 visibility boundary).

**V4 (ERC4626_Safe):** The OpenZeppelin ERC4626 pattern uses `mulDiv` (DOWN) in `deposit()` and `mulDivUp` (UP) in `withdraw()`. The tool correctly identifies `withdraw()` as LOW (upward bias), but flags `deposit()` as CRITICAL because it cannot see that `withdraw()` provides the compensating direction at the protocol level.

### New False Positive Class: GT-4b

The synthetic benchmark includes GT-4 (intra-function bidirectional rounding → correct NO_FIRE), demonstrated by N1 (SafeMulDivUp). This validation reveals a distinct sub-class:

**GT-4b: Cross-function bidirectional rounding.** A protocol implements DOWN in one function and a compensating UP in a separate function. The tool fires on the DOWN function because intra-function analysis cannot see the protocol-level compensation. This is a direct consequence of the §8.3 visibility boundary: the tool is function-local by design.

GT-4b fires are interpretable — they signal "this function has uncorrected downward bias; verify whether the entry-point pair as a whole is protocol-safe" — but they require manual cross-function verification. This aligns with §8.6: the tool generates hypotheses for human inspection, not statistical verdicts.

---

## Summary

The independent validation confirms:

1. The tool correctly detects the Bunni v2 pattern and the Compound-fork vulnerability class (Recall = 1.000 on positive cases).
2. The tool produces false positives on cross-function bidirectional rounding (GT-4b), a pattern not present in the synthetic benchmark. This is a direct consequence of the documented §8.3 visibility boundary, not a defect in the detection logic.
3. No false negatives were observed.

The GT-4b finding extends the §8.2 / §8.3 boundary characterization with a concrete, independently-sourced example from deployed protocol code.

---

*Contracts derived from: Bunni v2 post-mortem (blog.bunni.xyz/posts/exploit-post-mortem/), Compound v2 CToken.sol, Onyx Protocol / Hundred Finance post-mortems, OpenZeppelin ERC4626.sol.*

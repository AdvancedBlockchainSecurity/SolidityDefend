# Removed Detectors

Detectors that were built but removed from the codebase. Each entry explains why it was removed so we don't rebuild the same thing twice.

---

## Bulk Removal — v1.10.22 (2026-02-13, commit e50e17b)

174 detectors removed after ground truth validation showed zero true positives. These were tested against the full internal test corpus (122 contracts, 149 expected TPs) and produced no confirmed findings.

Common failure patterns:
- Pattern matching too narrow (only matched exact contract/function names from examples)
- Checked file-level `ctx.source_code` instead of walking AST per-function → fired on wrong functions
- Vulnerability class not represented in any test contracts (e.g. EIP-3074 patterns, modular blockchain)
- Overlapped with a better-implemented registered detector

If any of these are revived, the minimum bar is: (1) fix the root cause identified below, (2) add a test contract with a known TP, (3) confirm 0 FPs on `tests/contracts/clean_examples/` and `tests/contracts/fp_benchmarks/`.

---

## Individual Removals

| Detector ID | File | Removed In | Reason |
|---|---|---|---|
| `aa-signature-aggregation` | `aa_signature_aggregation.rs` | v2.0.12 | Exact ID collision with active `aa/signature_aggregation.rs` — registering both produces duplicate findings |
| `erc4337-paymaster-abuse` | `erc4337_paymaster_abuse.rs` | v2.0.12 | Exact ID collision with active `aa/paymaster_abuse.rs` — same issue |
| `erc7683-unsafe-permit2` | `erc7683_permit2_integration.rs` | v2.0.12 | Zero TPs in all test corpora; scans `ctx.source_code` (entire file) instead of per-function AST walk causing FPs; no ERC-7683 permit2 contracts in test suite to validate against |

---

## Notes on High-Value Candidates for Future Revival

These were removed for zero TPs but cover real vulnerability classes worth revisiting if test coverage improves:

- **`blockhash-randomness`** (`blockhash_randomness.rs`, 847 lines) — Blockhash used for randomness. Real vulnerability but test contracts don't use this pattern. Add a test contract first.
- **`missing-eip712-domain`** (`missing_eip712_domain.rs`) — EIP-712 domain separator missing. Common real-world issue. Needs test contract.
- **`multicall-msgvalue-reuse`** (`multicall_msgvalue_reuse.rs`) — msg.value reused across multicall iterations. Known MEV/theft vector. Needs test contract.
- **`erc721-callback-reentrancy`** (`erc721_callback_reentrancy.rs`) — safeTransferFrom callback reentrancy. Real vulnerability class. Needs test contract with ERC-721 + reentrancy.
- **`unchecked-math`** (`unchecked_math.rs`) — unchecked arithmetic blocks used unsafely. Needs tighter pattern to avoid FPs on intentional gas optimizations.
- **`diamond-selector-collision`** (`diamond_selector_collision.rs`) — Diamond proxy function selector collisions. Complex detection; needs diamond proxy test contracts.

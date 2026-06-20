# Ground Truth Baseline Documentation

This directory contains baseline measurements for the SolidityDefend false positive reduction process. These baselines track findings across 18 test targets (122 individual contracts) and are used to measure the effectiveness of each FP reduction round.

## Ground Truth Coverage

| Metric | Count |
|--------|-------|
| Total contracts in ground truth | 122 |
| Clean/secure contracts | 43 |
| Vulnerable contracts | 79 |
| Expected true positives | 149 |
| Parse error contracts | 0 |
| Validated recall | 100% (149/149) |
| False positives | 0 |
| Precision | 100.0% |
| Coverage | **100%** of test corpus |

See `tests/validation/ground_truth.json` (v1.4.0, updated 2026-02-16) for the complete dataset.

### Detector Count

| Version | Active Detectors |
|---------|-----------------|
| v2.0.10 | 81 |
| v2.0.11 | 90 |

## Test Targets (18 directories)

### Clean Contracts (5 targets) — All findings are false positives
1. `tests/contracts/clean_examples/clean_contract.sol`
2. `tests/contracts/fp_benchmarks/safe_amm_pool.sol`
3. `tests/contracts/fp_benchmarks/safe_chainlink_consumer.sol`
4. `tests/contracts/fp_benchmarks/safe_erc4626_vault.sol`
5. `tests/contracts/fp_benchmarks/safe_flash_loan_provider.sol`

### Vulnerable Contracts (13 targets) — Mix of TPs and FPs
6. `tests/contracts/basic_vulnerabilities/reentrancy_issues.sol`
7. `tests/contracts/basic_vulnerabilities/validation_issues.sol`
8. `tests/contracts/vulnerable/`
9. `tests/contracts/flash_loans/`
10. `tests/contracts/erc4626_vaults/`
11. `tests/contracts/price-manipulation/`
12. `tests/contracts/cross_chain/`
13. `tests/contracts/delegatecall/`
14. `tests/contracts/signatures/`
15. `tests/contracts/specialized/`
16. `tests/contracts/restaking/`
17. `tests/contracts/account_abstraction/`
18. `tests/contracts/amm_context/`

### Additional Annotated Contracts (not in baseline targets but in ground truth)
- `tests/contracts/2025_eips/` — EIP-1153, EIP-7702, ERC-7821
- `tests/contracts/commit-reveal/` — Commit-reveal patterns
- `tests/contracts/critical_vulnerabilities/` — CREATE2, metamorphic, permit, selfdestruct
- `tests/contracts/complex_scenarios/` — Cross-chain, MEV, governance, yield farming
- `tests/contracts/deadline/` — Missing deadline patterns
- `tests/contracts/front-running/` — Allowance TOCTOU, approve race, token frontrun
- `tests/contracts/phase21_diamond/` — Diamond proxy
- `tests/contracts/phase22_metamorphic/` — Metamorphic factory
- `tests/contracts/phase23_v1.0/` — Multisig, permit, upgradeable
- `tests/contracts/phase51_eip3074_future/` — EIP-3074, EIP-4844, EIP-6780, PUSH0

## Known True Positives (Must Always Be Detected)

| TP Category | Contract | Expected Detector |
|-------------|----------|-------------------|
| Reentrancy | `reentrancy_issues.sol` | `classic-reentrancy` |
| Read-Only Reentrancy | `CurveFinance2023Attack.sol` | `readonly-reentrancy` |
| Access Control | `validation_issues.sol` | `array-bounds-check` |
| Vault Inflation | `erc4626_vaults/` | `vault-share-inflation`, `vault-donation-attack` |
| Vault DOS | `VulnerableVault_WithdrawalDOS.sol` | `vault-withdrawal-dos` |
| Chain-ID Missing | `cross_chain/` | `missing-chainid-validation`, `cross-chain-replay` |
| Delegatecall | `UserControlledDelegatecall.sol` | `delegatecall-untrusted-library` |
| Proxy Storage | `ProxyStorageCollision.sol` | `proxy-storage-collision` |
| Flash Loan | `VulnerableFlashLoan.sol` | `flash-loan-price-manipulation-advanced` |
| Price Manipulation | `PriceManipulation.sol` | `price-manipulation` |
| Signatures | `SignatureVulnerabilities.sol` | `missing-eip712-domain` |
| MEV | `FlashLoanArbitrage.sol` | `mev-extractable-value`, `missing-slippage-protection` |
| Governance | `DAOGovernance.sol` | `delegation-loop` |
| ZK Proofs | `ProofBypassAttacks.sol` | `zk-proof-bypass` |
| Restaking | `vulnerable_restaking.sol` | `restaking-withdrawal-delays` |
| AA Paymaster | `VulnerablePaymaster.sol` | `erc4337-paymaster-abuse` |
| EIP-7702 | `DelegateAccessControl.sol` | `eip7702-delegate-access-control` |

## How to Run a Baseline Scan

```bash
# Build release binary
cargo build --release

# Run scan on all 18 targets
for f in \
  tests/contracts/clean_examples/clean_contract.sol \
  tests/contracts/fp_benchmarks/safe_amm_pool.sol \
  tests/contracts/fp_benchmarks/safe_chainlink_consumer.sol \
  tests/contracts/fp_benchmarks/safe_erc4626_vault.sol \
  tests/contracts/fp_benchmarks/safe_flash_loan_provider.sol \
  tests/contracts/basic_vulnerabilities/reentrancy_issues.sol \
  tests/contracts/basic_vulnerabilities/validation_issues.sol \
  tests/contracts/vulnerable/ \
  tests/contracts/flash_loans/ \
  tests/contracts/erc4626_vaults/ \
  tests/contracts/price-manipulation/ \
  tests/contracts/cross_chain/ \
  tests/contracts/delegatecall/ \
  tests/contracts/signatures/ \
  tests/contracts/specialized/ \
  tests/contracts/restaking/ \
  tests/contracts/account_abstraction/ \
  tests/contracts/amm_context/; do
  COUNT=$(./target/release/soliditydefend -f json "$f" 2>/dev/null | \
    python3 -c "
import sys, json
data = sys.stdin.read()
lines = data.split('\n')
json_lines, in_json, brace_count = [], False, 0
for line in lines:
    if not in_json and line.strip().startswith('{'):
        in_json = True
    if in_json:
        json_lines.append(line)
        brace_count += line.count('{') - line.count('}')
        if brace_count == 0: break
print(len(json.loads('\n'.join(json_lines)).get('findings', [])))" 2>/dev/null)
  echo "$COUNT $f"
done
```

## Baselines

See individual baseline files:
- [v2.0.1-v16-baseline.md](v2.0.1-v16-baseline.md) — v16 baseline (81 detectors all active, 18.4% precision, 0 disabled)
- [v1.10.23-v15-baseline.md](v1.10.23-v15-baseline.md) — v15 baseline (67 detectors, 18.4% precision)
- [v1.10.22-v14-baseline.md](v1.10.22-v14-baseline.md) — Phase 1 baseline (v14, 174 zero-TP detectors removed)
- [v1.10.21-v13-baseline.md](v1.10.21-v13-baseline.md) — v13 baseline (90 obsolete detectors removed)
- [v1.10.20-v12-baseline.md](v1.10.20-v12-baseline.md) — v12 baseline (after precision audit)
- [v1.10.20-baseline.md](v1.10.20-baseline.md) — FP reduction v6 baseline
- [v1.10.19-baseline.md](v1.10.19-baseline.md) — FP reduction v5 baseline

## FP Reduction History

| Version | Round | Detectors | FPs Eliminated | Total Findings | Clean FPs | Recall |
|---------|-------|-----------|----------------|----------------|-----------|--------|
| v1.10.14 | v1 | 10 | — | — | — | — |
| v1.10.16 | v2 | 10 | 37 | — | — | — |
| v1.10.17 | v3 | 10 | 88 | — | — | — |
| v1.10.18 | v4 | 10 | 52 (net -22) | 1,776 | 45 | — |
| v1.10.19 | v5 | 20 | 191 | 1,585 | 42 | — |
| v1.10.20 | v6 | 30 | 585 | 1,000 | 26 | — |
| v1.10.20 | v7 | 331+14 | 254 | 746 | 0 | — |
| v1.10.20 | v8 | 7 | 319 | 427 | 0 | — |
| v1.10.20 | v9 | 9 | 81 | 346 | 0 | 75/78 |
| v1.10.20 | v10 | 4 | — | ~346 | 0 | 78/78 |
| v1.10.21 | v11 | 73 disabled + 15 fixed | 365 secure-file FPs | — | 4 | 78/78 |
| v1.10.21 | v12 | baseline | — | 1,089 | 3 | 78/78 |
| v1.10.21 | v13 | 90 removed | 649 | 440 | 0 | 77/77 |
| v1.10.22 | v14 | 174 removed | 1,568 | 1,142 | 0 | 77/77 |
| v1.10.23 | v15 | 20+ tightened | 724 | 418 | 0 | 77/77 |
| v2.0.1 | v16 | 3 re-enabled | 215 | 418 | 0 | 77/77 |
| v2.0.3 | v17 | 22 consolidated | 58 | — | 0 | 103/103 |
| v2.0.4 | v18 | 6 consolidated | 4 | — | 0 | 103/103 |
| v2.0.5 | v19 | 6 domain-filtered | 8 | — | 0 | 103/103 |
| v2.0.6 | v20 | 3 domain-filtered | 3 | — | 0 | 103/103 |
| v2.0.7 | v21 | 2 domain-filtered | 4 | — | 0 | 103/103 |
| v2.0.8 | v22 | 46 GT reclassified | 46 | — | 0 | 149/149 |
| v2.0.11 | v23 | 8 registered, 6 fixed, 1 FP filter | +174 TPs | 368 (ext.) | 0 | 149/149 |

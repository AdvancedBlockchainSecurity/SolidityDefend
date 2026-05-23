# Testing Guide

This document describes the testing methodology and real-world validation of SolidityDefend.

## Table of Contents

- [Unit Tests](#unit-tests)
- [Real-World Contract Testing](#real-world-contract-testing)
- [Framework Detection Testing](#framework-detection-testing)
- [Detector Validation](#detector-validation)
- [Performance Benchmarks](#performance-benchmarks)

## Unit Tests

Run the test suite:

```bash
# All tests
cargo test --workspace

# Library tests only
cargo test --workspace --lib

# Specific crate
cargo test -p detectors

# With output
cargo test -- --nocapture
```

### Test Results (v2.0.10)

```
Total: 444 detector tests + 4 parser tests + 13 IR tests
Ground truth: 122 contracts (43 clean, 79 vulnerable, 149 expected TPs)
Ground truth coverage: 100% of test corpus
Clean contract FP rate: 0% (across 43 clean/secure contracts)
Parse errors: 0 (all 122 contracts parse successfully)
Recall: 100% (149/149 TPs detected, 0 false negatives)
External validation: 63 contracts from vulnerable-smart-contract-examples (222 findings, 0 errors)
```

### Regression Test Coverage (v2.0.10)

The following detectors have inline unit tests for their core detection logic:

| Detector | Tests | Key coverage |
|----------|-------|-------------|
| `classic-reentrancy` | 5 | Pull-payment pattern (skip vs. not-skip), OZ PullPayment, escrow |
| `missing-access-modifiers` | 11 | Ownership-change verbs, inline access control, proxy context |
| `unchecked-external-call` | 5 | Call-options wrapper peeling, array exclusion, inline success check |
| `delegatecall-return-ignored` | 7 | Statement detection, captured-but-not-validated, require/if checks |
| `bridge-token-mint-control` | 7 | Empty modifier detection, require/revert/checkRole, inherited modifiers |

## Real-World Contract Testing

SolidityDefend is validated against production contracts from leading DeFi protocols.

### Test Cases

#### 1. Proxy Contracts (OpenZeppelin v5.0)

**Source:** OpenZeppelin Contracts v5.0.0

**Files Tested:**
- `Proxy.sol` - Abstract base proxy
- `ERC1967Proxy.sol` - ERC-1967 compliant proxy
- `ERC1967Utils.sol` - Proxy utility library
- `TransparentUpgradeableProxy.sol` - Transparent proxy pattern
- `BeaconProxy.sol` - Beacon proxy pattern
- `UpgradeableBeacon.sol` - Beacon controller

**Results:**
| Severity | Count |
|----------|-------|
| Critical | 4 |
| High | 17 |
| Medium | 7 |
| **Total** | **28** |

**Analysis Time:** 0.08s

**Key Findings:**
- Beacon downgrade vulnerabilities
- EXTCODESIZE bypass risks
- Missing storage gaps
- Upgrade event emissions

#### 2. Upgradeable Contracts (OpenZeppelin + Compound)

**Source:** OpenZeppelin Upgradeable v5.0.0 + Compound Protocol

**Files Tested:**
- `Initializable.sol` - Initialization guard
- `UUPSUpgradeable.sol` - UUPS upgrade pattern
- `OwnableUpgradeable.sol` - Upgradeable ownership
- `Comptroller.sol` - Compound Comptroller (62KB)
- `ComptrollerStorage.sol` - Comptroller storage layout

**Results:**
| Severity | Count |
|----------|-------|
| Critical | 21 |
| High | 31 |
| Medium | 67 |
| Low | 12 |
| Info | 8 |
| **Total** | **139** |

**Analysis Time:** 1.02s

**Key Findings:**
- Missing `_disableInitializers()` calls
- Single-step ownership transfers
- Oracle manipulation risks
- MEV extraction opportunities
- Access control patterns

#### 3. Foundry Project (Uniswap Permit2)

**Source:** Uniswap Permit2

**Project Structure:**
```
foundry-permit2/
├── foundry.toml
└── src/
    ├── Permit2.sol
    ├── SignatureTransfer.sol
    ├── AllowanceTransfer.sol
    └── EIP712.sol
```

**Framework Detection:** Foundry (auto-detected)

**Results:**
| Severity | Count |
|----------|-------|
| Critical | 2 |
| High | 30 |
| Medium | 16 |
| Low | 3 |
| Info | 3 |
| **Total** | **54** |

**Analysis Time:** 0.05s

**Key Findings:**
- Zero address checks
- Block stuffing vulnerabilities
- Circular dependency patterns
- DoS via unbounded arrays

#### 4. Hardhat Project (Aave V3)

**Source:** Aave V3 Core

**Project Structure:**
```
hardhat-aave/
├── hardhat.config.js
└── contracts/
    ├── Pool.sol
    ├── PoolStorage.sol
    ├── SupplyLogic.sol
    ├── BorrowLogic.sol
    └── FlashLoanSimpleReceiverBase.sol
```

**Framework Detection:** Hardhat (auto-detected)

**Results:**
| Severity | Count |
|----------|-------|
| Critical | 23 |
| High | 44 |
| Medium | 51 |
| Low | 24 |
| Info | 4 |
| **Total** | **146** |

**Analysis Time:** 0.31s

**Key Findings:**
- MEV extractable value
- Flash loan reentrancy risks
- Oracle time window attacks
- ERC-777 hook vulnerabilities
- Cross-function reentrancy

## Framework Detection Testing

SolidityDefend automatically detects project frameworks:

### Foundry Detection

**Triggers:**
- Presence of `foundry.toml`
- `src/` directory structure
- `lib/` dependency directory

**Behavior:**
```
=== SolidityDefend Project Analysis ===
Framework: Foundry (auto-detected)
Project Root: /path/to/project

Source Directories:
  [SCAN] src - N files
  [SKIP] test - excluded by default
  [SKIP] script - excluded by default
  [DEPS] lib - use --include-deps to scan
```

### Hardhat Detection

**Triggers:**
- Presence of `hardhat.config.js` or `hardhat.config.ts`
- `contracts/` directory structure
- `node_modules/` dependency directory

**Behavior:**
```
=== SolidityDefend Project Analysis ===
Framework: Hardhat (auto-detected)
Project Root: /path/to/project

Source Directories:
  [SCAN] contracts - N files
  [SKIP] test - excluded by default
  [SKIP] tests - excluded by default
  [DEPS] node_modules - use --include-deps to scan
```

### Plain Detection

**Triggers:**
- No framework-specific files detected
- Fallback for generic Solidity directories

**Behavior:**
```
=== SolidityDefend Project Analysis ===
Framework: Plain (auto-detected)
Project Root: /path/to/project

Source Directories:
  [SCAN] . - N files
```

## Detector Validation

### Detector Count

```bash
soliditydefend --list-detectors | wc -l
# 333 detectors
```

### Detector Categories

| Category | Count | Examples |
|----------|-------|----------|
| Reentrancy | 6+ | classic, hook-based, read-only, transient |
| Access Control | 15+ | missing modifiers, role escalation |
| DeFi/MEV | 28+ | sandwich, JIT liquidity, frontrunning |
| Oracle | 10+ | manipulation, stale data, TWAP |
| Proxy/Upgradeable | 45+ | UUPS, beacon, storage collision |
| Flash Loan | 8+ | callback exploitation, reentrancy |
| EIP-7702 | 11 | account delegation, sweeper attacks |
| ERC-4626 | 5+ | vault inflation, share manipulation |

## Performance Benchmarks

### Analysis Speed

| Contract Type | Size | Time |
|--------------|------|------|
| Simple ERC-20 | 200 LOC | 20-30ms |
| ERC-721 with metadata | 500 LOC | 30-50ms |
| Complex vault | 1000 LOC | 80-120ms |
| Diamond proxy | 2000+ LOC | 150-180ms |
| Full DeFi project | 50 contracts | 2-5s |
| Large project | 100+ contracts | 5-10s |

### Resource Usage

| Metric | Typical | Maximum |
|--------|---------|---------|
| Memory | 100-500MB | 2GB |
| CPU | Single core | All cores (parallel) |
| Disk I/O | Minimal | Cache-dependent |

## Running Tests

### Quick Validation

```bash
# Build and test
cargo build --release
cargo test --workspace --lib

# Verify binary
./target/release/soliditydefend --version
./target/release/soliditydefend --list-detectors | head -20
```

### Real-World Test

```bash
# Download test contracts
mkdir -p /tmp/test-contracts
curl -sL "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/v5.0.0/contracts/proxy/Proxy.sol" \
  -o /tmp/test-contracts/Proxy.sol

# Run analysis
soliditydefend /tmp/test-contracts/
```

### Framework Test

```bash
# Create Foundry project
mkdir -p /tmp/foundry-test/src
echo '[profile.default]
src = "src"' > /tmp/foundry-test/foundry.toml
echo 'pragma solidity ^0.8.0; contract Test {}' > /tmp/foundry-test/src/Test.sol

# Verify detection
soliditydefend /tmp/foundry-test/
# Should show: Framework: Foundry (auto-detected)
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Security Scan
  run: |
    soliditydefend -f json -o results.json ./contracts

- name: Check Results
  run: |
    CRITICAL=$(jq '.summary.by_severity.critical // 0' results.json)
    if [ "$CRITICAL" -gt 0 ]; then
      echo "Critical issues found!"
      exit 1
    fi
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success - no high/critical issues |
| 1 | Found high or critical issues |
| 2 | Command-line error |
| 3 | File not found |
| 4 | Parse error |
| 5 | Internal error |

## See Also

- [CLI Reference](CLI.md)
- [Usage Guide](USAGE.md)
- [Detector Documentation](DETECTORS.md)

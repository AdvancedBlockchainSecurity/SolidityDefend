# Reentrancy Detectors

**Total:** 6 detectors

---

## Classic Reentrancy

**ID:** `classic-reentrancy`  
**Severity:** High  
**Categories:** ReentrancyAttacks  

### Description

State changes after external calls enable reentrancy attacks (CEI violation).

### FP Reduction: Pull Payment Skip

The detector skips functions that match the **pull payment** pattern, where users claim from a dedicated per-user credit ledger. A function is skipped only when its source contains:
- Ledger keywords: `pending`, `unclaimed`, `claimable`, `owed[`, `escrow[`
- OpenZeppelin helpers: `PullPayment`, `_asyncTransfer`, `withdrawPayments`

Classic `withdraw()` using `balances[msg.sender]` is **not** skipped — that mapping receives deposits and is the canonical CEI-violation target.

### Source

`src/reentrancy.rs`

---

## Hook-Based Reentrancy Enhanced

**ID:** `hook-reentrancy-enhanced`  
**Severity:** High  
**Categories:** DeFi, Reentrancy  

### Description

Detects reentrancy vulnerabilities in Uniswap V4 hooks and similar callback systems where external calls in hooks can re-enter the contract

### Remediation

- Add reentrancy guard (nonReentrant modifier) or follow checks-effects-interactions pattern in hook functions
- Validate callback sender (e.g., require(msg.sender == pool)) to prevent unauthorized reentry

### Source

`defi_advanced/hook_reentrancy_enhanced.rs`

---

## Read-Only Reentrancy

**ID:** `readonly-reentrancy`  
**Severity:** Medium  
**Categories:** ReentrancyAttacks  

### Description

Read-only functions may be vulnerable to view reentrancy

### Source

`src/reentrancy.rs`

---

## Transient Reentrancy Guard Issues

**ID:** `transient-reentrancy-guard`  
**Severity:** Medium  
**Categories:** Reentrancy  

### Description

Detects transient reentrancy guards that may not protect against new EIP-1153 attack vectors

### Source

`transient/guard.rs`

---

## Transient Storage Reentrancy

**ID:** `transient-storage-reentrancy`  
**Severity:** Critical  
**Categories:** Reentrancy, ReentrancyAttacks  

### Description

Detects low-gas reentrancy via EIP-1153 transient storage breaking transfer()/send() safety assumptions

### Source

`transient/reentrancy.rs`

---

## Vault Hook Reentrancy

**ID:** `vault-hook-reentrancy`  
**Severity:** High  
**Categories:** Reentrancy, DeFi  
**CWE:** CWE-362, CWE-841  

### Description

Detects ERC4626 vaults vulnerable to reentrancy attacks via ERC-777/ERC-1363 token callback hooks

### Source

`src/vault_hook_reentrancy.rs`

---


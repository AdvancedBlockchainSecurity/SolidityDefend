# Detector Types

> **Note**: This file documents an older snapshot (209 detectors). For the current complete list of all **333 detectors**, see [detectors/README.md](detectors/README.md) and [detectors/all_detectors.json](detectors/all_detectors.json).

Legacy list of 209 security detectors organized by category.

## Table of Contents

- [AI Agent Security](#ai-agent-security) (3 detectors)
- [AMM & DEX](#amm-dex) (3 detectors)
- [Access Control & Authentication](#access-control-authentication) (4 detectors)
- [Account Abstraction (ERC-4337)](#account-abstraction-erc-4337) (13 detectors)
- [Arithmetic & Integer](#arithmetic-integer) (3 detectors)
- [Cross-Chain & Bridges](#cross-chain-bridges) (5 detectors)
- [DeFi Protocols](#defi-protocols) (3 detectors)
- [Delegation & Governance](#delegation-governance) (3 detectors)
- [Diamond Pattern (EIP-2535)](#diamond-pattern-eip-2535) (5 detectors)
- [Flash Loans](#flash-loans) (5 detectors)
- [Gas & DoS](#gas-dos) (5 detectors)
- [General Security](#general-security) (78 detectors)
- [Layer 2 & Rollups](#layer-2-rollups) (5 detectors)
- [Lending Protocols](#lending-protocols) (2 detectors)
- [MEV Protection](#mev-protection) (5 detectors)
- [Oracle & Price Feeds](#oracle-price-feeds) (3 detectors)
- [Reentrancy](#reentrancy) (6 detectors)
- [Restaking & LRT](#restaking-lrt) (4 detectors)
- [Signature & Cryptography](#signature-cryptography) (4 detectors)
- [Storage & State](#storage-state) (12 detectors)
- [Timing & Randomness](#timing-randomness) (4 detectors)
- [Token Standards (ERC)](#token-standards-erc) (15 detectors)
- [Upgradeable Contracts](#upgradeable-contracts) (1 detectors)
- [Validator & Staking](#validator-staking) (3 detectors)
- [Vault Security (ERC-4626)](#vault-security-erc-4626) (5 detectors)
- [Zero-Knowledge Proofs](#zero-knowledge-proofs) (5 detectors)

---

## AI Agent Security

**Total: 3 detectors**

- **`ai-agent-decision-manipulation`** - AI Agent Decision Manipulation (High)
- **`ai-agent-prompt-injection`** - AI Agent Prompt Injection (High)
- **`ai-agent-resource-exhaustion`** - AI Agent Resource Exhaustion (Medium)

---

## AMM & DEX

**Total: 3 detectors**

- **`amm-invariant-manipulation`** - AMM Invariant Manipulation (High)
- **`amm-k-invariant-violation`** - AMM Constant Product Violation (Critical)
- **`amm-liquidity-manipulation`** - AMM Liquidity Manipulation (Critical)

---

## Access Control & Authentication

**Total: 4 detectors**

- **`eip7702-delegate-access-control`** - EIP-7702 Delegate Access Control (Critical)
- **`enhanced-access-control`** - Enhanced Access Control (Critical)
- **`missing-access-modifiers`** - Missing Access Control Modifiers (Critical)
- **`tx-origin-authentication`** - tx.origin Authentication (Critical)

---

## Account Abstraction (ERC-4337)

**Total: 13 detectors**

- **`aa-account-takeover`** - Account Abstraction Takeover Vulnerability (Critical)
- **`aa-bundler-dos`** - Account Abstraction Bundler DoS (Medium)
- **`aa-bundler-dos-enhanced`** - AA Bundler DOS Enhanced (High)
- **`aa-calldata-encoding-exploit`** - AA Calldata Encoding Exploit (Critical)
- **`aa-entry-point-reentrancy`** - AA Entry Point Reentrancy (Medium)
- **`aa-initialization-vulnerability`** - Account Abstraction Initialization Vulnerability (High)
- **`aa-nonce-management`** - AA Nonce Management Vulnerabilities (High)
- **`aa-paymaster-fund-drain`** - AA Paymaster Fund Drain (Critical)
- **`aa-session-key-vulnerabilities`** - Session Key Vulnerabilities (High)
- **`aa-signature-aggregation`** - AA Signature Aggregation Bypass (Medium)
- **`aa-signature-aggregation-bypass`** - AA Signature Aggregation Bypass (High)
- **`aa-social-recovery`** - Social Recovery Attacks (Medium)
- **`aa-user-operation-replay`** - AA User Operation Replay (High)

---

## Arithmetic & Integer

**Total: 3 detectors**

- **`batch-transfer-overflow`** - Batch Transfer Overflow (Critical)
- **`integer-overflow`** - Integer Overflow/Underflow (High)
- **`post-080-overflow`** - Post-0.8.0 Overflow Detection (Medium)

---

## Cross-Chain & Bridges

**Total: 5 detectors**

- **`bridge-message-verification`** - Bridge Message Verification (Critical)
- **`bridge-token-mint-control`** - Bridge Token Minting Control (Critical)
- **`cross-chain-message-ordering`** - Cross-Chain Message Ordering (High)
- **`cross-chain-replay`** - Cross-Chain Replay Attack (Critical)
- **`cross-rollup-atomicity`** - Cross-Rollup Atomicity (Critical)

---

## DeFi Protocols

**Total: 3 detectors**

- **`defi-jit-liquidity-attacks`** - JIT Liquidity Attacks (High)
- **`defi-liquidity-pool-manipulation`** - Liquidity Pool Manipulation (Critical)
- **`defi-yield-farming-exploits`** - Yield Farming Exploits (High)

---

## Delegation & Governance

**Total: 3 detectors**

- **`delegation-loop`** - Delegation Loop Vulnerability (High)
- **`flashloan-governance-attack`** - Flash Loan Governance Attack (High)
- **`test-governance`** - Governance Attacks (High)

---

## Diamond Pattern (EIP-2535)

**Total: 5 detectors**

- **`diamond-delegatecall-zero`** - Diamond Delegatecall to Zero Address (Critical)
- **`diamond-init-reentrancy`** - Diamond Initialization Reentrancy (High)
- **`diamond-loupe-violation`** - Diamond Loupe Standard Violation (Medium)
- **`diamond-selector-collision`** - Diamond Function Selector Collision (High)
- **`diamond-storage-collision`** - Diamond Storage Collision (Critical)

---

## Flash Loans

**Total: 5 detectors**

- **`flash-loan-collateral-swap`** - Flash Loan Collateral Swap (High)
- **`flash-loan-governance-attack`** - Flash Loan Governance Attack (Critical)
- **`flash-loan-price-manipulation-advanced`** - Flash Loan Price Manipulation Advanced (Critical)
- **`flash-loan-reentrancy-combo`** - Flash Loan Reentrancy Combo (Critical)
- **`flash-loan-staking`** - Flash Loan Staking Attack (Critical)

---

## Gas & DoS

**Total: 5 detectors**

- **`dos-failed-transfer`** - DoS by Failed Transfer (High)
- **`dos-unbounded-operation`** - DOS via Unbounded Operation (High)
- **`excessive-gas-usage`** - Excessive Gas Usage (Low)
- **`gas-griefing`** - Gas Griefing Attack (Medium)
- **`gas-price-manipulation`** - Gas Price Manipulation (Medium)

---

## General Security

**Total: 78 detectors**

- **`array-bounds-check`** - Array Bounds Check (High)
- **`array-length-mismatch`** - Array Length Mismatch (Medium)
- **`auction-timing-manipulation`** - Auction Timing Manipulation (High)
- **`autonomous-contract-oracle-dependency`** - Autonomous Contract Oracle Dependency (Medium)
- **`avs-validation-bypass`** - AVS Validation Bypass (High)
- **`celestia-data-availability`** - Celestia Data Availability (High)
- **`centralization-risk`** - Centralization Risk (High)
- **`circular-dependency`** - Circular Dependency (High)
- **`create2-frontrunning`** - CREATE2 Frontrunning Protection (High)
- **`dangerous-delegatecall`** - Dangerous Delegatecall (Critical)
- **`default-visibility`** - Default Visibility (Medium)
- **`deprecated-functions`** - Deprecated Functions (Low)
- **`division-before-multiplication`** - Division Before Multiplication (Medium)
- **`eip7702-batch-phishing`** - EIP-7702 Batch Phishing (High)
- **`eip7702-init-frontrun`** - EIP-7702 Initialization Front-Running (Critical)
- **`eip7702-sweeper-detection`** - EIP-7702 Malicious Sweeper Detection (Critical)
- **`eip7702-txorigin-bypass`** - EIP-7702 tx.origin Bypass (High)
- **`emergency-function-abuse`** - Emergency Function Abuse (Medium)
- **`emergency-pause-centralization`** - Emergency Pause Centralization (Medium)
- **`emergency-withdrawal-abuse`** - Emergency Withdrawal Abuse (Medium)
- **`enhanced-input-validation`** - Enhanced Input Validation (High)
- **`extcodesize-bypass`** - EXTCODESIZE Bypass Detection (Medium)
- **`external-calls-loop`** - External Calls in Loop (High)
- **`flashloan-price-oracle-manipulation`** - Flash Loan Price Oracle Manipulation (Critical)
- **`flashmint-token-inflation`** - Flash Mint Token Inflation Attack (High)
- **`floating-pragma`** - Floating Pragma (Low)
- **`front-running`** - Front Running (Medium)
- **`front-running-mitigation`** - Missing Front-Running Mitigation (High)
- **`guardian-role-centralization`** - Guardian Role Centralization (Medium)
- **`hardware-wallet-delegation`** - Hardware Wallet Delegation Vulnerability (High)
- **`insufficient-randomness`** - Insufficient Randomness (High)
- **`intent-nonce-management`** - Intent Nonce Management (High)
- **`intent-settlement-validation`** - Intent Settlement Validation (High)
- **`intent-signature-replay`** - Intent Signature Replay (Critical)
- **`intent-solver-manipulation`** - Intent Solver Manipulation (High)
- **`jit-liquidity-sandwich`** - JIT Liquidity Sandwich (High)
- **`liquidity-bootstrapping-abuse`** - Liquidity Bootstrapping Pool Abuse (Medium)
- **`logic-error-patterns`** - Logic Error Patterns (High)
- **`lrt-share-inflation`** - LRT Share Inflation Attack (Critical)
- **`metamorphic-contract`** - Metamorphic Contract Detection (Critical)
- **`missing-chainid-validation`** - Missing Chain-ID Validation (High)
- **`missing-commit-reveal`** - Missing Commit-Reveal Scheme (Medium)
- **`missing-input-validation`** - Missing Input Validation (Medium)
- **`missing-price-validation`** - Missing Price Validation (Medium)
- **`missing-slippage-protection`** - Missing Slippage Protection (High)
- **`missing-zero-address-check`** - Missing Zero Address Check (Medium)
- **`multi-role-confusion`** - Multi-Role Confusion (High)
- **`multisig-bypass`** - Multi-Signature Bypass Detection (Critical)
- **`nonce-reuse`** - Nonce Reuse Vulnerability (Medium)
- **`parameter-consistency`** - Parameter Consistency Check (Medium)
- **`permit-signature-exploit`** - Permit Signature Exploitation (High)
- **`pool-donation-enhanced`** - Pool Donation Attack Enhanced (High)
- **`price-impact-manipulation`** - Price Impact Manipulation (High)
- **`price-oracle-stale`** - Stale Price Oracle Data (Critical)
- **`private-variable-exposure`** - Private Variable Exposure (High)
- **`privilege-escalation-paths`** - Privilege Escalation Paths (High)
- **`redundant-checks`** - Redundant Checks (Low)
- **`reward-calculation-manipulation`** - Reward Calculation Manipulation (Medium)
- **`role-hierarchy-bypass`** - Role Hierarchy Bypass (Critical)
- **`sandwich-attack`** - Sandwich Attack (Medium)
- **`sandwich-resistant-swap`** - Missing Sandwich Attack Protection (High)
- **`selfdestruct-abuse`** - Selfdestruct Abuse (High)
- **`selfdestruct-recipient-manipulation`** - SELFDESTRUCT Recipient Manipulation (High)
- **`shadowing-variables`** - Variable Shadowing (Medium)
- **`short-address-attack`** - Short Address Attack (Medium)
- **`single-oracle-source`** - Single Oracle Source (High)
- **`sovereign-rollup-validation`** - Sovereign Rollup Validation (Medium)
- **`time-locked-admin-bypass`** - Time-Locked Admin Bypass (Critical)
- **`token-decimal-confusion`** - Token Decimal Confusion (High)
- **`token-permit-front-running`** - Token Permit Front-Running (Medium)
- **`token-supply-manipulation`** - Token Supply Manipulation (Critical)
- **`unchecked-external-call`** - Unchecked External Call (Medium)
- **`unchecked-math`** - Unchecked Math Operations (Medium)
- **`uniswapv4-hook-issues`** - Uniswap V4 Hook Vulnerabilities (High)
- **`unprotected-initializer`** - Unprotected Initializer (High)
- **`unsafe-type-casting`** - Unsafe Type Casting (Medium)
- **`withdrawal-delay`** - Withdrawal Delay Vulnerability (High)
- **`yield-farming-manipulation`** - Yield Farming Reward Manipulation (Medium)

---

## Layer 2 & Rollups

**Total: 5 detectors**

- **`l2-bridge-message-validation`** - L2 Bridge Message Validation (Critical)
- **`l2-data-availability`** - L2 Data Availability Failure (High)
- **`l2-fee-manipulation`** - L2 Fee Manipulation (Medium)
- **`optimistic-challenge-bypass`** - Optimistic Rollup Challenge Period Bypass (Critical)
- **`optimistic-fraud-proof-timing`** - Optimistic Fraud Proof Timing (High)

---

## Lending Protocols

**Total: 2 detectors**

- **`lending-borrow-bypass`** - Lending Protocol Borrow Bypass (Critical)
- **`lending-liquidation-abuse`** - Lending Liquidation Abuse (Critical)

---

## MEV Protection

**Total: 5 detectors**

- **`mev-backrun-opportunities`** - MEV Backrun Opportunities (Medium)
- **`mev-extractable-value`** - MEV Extractable Value (High)
- **`mev-priority-gas-auction`** - MEV Priority Gas Auction (Medium)
- **`mev-sandwich-vulnerable-swaps`** - MEV Sandwich Vulnerable Swaps (High)
- **`mev-toxic-flow-exposure`** - MEV Toxic Flow Exposure (Medium)

---

## Oracle & Price Feeds

**Total: 3 detectors**

- **`oracle-manipulation`** - Oracle Price Manipulation (Critical)
- **`oracle-staleness-heartbeat`** - Oracle Staleness Heartbeat (Medium)
- **`oracle-time-window-attack`** - Oracle Time Window Attack (High)

---

## Reentrancy

**Total: 6 detectors**

- **`classic-reentrancy`** - Classic Reentrancy (High)
- **`flashloan-callback-reentrancy`** - Flash Loan Callback Reentrancy (Medium)
- **`hook-reentrancy-enhanced`** - Hook-Based Reentrancy Enhanced (High)
- **`readonly-reentrancy`** - Read-Only Reentrancy (Medium)
- **`transient-reentrancy-guard`** - Transient Reentrancy Guard Issues (Medium)
- **`transient-storage-reentrancy`** - Transient Storage Reentrancy (Critical)

---

## Restaking & LRT

**Total: 4 detectors**

- **`restaking-delegation-manipulation`** - Restaking Delegation Manipulation (Critical)
- **`restaking-rewards-manipulation`** - Restaking Rewards Manipulation (Medium)
- **`restaking-slashing-conditions`** - Restaking Slashing Conditions Bypass (Critical)
- **`restaking-withdrawal-delays`** - Restaking Withdrawal Delays Not Enforced (High)

---

## Signature & Cryptography

**Total: 4 detectors**

- **`signature-malleability`** - Signature Malleability (High)
- **`signature-replay`** - Signature Replay Attack (High)
- **`weak-commit-reveal`** - Weak Commit-Reveal Scheme (Medium)
- **`weak-signature-validation`** - Weak Signature Validation (High)

---

## Storage & State

**Total: 12 detectors**

- **`eip7702-storage-collision`** - EIP-7702 Storage Collision (High)
- **`inefficient-storage`** - Inefficient Storage Usage (Low)
- **`invalid-state-transition`** - Invalid State Transition (High)
- **`plaintext-secret-storage`** - Plaintext Secret Storage (High)
- **`storage-collision`** - Storage Collision Vulnerability (Critical)
- **`storage-layout-upgrade`** - Storage Layout Upgrade Violation (Critical)
- **`storage-slot-predictability`** - Storage Slot Predictability (Medium)
- **`transient-storage-composability`** - Transient Storage Composability Issues (High)
- **`transient-storage-misuse`** - Transient Storage Misuse (Medium)
- **`transient-storage-state-leak`** - Transient Storage State Leak (Medium)
- **`uninitialized-storage`** - Uninitialized Storage Pointer (High)
- **`unused-state-variables`** - Unused State Variables (Low)

---

## Timing & Randomness

**Total: 4 detectors**

- **`block-dependency`** - Block Dependency (Medium)
- **`block-stuffing-vulnerable`** - Block Stuffing Vulnerable (High)
- **`deadline-manipulation`** - Deadline Manipulation (Medium)
- **`timestamp-manipulation`** - Timestamp Manipulation (High)

---

## Token Standards (ERC)

**Total: 15 detectors**

- **`erc1155-batch-validation`** - ERC-1155 Batch Validation (Medium)
- **`erc20-approve-race`** - ERC-20 Approve Race Condition (Info)
- **`erc20-infinite-approval`** - Infinite Approval Risk (Low)
- **`erc20-transfer-return-bomb`** - ERC-20 Transfer Return Bomb (Medium)
- **`erc4337-entrypoint-trust`** - ERC-4337 Untrusted EntryPoint (Critical)
- **`erc4337-gas-griefing`** - ERC-4337 Gas Griefing Attacks (Low)
- **`erc4337-paymaster-abuse`** - ERC-4337 Paymaster Abuse (Critical)
- **`erc721-callback-reentrancy`** - ERC-721/1155 Callback Reentrancy (High)
- **`erc721-enumeration-dos`** - ERC-721 Enumeration DOS (Medium)
- **`erc7683-crosschain-validation`** - ERC-7683 Cross-Chain Validation (Critical)
- **`erc777-reentrancy-hooks`** - ERC-777 Reentrancy Hooks (High)
- **`erc7821-batch-authorization`** - ERC-7821 Batch Authorization (High)
- **`erc7821-msg-sender-validation`** - ERC-7821 msg.sender Validation (Medium)
- **`erc7821-replay-protection`** - ERC-7821 Replay Protection (High)
- **`erc7821-token-approval`** - ERC-7821 Token Approval Security (Critical)

---

## Upgradeable Contracts

**Total: 1 detectors**

- **`upgradeable-proxy-issues`** - Upgradeable Proxy Issues (Critical)

---

## Validator & Staking

**Total: 3 detectors**

- **`slashing-mechanism`** - Slashing Mechanism Vulnerability (High)
- **`validator-front-running`** - Validator Front-Running (High)
- **`validator-griefing`** - Validator Griefing Attack (High)

---

## Vault Security (ERC-4626)

**Total: 5 detectors**

- **`vault-donation-attack`** - Vault Donation Attack (High)
- **`vault-fee-manipulation`** - Vault Fee Manipulation (Medium)
- **`vault-hook-reentrancy`** - Vault Hook Reentrancy (High)
- **`vault-share-inflation`** - Vault Share Inflation Attack (Critical)
- **`vault-withdrawal-dos`** - Vault Withdrawal DOS (High)

---

## Zero-Knowledge Proofs

**Total: 5 detectors**

- **`zk-circuit-under-constrained`** - ZK Circuit Under-Constrained (Critical)
- **`zk-proof-bypass`** - ZK Proof Verification Bypass (Critical)
- **`zk-proof-malleability`** - ZK Proof Malleability (Critical)
- **`zk-recursive-proof-validation`** - ZK Recursive Proof Validation (High)
- **`zk-trusted-setup-bypass`** - ZK Trusted Setup Bypass (High)

---

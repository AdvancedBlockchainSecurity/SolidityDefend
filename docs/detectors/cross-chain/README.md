# Cross-Chain Security Detectors

**Total:** 11 detectors

---

## Bridge Message Verification

**ID:** `bridge-message-verification`  
**Severity:** Critical  
**Categories:** CrossChain  

### Description

Detects missing message verification in bridge contracts

### Source

`src/bridge_message_verification.rs`

---

## Bridge Token Minting Control

**ID:** `bridge-token-mint-control`  
**Severity:** Critical  
**Categories:** CrossChain, AccessControl  

### Description

Detects unsafe token minting in bridge contracts. Checks for unrestricted minting (no access control), missing message validation, and missing mint amount limits.

### Modifier Validation (v2.0.10)

The detector validates that modifiers actually enforce access control by scanning the modifier definition body. Empty modifiers (e.g., `modifier onlyTest() { _; }`) are not trusted. The body must contain at least one of: `require()`, `revert()`, `msg.sender`, `if()`, `assert()`, `_checkRole()`, or `_checkOwner()`. Modifiers not defined in the current file are assumed inherited and trusted to avoid false positives.

### Source

`src/bridge_token_minting.rs`

---

## Celestia Data Availability

**ID:** `celestia-data-availability`  
**Severity:** High  
**Categories:** DataAvailability  

### Description

Detects data availability issues in modular blockchains

### Vulnerable Patterns

- No DA proof verification

### Remediation

- Verify DA proof: require(verifyDataRoot(dataRoot, proof), \

### Source

`modular_blockchain/data_availability.rs`

---

## Cross-Chain Message Ordering

**ID:** `cross-chain-message-ordering`  
**Severity:** High  
**Categories:** CrossChain  

### Description

Detects message ordering issues across chains

### Remediation

- Add sequence number: mapping(bytes32 => uint256) public messageNonce

### Source

`modular_blockchain/message_ordering.rs`

---

## Cross-Chain Replay Attack

**ID:** `cross-chain-replay`  
**Severity:** Critical  
**Categories:** CrossChain, Auth  
**CWE:** CWE-294, CWE-345  

### Description

Detects signature/hash generation missing chain ID, enabling replay attacks across chains

### Source

`src/cross_chain_replay.rs`

---

## Cross-Rollup Atomicity

**ID:** `cross-rollup-atomicity`  
**Severity:** Critical  
**Categories:** CrossChain  

### Description

Detects cross-rollup atomic operation issues

### Remediation

- Implement two-phase commit or rollback mechanism

### Source

`modular_blockchain/cross_rollup_atomicity.rs`

---

## Intent Signature Replay

**ID:** `intent-signature-replay`  
**Severity:** Critical  
**Categories:** CrossChain, DeFi  

### Description

Detects missing chainId and nonce validation enabling cross-chain replay attacks in ERC-7683 intents

### Remediation

- Add chainId validation: require(order.originChainId == block.chainid, \
- Add nonce validation and tracking: \
     require(!usedNonces[order.user][order.nonce], \
- After validating nonce, mark it as used: \
      usedNonces[order.user][order.nonce] = true; \
      Or increment sequential nonce: \
      userNonces[order.user]++;
- Include chainId in EIP-712 domain separator: \
     DOMAIN_SEPARATOR = keccak256( \
      abi.encode( \
       keccak256(\

### Source

`erc7683/signature_replay.rs`

---

## L2 Bridge Message Validation

**ID:** `l2-bridge-message-validation`  
**Severity:** Critical  
**Categories:** CrossChain, L2  
**CWE:** CWE-345  

### Description

Detects missing or weak validation in L2↔L1 bridge message processing, including missing Merkle proofs, inadequate finality checks, and replay vulnerabilities

### Source

`src/l2_bridge_message_validation.rs`

---

## L2 Data Availability Failure

**ID:** `l2-data-availability`  
**Severity:** High  
**Categories:** L2, DataAvailability  
**CWE:** CWE-284, CWE-345  

### Description

Detects missing data publication to L1, inadequate data availability guarantees, and lack of force inclusion mechanisms that could lead to censorship or data withholding attacks

### Source

`src/l2_data_availability.rs`

---

## L2 Fee Manipulation

**ID:** `l2-fee-manipulation`  
**Severity:** Medium  
**Categories:** L2, DeFi  
**CWE:** CWE-362, CWE-682  

### Description

Detects vulnerabilities in L2 fee mechanisms including unbounded oracle-based fees, front-runnable fee updates, and lack of fee bounds that could lead to economic attacks or denial of service

### Source

`src/l2_fee_manipulation.rs`

---

## Sovereign Rollup Validation

**ID:** `sovereign-rollup-validation`  
**Severity:** Medium  
**Categories:** L2  

### Description

Detects sovereign rollup state validation issues

### Remediation

- Validate state transitions: require(validateStateTransition(oldState, newState))

### Source

`modular_blockchain/sovereign_rollup.rs`

---


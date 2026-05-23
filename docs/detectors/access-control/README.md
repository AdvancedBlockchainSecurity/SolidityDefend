# Access Control Detectors

**Total:** 15 detectors

---

## Centralization Risk

**ID:** `centralization-risk`  
**Severity:** High  
**Categories:** AccessControl  
**CWE:** CWE-269, CWE-284  

### Description

Detects dangerous concentration of control in single address or entity creating single points of failure

### Vulnerable Patterns

- Single owner with no multi-sig
- Critical functions without timelock

### Remediation

- Implement decentralized governance. \
    Use: (1) Multi-signature wallet (Gnosis Safe), \
    (2) Timelock delays for critical operations, \
    (3) DAO governance with voting mechanisms, \
    (4) Role-based access control (OpenZeppelin AccessControl), \
    (5) Emergency pause with multiple approvers.

### Source

`src/centralization_risk.rs`

---

## Dangerous Delegatecall

**ID:** `dangerous-delegatecall`  
**Severity:** Critical  
**Categories:** AccessControl, Logic  
**CWE:** CWE-494, CWE-829  

### Description

Detects delegatecall to user-controlled or untrusted addresses that can lead to complete contract takeover

### Vulnerable Patterns

- Delegatecall with user-controlled target
- Delegatecall without access control
- Delegatecall without target validation
- Explicit vulnerability marker

### Source

`src/dangerous_delegatecall.rs`

---

## Default Visibility

**ID:** `default-visibility`  
**Severity:** Medium  
**Categories:** AccessControl  
**CWE:** CWE-200  

### Description

Detects functions and state variables using default visibility

### Source

`src/access_control.rs`

---

## Emergency Pause Centralization

**ID:** `emergency-pause-centralization`  
**Severity:** Medium  
**Categories:** AccessControl, BestPractices  

### Description

Detects emergency pause functionality controlled by a single entity without multisig protection

### Source

`src/governance.rs`

---

## Enhanced Access Control

**ID:** `enhanced-access-control`  
**Severity:** Critical  
**Categories:** AccessControl, BestPractices  

### Description

Detects role management flaws and privilege escalation ($953M impact)

### Remediation

- 🚨 CRITICAL: Access control failures caused $953M in losses (2024) \
     \
     ❌ VULNERABLE - Anyone can grant roles: \
     function grantRole(bytes32 role, address account) public { \
      roles[role][account] = true; // No protection! \
     } \
     \
     ✅ PROTECTED - Only admin can grant: \
     bytes32 public constant ADMIN_ROLE = keccak256(\

### Source

`owasp2025/enhanced_access_control.rs`

---

## Guardian Role Centralization

**ID:** `guardian-role-centralization`  
**Severity:** Medium  
**Categories:** AccessControl  

### Description

Detects guardian/emergency roles with excessive power creating centralization risks

### Vulnerable Patterns

- Guardian can pause without timelock or multisig
- Guardian can withdraw funds
- Guardian role assigned to EOA instead of multisig

### Remediation

- Require multisig approval or implement delay mechanism for emergency pause actions
- Emergency withdrawals should route to DAO treasury or require multisig, not go directly to guardian
- Assign guardian role to multisig contract (e.g., Gnosis Safe) rather than EOA

### Source

`access_control_advanced/guardian_role_centralization.rs`

---

## Hardware Wallet Delegation Vulnerability

**ID:** `hardware-wallet-delegation`  
**Severity:** High  
**Categories:** AccessControl, Validation  
**CWE:** CWE-250, CWE-269, CWE-404, CWE-665, CWE-672, CWE-1188  

### Description

Detects unsafe EIP-7702 delegation patterns that can brick hardware wallets or compromise security when delegating EOA control

### Vulnerable Patterns

- Hardcoded relayer dependency
- Unsafe delegation without recovery
- Missing asset protection

### Remediation

- Avoid hardcoded relayer dependencies: \
     (1) Support multiple relayer backends, \
     (2) Allow relayer switching via user signature, \
     (3) Implement fallback to direct transaction submission, \
     (4) Never require single trusted relayer, \
     (5) Follow EIP-7702 decentralization principles.
- Implement delegation recovery: \
     (1) Add removeDelegation function, \
     (2) Allow switching delegation targets, \
     (3) Implement emergency mode fallback, \
     (4) Support direct EOA transactions, \
     (5) Require hardware wallet signature for changes.

### Source

`src/hardware_wallet_delegation.rs`

---

## Missing Access Control Modifiers

**ID:** `missing-access-modifiers`  
**Severity:** Critical  
**Categories:** AccessControl  

### Description

Detects functions that perform critical operations without proper access control modifiers.

### Admin-Only Patterns (v2.0.10)

Functions are flagged when their name contains ownership-change or privileged-operation verbs, including: `setOwner`, `changeOwner`, `updateOwner`, `swapOwner`, `replaceOwner`, `newOwner`, `changeAdmin`, `updateAdmin`, `changeGovernor`, `changeManager`, `setRole`, `grantRole`, `revokeRole`, `setMinter`, `setBurner`, `setOperator`, `setExecutor`, `setUpgrader`, `setPauser`, `transferOwnership`, `renounceOwnership`, `pause`, `unpause`, `upgrade`, `destroy`, `setFee`, `setConfig`, `configure`, `setWhitelist`, `setBlacklist`, and others.

### Source

`src/access_control.rs`

---

## Multi-Role Confusion

**ID:** `multi-role-confusion`  
**Severity:** High  
**Categories:** AccessControl  

### Description

Detects contradictory role requirements and inconsistent access patterns

### Vulnerable Patterns

- Functions with multiple onlyRole modifiers
- Inconsistent access control on paired functions
- Role without clear purpose

### Remediation

- Ensure clear separation of duties - same storage should not be modifiable by multiple unrelated roles
- Paired functions should have consistent access control (same role for both or hierarchical roles)
- Document each role

### Source

`access_control_advanced/multi_role_confusion.rs`

---

## Privilege Escalation Paths

**ID:** `privilege-escalation-paths`  
**Severity:** High  
**Categories:** AccessControl  

### Description

Detects indirect paths to gain higher privileges through function chains

### Vulnerable Patterns

- Public/external functions that call grantRole without proper checks
- Delegatecall in privileged functions
- Functions that modify access control state without proper guards

### Remediation

- Ensure all functions that call grantRole are protected with onlyRole(DEFAULT_ADMIN_ROLE) or equivalent
- Add strict whitelist validation for delegatecall targets in privileged functions

### Source

`access_control_advanced/privilege_escalation_paths.rs`

---

## Role Hierarchy Bypass

**ID:** `role-hierarchy-bypass`  
**Severity:** Critical  
**Categories:** AccessControl  

### Description

Detects role hierarchy violations where lower privilege roles can execute admin functions

### Vulnerable Patterns

- Role grant without DEFAULT_ADMIN_ROLE check
- Multiple roles with overlapping admin privileges
- Role-protected functions without hierarchy validation

### Remediation

- Add onlyRole(DEFAULT_ADMIN_ROLE) modifier to grantRole function or use OpenZeppelin
- Use _setRoleAdmin to establish clear role hierarchy where admin roles control lower privilege roles
- Ensure critical functions like upgradeTo, pause, withdraw use DEFAULT_ADMIN_ROLE or highest privilege role

### Source

`access_control_advanced/role_hierarchy_bypass.rs`

---

## Time-Locked Admin Bypass

**ID:** `time-locked-admin-bypass`  
**Severity:** Critical  
**Categories:** AccessControl  

### Description

Detects timelock circumvention and missing delay enforcement on critical admin functions

### Vulnerable Patterns

- Admin functions not going through timelock
- Missing delay check in upgrade functions
- Direct state changes bypassing proposed→queued→executed flow
- Emergency functions bypassing timelock

### Remediation

- Route all admin functions through timelock contract with schedule→execute pattern
- Add minimum delay period before upgrade execution (e.g., 2-7 days)
- Implement complete timelock flow: propose→queue→wait(delay)→execute

### Source

`access_control_advanced/time_locked_admin_bypass.rs`

---

## tx.origin Authentication

**ID:** `tx-origin-authentication`  
**Severity:** Critical  
**Categories:** AccessControl, BestPractices  
**CWE:** CWE-284, CWE-477  

### Description

Detects use of tx.origin for authentication/authorization which is vulnerable to phishing attacks

### Vulnerable Patterns

- tx.origin in comparison (likely authentication)
- tx.origin in require/if/revert (control flow)

### Source

`src/auth.rs`

---

## Unprotected Initializer

**ID:** `unprotected-initializer`  
**Severity:** High  
**Categories:** AccessControl  
**CWE:** CWE-284, CWE-665  

### Description

Initializer functions lack proper access control

### Source

`src/access_control.rs`

---

## Unprotected Initializer

**ID:** `unprotected-initializer`  
**Severity:** Critical  
**Categories:** AccessControl  
**CWE:** CWE-284  

### Description

Detects initializer functions that can be called by anyone

### Source

`src/access_control.rs`

---


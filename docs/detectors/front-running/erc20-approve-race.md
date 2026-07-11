# ERC20 Approve Race Condition

**Detector ID:** `erc20-approve-race`
**Severity:** Info
**Category:** Front-Running, ERC Standards, MEV
**CWE:** CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization)
**SWC:** SWC-114 (Transaction Order Dependence)

## Description

The ERC20 approve race condition is a well-known vulnerability in the standard ERC20 `approve()` function that allows a malicious spender to extract more tokens than intended by front-running approve transactions.

This detector identifies ERC20 tokens that implement `approve()` without providing safe alternatives like `increaseAllowance()` and `decreaseAllowance()`, making them vulnerable to front-running attacks.

## Vulnerability Details

### The Attack Scenario

1. **Initial State**: Alice has approved Bob for 100 tokens
2. **Alice's Intent**: Alice wants to reduce Bob's approval to 50 tokens
3. **Alice's Action**: Alice calls `approve(bob, 50)`
4. **Bob's Attack**:
   - Bob monitors the mempool and sees Alice's transaction
   - Bob front-runs by calling `transferFrom(alice, bob, 100)` with higher gas
   - Bob extracts the original 100 token allowance
5. **Transaction Ordering**:
   - Bob's `transferFrom(100)` executes first
   - Alice's `approve(50)` executes second
6. **Bob's Second Action**: Bob calls `transferFrom(alice, bob, 50)`
7. **Result**: Bob extracted 150 tokens instead of the intended 50

### Root Cause

The vulnerability exists because `approve()` directly sets the allowance value without checking or validating the current allowance:

```solidity
function approve(address spender, uint256 value) external returns (bool) {
    allowance[msg.sender][spender] = value;  // Direct assignment
    emit Approval(msg.sender, spender, value);
    return true;
}
```

This creates a **check-time-of-use (TOCTOU)** race condition where the spender can use the old allowance before the new approval takes effect.

## Real-World Impact

### Historical Context

- **Discovered**: 2016 by Mikhail Vladimirov
- **Disclosure**: Smart Contract Security Blog (2016)
- **Industry Response**: OpenZeppelin added `increaseAllowance`/`decreaseAllowance` in 2018
- **Current Status**: Still affects many ERC20 tokens due to backward compatibility

### Attack Prerequisites

1. Malicious spender with existing non-zero allowance
2. Mempool monitoring capability (MEV infrastructure)
3. Ability to submit transactions with higher gas prices
4. User attempting to change (not zero-out) an existing approval

### Estimated Impact

- **Severity**: Info (the SWC-114 race is inherent to the ERC-20/6909 standard — every compliant `approve` is affected, including OpenZeppelin v5 which removed `increase/decreaseAllowance`; reported informationally rather than as a per-token defect)
- **Exploitability**: Moderate (requires mempool access and gas optimization)
- **Affected Tokens**: Thousands of ERC20 tokens without safe alternatives
- **Financial Risk**: Potential loss of entire approved amount plus new approval

## Vulnerable Code Examples

### Example 1: Basic Vulnerable ERC20

```solidity
contract VulnerableToken {
    mapping(address => mapping(address => uint256)) public allowance;

    // VULNERABLE: Standard approve without protection
    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    // Missing: increaseAllowance()
    // Missing: decreaseAllowance()
}
```

**Why Vulnerable:**
- Direct allowance assignment
- No safe alternatives provided
- Users forced to use vulnerable `approve()`

### Example 2: Incomplete Protection

```solidity
contract IncompleteProtection {
    mapping(address => mapping(address => uint256)) public allowance;

    // STILL VULNERABLE: This check doesn't prevent the race
    function approve(address spender, uint256 value) external returns (bool) {
        // This only prevents non-zero to non-zero changes
        // But attacker can still extract old value first
        require(allowance[msg.sender][spender] == 0 || value == 0, "Reset to 0 first");

        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }
}
```

**Why Still Vulnerable:**
- Forces two-step process (reset to 0, then set new value)
- Attacker can front-run the first transaction (reset to 0)
- Adds friction without solving the race condition

## Secure Implementation

### Solution 1: increaseAllowance/decreaseAllowance (Recommended)

```solidity
contract SecureToken {
    mapping(address => mapping(address => uint256)) public allowance;

    // Standard approve (users should prefer increase/decrease)
    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    // SECURE: Atomic increase
    function increaseAllowance(address spender, uint256 addedValue) external returns (bool) {
        allowance[msg.sender][spender] += addedValue;
        emit Approval(msg.sender, spender, allowance[msg.sender][spender]);
        return true;
    }

    // SECURE: Atomic decrease
    function decreaseAllowance(address spender, uint256 subtractedValue) external returns (bool) {
        uint256 currentAllowance = allowance[msg.sender][spender];
        require(currentAllowance >= subtractedValue, "Decreased below zero");
        allowance[msg.sender][spender] = currentAllowance - subtractedValue;
        emit Approval(msg.sender, spender, allowance[msg.sender][spender]);
        return true;
    }
}
```

**Why Secure:**
- Additive/subtractive changes instead of direct assignment
- Even if spender uses current allowance, the increase/decrease applies correctly
- No race condition possible

### Solution 2: Approve with Expected Current Value

```solidity
contract SecureTokenExpected {
    mapping(address => mapping(address => uint256)) public allowance;

    // SECURE: Validates current allowance before changing
    function approveWithExpected(
        address spender,
        uint256 expectedCurrent,
        uint256 newValue
    ) external returns (bool) {
        require(
            allowance[msg.sender][spender] == expectedCurrent,
            "Current allowance mismatch"
        );
        allowance[msg.sender][spender] = newValue;
        emit Approval(msg.sender, spender, newValue);
        return true;
    }
}
```

**Why Secure:**
- Atomic check-and-set operation
- Transaction fails if current allowance doesn't match expected
- Spender cannot change allowance between check and set

### Solution 3: Modern Approach (No Standard Approve)

```solidity
contract ModernToken {
    mapping(address => mapping(address => uint256)) public allowance;

    // NO approve() function at all - only safe alternatives

    function setAllowance(address spender, uint256 value) external returns (bool) {
        require(allowance[msg.sender][spender] == 0, "Must be zero");
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function increaseAllowance(address spender, uint256 addedValue) external returns (bool) {
        allowance[msg.sender][spender] += addedValue;
        emit Approval(msg.sender, spender, allowance[msg.sender][spender]);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) external returns (bool) {
        uint256 currentAllowance = allowance[msg.sender][spender];
        require(currentAllowance >= subtractedValue, "Decreased below zero");
        allowance[msg.sender][spender] = currentAllowance - subtractedValue;
        emit Approval(msg.sender, spender, allowance[msg.sender][spender]);
        return true;
    }

    function revokeAllowance(address spender) external returns (bool) {
        allowance[msg.sender][spender] = 0;
        emit Approval(msg.sender, spender, 0);
        return true;
    }
}
```

**Why Secure:**
- Removes vulnerable function entirely
- Forces users to use safe patterns
- Breaks ERC20 standard but provides maximum security

## Detection Strategy

The detector identifies vulnerable contracts by checking:

1. **Is this an ERC20 token?**
   - Has `transfer()`, `transferFrom()`, and `approve()` functions
   - Follows ERC20 interface pattern

2. **Does it have `approve()`?**
   - Function named "approve" with correct signature
   - Takes `address` and `uint256` parameters

3. **Are safe alternatives provided?**
   - Check for `increaseAllowance(address, uint256)`
   - Check for `decreaseAllowance(address, uint256)`

4. **Does `approve()` have built-in protection?**
   - Check for `require()` validating current allowance
   - Check for expected current value parameter
   - Check for SafeERC20 library usage

5. **Report if vulnerable:**
   - `approve()` exists
   - No `increaseAllowance()` or `decreaseAllowance()`
   - No built-in protection in `approve()`

## Best Practices

### For Token Developers

1. **Always implement both alternatives:**
   ```solidity
   function increaseAllowance(address spender, uint256 addedValue) external;
   function decreaseAllowance(address spender, uint256 subtractedValue) external;
   ```

2. **Use OpenZeppelin's ERC20 implementation:**
   - Includes safe alternatives by default
   - Well-tested and audited
   - Industry standard

3. **Document the vulnerability:**
   - Warn users about `approve()` risks in comments
   - Recommend `increaseAllowance`/`decreaseAllowance` in docs
   - Provide migration guides

4. **Consider permit (EIP-2612):**
   - Gasless approvals via signatures
   - No transaction ordering issues
   - Better UX

### For DApp Developers

1. **Never use `approve()` directly:**
   - Always use `increaseAllowance()`/`decreaseAllowance()`
   - Check if token supports safe alternatives first

2. **If `approve()` must be used:**
   - Always reset to 0 first: `approve(spender, 0)`
   - Then set new value: `approve(spender, newValue)`
   - Wait for first transaction to confirm

3. **Use SafeERC20 library:**
   ```solidity
   import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

   using SafeERC20 for IERC20;

   token.safeIncreaseAllowance(spender, amount);
   ```

4. **Implement MEV protection:**
   - Use private transaction pools (Flashbots)
   - Add slippage protection
   - Consider commit-reveal schemes

### For Users

1. **Revoke unused approvals:**
   - Use tools like Revoke.cash
   - Set allowance to 0 when done
   - Don't leave unlimited approvals

2. **Monitor your approvals:**
   - Check active approvals regularly
   - Revoke suspicious or old approvals
   - Use approval tracking tools

3. **Prefer protocols with safe patterns:**
   - Look for `increaseAllowance` usage
   - Check protocol's approval handling
   - Read security audits

## Testing Recommendations

### Unit Tests

```solidity
function test_approve_race_protection() public {
    // Test that increaseAllowance exists
    token.increaseAllowance(spender, 100);
    assertEq(token.allowance(address(this), spender), 100);

    // Test that decreaseAllowance exists
    token.decreaseAllowance(spender, 50);
    assertEq(token.allowance(address(this), spender), 50);
}

function test_approve_race_vulnerability() public {
    // Simulate the attack
    token.approve(attacker, 100);

    // Attacker front-runs
    vm.prank(attacker);
    token.transferFrom(address(this), attacker, 100);

    // Victim's approve executes
    token.approve(attacker, 50);

    // Attacker extracts again
    vm.prank(attacker);
    token.transferFrom(address(this), attacker, 50);

    // Attacker got 150 instead of 50
    assertEq(token.balanceOf(attacker), 150);
}
```

### Integration Tests

1. Test all approval patterns in the token
2. Verify safe alternatives are available
3. Check for proper event emissions
4. Test boundary conditions (zero amounts, max uint256)

## References

- [SWC-114: Transaction Order Dependence](https://swcregistry.io/docs/SWC-114)
- [EIP-20: Token Standard](https://eips.ethereum.org/EIPS/eip-20)
- [EIP-2612: Permit Extension](https://eips.ethereum.org/EIPS/eip-2612)
- [OpenZeppelin ERC20 Implementation](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/ERC20.sol)
- [Mikhail Vladimirov's Original Disclosure (2016)](https://docs.google.com/document/d/1YLPtQxZu1UAvO9cZ1O2RPXBbT0mooh4DYKjA_jp-RLM/)
- [OpenZeppelin Blog: Safe Approve](https://blog.openzeppelin.com/the-new-solidity-dev-stack-buidler-ethers-waffle-typescript)

## Related Detectors

- `token-transfer-frontrun`: Front-running in token transfers
- `allowance-toctou`: Time-of-check-time-of-use in allowances
- `mev-extractable-value`: General MEV extraction patterns
- `tx-ordering-dependency`: Transaction ordering vulnerabilities

## Changelog

- **v1.3.4** (2025-11-12): Initial implementation
  - Detects missing increaseAllowance/decreaseAllowance
  - Checks for ERC20 token patterns
  - Validates approve function protection mechanisms

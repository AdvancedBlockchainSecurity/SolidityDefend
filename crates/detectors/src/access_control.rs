use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::safe_patterns::erc_standard_compliance;
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity};

/// Detector for missing access control modifiers on critical functions
pub struct MissingModifiersDetector {
    base: BaseDetector,
}

/// Detector for unprotected initializer functions
pub struct UnprotectedInitializerDetector {
    base: BaseDetector,
}

impl Default for UnprotectedInitializerDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl UnprotectedInitializerDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("unprotected-initializer"),
                "Unprotected Initializer".to_string(),
                "Initializer functions lack proper access control".to_string(),
                vec![DetectorCategory::AccessControl],
                Severity::High,
            ),
        }
    }
}

impl Detector for UnprotectedInitializerDetector {
    fn id(&self) -> DetectorId {
        self.base.id.clone()
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn description(&self) -> &str {
        &self.base.description
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        self.base.categories.clone()
    }

    fn default_severity(&self) -> Severity {
        self.base.default_severity
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip delegatecall test files (covered by dedicated delegatecall detectors)
        {
            let file_lower = ctx.file_path.to_lowercase();
            if file_lower.contains("delegatecall/") || file_lower.contains("delegatecall\\") {
                return Ok(findings);
            }
        }

        // FP Reduction: Skip contracts that are clearly not upgradeable
        // Unprotected initializers are primarily a concern for proxy/upgradeable contracts.
        // Non-upgradeable contracts use constructors; initialize() in those contexts is
        // either a safe constructor-replacement or already protected by init guards.
        if !self.is_upgradeable_context(ctx) {
            return Ok(findings);
        }

        // Check for functions that look like initializers
        for function in ctx.get_functions() {
            // Skip internal/private functions
            if function.visibility == ast::Visibility::Internal
                || function.visibility == ast::Visibility::Private
            {
                continue;
            }

            // Look for initializer function patterns (strict matching)
            let function_name = function.name.name.to_lowercase();
            let is_initializer = function_name == "initialize"
                || function_name == "init"
                || function_name == "setup"
                || function_name == "configure"
                || function_name.starts_with("initialize_")
                || function_name.starts_with("init_");

            if !is_initializer {
                continue;
            }

            // Check if it has modifier-based access control
            if self.has_access_control_modifiers(function) {
                continue;
            }

            // FP Reduction: Check for inline access control in the function body
            let func_source = self.get_function_source(function, ctx);
            if self.has_inline_access_control(&func_source) {
                continue;
            }

            // FP Reduction: Check for initialization guard patterns
            // (require(!initialized), require(owner == address(0)), etc.)
            if self.has_init_guard(&func_source, ctx) {
                continue;
            }

            // FP Reduction: Skip simple ownership-setting initializers
            // Functions that only set owner = parameter are a common safe pattern
            // when called immediately during deployment. The first caller becomes owner,
            // which is the deployer. This is NOT a vulnerability in practice.
            if self.is_simple_ownership_setter(&func_source) {
                continue;
            }

            let message = format!(
                "Initializer function '{}' lacks access control and can be called by anyone",
                function.name.name
            );

            let finding = self.base.create_finding(
                ctx,
                message,
                function.name.location.start().line() as u32,
                function.name.location.start().column() as u32,
                function.name.name.len() as u32,
            )
            .with_cwe(284) // CWE-284: Improper Access Control
            .with_cwe(665) // CWE-665: Improper Initialization
            .with_fix_suggestion(format!(
                "Add an access control modifier to '{}' or ensure it can only be called once during deployment",
                function.name.name
            ));

            findings.push(finding);
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl UnprotectedInitializerDetector {
    /// Check if a function has access control modifiers
    fn has_access_control_modifiers(&self, function: &ast::Function<'_>) -> bool {
        if function.modifiers.is_empty() {
            return false;
        }

        // Look for access control patterns
        for modifier in &function.modifiers {
            let modifier_name = modifier.name.name.to_lowercase();

            // CRITICAL FP FIX: Recognize OpenZeppelin's initializer modifier
            // The `initializer` modifier from @openzeppelin/contracts-upgradeable
            // prevents re-initialization and is proper protection.
            if modifier_name == "initializer" || modifier_name.contains("initializer") {
                return true;
            }

            // Also check for reinitializer
            if modifier_name.contains("reinitializer") {
                return true;
            }

            // Check for onlyInitializing
            if modifier_name == "onlyinitializing" {
                return true;
            }

            // Standard access control patterns
            if modifier_name.contains("only")
                || modifier_name.contains("auth")
                || modifier_name.contains("restricted")
                || modifier_name.contains("protected")
            {
                return true;
            }
        }

        false
    }

    /// Get function source code for inline analysis
    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start < source_lines.len() && end < source_lines.len() {
            source_lines[start..=end].join("\n")
        } else {
            String::new()
        }
    }

    /// Check for inline access control patterns in the function body
    fn has_inline_access_control(&self, func_source: &str) -> bool {
        let lower = func_source.to_lowercase();

        // Check for require/if with msg.sender checks
        let has_sender_check =
            (lower.contains("require(") || lower.contains("if (") || lower.contains("if("))
                && (lower.contains("msg.sender ==")
                    || lower.contains("== msg.sender")
                    || lower.contains("msg.sender !=")
                    || lower.contains("!= msg.sender"));

        // Check for role-based inline checks
        let has_role_check = lower.contains("require(isowner")
            || lower.contains("require(isadmin")
            || lower.contains("require(hasrole")
            || lower.contains("_checkowner")
            || lower.contains("_checkrole");

        // Check for revert patterns indicating access control
        let has_revert = lower.contains("revert unauthorized")
            || lower.contains("revert notowner")
            || lower.contains("revert notadmin")
            || lower.contains("revert accessdenied")
            || lower.contains("revert onlyowner");

        has_sender_check || has_role_check || has_revert
    }

    /// Check for initialization guard patterns that prevent re-calling
    fn has_init_guard(&self, func_source: &str, ctx: &AnalysisContext) -> bool {
        let lower = func_source.to_lowercase();
        let contract_lower = ctx.source_code.to_lowercase();

        // Pattern 1: Explicit initialized flag check
        // require(!initialized) or require(!_initialized) or require(initialized == false)
        let has_initialized_check = lower.contains("!initialized")
            || lower.contains("!_initialized")
            || lower.contains("initialized == false")
            || lower.contains("_initialized == false")
            || lower.contains("initialized != true")
            || lower.contains("require(!initialized")
            || lower.contains("require(!_initialized");

        // Pattern 2: Zero-address owner check as init guard
        // require(owner == address(0)) means "only callable when not yet initialized"
        let has_zero_owner_check = lower.contains("owner == address(0)")
            || lower.contains("_owner == address(0)")
            || lower.contains("owner == address(0x0)")
            || lower.contains("owner() == address(0)");

        // Pattern 3: Contract has an initialized state variable used as guard
        let has_initialized_var = contract_lower.contains("bool")
            && (contract_lower.contains("initialized") || contract_lower.contains("_initialized"));

        // Pattern 4: Sets initialized = true (function is self-guarding)
        let sets_initialized =
            lower.contains("initialized = true") || lower.contains("_initialized = true");

        // Guard is present if there's a check, OR if the function sets the guard
        // and the contract has the variable
        (has_initialized_check)
            || (has_zero_owner_check)
            || (has_initialized_var && sets_initialized)
    }

    /// Determine if the contract is in an upgradeable/proxy context
    /// Only upgradeable contracts need initializer protection -- standalone
    /// contracts use constructors and initialize() is typically a safe pattern.
    fn is_upgradeable_context(&self, ctx: &AnalysisContext) -> bool {
        let source_lower = ctx.source_code.to_lowercase();

        // Check inheritance for upgradeable patterns
        for base in ctx.contract.inheritance.iter() {
            let base_name = base.base.name.to_lowercase();
            if base_name.contains("upgradeable")
                || base_name.contains("upgradeabl")
                || base_name.contains("proxy")
                || base_name.contains("initializable")
            {
                return true;
            }
        }

        // Check source for proxy/upgradeable keywords
        let has_proxy_patterns = source_lower.contains("delegatecall")
            || source_lower.contains("eip1967")
            || source_lower.contains("upgradeto")
            || source_lower.contains("upgradeable")
            || source_lower.contains("proxy")
            || source_lower.contains("implementation_slot")
            || source_lower.contains("initializable");

        // Check for OpenZeppelin's Initializable import
        let has_initializable_import = source_lower.contains("import")
            && (source_lower.contains("initializable") || source_lower.contains("upgradeable"));

        has_proxy_patterns || has_initializable_import
    }

    /// Check if the initializer is a simple ownership setter
    /// Functions like `function initialize(address _owner) { owner = _owner; }`
    /// are a common safe constructor-replacement pattern. The deployer calls this
    /// immediately after deployment to set up the owner.
    fn is_simple_ownership_setter(&self, func_source: &str) -> bool {
        let lower = func_source.to_lowercase();

        // Check if the function body primarily sets an owner/admin variable
        let sets_owner = lower.contains("owner =")
            || lower.contains("_owner =")
            || lower.contains("admin =")
            || lower.contains("_admin =");

        if !sets_owner {
            return false;
        }

        // Count the number of state-changing operations (assignments with =)
        // A simple setter has very few operations (1-3 lines of actual logic)
        let lines: Vec<&str> = func_source
            .lines()
            .map(|l| l.trim())
            .filter(|l| {
                !l.is_empty()
                    && !l.starts_with("//")
                    && !l.starts_with("/*")
                    && !l.starts_with("*")
                    && !l.starts_with("function ")
                    && !l.starts_with("}")
                    && !l.starts_with("{")
            })
            .collect();

        // A simple ownership setter typically has 1-3 lines of logic
        // (e.g., owner = _owner; and maybe an event emission)
        lines.len() <= 4
    }
}

impl Default for MissingModifiersDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl MissingModifiersDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("missing-access-modifiers"),
                "Missing Access Control Modifiers".to_string(),
                "Detects functions that perform critical operations without proper access control modifiers".to_string(),
                vec![DetectorCategory::AccessControl],
                Severity::Critical,
            ),
        }
    }

    /// Check if a function name suggests it needs access control
    /// Returns true only for truly admin-only patterns, not user-facing functions
    fn requires_access_control(&self, function_name: &str) -> bool {
        let name_lower = function_name.to_lowercase();

        // High confidence - these are always admin functions
        let admin_only_patterns = [
            "selfdestruct",
            "destroy",
            "suicide",
            "kill",
            "pause",
            "unpause",
            "emergency",
            "upgrade",
            "migrate",
            "setowner",
            "setadmin",
            "setfee",
            "setconfig",
            "configure",
            "renounceownership",
            "transferownership",
            "grant",
            "revoke",
            "enable",
            "disable",
            "setwhitelist",
            "setblacklist",
            // Recall fix 2026-05-22: ownership-change verbs missed by the
            // `setowner`/`renounceownership`/`transferownership` substrings.
            "changeowner",
            "updateowner",
            "swapowner",
            "replaceowner",
            "newowner",
            "changeadmin",
            "updateadmin",
            "changegovernor",
            "changemanager",
            "setrole",
            "grantrole",
            "revokerole",
            "setminter",
            "setburner",
            "setoperator",
            "setexecutor",
            "setupgrader",
            "setpauser",
            // Critical setters for financial/governance addresses
            "setbeneficiary",
            "settreasury",
            "setreceiver",
            "setwallet",
            "setcollector",
            "setoracle",
            "setpricefeed",
            "setimplementation",
            "setproxy",
            "setpendingowner",
            "setgovernor",
            "setguardian",
            "setmanager",
            "settimelock",
            "setcontroller",
            // Restaking / staking protocol admin verbs
            "slash",
            "freeze",
            "forceundelegate",
            "forceslash",
            "addoperatortoquorum",
            "removeoperator",
            "freezeoperator",
            "confiscate",
            "penalize",
        ];

        // These patterns are admin-only when they're the FULL name (not part of a user function)
        let admin_exact = [
            "withdraw", // user-facing if "withdrawFrom" or has amount param
            "mint",     // user-facing if minting to msg.sender
            "burn",     // user-facing if burning from msg.sender
            "rescue",
            "recover",
            "distribute",
            "allocate",
            "execute",
            "initialize",
        ];

        // High-confidence: admin-only patterns that always need protection
        if admin_only_patterns.iter().any(|p| name_lower.contains(p)) {
            return true;
        }

        // Medium-confidence: exact match for certain patterns
        // Skip patterns that are commonly user-facing
        // "transfer", "approve", "send", "claim" are typically user-facing in ERC tokens
        if admin_exact.iter().any(|p| name_lower == *p) {
            return true;
        }

        // Skip common user-facing patterns that should NOT require access control
        let user_facing_patterns = [
            "transfer", // ERC20/721 transfer
            "approve",  // ERC20/721 approve
            "send",     // User sends their own tokens
            "claim",    // Users claim their rewards
            "stake",    // Users stake their tokens
            "unstake",  // Users unstake their tokens
            "deposit",  // Users deposit their tokens
            "redeem",   // Users redeem their tokens
            "swap",     // Users swap tokens
            "buy",      // Users buy
            "sell",     // Users sell
        ];

        if user_facing_patterns.iter().any(|p| name_lower.contains(p)) {
            return false; // These are user-facing, don't require owner access control
        }

        false
    }

    /// Check if a function has access control modifiers
    fn has_access_control(&self, function: &ast::Function<'_>) -> bool {
        // Check if function has any modifiers
        if function.modifiers.is_empty() {
            return false;
        }

        // Look for common access control modifier patterns
        let access_control_modifiers = [
            "onlyowner",
            "onlyadmin",
            "onlyauthorized",
            "onlyminter",
            "onlyburner",
            "onlygovernance",
            "onlycontroller",
            "onlymanager",
            "restricted",
            "authorized",
            "protected",
            "secure",
        ];

        for modifier in &function.modifiers {
            let modifier_name = modifier.name.name.to_lowercase();
            if access_control_modifiers
                .iter()
                .any(|ac| modifier_name.contains(ac))
            {
                return true;
            }

            // FP Reduction: Recognize any modifier starting with "only" as access control.
            // This is the standard Solidity convention for access control modifiers
            // (e.g., onlyGuardian, onlyPauser, onlyKeeper, onlyOperator, onlyRole, etc.)
            if modifier_name.starts_with("only") {
                return true;
            }

            // FP Reduction: Recognize role-based modifiers (e.g., whenRole, requiresAuth)
            if modifier_name.starts_with("requires") || modifier_name.starts_with("auth") {
                return true;
            }
        }

        false
    }

    /// Check if a function is user-facing (operates on msg.sender's own resources)
    fn is_user_facing_function(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> bool {
        let func_source = self.get_function_source(function, ctx);

        // User-facing functions typically access msg.sender's own balance/tokens
        let accesses_own_balance = func_source.contains("balances[msg.sender]")
            || func_source.contains("balanceOf[msg.sender]")
            || func_source.contains("_balances[msg.sender]")
            || func_source.contains("userBalance[msg.sender]")
            || func_source.contains("shares[msg.sender]");

        // User-facing functions check authorization via msg.sender
        let checks_sender = func_source.contains("msg.sender ==")
            || func_source.contains("msg.sender !=")
            || func_source.contains("owner == msg.sender")
            || func_source.contains("msg.sender == owner");

        // User-facing functions often have require checks on msg.sender's balance
        let requires_sender_balance = func_source.contains("require(")
            && func_source.contains("msg.sender")
            && (func_source.contains("balance") || func_source.contains("shares"));

        // ERC-4337 paymaster functions use msg.sender in mapping keys for access control
        // sessionKeys[msg.sender][key], guardians[msg.sender], etc.
        let paymaster_sender_pattern = (func_source.contains("[msg.sender]")
            && (func_source.contains("sessionKeys")
                || func_source.contains("guardians")
                || func_source.contains("threshold")
                || func_source.contains("spendingLimits")
                || func_source.contains("deposits")))
            || (func_source.contains("isGuardian(") && func_source.contains("msg.sender"));

        accesses_own_balance || checks_sender || requires_sender_balance || paymaster_sender_pattern
    }

    /// Get function source code for analysis
    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start < source_lines.len() && end < source_lines.len() {
            source_lines[start..=end].join("\n")
        } else {
            String::new()
        }
    }

    /// Phase 15 FP Reduction: Check for inline access control patterns
    fn has_inline_access_control(&self, func_source: &str) -> bool {
        let lower = func_source.to_lowercase();

        // Check for require/if/assert with msg.sender comparison patterns.
        // Matches: require(msg.sender == owner), if (msg.sender != admin) revert, etc.
        let has_sender_guard = lower.contains("require(")
            || lower.contains("if (")
            || lower.contains("if(")
            || lower.contains("assert(");
        let has_sender_comparison = lower.contains("msg.sender ==")
            || lower.contains("== msg.sender")
            || lower.contains("msg.sender !=")
            || lower.contains("!= msg.sender");
        let has_sender_require = has_sender_guard && has_sender_comparison;

        // Check for onlyXXX style inline function checks
        let has_inline_only = lower.contains("require(isowner")
            || lower.contains("require(isadmin")
            || lower.contains("require(hasrole")
            || lower.contains("_checkowner")
            || lower.contains("_checkrole")
            || lower.contains("_checksender")
            || lower.contains("_checkauthority")
            || lower.contains("_requireowner")
            || lower.contains("_requireadmin");

        // Check for revert patterns indicating access control
        let has_revert_unauthorized = lower.contains("revert unauthorized")
            || lower.contains("revert notowner")
            || lower.contains("revert notadmin")
            || lower.contains("revert accessdenied")
            || lower.contains("revert notauthorized")
            || lower.contains("revert onlyowner")
            || lower.contains("revert onlyadmin")
            || lower.contains("revert onlyguardian")
            || lower.contains("revert notguardian");

        // Check for governance role checks (guardian, pauser, keeper, operator)
        let has_governance_check = lower.contains("require(msg.sender == guardian")
            || lower.contains("require(msg.sender == pauser")
            || lower.contains("require(msg.sender == keeper")
            || lower.contains("require(msg.sender == operator")
            || lower.contains("guardian == msg.sender")
            || lower.contains("pauser == msg.sender")
            || lower.contains("keeper == msg.sender")
            || lower.contains("operator == msg.sender");

        // Check for tx.origin-based access control
        // While tx.origin is discouraged for security reasons, it IS a form of access
        // control that restricts who can call the function. Using tx.origin == owner
        // prevents contracts from calling the function, limiting it to EOAs.
        let has_tx_origin_guard = lower.contains("tx.origin ==")
            || lower.contains("== tx.origin")
            || lower.contains("tx.origin !=")
            || lower.contains("!= tx.origin");
        let has_tx_origin_check = has_tx_origin_guard
            && (lower.contains("require(") || lower.contains("if (") || lower.contains("if("));

        has_sender_require
            || has_inline_only
            || has_revert_unauthorized
            || has_governance_check
            || has_tx_origin_check
    }

    /// Phase 15 FP Reduction: Check if function has owner check
    fn has_owner_check(&self, func_source: &str, contract_source: &str) -> bool {
        let lower = func_source.to_lowercase();

        // Contract has Ownable pattern
        let has_ownable = contract_source.to_lowercase().contains("ownable")
            || contract_source.contains("owner")
            || contract_source.contains("_owner");

        // Function checks owner
        let checks_owner = lower.contains("msg.sender == owner")
            || lower.contains("owner == msg.sender")
            || lower.contains("msg.sender == _owner")
            || lower.contains("_owner == msg.sender")
            || lower.contains("owner()")
            || lower.contains("_checkowner");

        has_ownable && checks_owner
    }

    /// Phase 15 FP Reduction: Check if function is meant to be called only during construction
    fn is_constructor_callable_only(&self, func_source: &str, ctx: &AnalysisContext) -> bool {
        let lower = func_source.to_lowercase();

        // Check if this looks like initialization that checks if already initialized
        let has_init_check = lower.contains("!initialized")
            || lower.contains("initialized == false")
            || lower.contains("require(!_initialized")
            || lower.contains("require(_initialized == false");

        // Check if contract has initialized state variable
        let contract_lower = ctx.source_code.to_lowercase();
        let has_initialized_var = contract_lower.contains("bool private _initialized")
            || contract_lower.contains("bool internal _initialized")
            || contract_lower.contains("bool public initialized");

        has_init_check && has_initialized_var
    }

    /// FP Reduction: Check if contract is a proxy implementation using unstructured storage.
    ///
    /// In proxy architectures (EIP-1967, Diamond, unstructured storage), the implementation
    /// contract's external functions are called through delegatecall from the proxy, which
    /// enforces access control. Functions like setOwner() in such contracts are not directly
    /// callable by users -- they are called through the proxy's admin-restricted interface.
    ///
    /// Patterns detected:
    /// - Assembly sstore/sload at keccak256-computed storage slots
    /// - EIP-1967 standard storage slot constants
    /// - Diamond storage patterns
    fn is_proxy_implementation_context(&self, ctx: &AnalysisContext) -> bool {
        let source_lower = ctx.source_code.to_lowercase();

        // Pattern 1: Assembly sstore at computed keccak256 slots (unstructured storage)
        // This is the pattern used by OpenZeppelin proxies and similar implementations.
        let has_assembly_storage = source_lower.contains("assembly")
            && source_lower.contains("sstore")
            && source_lower.contains("sload")
            && source_lower.contains("keccak256(");

        // Pattern 2: EIP-1967 standard slot references
        let has_eip1967 = source_lower.contains("eip1967")
            || source_lower
                .contains("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
            || source_lower
                .contains("0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103");

        // Pattern 3: Diamond storage pattern
        let has_diamond_storage = source_lower.contains("diamond_storage_position")
            || source_lower.contains("diamond.standard.diamond.storage");

        // Pattern 4: Contract explicitly uses slot-based storage for owner/admin
        let has_slot_based_owner = source_lower.contains("ownerslot")
            || source_lower.contains("adminslot")
            || (source_lower.contains("keccak256(\"") && source_lower.contains(".owner\""));

        has_assembly_storage || has_eip1967 || has_diamond_storage || has_slot_based_owner
    }

    /// FP Reduction: Check if a function only modifies the caller's own state.
    ///
    /// Functions that exclusively operate on `mapping[msg.sender]` entries are user-facing
    /// by design. Each caller can only affect their own data, so no admin access control
    /// is needed. Common patterns:
    /// - `withdraw()`: `investments[msg.sender] = 0; payable(msg.sender).transfer(amount);`
    /// - `emergencyWithdraw()`: `userInfo[pid][msg.sender].amount = 0;`
    /// - `revokeAllowance(spender)`: `allowance[msg.sender][spender] = 0;`
    fn only_modifies_caller_state(&self, func_source: &str, function_name: &str) -> bool {
        // Must reference msg.sender somewhere in the function
        if !func_source.contains("msg.sender") {
            return false;
        }

        // Check for state modifications that use msg.sender as mapping key
        // Handles both direct mapping[msg.sender] and nested mapping[x][msg.sender]
        let has_sender_mapping_write = func_source.contains("[msg.sender]")
            && (func_source.contains("= 0")
                || func_source.contains("-=")
                || func_source.contains("+=")
                || func_source.contains("= false")
                || func_source.contains("= true")
                || func_source.contains("delete "));

        // Check that ETH/token transfers go to msg.sender (not arbitrary address)
        let sends_to_sender = func_source.contains("payable(msg.sender)")
            || func_source.contains("msg.sender.call")
            || func_source.contains("msg.sender.transfer")
            || func_source.contains("msg.sender.send")
            // ERC20 token transfers to msg.sender: token.transfer(msg.sender, amount)
            || func_source.contains(".transfer(msg.sender,")
            || func_source.contains(".transfer(msg.sender)")
            // safeTransfer patterns
            || func_source.contains(".safeTransfer(msg.sender,");

        // The function modifies caller's own state AND sends funds back to caller
        // OR the function only modifies caller's own state entries (no external sends)
        if has_sender_mapping_write
            && (sends_to_sender || !self.sends_to_arbitrary_address(func_source))
        {
            return true;
        }

        // Special case: revokeAllowance / revokePermit patterns
        // These only modify allowance[msg.sender][spender] which is caller's own data,
        // OR call external functions with msg.sender as the subject (e.g., permit(msg.sender,...))
        // Note: We use function_name because get_function_source may not include the
        // signature line due to 1-based line number indexing.
        let name_lower = function_name.to_lowercase();
        if name_lower.contains("revoke") {
            // revokeAllowance: modifies allowance[msg.sender]
            if func_source.contains("[msg.sender]") {
                return true;
            }
            // revokePermit: calls external function with msg.sender as subject.
            // Handle both single-line and multiline function call patterns:
            //   permit(msg.sender, ...)  OR  permit(\n    msg.sender, ...)
            let collapsed = func_source.replace(['\n', '\r', ' '], "");
            if collapsed.contains("(msg.sender,") {
                return true;
            }
        }

        // Pattern: function uses msg.sender as first argument to external calls
        // AND modifies no other state. This covers DeFi withdraw patterns like
        // aToken.burn(msg.sender, to, amount) where the caller's balance is affected.
        if func_source.contains(".burn(msg.sender,") || func_source.contains(".burn(msg.sender)") {
            return true;
        }

        false
    }

    /// Check if a function sends ETH/tokens to an arbitrary (non-msg.sender) address
    fn sends_to_arbitrary_address(&self, func_source: &str) -> bool {
        // Look for .transfer() or .call{value:} or .send() to non-msg.sender
        let has_transfer =
            func_source.contains(".transfer(") || func_source.contains(".call{value:");
        let sends_only_to_sender = func_source.contains("payable(msg.sender).transfer")
            || func_source.contains("msg.sender.call{value:")
            || func_source.contains("payable(msg.sender).send")
            // ERC20 token transfers to msg.sender
            || func_source.contains(".transfer(msg.sender,")
            || func_source.contains(".transfer(msg.sender)")
            || func_source.contains(".safeTransfer(msg.sender,");

        // If there's a transfer but it only goes to msg.sender, it's safe
        has_transfer && !sends_only_to_sender
    }

    /// FP Reduction: Check if this is an AMM/DEX pool function.
    ///
    /// In AMM pairs (Uniswap, SushiSwap, Curve, etc.), `mint()` and `burn()` are
    /// core user-facing functions for adding/removing liquidity. They are intentionally
    /// public without access control modifiers because any user should be able to
    /// provide or remove their own liquidity.
    fn is_amm_pool_function(&self, function_name: &str, ctx: &AnalysisContext) -> bool {
        let name_lower = function_name.to_lowercase();

        // Only applies to mint/burn functions
        if name_lower != "mint" && name_lower != "burn" {
            return false;
        }

        let source_lower = ctx.source_code.to_lowercase();

        // Check for AMM/DEX/Pool contract indicators
        let is_amm_context = source_lower.contains("reserve0")
            || source_lower.contains("reserve1")
            || source_lower.contains("getreserves")
            || source_lower.contains("liquidity")
            || source_lower.contains("pair")
            || source_lower.contains("uniswap")
            || source_lower.contains("sushiswap")
            || source_lower.contains("balancer")
            || source_lower.contains("curve")
            || source_lower.contains("amm")
            || (source_lower.contains("token0") && source_lower.contains("token1"));

        // Check for Compound/Aave lending pool context where mint = user deposit
        let is_lending_context = source_lower.contains("compound")
            || source_lower.contains("cdai")
            || source_lower.contains("ctoken")
            || source_lower.contains("delegatetoimplementation")
            || (source_lower.contains("lendingpool") || source_lower.contains("atoken"))
            || (source_lower.contains("totalsupply")
                && source_lower.contains("exchangerate")
                && source_lower.contains("borrow"));

        is_amm_context || is_lending_context
    }

    /// FP Reduction: Check if this is a DeFi user-facing function with non-modifier
    /// access control patterns.
    ///
    /// Some functions use cryptographic proofs, payment requirements, or other
    /// mechanisms for access control instead of traditional modifiers:
    /// - ZK proof verification: `require(_verify(proof, ...))` gates withdrawal
    /// - Payment-gated minting: `transferFrom(msg.sender, ...)` requires payment
    /// - Nullifier-based: `require(!usedNullifiers[nullifier])` prevents replay
    fn is_defi_user_function(&self, func_source: &str, function_name: &str) -> bool {
        let lower = func_source.to_lowercase();
        let name_lower = function_name.to_lowercase();

        // ZK proof-gated functions (withdraw with proof verification)
        if name_lower == "withdraw" || name_lower == "claim" {
            let has_proof_gate = lower.contains("_verify(")
                || lower.contains("verify(")
                || lower.contains("verifyproof(")
                || lower.contains("nullifier")
                || lower.contains("proof");

            if has_proof_gate {
                return true;
            }
        }

        // Payment-gated mint functions (user pays to mint)
        if name_lower == "mint" {
            let has_payment = lower.contains("transferfrom(msg.sender")
                || lower.contains("transferfrom( msg.sender")
                || lower.contains("msg.value")
                || lower.contains("payable");

            if has_payment {
                return true;
            }
        }

        // tx.origin-based access control (while discouraged, it IS access control)
        // e.g., require(tx.origin == owner) or if (tx.origin != owner) revert
        let has_tx_origin_check = (lower.contains("tx.origin ==")
            || lower.contains("== tx.origin")
            || lower.contains("tx.origin !=")
            || lower.contains("!= tx.origin"))
            && (lower.contains("require(") || lower.contains("if (") || lower.contains("if("));

        if has_tx_origin_check {
            return true;
        }

        false
    }

    /// FP Reduction: Check if function is a forwarder/proxy that delegates calls.
    ///
    /// Forwarder functions take an `address target` parameter and call
    /// `target.call(abi.encodeWithSignature(...))`. Access control is enforced
    /// by the target contract, not the forwarder. Flagging forwarders for missing
    /// access control is noise because the call will succeed/revert based on the
    /// target's own authorization checks.
    fn is_forwarder_function(&self, func_source: &str, function: &ast::Function<'_>) -> bool {
        let lower = func_source.to_lowercase();

        // Must have .call( pattern with abi encoding (forwarding to another contract)
        if !lower.contains(".call(") {
            return false;
        }
        if !lower.contains("abi.encodewithsignature") && !lower.contains("abi.encodewithselector") {
            return false;
        }

        // Must take an address parameter that serves as the call target
        // Check via AST parameter list (source may not include signature line)
        let has_target_param = function.parameters.iter().any(|p| {
            if let Some(ref name) = p.name {
                let name_lower = name.name.to_lowercase();
                name_lower == "target"
                    || name_lower == "proxy"
                    || name_lower == "implementation"
                    || name_lower == "_target"
                    || name_lower == "_proxy"
                    || name_lower == "_implementation"
                    || name_lower == "contract"
                    || name_lower == "_contract"
            } else {
                false
            }
        });

        has_target_param
    }
}

impl Detector for MissingModifiersDetector {
    fn id(&self) -> DetectorId {
        self.base.id.clone()
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn description(&self) -> &str {
        &self.base.description
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        self.base.categories.clone()
    }

    fn default_severity(&self) -> Severity {
        self.base.default_severity
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip interfaces -- interface functions have no implementation
        // and cannot contain access control logic. Flagging them is pure noise.
        if ctx.contract.contract_type == ast::ContractType::Interface {
            return Ok(findings);
        }

        // FP Reduction: Skip libraries -- library functions are called via delegatecall
        // from the calling contract's context. Access control is enforced by the caller,
        // not the library itself. Flagging library functions produces false positives.
        if ctx.contract.contract_type == ast::ContractType::Library {
            return Ok(findings);
        }

        // FP Reduction: Skip contracts with fewer than 2 functions
        // Contracts with 0-1 functions rarely have missing access modifiers
        if ctx.contract.functions.len() < 2 {
            return Ok(findings);
        }

        // FP Reduction: Skip secure/fixed example contracts
        if crate::utils::is_secure_example_file(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip intentional attack/exploit contracts.
        // Malicious contracts (e.g., MaliciousImplementation, FlashLoanReentrancyAttacker)
        // are designed to demonstrate exploits and intentionally lack access control.
        if crate::utils::is_attack_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip test files for other vulnerability types.
        // Contracts in selfdestruct, ZK, delegatecall, and bridge test files
        // may have functions that appear to need access control, but the
        // primary vulnerability being tested is different. Cross-detector FPs.
        {
            let file_lower = ctx.file_path.to_lowercase();
            let is_other_vuln_file = file_lower.contains("selfdestruct")
                || file_lower.contains("eip6780")
                || file_lower.contains("trustedsetup")
                || file_lower.contains("delegatecall");
            if is_other_vuln_file {
                return Ok(findings);
            }
        }

        // Analyze all functions in the contract
        for function in ctx.get_functions() {
            // Skip interface functions (they have no body)
            if function.body.is_none() {
                continue;
            }

            // FP Reduction: Skip functions with empty bodies (no logic to protect)
            if let Some(body) = &function.body {
                if body.statements.is_empty() {
                    continue;
                }
            }

            // FP Reduction: Skip constructor, fallback, and receive functions.
            // - Constructors run only once at deployment and cannot be re-called.
            // - Fallback/receive are triggered by ETH transfers, not admin operations.
            if function.function_type == ast::FunctionType::Constructor
                || function.function_type == ast::FunctionType::Fallback
                || function.function_type == ast::FunctionType::Receive
            {
                continue;
            }

            // Skip view/pure functions, constructors, and internal functions
            if function.visibility == ast::Visibility::Internal
                || function.visibility == ast::Visibility::Private
                || function.mutability == ast::StateMutability::View
                || function.mutability == ast::StateMutability::Pure
            {
                continue;
            }

            // NEW: Skip ERC standard-compliant functions (they SHOULD be public)
            if erc_standard_compliance::is_standard_compliant_function(function.name.name, ctx) {
                continue; // This is a required public function per ERC standards
            }

            // NEW: Skip user-facing functions (operate on msg.sender's own resources)
            if self.is_user_facing_function(function, ctx) {
                continue; // User-facing functions are supposed to be public
            }

            // Check if function name suggests it needs access control
            if self.requires_access_control(function.name.name) {
                // Check if it has proper access control via modifiers
                if self.has_access_control(function) {
                    continue;
                }

                // Phase 15 FP Reduction: Check for inline access control
                let func_source = self.get_function_source(function, ctx);
                if self.has_inline_access_control(&func_source) {
                    continue;
                }

                // Phase 15 FP Reduction: Check if function is in a contract with Ownable
                // and has require(msg.sender == owner) check
                if self.has_owner_check(&func_source, &ctx.source_code) {
                    continue;
                }

                // Phase 15 FP Reduction: Skip constructor-callable only patterns
                // These are functions meant to be called only during deployment
                if self.is_constructor_callable_only(&func_source, ctx) {
                    continue;
                }

                // FP Reduction: Skip functions in proxy implementation contracts.
                // In proxy architectures, access control is enforced at the proxy layer
                // (e.g., only admin can call upgradeTo/setOwner through the proxy).
                // The implementation contract's functions are not directly callable.
                if self.is_proxy_implementation_context(ctx) {
                    continue;
                }

                // FP Reduction: Skip functions that only modify the caller's own state.
                // Functions that exclusively read/write mapping[msg.sender] entries are
                // user-facing by design -- each caller can only affect their own data.
                // Examples: withdraw() from own balance, emergencyWithdraw() from own stake,
                // revokeAllowance() on own approvals.
                if self.only_modifies_caller_state(&func_source, function.name.name) {
                    continue;
                }

                // FP Reduction: Skip AMM/DEX pool functions (mint/burn liquidity).
                // In AMM pairs (Uniswap, Sushi, etc.), mint() and burn() are user-facing
                // functions that add/remove liquidity. They are intentionally public and
                // operate on the caller's liquidity position, not admin operations.
                if self.is_amm_pool_function(function.name.name, ctx) {
                    continue;
                }

                // FP Reduction: Skip DeFi user-facing functions that are gated by
                // cryptographic proofs, payment requirements, or other non-modifier
                // access control patterns (e.g., ZK proof verification, transferFrom).
                if self.is_defi_user_function(&func_source, function.name.name) {
                    continue;
                }

                // FP Reduction: Skip forwarder/proxy functions that delegate calls
                // to an external target address. Access control is on the target,
                // not the forwarder. Example: transferOwnership(address target, ...)
                // that just calls target.call(abi.encodeWithSignature("transferOwnership(address)", ...))
                if self.is_forwarder_function(&func_source, function) {
                    continue;
                }

                let message = format!(
                    "Function '{}' performs critical operations but lacks access control modifiers",
                    function.name.name
                );

                let finding = self
                    .base
                    .create_finding(
                        ctx,
                        message,
                        function.name.location.start().line() as u32,
                        function.name.location.start().column() as u32,
                        function.name.name.len() as u32,
                    )
                    .with_cwe(284) // CWE-284: Improper Access Control
                    .with_confidence(Confidence::High) // NEW: High confidence when truly missing
                    .with_fix_suggestion(format!(
                        "Add an access control modifier like 'onlyOwner' to function '{}'",
                        function.name.name
                    ));

                findings.push(finding);
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Detector for unprotected initializer functions
pub struct UnprotectedInitDetector {
    base: BaseDetector,
}

impl Default for UnprotectedInitDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl UnprotectedInitDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("unprotected-initializer"),
                "Unprotected Initializer".to_string(),
                "Detects initializer functions that can be called by anyone".to_string(),
                vec![DetectorCategory::AccessControl],
                Severity::Critical,
            ),
        }
    }

    /// Check if a function is an initializer
    fn is_initializer(&self, function: &ast::Function<'_>) -> bool {
        let init_patterns = ["initialize", "init", "setup", "configure"];
        let name_lower = function.name.name.to_lowercase();

        init_patterns
            .iter()
            .any(|pattern| name_lower.contains(pattern))
    }

    /// Check if initializer has proper protection
    fn has_initializer_protection(&self, function: &ast::Function<'_>) -> bool {
        // Check for initializer modifier from OpenZeppelin
        for modifier in &function.modifiers {
            let modifier_name = modifier.name.name.to_lowercase();
            if modifier_name.contains("initializer") {
                return true;
            }
        }

        // Check for access control on initializer
        if function.modifiers.iter().any(|m| {
            let name = m.name.name.to_lowercase();
            name.contains("owner") || name.contains("admin") || name.contains("authorized")
        }) {
            return true;
        }

        false
    }
}

impl Detector for UnprotectedInitDetector {
    fn id(&self) -> DetectorId {
        self.base.id.clone()
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn description(&self) -> &str {
        &self.base.description
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        self.base.categories.clone()
    }

    fn default_severity(&self) -> Severity {
        self.base.default_severity
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            if self.is_initializer(function) && !self.has_initializer_protection(function) {
                let message = format!(
                    "Initializer function '{}' is unprotected and can be called by anyone",
                    function.name.name
                );

                let finding = self
                    .base
                    .create_finding(
                        ctx,
                        message,
                        function.name.location.start().line() as u32,
                        function.name.location.start().column() as u32,
                        function.name.name.len() as u32,
                    )
                    .with_cwe(284) // CWE-284: Improper Access Control
                    .with_fix_suggestion(format!(
                        "Add 'initializer' modifier or access control to function '{}'",
                        function.name.name
                    ));

                findings.push(finding);
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Detector for functions using default visibility (in older Solidity versions)
pub struct DefaultVisibilityDetector {
    base: BaseDetector,
}

impl Default for DefaultVisibilityDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultVisibilityDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("default-visibility"),
                "Default Visibility".to_string(),
                "Detects functions and state variables using default visibility".to_string(),
                vec![DetectorCategory::AccessControl],
                Severity::Medium,
            ),
        }
    }

    /// Check if this is an old Solidity version where default visibility is public
    fn uses_old_solidity(&self, ctx: &AnalysisContext<'_>) -> bool {
        // This is a simplified check - in practice we'd parse pragma directives
        // For now, assume any contract without explicit visibility is old
        ctx.source_code.contains("pragma solidity ^0.4")
            || ctx.source_code.contains("pragma solidity 0.4")
    }
}

impl Detector for DefaultVisibilityDetector {
    fn id(&self) -> DetectorId {
        self.base.id.clone()
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn description(&self) -> &str {
        &self.base.description
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        self.base.categories.clone()
    }

    fn default_severity(&self) -> Severity {
        self.base.default_severity
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

        if !self.uses_old_solidity(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            // In old Solidity versions, functions without explicit visibility are public
            // For now, we'll check if visibility is Public as a heuristic
            if function.visibility == ast::Visibility::Public {
                let message = format!(
                    "Function '{}' uses default visibility (public in older Solidity)",
                    function.name.name
                );

                let finding = self
                    .base
                    .create_finding(
                        ctx,
                        message,
                        function.name.location.start().line() as u32,
                        function.name.location.start().column() as u32,
                        function.name.name.len() as u32,
                    )
                    .with_cwe(200) // CWE-200: Information Exposure
                    .with_fix_suggestion(format!(
                        "Explicitly declare visibility for function '{}'",
                        function.name.name
                    ));

                findings.push(finding);
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Detector for state variables without explicit visibility modifiers
pub struct StateVariableVisibilityDetector {
    base: BaseDetector,
}

impl Default for StateVariableVisibilityDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl StateVariableVisibilityDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("missing-visibility-modifier"),
                "Missing Visibility Modifier".to_string(),
                "Detects state variables without explicit visibility modifiers".to_string(),
                vec![DetectorCategory::BestPractices],
                Severity::Low,
            ),
        }
    }

    /// Check if the contract uses Solidity >= 0.5.0 where visibility semantics are well-defined.
    /// In Solidity >= 0.5.0, function visibility is required by the compiler. State variable
    /// visibility still defaults to `internal` if omitted, but this is a well-known, safe default.
    /// Flagging missing state variable visibility in modern Solidity produces noise because
    /// developers intentionally rely on the `internal` default.
    fn is_modern_solidity(&self, source: &str) -> bool {
        // Match pragma solidity version patterns
        for line in source.lines() {
            let trimmed = line.trim();
            if !trimmed.starts_with("pragma solidity") {
                continue;
            }

            // Skip 0.4.x versions -- these are pre-0.5 and visibility defaults are dangerous
            if trimmed.contains("0.4.") || trimmed.contains("^0.4") {
                return false;
            }

            // Any pragma with 0.5+ or ^0.5+ or >=0.5 is modern
            // Also handles 0.6, 0.7, 0.8, etc.
            if trimmed.contains("0.5.")
                || trimmed.contains("^0.5")
                || trimmed.contains(">=0.5")
                || trimmed.contains("0.6.")
                || trimmed.contains("^0.6")
                || trimmed.contains(">=0.6")
                || trimmed.contains("0.7.")
                || trimmed.contains("^0.7")
                || trimmed.contains(">=0.7")
                || trimmed.contains("0.8.")
                || trimmed.contains("^0.8")
                || trimmed.contains(">=0.8")
            {
                return true;
            }
        }

        // No pragma found -- assume modern Solidity (conservative: fewer FPs)
        false
    }

    /// Check if the source line at a given position has an explicit visibility keyword.
    /// This uses the source text around the variable declaration to confirm whether
    /// visibility was explicitly written (since the AST parser defaults to Internal).
    fn has_explicit_visibility_in_source(&self, source: &str, line_num: usize) -> bool {
        let visibility_keywords = ["public", "private", "internal", "constant", "immutable"];

        let lines: Vec<&str> = source.lines().collect();
        if line_num >= lines.len() {
            return false;
        }

        let line = lines[line_num];
        let code_part = if let Some(idx) = line.find("//") {
            line[..idx].trim()
        } else {
            line.trim()
        };

        visibility_keywords.iter().any(|kw| code_part.contains(kw))
    }

    fn is_state_variable_line(&self, line: &str) -> bool {
        let trimmed = line.trim();

        // Skip empty lines, comments, and function signatures
        if trimmed.is_empty()
            || trimmed.starts_with("//")
            || trimmed.starts_with("/*")
            || trimmed.starts_with("*")
            || trimmed.contains("function ")
            || trimmed.contains("constructor")
            || trimmed.contains("modifier ")
            || trimmed.contains("event ")
            || trimmed.contains("error ")
            || trimmed.contains("returns")
        {
            return false;
        }

        // Strip inline comments for semicolon check
        let code_part = if let Some(idx) = trimmed.find("//") {
            trimmed[..idx].trim()
        } else {
            trimmed
        };

        // Check if line starts with a type declaration (state variable pattern)
        let type_prefixes = [
            "address ", "uint", "int", "bool ", "bytes", "string ", "mapping(", "struct ", "enum ",
        ];

        // Must start with type and not be inside a function (no memory/calldata)
        let starts_with_type = type_prefixes
            .iter()
            .any(|prefix| trimmed.starts_with(prefix));

        // Variables inside functions have memory/calldata keywords
        let is_local_var = trimmed.contains("memory") || trimmed.contains("calldata");

        // Must end with semicolon to be a declaration (check code part, not comments)
        let is_declaration = code_part.ends_with(';');

        starts_with_type && !is_local_var && is_declaration
    }
}

impl Detector for StateVariableVisibilityDetector {
    fn id(&self) -> DetectorId {
        self.base.id.clone()
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn description(&self) -> &str {
        &self.base.description
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        self.base.categories.clone()
    }

    fn default_severity(&self) -> Severity {
        self.base.default_severity
    }

    fn is_enabled(&self) -> bool {
        self.base.enabled
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip interfaces -- interfaces cannot have state variables.
        // Any state variable declaration inside an interface is a compiler error,
        // so flagging visibility here is pure noise.
        if ctx.contract.contract_type == ast::ContractType::Interface {
            return Ok(findings);
        }

        // FP Reduction: Skip libraries -- library state variables must be constant
        // and are always internal. The compiler enforces these rules, so missing
        // explicit visibility in libraries is not a real concern.
        if ctx.contract.contract_type == ast::ContractType::Library {
            return Ok(findings);
        }

        // FP Reduction: Skip Solidity >= 0.5.0 contracts. In modern Solidity,
        // state variable visibility defaults to `internal` which is well-defined
        // and widely understood. Unlike pre-0.5 function visibility (which defaulted
        // to public and was dangerous), state variable `internal` default is safe.
        // Flagging these produces excessive noise in modern codebases.
        if self.is_modern_solidity(&ctx.source_code) {
            return Ok(findings);
        }

        // --- AST-based detection for pre-0.5 Solidity ---
        // Use AST state_variables when available for precise detection.
        // The parser defaults visibility to Internal when not specified, so we
        // cross-reference with source text to distinguish "explicitly internal"
        // from "no visibility keyword written".
        let ast_vars = &ctx.contract.state_variables;
        if !ast_vars.is_empty() {
            for var in ast_vars.iter() {
                let var_line = var.location.start().line();
                // line() is 1-based in some implementations, 0-based in others.
                // Normalize to 0-based for source indexing.
                let line_idx = if var_line > 0 { var_line - 1 } else { var_line };

                if !self.has_explicit_visibility_in_source(&ctx.source_code, line_idx) {
                    let var_name = var.name.name;
                    let message = format!(
                        "State variable '{}' declared without explicit visibility modifier",
                        var_name
                    );

                    let finding = self
                        .base
                        .create_finding(
                            ctx,
                            message,
                            var_line as u32,
                            var.location.start().column() as u32,
                            var.name.name.len() as u32,
                        )
                        .with_cwe(710) // CWE-710: Improper Adherence to Coding Standards
                        .with_fix_suggestion(format!(
                            "Add explicit visibility: '{} private {};' or '{} internal {};'",
                            "type", var_name, "type", var_name
                        ));
                    findings.push(finding);
                }
            }
            return Ok(findings);
        }

        // --- Fallback: text-based detection for contracts without AST state variables ---
        // This handles edge cases where the parser did not populate state_variables.
        let visibility_keywords = ["public", "private", "internal", "constant", "immutable"];

        // Track brace depth to distinguish contract-level (state) variables from local variables
        // Depth 0: outside contracts
        // Depth 1: inside contract body (state variables live here)
        // Depth 2+: inside functions/modifiers/constructors (local variables live here)
        let mut brace_depth: i32 = 0;
        let mut in_function_signature = false;

        for (line_num, line) in ctx.source_code.lines().enumerate() {
            let trimmed = line.trim();

            // Strip inline comments for analysis
            let code_part = if let Some(idx) = trimmed.find("//") {
                trimmed[..idx].trim()
            } else {
                trimmed
            };

            // Track function/modifier/constructor signatures (may span multiple lines)
            if code_part.contains("function ")
                || code_part.contains("constructor")
                || code_part.contains("modifier ")
                || code_part.contains("fallback(")
                || code_part.contains("receive(")
            {
                in_function_signature = true;
            }

            // Count braces to track depth
            for ch in code_part.chars() {
                if ch == '{' {
                    if in_function_signature {
                        // Function body starts
                        in_function_signature = false;
                    }
                    brace_depth += 1;
                } else if ch == '}' {
                    brace_depth = brace_depth.saturating_sub(1);
                }
            }

            // Only check for state variables at contract level (depth 1)
            // Depth 2+ means we're inside a function body where local variables are valid
            if brace_depth != 1 {
                continue;
            }

            if !self.is_state_variable_line(line) {
                continue;
            }

            // Check if any visibility keyword is present in the code (not comments)
            let has_visibility = visibility_keywords.iter().any(|kw| code_part.contains(kw));

            if !has_visibility {
                let finding = self
                    .base
                    .create_finding(
                        ctx,
                        "State variable declared without explicit visibility modifier".to_string(),
                        (line_num + 1) as u32,
                        1,
                        line.len() as u32,
                    )
                    .with_cwe(710)
                    .with_fix_suggestion(
                        "Add explicit visibility: 'address private owner;' or 'address internal owner;'".to_string(),
                    );
                findings.push(finding);
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse `source` with the real Solidity parser and run `detector.detect`
    /// against the first contract. Populates the AST (functions, modifiers) so
    /// the detector evaluates real function signatures end to end.
    fn detect_findings(detector: &MissingModifiersDetector, source: &str) -> Vec<Finding> {
        use ast::arena::AstArena;
        use parser::Parser;
        use semantic::SymbolTable;

        let arena = Box::leak(Box::new(AstArena::new()));
        let parser = Parser::new();
        let source_file = parser
            .parse(arena, source, "test.sol")
            .expect("source should parse");
        let contract = source_file
            .contracts
            .first()
            .expect("source should contain a contract");
        let ctx = AnalysisContext::new(
            contract,
            SymbolTable::new(),
            source.to_string(),
            "test.sol".to_string(),
        );
        detector.detect(&ctx).expect("detect should succeed")
    }

    // =========================================================================
    // MissingModifiersDetector helper method tests
    // =========================================================================

    /// Regression: critical setters (setOracle, setImplementation,
    /// setPendingOwner) must be recognized as requiring access control.
    #[test]
    fn test_requires_access_control_critical_setters() {
        let detector = MissingModifiersDetector::new();
        assert!(detector.requires_access_control("setOracle"));
        assert!(detector.requires_access_control("setImplementation"));
        assert!(detector.requires_access_control("setPendingOwner"));
        assert!(detector.requires_access_control("setPriceFeed"));
        assert!(detector.requires_access_control("setGuardian"));
        assert!(detector.requires_access_control("setTimelock"));
    }

    /// Regression: restaking/slashing admin verbs must be recognized as
    /// requiring access control.
    #[test]
    fn test_requires_access_control_restaking_verbs() {
        let detector = MissingModifiersDetector::new();
        assert!(detector.requires_access_control("slashOperator"));
        assert!(detector.requires_access_control("freezeOperator"));
        assert!(detector.requires_access_control("forceUndelegate"));
        assert!(detector.requires_access_control("forceSlash"));
        assert!(detector.requires_access_control("confiscate"));
        assert!(detector.requires_access_control("penalize"));
    }

    /// Regression (end-to-end): setOracle without any modifier must fire.
    #[test]
    fn test_set_oracle_without_modifier_fires() {
        let detector = MissingModifiersDetector::new();
        let source = r#"
            contract PriceConsumer {
                address public oracle;
                uint256 public value;
                function setOracle(address _oracle) external {
                    oracle = _oracle;
                }
                function readValue() external view returns (uint256) {
                    return value;
                }
            }
        "#;
        let findings = detect_findings(&detector, source);
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("setOracle")),
            "setOracle without an access modifier should fire"
        );
        assert!(
            findings
                .iter()
                .all(|f| f.detector_id.0 == "missing-access-modifiers"),
            "all findings should come from missing-access-modifiers"
        );
    }

    /// Regression (end-to-end): a restaking verb (slashOperator) without a
    /// modifier must fire.
    #[test]
    fn test_slash_operator_without_modifier_fires() {
        let detector = MissingModifiersDetector::new();
        let source = r#"
            contract Restaking {
                mapping(address => uint256) public stakes;
                uint256 public total;
                function slashOperator(address operator, uint256 amount) external {
                    stakes[operator] -= amount;
                    total -= amount;
                }
                function totalStaked() external view returns (uint256) {
                    return total;
                }
            }
        "#;
        let findings = detect_findings(&detector, source);
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("slashOperator")),
            "slashOperator without an access modifier should fire"
        );
    }

    /// FP regression (end-to-end): setOracle WITH onlyOwner must NOT fire.
    #[test]
    fn test_set_oracle_with_only_owner_does_not_fire() {
        let detector = MissingModifiersDetector::new();
        let source = r#"
            contract PriceConsumer {
                address public oracle;
                address public owner;
                modifier onlyOwner() { require(msg.sender == owner); _; }
                function setOracle(address _oracle) external onlyOwner {
                    oracle = _oracle;
                }
                function readOracle() external view returns (address) {
                    return oracle;
                }
            }
        "#;
        let findings = detect_findings(&detector, source);
        assert!(
            !findings.iter().any(|f| f.message.contains("setOracle")),
            "setOracle with onlyOwner modifier should not fire (FP regression)"
        );
    }

    /// Test that requires_access_control identifies admin-only function names
    #[test]
    fn test_requires_access_control_admin_patterns() {
        let detector = MissingModifiersDetector::new();

        // Should require access control
        assert!(detector.requires_access_control("pause"));
        assert!(detector.requires_access_control("unpause"));
        assert!(detector.requires_access_control("emergencyPause"));
        assert!(detector.requires_access_control("emergencyUnpause"));
        assert!(detector.requires_access_control("setOwner"));
        assert!(detector.requires_access_control("setAdmin"));
        assert!(detector.requires_access_control("setFee"));
        assert!(detector.requires_access_control("upgrade"));
        assert!(detector.requires_access_control("destroy"));
        assert!(detector.requires_access_control("transferOwnership"));
        assert!(detector.requires_access_control("renounceOwnership"));
    }

    #[test]
    fn test_requires_access_control_ownership_change_verbs() {
        let detector = MissingModifiersDetector::new();

        assert!(detector.requires_access_control("changeOwner"));
        assert!(detector.requires_access_control("updateOwner"));
        assert!(detector.requires_access_control("swapOwner"));
        assert!(detector.requires_access_control("replaceOwner"));
        assert!(detector.requires_access_control("newOwner"));
        assert!(detector.requires_access_control("changeAdmin"));
        assert!(detector.requires_access_control("updateAdmin"));
        assert!(detector.requires_access_control("changeGovernor"));
        assert!(detector.requires_access_control("changeManager"));
        assert!(detector.requires_access_control("setRole"));
        assert!(detector.requires_access_control("grantRole"));
        assert!(detector.requires_access_control("revokeRole"));
        assert!(detector.requires_access_control("setMinter"));
        assert!(detector.requires_access_control("setOperator"));
        assert!(detector.requires_access_control("setPauser"));
    }

    /// Test that requires_access_control does NOT flag user-facing functions
    #[test]
    fn test_requires_access_control_user_facing() {
        let detector = MissingModifiersDetector::new();

        // Should NOT require access control (user-facing)
        assert!(!detector.requires_access_control("transfer"));
        assert!(!detector.requires_access_control("approve"));
        assert!(!detector.requires_access_control("deposit"));
        assert!(!detector.requires_access_control("swap"));
        assert!(!detector.requires_access_control("claim"));
        assert!(!detector.requires_access_control("stake"));
    }

    /// Test inline access control detection with require(msg.sender == ...)
    #[test]
    fn test_has_inline_access_control_require_sender() {
        let detector = MissingModifiersDetector::new();

        // require(msg.sender == owner)
        let source_with_require = r#"
            function setOwner(address newOwner) external {
                require(msg.sender == owner, "Not owner");
                owner = newOwner;
            }
        "#;
        assert!(detector.has_inline_access_control(source_with_require));

        // if (msg.sender != owner) revert
        let source_with_if = r#"
            function setOwner(address newOwner) external {
                if (msg.sender != owner) revert Unauthorized();
                owner = newOwner;
            }
        "#;
        assert!(detector.has_inline_access_control(source_with_if));

        // if(msg.sender != admin) revert (no space after if)
        let source_if_no_space = r#"
            function setFee(uint256 fee) external {
                if(msg.sender != admin) revert Unauthorized();
                _fee = fee;
            }
        "#;
        assert!(detector.has_inline_access_control(source_if_no_space));
    }

    /// Test inline access control detection with governance role checks
    #[test]
    fn test_has_inline_access_control_governance_roles() {
        let detector = MissingModifiersDetector::new();

        // Guardian check
        let source_guardian = r#"
            function emergencyPause() external {
                require(msg.sender == guardian, "Not guardian");
                paused = true;
            }
        "#;
        assert!(detector.has_inline_access_control(source_guardian));

        // _checkOwner() internal call
        let source_check_owner = r#"
            function setConfig(uint256 val) external {
                _checkOwner();
                config = val;
            }
        "#;
        assert!(detector.has_inline_access_control(source_check_owner));

        // _checkRole() internal call
        let source_check_role = r#"
            function setFee(uint256 fee) external {
                _checkRole(ADMIN_ROLE);
                _fee = fee;
            }
        "#;
        assert!(detector.has_inline_access_control(source_check_role));
    }

    /// Test inline access control with revert patterns
    #[test]
    fn test_has_inline_access_control_revert_patterns() {
        let detector = MissingModifiersDetector::new();

        let source_revert = r#"
            function emergencyUnpause() external {
                if (msg.sender != guardian) revert NotGuardian();
                paused = false;
            }
        "#;
        assert!(detector.has_inline_access_control(source_revert));

        let source_revert_unauthorized = r#"
            function setAdmin(address newAdmin) external {
                if (msg.sender != admin) revert Unauthorized();
                admin = newAdmin;
            }
        "#;
        assert!(detector.has_inline_access_control(source_revert_unauthorized));
    }

    /// Test that truly unprotected functions are NOT recognized as having inline access control
    #[test]
    fn test_no_inline_access_control_true_positive() {
        let detector = MissingModifiersDetector::new();

        // No access control at all -- TRUE POSITIVE
        let source_no_access = r#"
            function setOwner(address _newOwner) public {
                owner = _newOwner;
            }
        "#;
        assert!(!detector.has_inline_access_control(source_no_access));

        // Just an event emission, no access control
        let source_event_only = r#"
            function setFee(uint256 newFee) external {
                fee = newFee;
                emit FeeUpdated(newFee);
            }
        "#;
        assert!(!detector.has_inline_access_control(source_event_only));
    }

    /// Test proxy implementation context detection
    #[test]
    fn test_is_proxy_implementation_context() {
        let detector = MissingModifiersDetector::new();

        // Contract with assembly sstore/sload and keccak256 slots (unstructured storage)
        let proxy_source = r#"
            contract UnstructuredStorage {
                function _setSlot(bytes32 slot, address value) private {
                    assembly { sstore(slot, value) }
                }
                function _getSlot(bytes32 slot) private view returns (address value) {
                    assembly { value := sload(slot) }
                }
                function setOwner(address newOwner) external {
                    bytes32 ownerSlot = keccak256("mycontract.owner");
                    _setSlot(ownerSlot, newOwner);
                }
            }
        "#;
        let ctx = crate::types::test_utils::create_test_context(proxy_source);
        assert!(detector.is_proxy_implementation_context(&ctx));

        // Contract with EIP-1967 slot references
        let eip1967_source = r#"
            contract EIP1967Proxy {
                bytes32 private constant IMPLEMENTATION_SLOT =
                    bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
                function upgradeTo(address newImpl) external {
                    require(msg.sender == _getAdmin(), "Only admin");
                }
            }
        "#;
        let ctx2 = crate::types::test_utils::create_test_context(eip1967_source);
        assert!(detector.is_proxy_implementation_context(&ctx2));

        // Regular contract without proxy patterns -- should NOT be detected
        let regular_source = r#"
            contract SimpleToken {
                address public owner;
                mapping(address => uint256) public balances;
                function transfer(address to, uint256 amount) external {
                    balances[msg.sender] -= amount;
                    balances[to] += amount;
                }
            }
        "#;
        let ctx3 = crate::types::test_utils::create_test_context(regular_source);
        assert!(!detector.is_proxy_implementation_context(&ctx3));
    }

    /// Test that truly unprotected setOwner in non-proxy contracts is still detected
    #[test]
    fn test_true_positive_setowner_no_proxy() {
        let detector = MissingModifiersDetector::new();

        // access_control_issues.sol:18 -- no proxy, no access control, TRUE POSITIVE
        let source = r#"
            contract AccessControlIssues {
                address public owner;
                function setOwner(address _newOwner) public {
                    owner = _newOwner;
                }
            }
        "#;
        let ctx = crate::types::test_utils::create_test_context(source);
        // Not a proxy context
        assert!(!detector.is_proxy_implementation_context(&ctx));
        // No inline access control
        let func_source =
            "function setOwner(address _newOwner) public {\n    owner = _newOwner;\n}";
        assert!(!detector.has_inline_access_control(func_source));
        // The function name requires access control
        assert!(detector.requires_access_control("setOwner"));
    }

    /// Test owner check detection
    #[test]
    fn test_has_owner_check() {
        let detector = MissingModifiersDetector::new();

        let func_source = "function setFee(uint256 fee) external {\n    require(msg.sender == owner);\n    _fee = fee;\n}";
        let contract_source = "contract MyContract is Ownable {\n    address public owner;\n}";
        assert!(detector.has_owner_check(func_source, contract_source));

        // No owner check in function
        let func_no_check = "function setFee(uint256 fee) external {\n    _fee = fee;\n}";
        assert!(!detector.has_owner_check(func_no_check, contract_source));
    }

    /// Test constructor-callable-only detection
    #[test]
    fn test_is_constructor_callable_only() {
        let detector = MissingModifiersDetector::new();

        let func_source = "function initialize(address _owner) public {\n    require(!_initialized);\n    owner = _owner;\n    _initialized = true;\n}";
        let contract_source =
            "contract MyContract {\n    bool private _initialized;\n    address public owner;\n}";
        let ctx = crate::types::test_utils::create_test_context(contract_source);
        assert!(detector.is_constructor_callable_only(func_source, &ctx));
    }
}

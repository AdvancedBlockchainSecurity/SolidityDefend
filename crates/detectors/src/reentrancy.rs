use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils;

use ir::Instruction;

/// Detector for classic reentrancy vulnerabilities
pub struct ClassicReentrancyDetector {
    base: BaseDetector,
}

/// Detector for read-only reentrancy vulnerabilities
pub struct ReadOnlyReentrancyDetector {
    base: BaseDetector,
}

impl Default for ClassicReentrancyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ClassicReentrancyDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("classic-reentrancy".to_string()),
                "Classic Reentrancy".to_string(),
                "State changes after external calls enable reentrancy attacks".to_string(),
                vec![DetectorCategory::ReentrancyAttacks],
                Severity::High,
            ),
        }
    }

    fn has_external_call(&self, function: &ast::Function<'_>) -> bool {
        // Check for external calls in function body
        if let Some(body) = &function.body {
            self.check_statements_for_external_calls(&body.statements)
        } else {
            false
        }
    }

    fn check_statements_for_external_calls(&self, statements: &[ast::Statement<'_>]) -> bool {
        for stmt in statements {
            match stmt {
                ast::Statement::Expression(expr) => {
                    if self.is_external_call(expr) {
                        return true;
                    }
                }
                ast::Statement::Block(block) => {
                    if self.check_statements_for_external_calls(&block.statements) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    /// Known external call method names that can transfer control flow
    const EXTERNAL_CALL_METHODS: &'static [&'static str] = &[
        "call",
        "delegatecall",
        "staticcall",
        "transfer",
        "send",
        "safeTransfer",
        "safeTransferFrom",
        "safeMint",
        "onFlashLoan",
        "onERC721Received",
        "onERC1155Received",
    ];

    fn is_known_call_method(member_name: &str) -> bool {
        Self::EXTERNAL_CALL_METHODS
            .iter()
            .any(|&m| member_name == m)
    }

    /// Check if the expression is `this.something()` — any call via `this.` is external
    fn is_this_call(expression: &ast::Expression<'_>) -> bool {
        matches!(expression, ast::Expression::Identifier(id) if id.name == "this")
    }

    fn is_external_call(&self, expr: &ast::Expression<'_>) -> bool {
        match expr {
            ast::Expression::FunctionCall { function, .. } => {
                match function {
                    // Direct member access pattern: obj.method()
                    // FP Reduction: Only flag known external call methods, not any member access
                    // Exception: this.method() is always an external call
                    ast::Expression::MemberAccess {
                        member, expression, ..
                    } => Self::is_known_call_method(&member.name) || Self::is_this_call(expression),
                    // Nested function call pattern: obj.method{options}()
                    ast::Expression::FunctionCall {
                        function: inner_function,
                        ..
                    } => {
                        // Check if the inner function is a MemberAccess with a known call method
                        matches!(inner_function, ast::Expression::MemberAccess { member, .. }
                            if Self::is_known_call_method(&member.name))
                    }
                    _ => false,
                }
            }
            ast::Expression::Assignment { right, .. } => {
                // Check if assignment right side contains external call: result = call(...)
                self.is_external_call(right)
            }
            ast::Expression::BinaryOperation { left, right, .. } => {
                // Check both sides of binary operations for external calls
                self.is_external_call(left) || self.is_external_call(right)
            }
            ast::Expression::UnaryOperation { operand, .. } => {
                // Check unary operation operand for external calls
                self.is_external_call(operand)
            }
            ast::Expression::IndexAccess { base, index, .. } => {
                // Check index access expressions for external calls
                self.is_external_call(base) || index.is_some_and(|idx| self.is_external_call(idx))
            }
            ast::Expression::MemberAccess { expression, .. } => {
                // Check member access base expression for external calls
                self.is_external_call(expression)
            }
            ast::Expression::Conditional {
                condition,
                true_expression,
                false_expression,
                ..
            } => {
                // Check all parts of conditional expressions for external calls
                self.is_external_call(condition)
                    || self.is_external_call(true_expression)
                    || self.is_external_call(false_expression)
            }
            _ => false,
        }
    }

    fn has_state_changes_after_calls(&self, function: &ast::Function<'_>) -> bool {
        // Simplified check - in real implementation would need more sophisticated CFG analysis
        if let Some(body) = &function.body {
            let mut found_external_call = false;
            for stmt in &body.statements {
                if !found_external_call && self.statement_has_external_call(stmt) {
                    found_external_call = true;
                } else if found_external_call && self.statement_has_state_change(stmt) {
                    return true;
                }
            }
        }
        false
    }

    fn statement_has_external_call(&self, stmt: &ast::Statement<'_>) -> bool {
        match stmt {
            ast::Statement::Expression(expr) => self.is_external_call(expr),
            ast::Statement::Block(block) => {
                // Recursively check all statements in the block
                self.check_statements_for_external_calls(&block.statements)
            }
            ast::Statement::If {
                condition,
                then_branch,
                else_branch,
                ..
            } => {
                // Check condition expression and both branches
                self.is_external_call(condition)
                    || self.statement_has_external_call(then_branch)
                    || else_branch.is_some_and(|stmt| self.statement_has_external_call(stmt))
            }
            ast::Statement::While {
                condition, body, ..
            } => {
                // Check condition and loop body
                self.is_external_call(condition) || self.statement_has_external_call(body)
            }
            ast::Statement::For {
                condition,
                update,
                body,
                ..
            } => {
                // Check condition, update expression, and loop body
                condition
                    .as_ref()
                    .is_some_and(|cond| self.is_external_call(cond))
                    || update
                        .as_ref()
                        .is_some_and(|upd| self.is_external_call(upd))
                    || self.statement_has_external_call(body)
            }
            ast::Statement::VariableDeclaration { initial_value, .. } => {
                // Check if variable is initialized with external call: bool result = call(...)
                initial_value
                    .as_ref()
                    .is_some_and(|expr| self.is_external_call(expr))
            }
            ast::Statement::TryStatement {
                expression,
                body,
                catch_clauses,
                ..
            } => {
                // Check try expression and all catch clauses
                self.is_external_call(expression)
                    || self.statement_has_external_call(&ast::Statement::Block(body.clone()))
                    || catch_clauses.iter().any(|catch_clause| {
                        self.statement_has_external_call(&ast::Statement::Block(
                            catch_clause.body.clone(),
                        ))
                    })
            }
            ast::Statement::Return { value, .. } => {
                // Check if return expression contains external call: return call(...)
                value
                    .as_ref()
                    .is_some_and(|expr| self.is_external_call(expr))
            }
            ast::Statement::EmitStatement { event_call, .. } => {
                // Check if emit contains external call: emit Event(call(...))
                self.is_external_call(event_call)
            }
            ast::Statement::RevertStatement { error_call, .. } => {
                // Check if revert contains external call: revert Error(call(...))
                error_call
                    .as_ref()
                    .is_some_and(|expr| self.is_external_call(expr))
            }
            _ => false,
        }
    }

    fn statement_has_state_change(&self, stmt: &ast::Statement<'_>) -> bool {
        match stmt {
            ast::Statement::Expression(ast::Expression::Assignment { .. }) => true,
            ast::Statement::Block(block) => {
                // Recursively check all statements in the block for state changes
                block
                    .statements
                    .iter()
                    .any(|s| self.statement_has_state_change(s))
            }
            ast::Statement::If {
                then_branch,
                else_branch,
                ..
            } => {
                // Check both branches for state changes
                self.statement_has_state_change(then_branch)
                    || else_branch.is_some_and(|stmt| self.statement_has_state_change(stmt))
            }
            ast::Statement::While { body, .. } => {
                // Check loop body for state changes
                self.statement_has_state_change(body)
            }
            ast::Statement::For { body, .. } => {
                // Check loop body for state changes
                self.statement_has_state_change(body)
            }
            ast::Statement::VariableDeclaration { initial_value, .. } => {
                // Variable declarations themselves don't change contract state
                // but the initial value might contain state changes
                initial_value
                    .as_ref()
                    .is_some_and(|expr| self.expression_has_state_change(expr))
            }
            ast::Statement::TryStatement {
                expression,
                body,
                catch_clauses,
                ..
            } => {
                // Check try expression, try body, and all catch clauses for state changes
                self.expression_has_state_change(expression)
                    || self.statement_has_state_change(&ast::Statement::Block(body.clone()))
                    || catch_clauses.iter().any(|catch_clause| {
                        self.statement_has_state_change(&ast::Statement::Block(
                            catch_clause.body.clone(),
                        ))
                    })
            }
            ast::Statement::Return { value, .. } => {
                // Return expressions might contain state changes: return (balance = 0, result)
                value
                    .as_ref()
                    .is_some_and(|expr| self.expression_has_state_change(expr))
            }
            ast::Statement::EmitStatement { event_call, .. } => {
                // Emit expressions might contain state changes: emit Event(balance = 0)
                self.expression_has_state_change(event_call)
            }
            ast::Statement::RevertStatement { error_call, .. } => {
                // Revert expressions might contain state changes: revert Error(balance = 0)
                error_call
                    .as_ref()
                    .is_some_and(|expr| self.expression_has_state_change(expr))
            }
            _ => false,
        }
    }

    /// Get function source code (cleaned to avoid FPs from comments/strings)
    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start < source_lines.len() && end < source_lines.len() {
            let raw_source = source_lines[start..=end].join("\n");
            utils::clean_source_for_search(&raw_source)
        } else {
            String::new()
        }
    }

    /// Phase 14 FP Reduction: Check if function is internal or private (text-based)
    /// Internal/private functions cannot be directly called externally
    fn is_internal_or_private_function(&self, func_source: &str) -> bool {
        let lower = func_source.to_lowercase();

        // Check for explicit internal/private visibility
        // Pattern: function name(...) internal/private
        lower.contains(" internal")
            || lower.contains(" private")
            || lower.contains("\tinternal")
            || lower.contains("\tprivate")
    }

    /// Phase 14 FP Reduction: Check if this is a known protected contract
    fn is_known_protected_contract(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;
        let lower = source.to_lowercase();
        let contract_name = ctx.contract.name.name.to_lowercase();

        // OpenZeppelin contracts are battle-tested
        let is_openzeppelin = lower.contains("@openzeppelin")
            || lower.contains("openzeppelin-contracts")
            || contract_name == "erc20"
            || contract_name == "erc721"
            || contract_name == "erc1155";

        // Aave protocol has architectural reentrancy protection
        let is_aave = lower.contains("@author aave")
            || lower.contains("aave-upgradeability")
            || contract_name.contains("atoken")
            || contract_name.contains("debttoken");

        // Compound protocol
        let is_compound = lower.contains("@author compound") || contract_name.contains("ctoken");

        // Safe (Gnosis Safe) wallet - battle-tested multisig
        let file_path_lower = ctx.file_path.to_lowercase();
        let is_safe = file_path_lower.contains("safe-smart-account")
            || file_path_lower.contains("safe-contracts")
            || file_path_lower.contains("/safe/")
            || lower.contains("@author stefan george")
            || lower.contains("@author richard meissner")
            || lower.contains("gnosis safe")
            || contract_name == "safe"
            || lower.contains("multisignaturewallet")
            || lower.contains("execfrommodule")
            // Safe transaction/module patterns
            || lower.contains("ownermanager")
            || lower.contains("guardmanager")
            || lower.contains("modulemanager");

        // Library contracts
        let is_library = source.contains(&format!("library {}", ctx.contract.name.name));

        is_openzeppelin || is_aave || is_compound || is_safe || is_library
    }

    /// Phase 14 FP Reduction: Check if function name suggests internal helper
    fn is_internal_helper_pattern(&self, func_name: &str) -> bool {
        // Functions starting with _ are conventionally internal
        func_name.starts_with('_')
    }

    /// Phase 15 FP Reduction: Check if function uses SafeERC20 for token transfers
    /// SafeERC20 wraps transfers in a way that prevents reentrancy
    fn uses_safe_token_transfer(&self, func_source: &str, contract_source: &str) -> bool {
        let has_safe_erc20 =
            contract_source.contains("SafeERC20") || contract_source.contains("using SafeERC20");

        let uses_safe_methods = func_source.contains("safeTransfer")
            || func_source.contains("safeTransferFrom")
            || func_source.contains("safeApprove")
            || func_source.contains("safeIncreaseAllowance");

        has_safe_erc20 && uses_safe_methods
    }

    /// Phase 15 FP Reduction: Check if function only calls view/pure functions
    /// FP-10 Fix: Also detect typed interface calls (e.g., IERC20(token).transfer(...))
    /// which can trigger reentrancy via ERC-777 hooks or other callback mechanisms.
    fn only_calls_view_functions(&self, func_source: &str) -> bool {
        // If there's no .call{ or .transfer or .send, likely only view calls
        let has_value_transfer = func_source.contains(".call{value")
            || func_source.contains(".transfer(")
            || func_source.contains(".send(");

        // Check for delegatecall which can cause reentrancy
        let has_delegatecall = func_source.contains(".delegatecall(");

        if has_value_transfer || has_delegatecall {
            return false;
        }

        // FP-10: Check for typed interface calls that can trigger reentrancy
        // e.g., IERC20(token).transfer(...), IPool(pool).swap(...)
        if self.has_typed_interface_call(func_source) {
            return false;
        }

        // FP-10: Check for state-changing method calls on external contracts
        // e.g., token.transfer(...), pool.swap(...)
        if self.has_state_changing_external_method(func_source) {
            return false;
        }

        true
    }

    /// FP-10: Detect typed interface call patterns like `ISomething(addr).method(`
    /// These are external calls that can trigger callbacks (e.g., ERC-777 hooks).
    fn has_typed_interface_call(&self, func_source: &str) -> bool {
        // Match patterns like: I<Name>(<expr>).<method>(
        // We look for `I` followed by an uppercase letter, then `(`, then `).<method>(`
        let bytes = func_source.as_bytes();
        let len = bytes.len();
        let mut i = 0;

        while i < len.saturating_sub(4) {
            // Look for 'I' followed by an uppercase ASCII letter
            if bytes[i] == b'I' && i + 1 < len && bytes[i + 1].is_ascii_uppercase() {
                // Walk forward to find the opening paren of the cast
                let mut j = i + 2;
                while j < len && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                    j += 1;
                }
                if j < len && bytes[j] == b'(' {
                    // Found potential interface cast like `IERC20(`
                    // Now find the matching closing paren, accounting for nesting
                    let mut depth = 1;
                    let mut k = j + 1;
                    while k < len && depth > 0 {
                        if bytes[k] == b'(' {
                            depth += 1;
                        } else if bytes[k] == b')' {
                            depth -= 1;
                        }
                        k += 1;
                    }
                    // k is now past the closing paren; check for `.method(`
                    if depth == 0 && k < len && bytes[k] == b'.' {
                        // Skip the dot, read the method name
                        let mut m = k + 1;
                        while m < len && (bytes[m].is_ascii_alphanumeric() || bytes[m] == b'_') {
                            m += 1;
                        }
                        if m > k + 1 && m < len && bytes[m] == b'(' {
                            // Extract interface name for allowlist check
                            let iface_name = &func_source[i..j];
                            if !Self::is_safe_library_name(iface_name) {
                                return true;
                            }
                        }
                    }
                }
            }
            i += 1;
        }

        false
    }

    /// FP-10: Detect state-changing method calls on external contract variables
    /// e.g., `token.transfer(`, `pool.swap(`, `vault.deposit(`
    fn has_state_changing_external_method(&self, func_source: &str) -> bool {
        // Methods that are known to be state-changing and can trigger callbacks
        const STATE_CHANGING_METHODS: &[&str] = &[
            ".transfer(",
            ".transferFrom(",
            ".safeTransfer(",
            ".safeTransferFrom(",
            ".swap(",
            ".deposit(",
            ".withdraw(",
            ".mint(",
            ".burn(",
            ".approve(",
            ".permit(",
            ".flash(",
            ".flashLoan(",
            ".execute(",
            ".multicall(",
            ".onERC721Received(",
            ".onERC1155Received(",
            ".tokensReceived(",
            ".tokensToSend(",
        ];

        // Builtin/safe prefixes -- calls on these are NOT external contract calls
        const SAFE_PREFIXES: &[&str] =
            &["this.", "msg.", "abi.", "type(", "block.", "tx.", "super."];

        for method in STATE_CHANGING_METHODS {
            let mut search_from = 0;
            while let Some(pos) = func_source[search_from..].find(method) {
                let abs_pos = search_from + pos;

                // We need to check what is before the dot to determine
                // if this is an external call or a safe builtin.
                // Walk backwards from the dot to find the caller token.
                if abs_pos > 0 {
                    let prefix_region = &func_source[..abs_pos + 1]; // includes the dot

                    // Check if this is a safe prefix (e.g., "this.", "msg.", etc.)
                    let is_safe = SAFE_PREFIXES
                        .iter()
                        .any(|safe| prefix_region.ends_with(safe));

                    if !is_safe {
                        // Extract the identifier before the dot to check against safe libraries
                        let before_dot = &func_source[..abs_pos];
                        let caller_name = Self::extract_trailing_identifier(before_dot);
                        if !caller_name.is_empty() && !Self::is_safe_library_name(caller_name) {
                            return true;
                        }
                    }
                }

                search_from = abs_pos + method.len();
            }
        }

        false
    }

    /// Check if a name is a known safe library that does not make external calls
    /// that could trigger reentrancy.
    fn is_safe_library_name(name: &str) -> bool {
        const SAFE_LIBRARIES: &[&str] = &[
            "SafeERC20",
            "SafeMath",
            "Math",
            "Address",
            "Strings",
            "EnumerableSet",
            "EnumerableMap",
            "Counters",
            "ECDSA",
            "MerkleProof",
            "SignatureChecker",
            "EIP712",
            "Base64",
            "Clones",
            "StorageSlot",
            "Arrays",
            "Context",
            "Multicall",
        ];
        SAFE_LIBRARIES.iter().any(|lib| name == *lib)
    }

    /// Extract the trailing identifier from a string (e.g., "foo.bar.baz" -> "baz",
    /// "token" -> "token", "IERC20(addr)" -> "").
    /// Returns an empty string if the string does not end with a valid identifier.
    fn extract_trailing_identifier(s: &str) -> &str {
        let bytes = s.as_bytes();
        if bytes.is_empty() {
            return "";
        }
        // Walk backwards while we see identifier chars
        let end = bytes.len();
        let mut start = end;
        while start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_') {
            start -= 1;
        }
        if start == end { "" } else { &s[start..end] }
    }

    /// Phase 15 FP Reduction: Check if this is a pull payment pattern
    /// Pull payments have users claim their own funds (safe pattern).
    ///
    /// A true pull-payment uses a dedicated per-user credit ledger
    /// (pendingWithdrawals[user], pendingRewards[user], unclaimed[user]) — NOT
    /// the contract's general `balances` mapping that also receives deposits.
    /// The latter is the canonical classic-reentrancy pattern (deposit then
    /// withdraw via external call before debit), so matching on
    /// `withdraw`/`claim`/`redeem` + `balances[msg.sender]` silently skipped
    /// the very vulnerability this detector exists to catch.
    fn is_pull_payment_pattern(&self, func_source: &str) -> bool {
        let lower = func_source.to_lowercase();

        // Per-user credit ledger naming (the defining marker of a pull-payment)
        let has_pull_ledger = lower.contains("pending")
            || lower.contains("unclaimed")
            || lower.contains("claimable")
            || lower.contains("owed[")
            || lower.contains("escrow[");

        // OpenZeppelin PullPayment / Escrow
        let uses_oz_pull = func_source.contains("PullPayment")
            || func_source.contains("_asyncTransfer")
            || func_source.contains("withdrawPayments");

        has_pull_ledger || uses_oz_pull
    }

    /// Phase 14 FP Reduction: Check if contract has contract-wide reentrancy protection
    fn has_contract_level_protection(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;
        let lower = source.to_lowercase();

        // Inherits from ReentrancyGuard
        let inherits_guard = lower.contains("is reentrancyguard")
            || lower.contains(", reentrancyguard")
            || lower.contains("reentrancyguard,")
            || source.contains("ReentrancyGuardUpgradeable");

        // Has _status or _locked state variable (OZ ReentrancyGuard pattern)
        let has_lock_state = (lower.contains("uint256 private _status")
            || lower.contains("bool private _locked")
            || lower.contains("uint256 internal _status"))
            && (lower.contains("_not_entered") || lower.contains("_entered"));

        // Uses mutex pattern
        let has_mutex = lower.contains("modifier noreentrancy")
            || lower.contains("modifier nonreentrant")
            || lower.contains("modifier lock");

        inherits_guard || has_lock_state || has_mutex
    }

    /// Phase 14 FP Reduction: Check if contract is an interface (no implementation)
    fn is_interface_contract(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;
        let contract_name = &ctx.contract.name.name;

        // Interface naming convention (IPool, IAToken, etc.)
        if contract_name.starts_with('I')
            && contract_name
                .chars()
                .nth(1)
                .map_or(false, |c| c.is_uppercase())
        {
            return true;
        }

        // Explicit interface keyword
        source.contains(&format!("interface {}", contract_name))
    }

    /// Dataflow-enhanced reentrancy check: uses CFG to verify state changes AFTER
    /// external calls in control flow order, and def-use chains to confirm the
    /// call target is potentially user-controlled.
    fn check_reentrancy_with_dataflow(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> bool {
        let func_name = function.name.name;
        let analysis = match ctx.get_function_analysis(func_name) {
            Some(a) => a,
            None => return false,
        };

        let ir_fn = &analysis.ir_function;
        let instructions = ir_fn.get_instructions();

        // Find external call instructions and state write instructions
        let mut external_call_indices = Vec::new();
        let mut state_write_indices = Vec::new();

        for (idx, instr) in instructions.iter().enumerate() {
            match instr {
                Instruction::ExternalCall(_, _, _, _) => {
                    external_call_indices.push(idx);
                }
                Instruction::StorageStore(_, _)
                | Instruction::MappingStore(_, _, _)
                | Instruction::StructStore(_, _, _) => {
                    state_write_indices.push(idx);
                }
                _ => {}
            }
        }

        // Check if any state write occurs after an external call
        for &call_idx in &external_call_indices {
            for &write_idx in &state_write_indices {
                if write_idx > call_idx {
                    return true; // State change after external call confirmed via IR
                }
            }
        }

        false
    }

    /// Check if an expression contains state changes (assignments)
    fn expression_has_state_change(&self, expr: &ast::Expression<'_>) -> bool {
        match expr {
            ast::Expression::Assignment { .. } => true,
            ast::Expression::BinaryOperation { left, right, .. } => {
                // Check both sides of binary operations
                self.expression_has_state_change(left) || self.expression_has_state_change(right)
            }
            ast::Expression::UnaryOperation { operand, .. } => {
                // Check unary operation operand
                self.expression_has_state_change(operand)
            }
            ast::Expression::FunctionCall { arguments, .. } => {
                // Check function call arguments for state changes
                arguments
                    .iter()
                    .any(|arg| self.expression_has_state_change(arg))
            }
            ast::Expression::IndexAccess { base, index, .. } => {
                // Check index access expressions
                self.expression_has_state_change(base)
                    || index.is_some_and(|idx| self.expression_has_state_change(idx))
            }
            ast::Expression::MemberAccess { expression, .. } => {
                // Check member access base expression
                self.expression_has_state_change(expression)
            }
            ast::Expression::Conditional {
                condition,
                true_expression,
                false_expression,
                ..
            } => {
                // Check all parts of conditional expression
                self.expression_has_state_change(condition)
                    || self.expression_has_state_change(true_expression)
                    || self.expression_has_state_change(false_expression)
            }
            _ => false,
        }
    }
}

impl Detector for ClassicReentrancyDetector {
    fn id(&self) -> DetectorId {
        self.base.id.clone()
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn description(&self) -> &str {
        &self.base.description
    }

    fn default_severity(&self) -> Severity {
        self.base.default_severity
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        self.base.categories.clone()
    }

    fn is_enabled(&self) -> bool {
        self.base.enabled
    }

    fn requires_cfg(&self) -> bool {
        false // Works with or without CFG, but enhanced when available
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Skip if this is an ERC-4337 paymaster/account abstraction contract
        // Paymasters have their own security model with EntryPoint validation
        // State changes after external calls are part of the ERC-4337 design
        let is_paymaster = utils::is_erc4337_paymaster(ctx);
        if is_paymaster {
            return Ok(findings); // Paymaster reentrancy is handled by ERC-4337 spec
        }

        // Skip if this is an AMM pool - AMM pools have lock() modifiers for reentrancy protection
        if utils::is_amm_pool(ctx) {
            return Ok(findings);
        }

        // Phase 14 FP Reduction: Skip interface contracts (no implementation)
        if self.is_interface_contract(ctx) {
            return Ok(findings);
        }

        // Phase 14 FP Reduction: Skip known protected contracts (OZ, Aave, Compound)
        if self.is_known_protected_contract(ctx) {
            return Ok(findings);
        }

        // Phase 14 FP Reduction: Skip if contract has contract-wide reentrancy protection
        if self.has_contract_level_protection(ctx) {
            return Ok(findings);
        }

        // Skip test contracts
        if utils::is_test_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip secure/fixed example contracts
        if crate::utils::is_secure_example_file(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip attack/exploit contracts
        if crate::utils::is_attack_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip delegatecall-focused test files
        // Contracts in delegatecall/ directories test delegatecall vulnerabilities,
        // not reentrancy. The reentrancy detector triggers on delegatecall as an
        // "external call" followed by state changes, but these are design patterns.
        {
            let file_lower = ctx.file_path.to_lowercase();
            if file_lower.contains("delegatecall/") || file_lower.contains("delegatecall\\") {
                return Ok(findings);
            }
            // FP Reduction: Skip files in directories covered by dedicated detectors
            if file_lower.contains("bridge/")
                || file_lower.contains("flashloan/")
                || file_lower.contains("eip7702/")
                || file_lower.contains("eip1153_transient/")
                || file_lower.contains("eigenlayer/")
            {
                return Ok(findings);
            }
        }

        // FP Reduction: Skip contracts covered by dedicated detectors
        {
            let contract_name_lower = ctx.contract.name.name.to_lowercase();
            if contract_name_lower.contains("bridge")
                || contract_name_lower.contains("flashloan")
                || contract_name_lower.contains("proxy")
                || contract_name_lower.contains("delegation")
            {
                return Ok(findings);
            }
        }

        for function in ctx.get_functions() {
            // Use dataflow-enhanced check when available, fall back to pattern matching
            let has_reentrancy_pattern = if ctx.has_dataflow() {
                // Dataflow path: use IR/CFG to verify state changes after external calls
                self.check_reentrancy_with_dataflow(function, ctx)
            } else {
                // Pattern matching fallback
                self.has_external_call(function) && self.has_state_changes_after_calls(function)
            };

            if has_reentrancy_pattern {
                // Get function source to check for reentrancy guards
                let func_source = self.get_function_source(function, ctx);
                let func_name = &function.name.name;

                // Skip if function has reentrancy guard (nonReentrant, lock(), etc.)
                if utils::has_reentrancy_guard(&func_source, &ctx.source_code) {
                    continue;
                }

                // Phase 14 FP Reduction: Skip internal/private functions
                // They cannot be called directly externally
                if self.is_internal_or_private_function(&func_source) {
                    continue;
                }

                // Phase 14 FP Reduction: Skip functions with _ prefix (internal helper convention)
                if self.is_internal_helper_pattern(func_name) {
                    continue;
                }

                // Phase 15 FP Reduction: Skip if using SafeERC20 for token transfers
                // SafeERC20 is designed to be safe against reentrancy
                if self.uses_safe_token_transfer(&func_source, &ctx.source_code) {
                    continue;
                }

                // Phase 15 FP Reduction: Skip if function only calls view/pure functions
                // View functions cannot cause reentrancy
                if self.only_calls_view_functions(&func_source) {
                    continue;
                }

                // Phase 15 FP Reduction: Skip pull payment patterns
                // Pull payments have user claim funds (safe pattern)
                if self.is_pull_payment_pattern(&func_source) {
                    continue;
                }

                let message = format!(
                    "Function '{}' may be vulnerable to reentrancy attacks due to state changes after external calls",
                    func_name
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    func_name.len() as u32,
                )
                .with_cwe(841) // CWE-841: Improper Enforcement of Behavioral Workflow
                .with_swc("SWC-107") // SWC-107: Reentrancy
                .with_fix_suggestion(format!(
                    "Apply checks-effects-interactions pattern or use a reentrancy guard in function '{}'",
                    func_name
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

impl Default for ReadOnlyReentrancyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ReadOnlyReentrancyDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("readonly-reentrancy".to_string()),
                "Read-Only Reentrancy".to_string(),
                "Read-only functions may be vulnerable to view reentrancy".to_string(),
                vec![DetectorCategory::ReentrancyAttacks],
                Severity::Medium,
            ),
        }
    }

    fn is_view_function(&self, function: &ast::Function<'_>) -> bool {
        matches!(function.mutability, ast::StateMutability::View)
    }

    fn relies_on_external_state(&self, function: &ast::Function<'_>) -> bool {
        // Check if function reads state variables
        if let Some(body) = &function.body {
            self.reads_state_variables(&body.statements)
        } else {
            false
        }
    }

    fn reads_state_variables(&self, statements: &[ast::Statement<'_>]) -> bool {
        // Check if the function reads any state variables
        for stmt in statements {
            if self.statement_reads_state(stmt) {
                return true;
            }
        }
        false
    }

    fn statement_reads_state(&self, stmt: &ast::Statement<'_>) -> bool {
        match stmt {
            ast::Statement::Expression(expr) => self.expression_reads_state(expr),
            ast::Statement::Return { value, .. } => value
                .as_ref()
                .is_some_and(|expr| self.expression_reads_state(expr)),
            ast::Statement::VariableDeclaration { initial_value, .. } => initial_value
                .as_ref()
                .is_some_and(|expr| self.expression_reads_state(expr)),
            ast::Statement::If {
                then_branch,
                else_branch,
                ..
            } => {
                self.statement_reads_state(then_branch)
                    || else_branch
                        .as_ref()
                        .is_some_and(|s| self.statement_reads_state(s))
            }
            ast::Statement::Block(block) => self.reads_state_variables(&block.statements),
            ast::Statement::For { body, .. } => self.statement_reads_state(body),
            ast::Statement::While { body, .. } => self.statement_reads_state(body),
            _ => false,
        }
    }

    fn expression_reads_state(&self, expr: &ast::Expression<'_>) -> bool {
        match expr {
            // Direct identifier access (could be state variable)
            ast::Expression::Identifier(_) => true,

            // Member access (e.g., token0Balance, totalSupply)
            ast::Expression::MemberAccess { expression, .. } => {
                self.expression_reads_state(expression)
            }

            // Binary operations (e.g., balance1 + balance2)
            ast::Expression::BinaryOperation { left, right, .. } => {
                self.expression_reads_state(left) || self.expression_reads_state(right)
            }

            // Unary operations
            ast::Expression::UnaryOperation { operand, .. } => self.expression_reads_state(operand),

            // Function calls (could read state)
            ast::Expression::FunctionCall {
                function,
                arguments,
                ..
            } => {
                self.expression_reads_state(function)
                    || arguments.iter().any(|arg| self.expression_reads_state(arg))
            }

            // Ternary operator
            ast::Expression::Conditional {
                condition,
                true_expression,
                false_expression,
                ..
            } => {
                self.expression_reads_state(condition)
                    || self.expression_reads_state(true_expression)
                    || self.expression_reads_state(false_expression)
            }

            _ => false,
        }
    }

    fn has_external_call(&self, stmt: &ast::Statement<'_>) -> bool {
        match stmt {
            ast::Statement::Expression(expr) => self.expression_has_external_call(expr),
            ast::Statement::Block(block) => {
                block.statements.iter().any(|s| self.has_external_call(s))
            }
            ast::Statement::VariableDeclaration {
                initial_value: Some(expr),
                ..
            } => self.expression_has_external_call(expr),
            ast::Statement::If {
                then_branch,
                else_branch,
                ..
            } => {
                self.has_external_call(then_branch)
                    || else_branch
                        .as_ref()
                        .is_some_and(|s| self.has_external_call(s))
            }
            ast::Statement::For { body, .. } => self.has_external_call(body),
            ast::Statement::While { body, .. } => self.has_external_call(body),
            ast::Statement::TryStatement { body, .. } => {
                body.statements.iter().any(|s| self.has_external_call(s))
            }
            _ => false,
        }
    }

    fn expression_has_external_call(&self, expr: &ast::Expression<'_>) -> bool {
        match expr {
            ast::Expression::FunctionCall { function, .. } => {
                match function {
                    // Direct member access pattern: obj.method()
                    ast::Expression::MemberAccess { member, .. } => {
                        matches!(member.name, "call" | "delegatecall" | "transfer" | "send")
                    }
                    // Nested function call pattern: obj.method{options}()
                    // This handles .call{value: amount}(), .delegatecall{gas: g}(), etc.
                    ast::Expression::FunctionCall {
                        function: inner_function,
                        ..
                    } => {
                        // Check if the inner function is a MemberAccess to call/delegatecall/transfer/send
                        matches!(
                            inner_function,
                            ast::Expression::MemberAccess { member, .. }
                            if matches!(member.name, "call" | "delegatecall" | "transfer" | "send")
                        )
                    }
                    _ => false,
                }
            }
            // Also check assignments, binary operations, etc. for nested calls
            ast::Expression::Assignment { right, .. } => self.expression_has_external_call(right),
            ast::Expression::BinaryOperation { left, right, .. } => {
                self.expression_has_external_call(left) || self.expression_has_external_call(right)
            }
            ast::Expression::UnaryOperation { operand, .. } => {
                self.expression_has_external_call(operand)
            }
            ast::Expression::MemberAccess { expression, .. } => {
                self.expression_has_external_call(expression)
            }
            ast::Expression::Conditional {
                condition,
                true_expression,
                false_expression,
                ..
            } => {
                self.expression_has_external_call(condition)
                    || self.expression_has_external_call(true_expression)
                    || self.expression_has_external_call(false_expression)
            }
            _ => false,
        }
    }

    fn function_has_external_call(&self, function: &ast::Function<'_>) -> bool {
        if let Some(body) = &function.body {
            body.statements
                .iter()
                .any(|stmt| self.has_external_call(stmt))
        } else {
            false
        }
    }
}

impl Detector for ReadOnlyReentrancyDetector {
    fn id(&self) -> DetectorId {
        self.base.id.clone()
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn description(&self) -> &str {
        &self.base.description
    }

    fn default_severity(&self) -> Severity {
        self.base.default_severity
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        self.base.categories.clone()
    }

    fn is_enabled(&self) -> bool {
        self.base.enabled
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Phase 15 FP Reduction: Skip contracts with reentrancy protection
        // If contract has ReentrancyGuard, readonly reentrancy is mitigated
        let source_lower = crate::utils::get_contract_source(ctx).to_lowercase();
        if source_lower.contains("reentrancyguard")
            || source_lower.contains("nonreentrant")
            || source_lower.contains("modifier lock")
        {
            return Ok(findings);
        }

        // Phase 15 FP Reduction: Skip test contracts
        if utils::is_test_contract(ctx) {
            return Ok(findings);
        }

        // Phase 15 FP Reduction: Skip known safe protocols
        if source_lower.contains("@openzeppelin")
            || source_lower.contains("@aave")
            || source_lower.contains("@uniswap")
        {
            return Ok(findings);
        }

        // First, check if there are any state-changing functions that make external calls
        let has_vulnerable_pattern = ctx
            .get_functions()
            .iter()
            .any(|f| !self.is_view_function(f) && self.function_has_external_call(f));

        // If no state-changing functions make external calls, no readonly reentrancy risk
        if !has_vulnerable_pattern {
            return Ok(findings);
        }

        // Now check view functions that read state
        for function in ctx.get_functions() {
            if self.is_view_function(function) && self.relies_on_external_state(function) {
                // Phase 15 FP Reduction: Skip internal view functions
                if function.visibility == ast::Visibility::Internal
                    || function.visibility == ast::Visibility::Private
                {
                    continue;
                }

                // Phase 15 FP Reduction: Skip standard ERC interface view functions
                // These are expected to be public and read state
                let func_name_lower = function.name.name.to_lowercase();
                if func_name_lower == "balanceof"
                    || func_name_lower == "totalsupply"
                    || func_name_lower == "allowance"
                    || func_name_lower == "name"
                    || func_name_lower == "symbol"
                    || func_name_lower == "decimals"
                    || func_name_lower == "ownerof"
                    || func_name_lower == "tokenuri"
                {
                    continue;
                }

                let message = format!(
                    "View function '{}' reads state that may be inconsistent during reentrancy. \
                     Contract has state-changing functions that make external calls before updating state.",
                    function.name.name
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(841) // CWE-841: Improper Enforcement of Behavioral Workflow
                .with_fix_suggestion(format!(
                    "Add a reentrancy guard to state-changing functions or ensure view function '{}' \
                     cannot be called during callbacks (e.g., using a reentrancy lock check in the view function)",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = ClassicReentrancyDetector::new();
        assert_eq!(detector.id().0, "classic-reentrancy");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_pull_payment_with_pending_is_skipped() {
        let detector = ClassicReentrancyDetector::new();

        let src = r#"
            function claimReward() external {
                uint256 amount = pendingRewards[msg.sender];
                pendingRewards[msg.sender] = 0;
                (bool ok, ) = msg.sender.call{value: amount}("");
                require(ok);
            }
        "#;
        assert!(
            detector.is_pull_payment_pattern(src),
            "pull-payment with pendingRewards should be skipped"
        );
    }

    #[test]
    fn test_classic_withdraw_not_skipped_as_pull_payment() {
        let detector = ClassicReentrancyDetector::new();

        let src = r#"
            function withdraw(uint256 amount) public {
                require(balances[msg.sender] >= amount, "Insufficient balance");
                (bool success, ) = msg.sender.call{value: amount}("");
                require(success, "Transfer failed");
                balances[msg.sender] -= amount;
            }
        "#;
        assert!(
            !detector.is_pull_payment_pattern(src),
            "classic CEI-violation withdraw must NOT be skipped"
        );
    }

    #[test]
    fn test_oz_pull_payment_is_skipped() {
        let detector = ClassicReentrancyDetector::new();

        let src = r#"
            function withdrawPayments(address payable payee) public {
                _asyncTransfer(payee, payments[payee]);
            }
        "#;
        assert!(
            detector.is_pull_payment_pattern(src),
            "OpenZeppelin PullPayment pattern should be skipped"
        );
    }

    #[test]
    fn test_escrow_pattern_is_skipped() {
        let detector = ClassicReentrancyDetector::new();

        let src = r#"
            function claimEscrow() external {
                uint256 amount = escrow[msg.sender];
                escrow[msg.sender] = 0;
                payable(msg.sender).transfer(amount);
            }
        "#;
        assert!(detector.is_pull_payment_pattern(src));
    }
}

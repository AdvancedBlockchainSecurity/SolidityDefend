use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct UncheckedCallDetector {
    base: BaseDetector,
}

impl Default for UncheckedCallDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl UncheckedCallDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("unchecked-external-call".to_string()),
                "Unchecked External Call".to_string(),
                "External calls without return value checking".to_string(),
                vec![DetectorCategory::ExternalCalls],
                Severity::Medium,
            ),
        }
    }
}

impl Detector for UncheckedCallDetector {
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
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

        // Phase 15 FP Reduction: Skip test contracts
        if crate::utils::is_test_contract(ctx) {
            return Ok(findings);
        }

        // Phase 15 FP Reduction: Skip contracts using SafeERC20 or Address library
        // These libraries handle return value checking
        let source_lower = crate::utils::get_contract_source(ctx).to_lowercase();
        if source_lower.contains("safeerc20") || source_lower.contains("using address for") {
            return Ok(findings);
        }

        // Phase 52 FP Reduction: Skip proxy contracts
        // Proxy contracts need unchecked delegatecalls in fallback
        if crate::utils::is_proxy_contract(ctx) {
            return Ok(findings);
        }

        // Phase 52 FP Reduction: Skip interfaces
        if crate::utils::is_interface_only(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            if let Some(body) = &function.body {
                // Phase 15 FP Reduction: Get function source for context checks
                let func_source = self.get_function_source(function, ctx);

                // Skip if function uses try/catch (handles errors properly)
                if func_source.contains("try ") && func_source.contains("catch") {
                    continue;
                }

                // Skip if function uses SafeERC20 methods
                if func_source.contains("safeTransfer")
                    || func_source.contains("safeTransferFrom")
                    || func_source.contains("safeApprove")
                {
                    continue;
                }

                self.check_statements_for_unchecked_calls(
                    &body.statements,
                    ctx,
                    &mut findings,
                    function,
                    &func_source,
                );
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl UncheckedCallDetector {
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

    /// Check statements for unchecked external calls
    fn check_statements_for_unchecked_calls(
        &self,
        statements: &[ast::Statement<'_>],
        ctx: &AnalysisContext<'_>,
        findings: &mut Vec<Finding>,
        function: &ast::Function<'_>,
        func_source: &str,
    ) {
        for stmt in statements {
            match stmt {
                ast::Statement::Expression(ast::Expression::FunctionCall {
                    function: call_expr,
                    ..
                }) => {
                    if self.is_external_call(call_expr) && !self.return_value_checked(stmt) {
                        // Phase 15 FP Reduction: Check if return value is checked inline
                        // e.g., (bool success, ) = addr.call{...}(...); require(success);
                        if self.has_inline_success_check(func_source) {
                            continue;
                        }

                        // Phase 52 FP Reduction: Skip chained call patterns
                        if self.is_chained_call_pattern(func_source) {
                            continue;
                        }

                        // Phase 52 FP Reduction: Skip known safe function patterns
                        if self.is_known_safe_function(func_source) {
                            continue;
                        }

                        let message = format!(
                            "External call in function '{}' does not check return value",
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
                            .with_cwe(252) // CWE-252: Unchecked Return Value
                            .with_fix_suggestion(format!(
                                "Check the return value of external calls in function '{}'",
                                function.name.name
                            ));

                        findings.push(finding);
                    }
                }
                ast::Statement::VariableDeclaration {
                    initial_value: Some(ast::Expression::FunctionCall {
                        function: call_expr,
                        ..
                    }),
                    ..
                } => {
                    if self.is_external_call(call_expr) {
                        if !self.has_inline_success_check(func_source) {
                            let message = format!(
                                "External call in function '{}' does not check return value",
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
                                .with_cwe(252)
                                .with_fix_suggestion(format!(
                                    "Check the return value of external calls in function '{}'",
                                    function.name.name
                                ));

                            findings.push(finding);
                        }
                    }
                }
                // Tuple destructure: (bool success, ) = addr.call{value:}("")
                // Parser represents as Expression(Assignment { right: FunctionCall })
                ast::Statement::Expression(ast::Expression::Assignment {
                    right,
                    ..
                }) => {
                    if let ast::Expression::FunctionCall {
                        function: call_expr,
                        ..
                    } = *right
                    {
                        if self.is_external_call(call_expr) {
                            if !self.has_inline_success_check(func_source) {
                                let message = format!(
                                    "External call in function '{}' does not check return value",
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
                                    .with_cwe(252)
                                    .with_fix_suggestion(format!(
                                        "Check the return value of external calls in function '{}'",
                                        function.name.name
                                    ));

                                findings.push(finding);
                            }
                        }
                    }
                }
                ast::Statement::Block(block) => {
                    self.check_statements_for_unchecked_calls(
                        &block.statements,
                        ctx,
                        findings,
                        function,
                        func_source,
                    );
                }
                ast::Statement::For { body, .. }
                | ast::Statement::While { body, .. } => {
                    self.recurse_into_statement(body, ctx, findings, function, func_source);
                }
                ast::Statement::If {
                    then_branch,
                    else_branch,
                    ..
                } => {
                    self.recurse_into_statement(then_branch, ctx, findings, function, func_source);
                    if let Some(else_stmt) = else_branch {
                        self.recurse_into_statement(else_stmt, ctx, findings, function, func_source);
                    }
                }
                ast::Statement::TryStatement {
                    body,
                    catch_clauses,
                    ..
                } => {
                    self.check_statements_for_unchecked_calls(
                        &body.statements,
                        ctx,
                        findings,
                        function,
                        func_source,
                    );
                    for clause in catch_clauses {
                        self.check_statements_for_unchecked_calls(
                            &clause.body.statements,
                            ctx,
                            findings,
                            function,
                            func_source,
                        );
                    }
                }
                _ => {}
            }
        }
    }

    fn recurse_into_statement(
        &self,
        stmt: &ast::Statement<'_>,
        ctx: &AnalysisContext<'_>,
        findings: &mut Vec<Finding>,
        function: &ast::Function<'_>,
        func_source: &str,
    ) {
        match stmt {
            ast::Statement::Block(block) => {
                self.check_statements_for_unchecked_calls(
                    &block.statements,
                    ctx,
                    findings,
                    function,
                    func_source,
                );
            }
            other => {
                self.check_statements_for_unchecked_calls(
                    std::slice::from_ref(other),
                    ctx,
                    findings,
                    function,
                    func_source,
                );
            }
        }
    }

    /// Phase 15 FP Reduction: Check if function has inline success check after call
    fn has_inline_success_check(&self, func_source: &str) -> bool {
        let lower = func_source.to_lowercase();

        // Pattern: (bool success, ) = ... followed by require(success)
        let has_success_var = lower.contains("bool success")
            || lower.contains("(bool success,")
            || lower.contains("(bool ok,")
            || lower.contains("bool ok =")
            || lower.contains("(bool sent,")
            || lower.contains("bool sent =");

        let has_success_require = lower.contains("require(success")
            || lower.contains("require(ok")
            || lower.contains("require(sent")
            || lower.contains("if (!success")
            || lower.contains("if(!success")
            || lower.contains("if (!ok")
            || lower.contains("if(!ok")
            || lower.contains("if (!sent")
            || lower.contains("if(!sent")
            || lower.contains("assert(success")
            || lower.contains("assert(ok")
            || lower.contains("assert(sent");

        has_success_var && has_success_require
    }

    /// Phase 52 FP Reduction: Check if this is a chained call where return isn't needed
    /// e.g., address(token).call(...) where we use the result
    fn is_chained_call_pattern(&self, func_source: &str) -> bool {
        let lower = func_source.to_lowercase();

        // Chained event emission
        let has_event_after = lower.contains("emit ") && lower.contains(".call");

        // Return value destructuring with only bytes (data processing)
        let processes_return_data = lower.contains("(, bytes memory data)")
            || lower.contains("(,bytes memory data)")
            || lower.contains("abi.decode(");

        has_event_after || processes_return_data
    }

    /// Phase 52 FP Reduction: Check if this is a known safe function pattern
    fn is_known_safe_function(&self, func_source: &str) -> bool {
        let lower = func_source.to_lowercase();

        // ERC20 approve that returns bool but is often ignored
        // (it's a design choice - some tokens don't return bool)
        let is_approve_pattern = lower.contains(".approve(")
            && (lower.contains("0xffffffff") || lower.contains("type(uint256).max"));

        // transferFrom where SafeERC20 wrapping might not be needed
        // if success is checked elsewhere
        let has_approval_check = lower.contains("allowance") || lower.contains("approve");

        is_approve_pattern || has_approval_check
    }

    /// Check if expression is an external call
    /// Only flags actual low-level call patterns: .call{}, .delegatecall{}, .staticcall{}, .send(), .transfer()
    /// Does NOT flag: array.push(), mapping access, or general method calls
    fn is_external_call(&self, expr: &ast::Expression<'_>) -> bool {
        // Peel an optional call-options wrapper. The parser represents
        // `recipient.call{value: x}(args)` as
        //   FunctionCall(function: FunctionCall(MemberAccess(.call), [x]), args)
        // (see crates/parser/src/arena.rs FunctionCallBlock handling). Without
        // this unwrap, the `.call{value:}` form with a discarded return tuple
        // is never recognized as an external call.
        let target = match expr {
            ast::Expression::FunctionCall { function, .. } => *function,
            _ => expr,
        };

        if let ast::Expression::MemberAccess {
            expression, member, ..
        } = target
        {
            // Only flag actual external call patterns - low-level calls
            let method = member.name.to_lowercase();

            // These are the only real external call patterns that need return value checking:
            // - .call{value:...}() - returns (bool, bytes)
            // - .delegatecall() - returns (bool, bytes)
            // - .staticcall() - returns (bool, bytes)
            // - .send() - returns bool
            //
            // NOT external calls (should not be flagged):
            // - .transfer() - reverts on failure, no return value to check
            // - array.push() - internal array operation
            // - mapping[key] - storage access
            // - contract.function() - handled by Solidity (reverts on failure)
            // Skip delegatecall — handled by dedicated delegatecall-return-ignored detector
            if method == "call" || method == "staticcall" || method == "send" {
                // Verify the expression is an address-like type, not an array or mapping
                // Skip if it looks like array/internal operations
                if !self.is_array_or_internal_operation(expression) {
                    return true;
                }
            }

            // Note: .transfer() reverts on failure, so there's no return value to check
            // It's not an unchecked call pattern - it fails loudly
        }
        false
    }

    /// Check if expression looks like an internal/array operation (not an external call target).
    /// Only suppresses push/pop on known collection names — NOT index access, because
    /// `array[i].call{value:}()` is a legitimate external call pattern (batch payouts).
    fn is_array_or_internal_operation(&self, expr: &ast::Expression<'_>) -> bool {
        match expr {
            ast::Expression::Identifier(id) => {
                let name = id.name.to_lowercase();
                // Only suppress known internal array methods, not address-typed arrays
                name.contains("array")
                    || name.contains("list")
                    || name.contains("shareholders")
                    || name.contains("allowances")
            }
            ast::Expression::MemberAccess {
                expression, member, ..
            } => {
                if member.name == "length" || member.name == "push" || member.name == "pop" {
                    return true;
                }
                self.is_array_or_internal_operation(expression)
            }
            _ => false,
        }
    }

    /// Check if return value is checked (simplified heuristic)
    fn return_value_checked(&self, stmt: &ast::Statement<'_>) -> bool {
        // This is a simplified check - in a real implementation we'd need
        // to track if the return value is assigned to a variable or used in a require
        match stmt {
            ast::Statement::Expression(_) => false, // Bare expression call
            _ => true, // If it's in any other context, assume it's checked
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bumpalo::collections::Vec as BumpVec;

    #[test]
    fn test_detector_properties() {
        let detector = UncheckedCallDetector::new();
        assert_eq!(detector.id().0, "unchecked-external-call");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_is_external_call_plain_member_access() {
        let detector = UncheckedCallDetector::new();
        let arena = ast::AstArena::new();

        let loc = ast::SourceLocation::new(
            "t.sol".into(),
            ast::Position::start(),
            ast::Position::start(),
        );
        let addr = arena.alloc(ast::Expression::Identifier(ast::Identifier::new(
            arena.alloc_str("recipient"),
            loc.clone(),
        )));
        let member = ast::Identifier::new(arena.alloc_str("call"), loc.clone());

        let expr = ast::Expression::MemberAccess {
            expression: addr,
            member,
            location: loc,
        };
        assert!(
            detector.is_external_call(&expr),
            "plain .call member access should be recognized"
        );
    }

    #[test]
    fn test_is_external_call_with_call_options_wrapper() {
        let detector = UncheckedCallDetector::new();
        let arena = ast::AstArena::new();

        let loc = ast::SourceLocation::new(
            "t.sol".into(),
            ast::Position::start(),
            ast::Position::start(),
        );
        let addr = arena.alloc(ast::Expression::Identifier(ast::Identifier::new(
            arena.alloc_str("recipient"),
            loc.clone(),
        )));
        let member = ast::Identifier::new(arena.alloc_str("call"), loc.clone());

        let inner_member_access = ast::Expression::MemberAccess {
            expression: addr,
            member,
            location: loc.clone(),
        };

        let call_options_wrapper = ast::Expression::FunctionCall {
            function: arena.alloc(inner_member_access),
            arguments: BumpVec::new_in(&arena.bump),
            names: BumpVec::new_in(&arena.bump),
            location: loc,
        };

        assert!(
            detector.is_external_call(&call_options_wrapper),
            "call-options wrapper should be peeled and recognized"
        );
    }

    #[test]
    fn test_is_not_external_call_for_arrays() {
        let detector = UncheckedCallDetector::new();
        let arena = ast::AstArena::new();

        let loc = ast::SourceLocation::new(
            "t.sol".into(),
            ast::Position::start(),
            ast::Position::start(),
        );
        let addr = arena.alloc(ast::Expression::Identifier(ast::Identifier::new(
            arena.alloc_str("shareholders"),
            loc.clone(),
        )));
        let member = ast::Identifier::new(arena.alloc_str("call"), loc.clone());

        let expr = ast::Expression::MemberAccess {
            expression: addr,
            member,
            location: loc,
        };
        assert!(
            !detector.is_external_call(&expr),
            "array-like names should not be flagged"
        );
    }

    #[test]
    fn test_has_inline_success_check() {
        let detector = UncheckedCallDetector::new();

        let checked = r#"
            (bool success, ) = addr.call{value: amount}("");
            require(success, "Transfer failed");
        "#;
        assert!(detector.has_inline_success_check(checked));

        let unchecked = r#"
            addr.call{value: amount}("");
        "#;
        assert!(!detector.has_inline_success_check(unchecked));
    }
}

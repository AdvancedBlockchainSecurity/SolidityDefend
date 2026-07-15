use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for gas griefing attack vulnerabilities
pub struct GasGriefingDetector {
    base: BaseDetector,
}

impl Default for GasGriefingDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl GasGriefingDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("gas-griefing".to_string()),
                "Gas Griefing Attack".to_string(),
                "Detects vulnerabilities where attackers can grief users by forcing high gas consumption".to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::ExternalCalls],
                Severity::Medium,
            ),
        }
    }
}

impl Detector for GasGriefingDetector {
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

        for function in ctx.get_functions() {
            if let Some(gas_issue) = self.check_gas_griefing(function, ctx) {
                let message = format!(
                    "Function '{}' has gas griefing vulnerability. {} \
                    Attackers can force users to waste gas or cause transactions to fail.",
                    function.name.name, gas_issue
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(400) // CWE-400: Uncontrolled Resource Consumption
                .with_cwe(405) // CWE-405: Asymmetric Resource Consumption
                .with_fix_suggestion(format!(
                    "Mitigate gas griefing in '{}'. \
                    Use pull pattern for transfers, limit array sizes, add gas stipends, \
                    implement gas-efficient loops, avoid unbounded operations, use OpenZeppelin SafeERC20.",
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

impl GasGriefingDetector {
    fn check_gas_griefing(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        function.body.as_ref()?;

        let func_source = self.get_function_source(function, ctx);

        // Skip functions with access control modifiers -- trusted callers cannot grief themselves
        if self.has_access_control(function, &func_source) {
            return None;
        }

        // Skip functions with reentrancy guards -- indicates protected execution context
        if self.has_reentrancy_guard(function, &func_source) {
            return None;
        }

        // Skip multicall/batch-executor patterns -- the caller supplies the call
        // targets and pays the gas, so there is no third party to grief
        if self.is_caller_supplied_batch(function, &func_source) {
            return None;
        }

        // Pattern 1: External .call{} in loop without explicit gas limit
        // Note: .transfer() is SAFE - it has built-in 2300 gas stipend and reverts on failure
        // Note: .send() is SAFE - it has built-in 2300 gas stipend and returns false on failure
        // Only .call{} without gas limits is vulnerable to gas griefing
        let has_loop = self.has_loop_construct(&func_source);
        let has_unsafe_call = func_source.contains(".call{") || func_source.contains(".call(");

        // .call{} without gas: specification forwards all gas - vulnerable to griefing
        if has_loop && has_unsafe_call {
            // Verify the .call{} is actually inside the loop body, not just co-existing
            // in the same function. A comparison loop followed by a single .call{} is not
            // a gas griefing vector.
            if !self.is_call_inside_loop(&func_source) {
                // The call exists in the function but not within the loop body -- not vulnerable
            } else {
                // Check if gas limit is specified
                let has_gas_limit = func_source.contains("gas:")
                    || func_source.contains("gas(")
                    || func_source.contains(".call{value:") && func_source.contains("gas:");

                if !has_gas_limit {
                    // Skip governance execute patterns where call targets are from approved proposals
                    if !self.is_governance_execute_pattern(function, &func_source) {
                        return Some(
                            "External .call{} in loop without gas limit forwards all gas to recipient, \
                            attacker can grief by consuming all gas in fallback function. \
                            Use .call{value: amount, gas: 10000}(\"\") or .transfer() instead"
                                .to_string(),
                        );
                    }
                }
            }
        }

        // Pattern 2: Push pattern for mass ETH distribution with .call{}
        // Only flag if using .call{} (not .transfer() which is safe)
        // .transfer() has built-in 2300 gas limit and reverts on failure - not a griefing vector
        if has_loop && has_unsafe_call && self.is_call_inside_loop(&func_source) {
            let distributes_to_many = func_source.contains("recipients")
                || func_source.contains("addresses")
                || func_source.contains("payees")
                || (func_source.contains("[") && func_source.contains("].length"));

            if distributes_to_many
                && !func_source.contains("pull")
                && !func_source.contains("withdraw")
            {
                return Some(
                    "Push pattern for mass ETH distribution using .call{} in loop. \
                    Single recipient with malicious fallback can consume excessive gas. \
                    Consider: (1) Use pull pattern (withdrawals), (2) Add gas limits, \
                    (3) Use .transfer() for small amounts, (4) Implement batch size limits"
                        .to_string(),
                );
            }
        }

        // Pattern 3: Delegatecall in loop (extremely dangerous)
        // Note: Skip this pattern -- delegatecall vulnerabilities are covered by dedicated
        // detectors (delegatecall-in-loop, delegatecall-user-controlled, etc.)
        // Flagging here is redundant and produces misleading "gas griefing" findings
        // when the real issue is arbitrary code execution via delegatecall.

        None
    }

    /// Check if the function source contains actual loop constructs (for/while statements).
    /// Uses word-boundary-aware matching to avoid false positives from substrings
    /// like "Transfer" containing "for", or "information" containing "for".
    fn has_loop_construct(&self, func_source: &str) -> bool {
        // Match "for " (for statement) or "for(" (for with no space before paren)
        // This avoids matching substrings in words like "Transfer", "information", "perform", etc.
        let has_for = func_source.contains("for ") || func_source.contains("for(");
        let has_while = func_source.contains("while ") || func_source.contains("while(");
        has_for || has_while
    }

    /// Check if the .call{} is actually inside a loop body, not just co-existing
    /// in the same function. For example, a function with a comparison loop followed
    /// by a single .call{} at the end is not vulnerable to gas griefing.
    /// Multicall / batch-executor pattern: the caller supplies the call targets
    /// and/or the payloads as parameters of this function and pays the gas for
    /// the batch. A callee that burns gas only fails the caller's own
    /// transaction, so there is no third party to grief. Covers Multicall3,
    /// ERC-7821 batch executors, and meta-transaction batchers.
    ///
    /// Deliberately does not match push-distribution over a storage recipient
    /// list (`payees[i].call{value: shares[i]}("")`), where one malicious
    /// fallback blocks every other payee -- that is the real griefing vector.
    fn is_caller_supplied_batch(&self, function: &ast::Function<'_>, func_source: &str) -> bool {
        // The payload is caller-supplied arbitrary calldata, e.g.
        //   calls[i].target.call{value: calls[i].value}(calls[i].data)
        //   targets[i].call(data[i])
        if func_source.contains("].data)")
            || func_source.contains(".call(data[")
            || func_source.contains(".call(calls[")
        {
            return true;
        }

        // A value-bearing call is a distribution, not a batch execution: a
        // blocked recipient harms the others, so keep flagging it.
        if func_source.contains(".call{value") {
            return false;
        }

        // The call target is indexed out of one of this function's own
        // parameters -- a fixed-selector callback loop over caller-chosen
        // recipients, e.g. `recipients[i].call(abi.encodeWithSignature(...))`.
        function.parameters.iter().any(|param| {
            param.name.as_ref().is_some_and(|n| {
                func_source.contains(&format!("{}[", n.name)) && func_source.contains("].call")
            })
        })
    }

    fn is_call_inside_loop(&self, func_source: &str) -> bool {
        // Strategy: find the loop construct, then check if .call{ appears
        // within its brace-delimited body.
        let lines: Vec<&str> = func_source.lines().collect();
        let mut in_loop = false;
        let mut brace_depth: i32 = 0;
        let mut loop_start_depth: i32 = 0;

        for line in &lines {
            let trimmed = line.trim();

            // Detect loop start
            if !in_loop {
                if (trimmed.contains("for ")
                    || trimmed.contains("for(")
                    || trimmed.contains("while ")
                    || trimmed.contains("while("))
                    && (trimmed.contains("{") || trimmed.ends_with(")"))
                {
                    in_loop = true;
                    loop_start_depth = brace_depth;
                }
            }

            // Track braces
            for ch in line.chars() {
                if ch == '{' {
                    brace_depth += 1;
                } else if ch == '}' {
                    brace_depth -= 1;
                    // If we drop back to or below the loop start depth, loop body ended
                    if in_loop && brace_depth <= loop_start_depth {
                        in_loop = false;
                    }
                }
            }

            // Check if .call{ appears inside the loop body
            if in_loop && (trimmed.contains(".call{") || trimmed.contains(".call(")) {
                return true;
            }
        }

        false
    }

    /// Check if the function has access control modifiers (onlyOwner, onlyAdmin, etc.)
    /// Trusted callers cannot grief themselves, so these are not gas griefing vulnerabilities.
    fn has_access_control(&self, function: &ast::Function<'_>, func_source: &str) -> bool {
        // Check AST modifiers
        let has_modifier = function.modifiers.iter().any(|m| {
            let name_lower = m.name.name.to_lowercase();
            name_lower.contains("only")
                || name_lower.contains("admin")
                || name_lower.contains("owner")
                || name_lower.contains("authorized")
                || name_lower.contains("guardian")
                || name_lower.contains("operator")
                || name_lower.contains("governance")
        });

        if has_modifier {
            return true;
        }

        // Check inline access control in source
        func_source.contains("require(msg.sender ==")
            || func_source.contains("require(hasRole")
            || func_source.contains("if (msg.sender !=")
    }

    /// Check if the function has a reentrancy guard modifier.
    /// Functions protected by reentrancy guards are in controlled execution contexts.
    fn has_reentrancy_guard(&self, function: &ast::Function<'_>, func_source: &str) -> bool {
        let has_modifier = function.modifiers.iter().any(|m| {
            let name_lower = m.name.name.to_lowercase();
            name_lower.contains("nonreentrant")
                || name_lower.contains("noreentrancy")
                || name_lower == "lock"
        });

        if has_modifier {
            return true;
        }

        // Check source-level patterns
        func_source.contains("nonReentrant") || func_source.contains("noReentrancy")
    }

    /// Check if this is a governance execute pattern where call targets come from
    /// governance-approved proposals (e.g., Compound Governor, OpenZeppelin Governor).
    /// In these patterns, the targets array is set during proposal creation and approved
    /// through voting -- they are not attacker-controlled at execution time.
    fn is_governance_execute_pattern(
        &self,
        function: &ast::Function<'_>,
        func_source: &str,
    ) -> bool {
        let func_name = function.name.name.to_lowercase();

        // Function name is "execute" or similar governance execution function
        let is_execute_func = func_name == "execute"
            || func_name == "executeproposal"
            || func_name == "executetransaction"
            || func_name == "executebatch";

        if !is_execute_func {
            return false;
        }

        // Has governance indicators: proposal state checks, proposal storage access
        func_source.contains("proposal")
            || func_source.contains("Proposal")
            || func_source.contains("proposalId")
            || func_source.contains("timelock")
            || func_source.contains("Queued")
    }

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = GasGriefingDetector::new();
        assert_eq!(detector.name(), "Gas Griefing Attack");
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }
}

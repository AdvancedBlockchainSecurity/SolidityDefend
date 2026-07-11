use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

/// Detector for ERC-20 approve race condition vulnerabilities (SWC-114)
pub struct Erc20ApproveRaceDetector {
    base: BaseDetector,
}

impl Default for Erc20ApproveRaceDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Erc20ApproveRaceDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("erc20-approve-race".to_string()),
                "ERC-20 Approve Race Condition".to_string(),
                "Detects ERC-20 approve functions vulnerable to front-running race conditions (SWC-114)".to_string(),
                vec![DetectorCategory::Logic, DetectorCategory::DeFi],
                // Info: the SWC-114 approve race is inherent to the ERC-20 standard itself,
                // not an implementation bug — mitigation is caller-side.
                Severity::Info,
            ),
        }
    }
}

impl Detector for Erc20ApproveRaceDetector {
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

        // FP Reduction: Skip secure/fixed example contracts
        if crate::utils::is_secure_example_file(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip attack/exploit contracts
        if crate::utils::is_attack_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip proxy contracts — approve() there merely forwards to the impl.
        if crate::utils::is_proxy_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip files in directories with dedicated detectors
        // Restaking tokens have standard approve() but are covered by restaking detectors
        // Critical vulnerability files are focused on other patterns (permit, create2, etc.)
        {
            let file_lower = ctx.file_path.to_lowercase();
            if file_lower.contains("restaking/") || file_lower.contains("critical_vulnerabilities/")
            {
                return Ok(findings);
            }
        }

        // FP Reduction: Consolidate per-function issues into 1 finding per contract
        let mut sub_issues: Vec<(String, u32)> = Vec::new();

        for function in ctx.get_functions() {
            if let Some(issue) = self.check_approve_race(function, ctx) {
                sub_issues.push((
                    format!("'{}': {}", function.name.name, issue),
                    function.name.location.start().line() as u32,
                ));
            }
        }

        if !sub_issues.is_empty() {
            let first_line = sub_issues[0].1;
            let descriptions: Vec<&str> = sub_issues.iter().map(|(d, _)| d.as_str()).collect();
            let consolidated_msg = format!(
                "Contract '{}' has {} approve race condition vulnerabilities: {}",
                ctx.contract.name.name,
                sub_issues.len(),
                descriptions.join("; ")
            );
            let finding = self
                .base
                .create_finding(ctx, consolidated_msg, first_line, 0, 40)
                .with_cwe(362)
                .with_fix_suggestion(
                    "The approve race is inherent to ERC-20/ERC-6909 (SWC-114); \
                    mitigation is caller-side: set the allowance to 0 before setting \
                    a new value, or use ERC-2612 permit. Note OpenZeppelin v5 removed \
                    increaseAllowance/decreaseAllowance."
                        .to_string(),
                );
            findings.push(finding);
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Erc20ApproveRaceDetector {
    /// Checks if a contract has increaseAllowance function
    fn has_increase_allowance(&self, ctx: &AnalysisContext) -> bool {
        ctx.get_functions()
            .iter()
            .any(|func| func.name.name == "increaseAllowance")
    }

    /// Checks if contract has decreaseAllowance function
    fn has_decrease_allowance(&self, ctx: &AnalysisContext) -> bool {
        ctx.get_functions()
            .iter()
            .any(|func| func.name.name == "decreaseAllowance")
    }

    /// Checks if this appears to be an ERC20 contract
    fn is_erc20_contract(&self, ctx: &AnalysisContext) -> bool {
        let functions = ctx.get_functions();

        // Check for minimal ERC20 interface
        let has_transfer = functions.iter().any(|f| f.name.name == "transfer");
        let has_transfer_from = functions.iter().any(|f| f.name.name == "transferFrom");
        let has_approve = functions.iter().any(|f| f.name.name == "approve");

        has_transfer && has_transfer_from && has_approve
    }

    fn check_approve_race(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        function.body.as_ref()?;

        let func_source = self.get_function_source(function, ctx);
        let name_lower = function.name.name.to_lowercase();

        if name_lower != "approve" {
            return None;
        }

        // Only report if this looks like an ERC20 contract
        if !self.is_erc20_contract(ctx) {
            return None;
        }

        // The approve body must actually write an allowance (directly or via _approve).
        let writes_allowance = func_source.contains("_approve(")
            || (func_source.contains("allowance") && func_source.contains('='));
        if !writes_allowance {
            return None;
        }

        // Check if contract provides safe alternatives
        let has_increase = self.has_increase_allowance(ctx);
        let has_decrease = self.has_decrease_allowance(ctx);

        // Check for race condition mitigations in the approve function itself
        let has_require_zero = func_source.contains("require")
            && func_source.contains("allowance")
            && (func_source.contains("== 0") || func_source.contains("!= 0"));

        let has_expected_param = function.parameters.iter().any(|param| {
            let param_name = param
                .name
                .as_ref()
                .map(|n| n.name.to_lowercase())
                .unwrap_or_default();
            param_name.contains("expected") || param_name.contains("current")
        });

        let has_safe_patterns = func_source.contains("SafeERC20")
            || func_source.contains("safeApprove")
            || has_expected_param;

        // Vulnerable if:
        // 1. No increaseAllowance/decreaseAllowance alternatives
        // 2. No protection in approve itself
        // 3. No safe pattern usage
        if !has_increase && !has_decrease && !has_require_zero && !has_safe_patterns {
            return Some(format!(
                "ERC-20 token implements approve() without safe alternatives. \
                Missing increaseAllowance() and decreaseAllowance() functions. \
                This is vulnerable to front-running attacks where a malicious spender \
                can extract both old and new allowance values (SWC-114)"
            ));
        }

        None
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
        let detector = Erc20ApproveRaceDetector::new();
        assert_eq!(detector.name(), "ERC-20 Approve Race Condition");
        assert_eq!(detector.default_severity(), Severity::Info);
    }
}

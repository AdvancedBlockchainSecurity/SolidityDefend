use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils;

/// Detector for dangerous centralization of control
pub struct CentralizationRiskDetector {
    base: BaseDetector,
}

impl Default for CentralizationRiskDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl CentralizationRiskDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("centralization-risk".to_string()),
                "Centralization Risk".to_string(),
                "Detects concentration of control that may create single points of failure"
                    .to_string(),
                vec![DetectorCategory::AccessControl],
                // P1 FIX: Default to Medium - severity is calibrated per finding
                // Simple Ownable patterns are INFO, dangerous patterns are HIGH
                Severity::Medium,
            ),
        }
    }
}

impl Detector for CentralizationRiskDetector {
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

        // Check contract-level centralization
        if let Some(contract_issue) = self.check_contract_centralization(ctx) {
            let message = format!(
                "Contract has centralization risk. {} \
                Single point of failure can lead to fund loss, governance attacks, or complete system compromise.",
                contract_issue
            );

            let finding = self
                .base
                .create_finding(ctx, message, 1, 0, 20)
                .with_cwe(269) // CWE-269: Improper Privilege Management
                .with_cwe(284) // CWE-284: Improper Access Control
                .with_fix_suggestion(
                    "Implement decentralized governance. \
                Use: (1) Multi-signature wallet (Gnosis Safe), \
                (2) Timelock delays for critical operations, \
                (3) DAO governance with voting mechanisms, \
                (4) Role-based access control (OpenZeppelin AccessControl), \
                (5) Emergency pause with multiple approvers."
                        .to_string(),
                );

            findings.push(finding);
        }

        // Check function-level centralization
        for function in ctx.get_functions() {
            if let Some(function_issue) = self.check_function_centralization(function, ctx) {
                let message = format!(
                    "Function '{}' has centralization risk. {} \
                    Critical function controlled by single address creates attack vector.",
                    function.name.name, function_issue
                );

                let finding = self.base.create_finding(
                    ctx,
                    message,
                    function.name.location.start().line() as u32,
                    function.name.location.start().column() as u32,
                    function.name.name.len() as u32,
                )
                .with_cwe(269)
                .with_cwe(284)
                .with_fix_suggestion(format!(
                    "Add decentralization to '{}'. \
                    Implement multi-signature requirements, timelock delays, or DAO governance for this critical function.",
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

impl CentralizationRiskDetector {
    fn check_contract_centralization(&self, ctx: &AnalysisContext) -> Option<String> {
        // Clean source to avoid FPs from comments/strings
        let contract_source = utils::clean_source_for_search(ctx.source_code.as_str());

        // P1 FP FIX: Recognize OpenZeppelin Ownable as standard accepted pattern
        // This is the most common access control pattern in production contracts
        let uses_oz_ownable = ctx.source_code.contains("Ownable")
            || ctx.source_code.contains("import \"@openzeppelin")
            || ctx.source_code.contains("import '@openzeppelin");

        // Phase 52 FP Reduction: Detect decentralization patterns
        // If any of these are present, the contract has meaningful decentralization
        let has_timelock = contract_source.contains("timelock")
            || contract_source.contains("TimelockController")
            || contract_source.contains("queueTransaction")
            || contract_source.contains("delay =")
            || contract_source.contains("executeTransaction")
            || (contract_source.contains("timestamp")
                && contract_source.contains("require(block.timestamp >="));

        let has_multisig = contract_source.contains("multisig")
            || contract_source.contains("MultiSig")
            || contract_source.contains("Gnosis")
            || contract_source.contains("threshold")
            || contract_source.contains("confirmations")
            || contract_source.contains("requiredSignatures")
            || contract_source.contains("Safe");

        let has_governance = contract_source.contains("Governor")
            || contract_source.contains("propose(")
            || contract_source.contains("castVote")
            || contract_source.contains("quorum")
            || contract_source.contains("votingPeriod")
            || contract_source.contains("votingDelay");

        let has_access_control_roles = contract_source.contains("AccessControl")
            || contract_source.contains("hasRole(")
            || contract_source.contains("grantRole(")
            || contract_source.contains("DEFAULT_ADMIN_ROLE")
            || contract_source.contains("_ROLE = keccak256");

        // Skip entirely if contract has proper decentralization mechanisms
        if has_timelock || has_multisig || has_governance {
            return None;
        }

        // P1 FP FIX: Only flag truly dangerous centralization
        // Standard Ownable without extra risk factors is just a design choice

        // Check for dangerous combinations that warrant HIGH severity
        let has_selfdestruct =
            contract_source.contains("selfdestruct") || contract_source.contains("suicide");

        // Only "owner drains tokens" if there is actually an owner/admin-gated path.
        let has_owner_gate = contract_source.contains("onlyOwner")
            || contract_source.contains("onlyAdmin")
            || contract_source.contains("msg.sender == owner")
            || contract_source.contains("msg.sender == admin");
        let has_arbitrary_token_transfer = has_owner_gate
            && (contract_source.contains("transferFrom(address(this)")
                || contract_source.contains(".transfer(owner")
                || contract_source.contains(".transfer(msg.sender"));

        // Phase 16 FN Recovery: Check for governance-specific centralization
        // Governance contracts have unique centralization risks even with OZ Ownable
        let is_governance_contract = contract_source.contains("governance")
            || contract_source.contains("proposal")
            || contract_source.contains("voting")
            || contract_source.contains("quorum")
            || ctx.contract.name.name.to_lowercase().contains("governance")
            || ctx.contract.name.name.to_lowercase().contains("dao");

        // Governance-specific centralization patterns
        let has_guardian_bypass = contract_source.contains("guardian")
            && (contract_source.contains("emergency")
                || contract_source.contains("bypass")
                || contract_source.contains("pause"));

        let has_centralized_parameter_control = contract_source.contains("onlyOwner")
            || contract_source.contains("msg.sender == owner");

        // Governance contracts with guardian/admin that can bypass voting
        if is_governance_contract && has_guardian_bypass && has_centralized_parameter_control {
            return Some(
                "Governance contract has admin/guardian that can bypass voting process. \
                Centralized emergency controls undermine decentralized governance"
                    .to_string(),
            );
        }

        // If using OZ Ownable without dangerous patterns, skip entirely
        // This is a standard, well-audited pattern
        if uses_oz_ownable && !has_selfdestruct && !has_arbitrary_token_transfer {
            // But still flag governance contracts with centralized control
            if is_governance_contract && has_centralized_parameter_control {
                return Some(
                    "Governance contract uses centralized Ownable pattern. \
                    Owner can modify governance parameters without community approval"
                        .to_string(),
                );
            }
            return None;
        }

        // Phase 52 FP Reduction: Skip if contract uses role-based access control
        // Role-based access is a design choice, not a vulnerability, unless combined with dangerous functions
        if has_access_control_roles && !has_selfdestruct && !has_arbitrary_token_transfer {
            return None;
        }

        // Pattern 1: Dangerous centralization - selfdestruct controlled by single owner
        if has_selfdestruct && !has_multisig && !has_timelock {
            return Some(
                "Contract has selfdestruct controllable by single address. \
                Owner can permanently destroy contract and steal funds"
                    .to_string(),
            );
        }

        // Pattern 2: Owner can drain arbitrary tokens without restriction
        if has_arbitrary_token_transfer && !has_multisig && !has_timelock {
            return Some(
                "Owner can transfer arbitrary tokens from contract without timelock. \
                Single key compromise enables immediate fund extraction"
                    .to_string(),
            );
        }

        // Skip basic Ownable warnings - they're design choices, not vulnerabilities
        // Pattern 3: Only flag non-OZ owner patterns as info
        let has_custom_owner = (contract_source.contains("address public owner")
            || contract_source.contains("address private owner"))
            && !uses_oz_ownable;

        if has_custom_owner && !has_multisig {
            // This is INFO-level - a design consideration, not a vulnerability
            // Return None to skip, or could return with reduced severity
            // For now, skip to reduce noise
            return None;
        }

        None
    }

    fn check_function_centralization(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        function.body.as_ref()?;

        let func_source = self.get_function_source(function, ctx);
        let func_name = &function.name.name;

        // P1 FP FIX: Recognize OpenZeppelin patterns as standard and accepted
        let uses_oz_patterns = ctx.source_code.contains("Ownable")
            || ctx.source_code.contains("@openzeppelin")
            || ctx.source_code.contains("AccessControl");

        // Pattern 1: Only flag DANGEROUS critical functions, not standard admin
        let is_owner_check =
            func_source.contains("msg.sender == owner") || func_source.contains("onlyOwner");

        // P1 FP FIX: Separate truly dangerous functions from standard admin
        // Standard admin: pause, unpause, setFee, updateConfig - these are expected
        // Dangerous: destroy, kill, selfdestruct, drain, rugpull
        let is_dangerous_function = func_name.to_lowercase().contains("destroy")
            || func_name.to_lowercase().contains("kill")
            || func_name.to_lowercase().contains("selfdestruct")
            || func_name.to_lowercase().contains("drain")
            || func_source.contains("selfdestruct");

        // Only flag truly dangerous functions
        if is_owner_check && is_dangerous_function {
            let has_decentralization = func_source.contains("require(multisig")
                || func_source.contains("timelock")
                || func_source.contains("governance")
                || func_source.contains("delay")
                || func_source.contains("TimelockController")
                || func_source.contains("queueTransaction")
                || func_source.contains("threshold")
                || ctx.source_code.contains("TimelockController")
                || ctx.source_code.contains("Gnosis")
                || ctx.source_code.contains("Safe");

            if !has_decentralization {
                return Some(format!(
                    "Dangerous '{}' function controlled by single owner. \
                    This function can cause irreversible damage or fund loss",
                    func_name
                ));
            }
        }

        // Pattern 2: Emergency functions - only flag if they can drain funds
        // Standard emergency pause is acceptable, emergency withdraw needs scrutiny
        if func_name.to_lowercase().contains("emergency") {
            // Check if this emergency function can move funds
            let can_move_funds = func_source.contains("transfer(")
                || func_source.contains("call{value:")
                || func_source.contains("safeTransfer(");

            let has_safeguards = func_source.contains("multisig")
                || func_source.contains("timelock")
                || func_source.contains("governance")
                || func_source.contains("threshold");

            // Only flag fund-moving emergency functions without safeguards
            if can_move_funds && !has_safeguards && !uses_oz_patterns {
                return Some(format!(
                    "Emergency function '{}' can move funds without multi-party approval. \
                    Consider adding timelock or multisig requirement",
                    func_name
                ));
            }
        }

        None
    }

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = CentralizationRiskDetector::new();
        assert_eq!(detector.name(), "Centralization Risk");
        // P1 FIX: Default severity changed to Medium (calibrated per finding)
        assert_eq!(detector.default_severity(), Severity::Medium);
        assert!(detector.is_enabled());
    }
}

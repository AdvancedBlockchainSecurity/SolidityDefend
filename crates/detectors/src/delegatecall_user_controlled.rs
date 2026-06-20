use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils;

/// Detector for user-controlled delegatecall targets
///
/// This detector identifies delegatecall operations where the target address
/// is controlled by user input or function parameters, allowing arbitrary
/// code execution in the contract's context.
///
/// **Vulnerability:** CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
/// **Severity:** Critical
///
/// ## Description
///
/// User-controlled delegatecall allows attackers to:
/// 1. Execute arbitrary code in contract's storage context
/// 2. Modify any state variable
/// 3. Drain all funds from the contract
/// 4. Take complete control of the contract
///
/// ## FP Reduction
///
/// Skips proxy/diamond pattern contracts, functions with access control modifiers,
/// and owner-managed storage lookups where the user only controls the index/key.
///
pub struct DelegatecallUserControlledDetector {
    base: BaseDetector,
}

impl Default for DelegatecallUserControlledDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DelegatecallUserControlledDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("delegatecall-user-controlled".to_string()),
                "User-Controlled Delegatecall".to_string(),
                "Detects delegatecall operations where the target address is controlled by user input"
                    .to_string(),
                vec![DetectorCategory::AccessControl, DetectorCategory::Logic],
                Severity::Critical,
            ),
        }
    }
}

impl Detector for DelegatecallUserControlledDetector {
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

        // FP Reduction: Skip proxy contracts - delegatecall is by design in proxies
        if utils::is_proxy_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip interface-only contracts (no implementation to analyze)
        if utils::is_interface_only(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip Diamond pattern (EIP-2535) contracts
        if self.is_diamond_contract(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            if let Some(risk_description) = self.has_user_controlled_delegatecall(function, ctx) {
                let message = format!(
                    "Function '{}' performs delegatecall with user-controlled target. {} \
                    This allows arbitrary code execution in the contract's storage context, \
                    enabling complete takeover and fund theft.",
                    function.name.name, risk_description
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
                    .with_cwe(829) // CWE-829: Inclusion of Functionality from Untrusted Control Sphere
                    .with_cwe(494) // CWE-494: Download of Code Without Integrity Check
                    .with_fix_suggestion(format!(
                        "Remove user control over delegatecall target in '{}'. \
                    Use a whitelist of approved addresses: mapping(address => bool) approvedTargets; \
                    Or avoid delegatecall entirely and use regular external calls.",
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

impl DelegatecallUserControlledDetector {
    /// Check if function has user-controlled delegatecall
    fn has_user_controlled_delegatecall(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        // Must have function body
        function.body.as_ref()?;

        // Get function source
        let func_source = self.get_function_source(function, ctx);

        // FP Reduction: Skip modifier definitions
        if func_source.trim_start().starts_with("modifier ") {
            return None;
        }

        // Check for delegatecall
        if !func_source.contains("delegatecall") {
            return None;
        }

        // FP Reduction: Skip functions with access control modifiers.
        if utils::has_access_control_modifier(&func_source)
            || func_source.contains("require(msg.sender ==")
            || func_source.contains("require(msg.sender==")
            || func_source.contains("if (msg.sender != ")
            || func_source.contains("if(msg.sender != ")
        {
            return None;
        }

        // FP Reduction: Skip owner-managed storage lookup patterns.
        if self.is_owner_managed_storage_lookup(&func_source, ctx) {
            return None;
        }

        if self.is_direct_address_param_delegatecall(&func_source, function) {
            return Some(
                "Delegatecall target comes directly from a function parameter, \
                allowing callers to execute arbitrary code in the contract's context."
                    .to_string(),
            );
        }

        if self.is_target_user_controlled_indirect(&func_source) {
            return Some(
                "Delegatecall target is derived from function parameters or user input, \
                allowing callers to specify arbitrary code to execute."
                    .to_string(),
            );
        }

        None
    }

    /// Check if function has a direct address parameter used in delegatecall.
    /// Check if a direct address parameter is used as the delegatecall target.
    fn is_direct_address_param_delegatecall(
        &self,
        source: &str,
        function: &ast::Function<'_>,
    ) -> bool {
        for param in &function.parameters {
            if let Some(param_name) = &param.name {
                let param_str = param_name.name;

                // Check if parameter type is address
                let type_str = format!("{:?}", param.type_name);
                if !type_str.to_lowercase().contains("address") {
                    continue;
                }

                // Direct address param used in delegatecall
                if source.contains(&format!("{}.delegatecall", param_str))
                    || source.contains(&format!("delegatecall({}", param_str))
                {
                    return true;
                }

                // Address param assigned to local variable that is then used in delegatecall
                // e.g., `address target = customLib != address(0) ? customLib : defaultLib;`
                // then `target.delegatecall(...)`
                if source.contains(&format!("= {}", param_str)) && source.contains("delegatecall") {
                    return true;
                }
            }
        }

        // Check for implementation parameter patterns in the function signature
        // Check for implementation parameter patterns in the function signature
        let sig_lines: Vec<&str> = source.lines().take(5).collect();
        let sig_area = sig_lines.join(" ");
        if (sig_area.contains("address _implementation")
            || sig_area.contains("address implementation")
            || sig_area.contains("address target")
            || sig_area.contains("address _target")
            || sig_area.contains("address to")
            || sig_area.contains("address _to")
            || sig_area.contains("address lib")
            || sig_area.contains("address _lib")
            || sig_area.contains("address customLib"))
            && source.contains("delegatecall")
        {
            return true;
        }

        false
    }

    /// Check if delegatecall target comes from owner-managed storage.
    /// When an array or mapping is populated by an owner-only function, the user
    /// only controls the index/key but cannot inject arbitrary addresses.
    fn is_owner_managed_storage_lookup(&self, func_source: &str, ctx: &AnalysisContext) -> bool {
        let contract_source = &ctx.source_code;

        // Pattern: target = someArray[index] where someArray is owner-managed
        // Look for array indexing into delegatecall target
        let has_array_lookup = func_source.contains("[index]")
            || func_source.contains("[_index]")
            || func_source.contains("[idx]")
            || func_source.contains("[i]");

        if has_array_lookup && func_source.contains("delegatecall") {
            // Check if the contract has owner-only functions that populate the array
            let has_owner_managed_push = (contract_source.contains(".push(")
                || contract_source.contains("libraries[")
                || contract_source.contains("approvedLibraries["))
                && (contract_source.contains("onlyOwner")
                    || contract_source.contains("require(msg.sender == owner")
                    || contract_source.contains("onlyAdmin"));

            if has_owner_managed_push {
                return true;
            }
        }

        // Pattern: target = mapping[key] where mapping is owner-managed
        // e.g., libraries[name] where setLibrary is owner-only
        let has_mapping_lookup = func_source.contains("libraries[")
            || func_source.contains("implementations[")
            || func_source.contains("facets[")
            || func_source.contains("modules[");

        if has_mapping_lookup && func_source.contains("delegatecall") {
            let has_owner_managed_setter = contract_source.contains("onlyOwner")
                || contract_source.contains("require(msg.sender == owner")
                || contract_source.contains("onlyAdmin");

            if has_owner_managed_setter {
                return true;
            }
        }

        false
    }

    /// Check if delegatecall target is user-controlled through indirect paths
    /// that indicate indirect user control of delegatecall targets.
    /// This catches more subtle patterns like msg.sender-based delegatecall.
    fn is_target_user_controlled_indirect(&self, source: &str) -> bool {
        // Check for msg.sender delegatecall (less common but still user-controlled)
        // Rare pattern: indirect user control of delegatecall target
        if source.contains("msg.sender.delegatecall") || source.contains("msg.sender).delegatecall")
        {
            return true;
        }

        false
    }

    /// Get function source code
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

    /// Check if contract is a Diamond pattern (EIP-2535)
    /// Diamond contracts use delegatecall to facets by design
    fn is_diamond_contract(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;
        let lower = source.to_lowercase();

        let has_diamond_cut = source.contains("diamondCut")
            || source.contains("DiamondCut")
            || source.contains("IDiamondCut");

        let has_diamond_loupe = source.contains("DiamondLoupe")
            || source.contains("IDiamondLoupe")
            || source.contains("facets()")
            || source.contains("facetAddress(");

        let has_facet_mapping = lower.contains("facets")
            && (lower.contains("mapping") || lower.contains("selectortoface"));

        let has_diamond_storage = source.contains("DiamondStorage")
            || source.contains("DIAMOND_STORAGE_POSITION")
            || source.contains("keccak256(\"diamond.standard.");

        let has_diamond_inheritance = source.contains("Diamond")
            && (source.contains("is ") || source.contains("contract Diamond"));

        (has_diamond_cut && has_diamond_loupe)
            || (has_diamond_storage && has_facet_mapping)
            || (has_diamond_inheritance && (has_diamond_cut || has_diamond_loupe))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse `source` with the real Solidity parser and run `detector.detect`
    /// against the first contract. Populates the AST so the detector sees the
    /// function bodies and parameters (unlike `create_test_context`).
    fn detect_findings(
        detector: &DelegatecallUserControlledDetector,
        source: &str,
    ) -> Vec<Finding> {
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

    #[test]
    fn test_detector_properties() {
        let detector = DelegatecallUserControlledDetector::new();
        assert_eq!(detector.name(), "User-Controlled Delegatecall");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
        assert_eq!(detector.id().0, "delegatecall-user-controlled");
    }

    /// Regression: this detector was previously unregistered (dead code).
    /// Verify it fires on a function whose delegatecall target is a
    /// user-controlled address parameter.
    #[test]
    fn test_user_controlled_delegatecall_target_fires() {
        let detector = DelegatecallUserControlledDetector::new();
        let source = r#"
            contract Proxy {
                function forward(address target, bytes calldata data) external {
                    (bool ok, ) = target.delegatecall(data);
                    require(ok, "delegatecall failed");
                }
            }
        "#;
        let findings = detect_findings(&detector, source);
        assert!(
            !findings.is_empty(),
            "delegatecall with user-controlled target parameter should fire"
        );
        assert!(
            findings
                .iter()
                .all(|f| f.detector_id.0 == "delegatecall-user-controlled"),
            "all findings should come from delegatecall-user-controlled"
        );
    }

    /// FP guard: a delegatecall whose target is gated by an inline owner check
    /// (require(msg.sender == owner)) must NOT fire.
    #[test]
    fn test_owner_checked_delegatecall_does_not_fire() {
        let detector = DelegatecallUserControlledDetector::new();
        let source = r#"
            contract OwnedProxy {
                address public owner;
                function forward(address target, bytes calldata data) external {
                    require(msg.sender == owner, "not owner");
                    (bool ok, ) = target.delegatecall(data);
                    require(ok, "delegatecall failed");
                }
            }
        "#;
        let findings = detect_findings(&detector, source);
        assert!(
            findings.is_empty(),
            "owner-checked delegatecall should not fire"
        );
    }
}

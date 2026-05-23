//! Bridge Token Minting Access Control Detector

use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct TokenMintingDetector {
    base: BaseDetector,
}

impl TokenMintingDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("bridge-token-mint-control".to_string()),
                "Bridge Token Minting Control".to_string(),
                "Detects unsafe token minting in bridge contracts".to_string(),
                vec![
                    DetectorCategory::CrossChain,
                    DetectorCategory::AccessControl,
                ],
                Severity::Critical,
            ),
        }
    }

    fn is_bridge_contract(&self, ctx: &AnalysisContext) -> bool {
        let source = ctx.source_code.to_lowercase();
        source.contains("bridge") || source.contains("relay") || source.contains("crosschain")
    }

    fn check_function(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Vec<(String, Severity, String)> {
        let mut issues = Vec::new();
        let name = function.name.name.to_lowercase();

        if !name.contains("mint") && !name.contains("issue") {
            return issues;
        }

        // Only check external/public functions
        let is_external = matches!(
            function.visibility,
            ast::Visibility::External | ast::Visibility::Public
        );

        if !is_external {
            return issues;
        }

        // Get function source with comments stripped
        let func_source = self.get_function_source(function, ctx).to_lowercase();

        // Check for access control modifiers (now that AST parser populates them!)
        // A modifier only counts if its body actually enforces access — an empty
        // modifier (`modifier onlyX() { _; }`) provides zero protection.
        let has_modifier = function
            .modifiers
            .iter()
            .any(|inv| self.modifier_enforces_access(&inv.name.name, ctx));

        // Also check for inline require statements as additional validation
        let has_inline_check = func_source.contains("require(msg.sender");

        let has_access = has_modifier || has_inline_check;

        let validates_message = func_source.contains("verify")
            && (func_source.contains("message")
                || func_source.contains("proof")
                || func_source.contains("signature"));

        let has_limits = func_source.contains("max") && func_source.contains("amount");

        if !has_access {
            issues.push((
                format!("Unrestricted token minting in '{}'", function.name.name),
                Severity::Critical,
                "Add access control: modifier onlyBridge { require(msg.sender == bridge); _; }"
                    .to_string(),
            ));
        }

        if has_access && !validates_message {
            // FP Reduction: Skip owner-only direct mint functions that aren't bridge callbacks.
            // Functions like ownerMint/adminMint are owner-controlled supply management,
            // not bridge-triggered minting — message validation isn't applicable.
            let is_owner_direct_mint = name.contains("owner")
                || name.contains("admin")
                || name.contains("manual")
                || (func_source.contains("msg.sender == owner")
                    || func_source.contains("msg.sender == admin"))
                    && !name.contains("bridge")
                    && !name.contains("relay")
                    && !name.contains("receive");
            if !is_owner_direct_mint {
                issues.push((
                    format!("Missing message validation before minting in '{}'", function.name.name),
                    Severity::Critical,
                    "Add: require(verifyMessage(hash, proof)); require(!processed[hash]); processed[hash] = true;".to_string()
                ));
            }
        }

        if has_access && validates_message && !has_limits {
            issues.push((
                format!("Missing mint amount limits in '{}'", function.name.name),
                Severity::High,
                "Add: require(amount <= MAX_MINT_AMOUNT);".to_string(),
            ));
        }

        issues
    }

    /// Check whether a modifier with the given name actually enforces access control.
    /// An empty modifier (only `_;`) provides zero protection regardless of name.
    /// The parser does not currently populate `ContractPart::ModifierDefinition` (see
    /// crates/parser/src/arena.rs:154), so this scans the raw source text for the
    /// modifier definition body. Returns true when the definition is not found in
    /// this file (likely inherited from a base contract) to avoid false positives.
    fn modifier_enforces_access(&self, name: &str, ctx: &AnalysisContext) -> bool {
        modifier_body_has_access_control(name, &ctx.source_code)
    }

    /// Get function source code with comments stripped to avoid false positives
    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start >= source_lines.len() || end >= source_lines.len() {
            return String::new();
        }

        // Strip single-line comments to avoid matching keywords in comments
        source_lines[start..=end]
            .iter()
            .map(|line| {
                if let Some(comment_pos) = line.find("//") {
                    &line[..comment_pos]
                } else {
                    line
                }
            })
            .collect::<Vec<&str>>()
            .join("\n")
    }
}

/// Check whether a modifier definition in `src` actually enforces access control.
/// Returns true when the definition is not found (assume inherited/safe) or when
/// the body contains auth-related patterns.
fn modifier_body_has_access_control(name: &str, src: &str) -> bool {
    let needle = format!("modifier {}", name);
    let Some(start) = src.find(&needle) else {
        return true;
    };

    let after_name = &src[start + needle.len()..];
    let Some(brace_offset) = after_name.find('{') else {
        return true;
    };
    let body_start = start + needle.len() + brace_offset + 1;

    let bytes = src.as_bytes();
    let mut depth = 1usize;
    let mut idx = body_start;
    while idx < bytes.len() && depth > 0 {
        match bytes[idx] {
            b'{' => depth += 1,
            b'}' => depth -= 1,
            _ => {}
        }
        if depth == 0 {
            break;
        }
        idx += 1;
    }
    if depth != 0 {
        return true;
    }
    let body = &src[body_start..idx];

    let stripped: String = body
        .lines()
        .map(|line| {
            if let Some(pos) = line.find("//") {
                &line[..pos]
            } else {
                line
            }
        })
        .collect::<Vec<&str>>()
        .join("\n")
        .to_lowercase();

    stripped.contains("require(")
        || stripped.contains("revert(")
        || stripped.contains("revert ")
        || stripped.contains("msg.sender")
        || stripped.contains("if (")
        || stripped.contains("if(")
        || stripped.contains("assert(")
        || stripped.contains("_checkrole")
        || stripped.contains("_checkowner")
}

impl Default for TokenMintingDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for TokenMintingDetector {
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

        if !self.is_bridge_contract(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            for (title, severity, remediation) in self.check_function(function, ctx) {
                let finding = self
                    .base
                    .create_finding_with_severity(
                        ctx,
                        title,
                        function.name.location.start().line() as u32,
                        0,
                        20,
                        severity,
                    )
                    .with_cwe(284) // CWE-284: Improper Access Control
                    .with_cwe(269) // CWE-269: Improper Privilege Management
                    .with_fix_suggestion(remediation);
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
        let detector = TokenMintingDetector::new();
        assert_eq!(detector.name(), "Bridge Token Minting Control");
        assert_eq!(detector.default_severity(), Severity::Critical);
        assert!(detector.is_enabled());
        assert!(
            detector
                .categories()
                .contains(&DetectorCategory::CrossChain)
        );
        assert!(
            detector
                .categories()
                .contains(&DetectorCategory::AccessControl)
        );
    }

    #[test]
    fn test_empty_modifier_not_trusted() {
        let src = r#"
contract Bridge {
    modifier onlyTest() {
        _;
    }
    function mint(uint256 amount) external onlyTest {}
}
"#;
        assert!(
            !modifier_body_has_access_control("onlyTest", src),
            "empty modifier (only _;) should not count as access control"
        );
    }

    #[test]
    fn test_modifier_with_require_is_trusted() {
        let src = r#"
contract Bridge {
    modifier onlyBridge() {
        require(msg.sender == bridge, "Not bridge");
        _;
    }
    function mint(uint256 amount) external onlyBridge {}
}
"#;
        assert!(
            modifier_body_has_access_control("onlyBridge", src),
            "modifier with require(msg.sender) should be trusted"
        );
    }

    #[test]
    fn test_modifier_with_if_revert_is_trusted() {
        let src = r#"
contract Bridge {
    modifier onlyAdmin() {
        if (msg.sender != admin) revert Unauthorized();
        _;
    }
}
"#;
        assert!(modifier_body_has_access_control("onlyAdmin", src));
    }

    #[test]
    fn test_modifier_with_oz_checkrole_is_trusted() {
        let src = r#"
contract Bridge {
    modifier onlyMinter() {
        _checkRole(MINTER_ROLE);
        _;
    }
}
"#;
        assert!(modifier_body_has_access_control("onlyMinter", src));
    }

    #[test]
    fn test_modifier_not_found_assumed_inherited() {
        let src = "contract Bridge { function mint() external onlyOwner {} }";
        assert!(
            modifier_body_has_access_control("onlyOwner", src),
            "modifier not defined locally should be assumed inherited (safe)"
        );
    }

    #[test]
    fn test_modifier_with_commented_require_not_trusted() {
        let src = r#"
contract Bridge {
    modifier onlyFake() {
        // require(msg.sender == owner);
        _;
    }
}
"#;
        assert!(
            !modifier_body_has_access_control("onlyFake", src),
            "commented-out require should not count"
        );
    }
}

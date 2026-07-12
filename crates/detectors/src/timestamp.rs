use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};

pub struct BlockDependencyDetector {
    base: BaseDetector,
}

impl Default for BlockDependencyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockDependencyDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("block-dependency".to_string()),
                "Block Dependency".to_string(),
                "Dangerous dependence on block properties including timestamp manipulation for time-based calculations".to_string(),
                vec![DetectorCategory::Timestamp, DetectorCategory::DeFi],
                Severity::Medium,
            ),
        }
    }
}

impl Detector for BlockDependencyDetector {
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

        // FP Reduction: Skip contracts where timestamp use is expected by design
        let source_lower = ctx.source_code.to_lowercase();

        // Governance, timelocks, vesting, staking, and yield farming all legitimately use timestamps
        let uses_time_by_design = source_lower.contains("timelock")
            || source_lower.contains("governance")
            || source_lower.contains("proposal")
            || source_lower.contains("voting")
            || source_lower.contains("vesting")
            || source_lower.contains("staking")
            || source_lower.contains("yield")
            || source_lower.contains("reward")
            || source_lower.contains("rewardpertoken")
            || source_lower.contains("lastupdate")
            || source_lower.contains("lastrewardtime")
            || source_lower.contains("periodfinish");

        if uses_time_by_design {
            return Ok(crate::utils::filter_fp_findings(findings, ctx));
        }

        for function in ctx.get_functions() {
            if let Some((has_dependency, manipulation_type)) =
                self.has_timestamp_dependency(function, ctx)
            {
                if has_dependency {
                    let message = match manipulation_type.as_str() {
                        "time_boost" => format!(
                            "Function '{}' calculates time-based boost using block.timestamp which \
                            miners can manipulate by ~15 seconds. This allows attackers to gain \
                            unfair advantages in reward calculations.",
                            function.name.name
                        ),
                        "timestamp_validation" => format!(
                            "Function '{}' uses block.timestamp for validation without proper bounds, \
                            allowing manipulation of time-dependent security checks.",
                            function.name.name
                        ),
                        _ => format!(
                            "Function '{}' has dangerous dependence on block timestamp or number \
                            which can be manipulated by miners within certain bounds (~15 seconds for timestamp).",
                            function.name.name
                        ),
                    };

                    let finding = self.base.create_finding(
                        ctx,
                        message,
                        function.name.location.start().line() as u32,
                        function.name.location.start().column() as u32,
                        function.name.name.len() as u32,
                    )
                    .with_cwe(330) // CWE-330: Use of Insufficiently Random Values
                    .with_cwe(367) // CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
                    .with_fix_suggestion(format!(
                        "Avoid using block.timestamp or block.number for critical logic in function '{}'. \
                        Use Chainlink VRF for randomness, or implement time delays with sufficient tolerance \
                        for miner manipulation (~15 second buffer).",
                        function.name.name
                    ));

                    findings.push(finding);
                }
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl BlockDependencyDetector {
    /// Check if function has dangerous timestamp dependencies
    fn has_timestamp_dependency(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<(bool, String)> {
        if let Some(body) = &function.body {
            if self.check_statements_for_timestamp_use(&body.statements) {
                return Some((true, "general".to_string()));
            }
        }
        Some((false, String::new()))
    }

    fn check_statements_for_timestamp_use(&self, statements: &[ast::Statement<'_>]) -> bool {
        for stmt in statements {
            match stmt {
                ast::Statement::Expression(expr) => {
                    if self.expression_uses_timestamp(expr) {
                        return true;
                    }
                }
                ast::Statement::Block(block) => {
                    if self.check_statements_for_timestamp_use(&block.statements) {
                        return true;
                    }
                }
                ast::Statement::VariableDeclaration {
                    initial_value: Some(expr),
                    ..
                } => {
                    if self.expression_uses_timestamp(expr) {
                        return true;
                    }
                }
                ast::Statement::If {
                    condition,
                    then_branch,
                    else_branch,
                    ..
                } => {
                    if self.expression_uses_timestamp(condition)
                        && !Self::is_deadline_comparison(condition)
                    {
                        return true;
                    }
                    if let ast::Statement::Block(b) = then_branch {
                        if self.check_statements_for_timestamp_use(&b.statements) {
                            return true;
                        }
                    }
                    if let Some(ast::Statement::Block(b)) = else_branch {
                        if self.check_statements_for_timestamp_use(&b.statements) {
                            return true;
                        }
                    }
                }
                ast::Statement::For { body, .. } | ast::Statement::While { body, .. } => {
                    if let ast::Statement::Block(b) = *body {
                        if self.check_statements_for_timestamp_use(&b.statements) {
                            return true;
                        }
                    }
                }
                ast::Statement::Return {
                    value: Some(expr), ..
                } => {
                    if self.expression_uses_timestamp(expr) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    fn expression_uses_timestamp(&self, expr: &ast::Expression<'_>) -> bool {
        match expr {
            ast::Expression::MemberAccess {
                expression, member, ..
            } => {
                if let ast::Expression::Identifier(id) = &**expression {
                    if id.name == "block" {
                        let member_name = member.name.to_lowercase();
                        if member_name == "timestamp"
                            || member_name == "number"
                            || member_name == "difficulty"
                        {
                            return true;
                        }
                    }
                }
                self.expression_uses_timestamp(expression)
            }
            ast::Expression::FunctionCall {
                function,
                arguments,
                ..
            } => {
                if let ast::Expression::Identifier(id) = &**function {
                    if id.name == "now" {
                        return true;
                    }
                }
                if self.expression_uses_timestamp(function) {
                    return true;
                }
                arguments.iter().any(|a| self.expression_uses_timestamp(a))
            }
            ast::Expression::BinaryOperation { left, right, .. } => {
                self.expression_uses_timestamp(left) || self.expression_uses_timestamp(right)
            }
            ast::Expression::Assignment { left, right, .. } => {
                self.expression_uses_timestamp(left) || self.expression_uses_timestamp(right)
            }
            ast::Expression::UnaryOperation { operand, .. } => {
                self.expression_uses_timestamp(operand)
            }
            ast::Expression::Conditional {
                condition,
                true_expression,
                false_expression,
                ..
            } => {
                self.expression_uses_timestamp(condition)
                    || self.expression_uses_timestamp(true_expression)
                    || self.expression_uses_timestamp(false_expression)
            }
            ast::Expression::IndexAccess { base, .. } => self.expression_uses_timestamp(base),
            _ => false,
        }
    }

    /// block.timestamp compared against a deadline/expiry value is the standard
    /// safe pattern (EIP-2612 permit, order expiry) — not flagged.
    fn is_deadline_comparison(expr: &ast::Expression<'_>) -> bool {
        if let ast::Expression::BinaryOperation {
            operator,
            left,
            right,
            ..
        } = expr
        {
            use ast::BinaryOperator::{Greater, GreaterEqual, Less, LessEqual};
            if matches!(operator, Greater | GreaterEqual | Less | LessEqual) {
                return Self::names_deadline(left) || Self::names_deadline(right);
            }
        }
        false
    }

    fn names_deadline(expr: &ast::Expression<'_>) -> bool {
        let name = match expr {
            ast::Expression::Identifier(id) => id.name.to_lowercase(),
            ast::Expression::MemberAccess { member, .. } => member.name.to_lowercase(),
            _ => return false,
        };
        name.contains("deadline")
            || name.contains("expir")
            || name.contains("validuntil")
            || name.contains("validafter")
            || name.contains("endtime")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::Detector;

    /// Parse `source` with the real Solidity parser and run `detector.detect`
    /// against the first contract. Returns the findings produced. Unlike
    /// `create_test_context`, this populates the AST (functions, statements,
    /// state variables) so AST-walking detectors actually see the code.
    fn detect_findings(detector: &BlockDependencyDetector, source: &str) -> Vec<Finding> {
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
        let detector = BlockDependencyDetector::new();
        assert_eq!(detector.id().0, "block-dependency");
        assert!(detector.is_enabled());
    }

    /// A lottery/random-selection contract that uses block.timestamp for
    /// selecting a winner must fire. This is the core TP for block-dependency.
    #[test]
    fn test_lottery_random_selection_fires() {
        let detector = BlockDependencyDetector::new();
        let source = r#"
            contract Lottery {
                address[] public players;
                address public winner;

                function pickWinner() external {
                    uint256 index = uint256(block.timestamp) % players.length;
                    winner = players[index];
                }
            }
        "#;
        let findings = detect_findings(&detector, source);
        assert!(
            !findings.is_empty(),
            "lottery using block.timestamp for winner selection should fire"
        );
        assert!(
            findings
                .iter()
                .all(|f| f.detector_id.0 == "block-dependency"),
            "all findings should come from block-dependency"
        );
    }

    /// FP regression: a staking contract that uses block.timestamp purely for
    /// reward accrual must NOT fire. The detector skips contracts where time
    /// use is expected by design ("staking"/"reward").
    #[test]
    fn test_staking_reward_calculation_does_not_fire() {
        let detector = BlockDependencyDetector::new();
        let source = r#"
            contract StakingRewards {
                mapping(address => uint256) public stakedAt;
                mapping(address => uint256) public balances;
                uint256 public rewardRate = 100;

                function stake(uint256 amount) external {
                    balances[msg.sender] += amount;
                    stakedAt[msg.sender] = block.timestamp;
                }

                function earned(address account) public view returns (uint256) {
                    uint256 duration = block.timestamp - stakedAt[account];
                    return duration * rewardRate * balances[account];
                }
            }
        "#;
        let findings = detect_findings(&detector, source);
        assert!(
            findings.is_empty(),
            "staking reward calculation using block.timestamp should not fire (FP regression)"
        );
    }

    /// FP regression: a governance/timelock contract that uses block.timestamp
    /// for execution delays must NOT fire. The detector skips "governance"/
    /// "timelock" contexts.
    #[test]
    fn test_governance_timelock_does_not_fire() {
        let detector = BlockDependencyDetector::new();
        let source = r#"
            contract Timelock {
                uint256 public constant DELAY = 2 days;
                mapping(bytes32 => uint256) public queuedAt;

                function queue(bytes32 id) external {
                    queuedAt[id] = block.timestamp;
                }

                function execute(bytes32 id) external {
                    require(block.timestamp >= queuedAt[id] + DELAY, "timelock not elapsed");
                    queuedAt[id] = 0;
                }
            }
        "#;
        let findings = detect_findings(&detector, source);
        assert!(
            findings.is_empty(),
            "governance/timelock using block.timestamp for delays should not fire (FP regression)"
        );
    }
}

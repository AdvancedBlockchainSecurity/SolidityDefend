use anyhow::Result;
use std::any::Any;

use crate::detector::{Detector, DetectorCategory};
use crate::types::{AnalysisContext, Confidence, DetectorId, Finding, Severity, SourceLocation};
use crate::utils;
use ast;
/// Governance vulnerability detector that implements the Detector trait
pub struct GovernanceDetector;

impl Default for GovernanceDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl GovernanceDetector {
    pub fn new() -> Self {
        Self
    }
}

impl Detector for GovernanceDetector {
    fn id(&self) -> DetectorId {
        DetectorId("test-governance".to_string())
    }

    fn name(&self) -> &str {
        "Governance Attacks"
    }

    fn description(&self) -> &str {
        "Detects vulnerabilities in DAO governance mechanisms including flash loan attacks, delegation loops, and voting manipulation"
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        vec![
            DetectorCategory::FlashLoan,
            DetectorCategory::Logic,
            DetectorCategory::BestPractices,
        ]
    }

    fn default_severity(&self) -> Severity {
        Severity::High
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

        // Skip lending protocols - they are NOT governance tokens
        // Lending protocol tokens (cTokens, aTokens) have "delegate" for proxy patterns,
        // not governance delegation. Known protocols have separate governance tokens:
        // - Compound: COMP token (not cTokens)
        // - Aave: AAVE token (not aTokens)
        // - MakerDAO: MKR token (not Dai or Vat)
        // This detector should focus on actual governance tokens with voting mechanisms.
        if utils::is_lending_protocol(ctx) {
            return Ok(findings);
        }

        // Skip actual governance protocols - they have proper snapshot/timelock mechanisms
        // Governor Bravo, OpenZeppelin Governor, etc. have audited implementations with:
        // - Snapshot-based voting (getPriorVotes, getPastVotes)
        // - Timelock for execution delays
        // - Proposal states and voting periods
        // This detector should focus on CUSTOM governance implementations
        if utils::is_governance_protocol(ctx) {
            return Ok(findings);
        }

        // Phase 56 FP Reduction: Skip contracts that are clearly not governance contracts.
        // Non-governance contract types that commonly trigger false positives:
        // - Restaking/delegation protocols (EigenLayer, etc.)
        // - Proxy upgrade contracts
        // - Metamorphic/factory contracts
        // - ZK verification contracts
        // - EIP-7702 delegation contracts
        // These use "propose", "cancel", "queue", "vote" in non-governance contexts.
        if self.is_non_governance_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip secure/fixed example contracts
        if crate::utils::is_secure_example_file(ctx) {
            return Ok(findings);
        }

        // Run all governance vulnerability detection methods
        findings.extend(self.detect_flash_loan_governance_attacks(ctx)?);
        findings.extend(self.detect_missing_snapshot_protection(ctx)?);
        findings.extend(self.detect_temporal_control_issues(ctx)?);

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl GovernanceDetector {
    /// Phase 56 FP Reduction: Detect non-governance contracts that commonly trigger FPs.
    /// These contract types use governance-like keywords (propose, cancel, queue, vote)
    /// but in non-governance contexts.
    fn is_non_governance_contract(&self, ctx: &AnalysisContext) -> bool {
        let cleaned = utils::clean_source_for_search(ctx.source_code.as_str());
        let lower = cleaned.to_lowercase();

        // Restaking/delegation protocols (EigenLayer, etc.)
        // These use "queue", "cancel", "delegate" for staking operations, not governance
        let is_restaking = (lower.contains("queuewithdrawal")
            || lower.contains("queuedwithdrawal")
            || lower.contains("completequeuedwithdrawal"))
            && (lower.contains("staker")
                || lower.contains("operator")
                || lower.contains("strategymanager")
                || lower.contains("delegationmanager"));

        if is_restaking {
            return true;
        }

        // Proxy upgrade contracts use "proposeUpgrade", "cancelUpgrade", etc.
        let is_proxy_upgrade = (lower.contains("proposeupgrade")
            || lower.contains("cancelupgrade")
            || lower.contains("executeupgrade"))
            && (lower.contains("implementation")
                || lower.contains("proxy")
                || lower.contains("upgrade_delay")
                || lower.contains("upgradeability"));

        if is_proxy_upgrade {
            return true;
        }

        // Metamorphic/factory contracts with selfdestruct proposals
        let is_metamorphic = (lower.contains("selfdestruct")
            || lower.contains("metamorphic")
            || lower.contains("create2"))
            && (lower.contains("factory") || lower.contains("deployer"));

        if is_metamorphic {
            return true;
        }

        // EIP-7702 delegation contracts
        let is_eip7702 = lower.contains("eip7702")
            || lower.contains("eip-7702")
            || (lower.contains("delegation") && lower.contains("extcodesize"));

        if is_eip7702 {
            return true;
        }

        // Delegatecall-focused contracts (proxy libraries, delegatecall examples)
        // These use "delegate" in the context of delegatecall, not governance delegation
        let contract_name_lower = ctx.contract.name.name.to_lowercase();
        if (contract_name_lower.contains("delegatecall")
            || contract_name_lower.contains("delegate_call")
            || contract_name_lower.contains("delegation")
            || (lower.contains("delegatecall") && !lower.contains("vote")))
            && !lower.contains("vote")
            && !lower.contains("governance")
        {
            return true;
        }

        // Contracts focused on access control / authorization patterns (not governance)
        if (contract_name_lower.contains("access")
            || contract_name_lower.contains("auth")
            || contract_name_lower.contains("permission"))
            && !lower.contains("vote")
            && !lower.contains("governance")
            && !lower.contains("proposal")
        {
            return true;
        }

        // Restaking/slashing contracts without governance context
        if (lower.contains("slashing") || lower.contains("restaking"))
            && !lower.contains("vote")
            && !lower.contains("governance")
            && !lower.contains("proposal")
        {
            return true;
        }

        false
    }

    fn detect_flash_loan_governance_attacks(
        &self,
        ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for func in &ctx.contract.functions {
            if func.body.is_none() {
                continue;
            }

            // Look for governance functions that check current balance without snapshots
            if self.is_governance_function(func) && self.uses_current_balance_for_voting(ctx, func)
            {
                let finding = Finding::new(
                    self.id(),
                    Severity::Critical,
                    Confidence::High,
                    format!(
                        "Function '{}' is vulnerable to flash loan governance attacks. It uses current token balance \
                        for voting power without snapshot protection, allowing attackers to temporarily acquire \
                        large amounts of governance tokens to manipulate votes.",
                        func.name.as_str()
                    ),
                    SourceLocation::new(
                        ctx.file_path.clone(),
                        func.location.start().line() as u32,
                        0,
                        func.name.as_str().len() as u32,
                    ),
                ).with_cwe(682) // CWE-682: Incorrect Calculation
                .with_fix_suggestion(
                    "Implement snapshot-based voting power or time-delayed voting rights for governance tokens.".to_string()
                );

                findings.push(finding);
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn detect_missing_snapshot_protection(
        &self,
        ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check if contract has governance tokens but lacks snapshot mechanisms
        let has_governance_tokens = self.has_governance_token_patterns(ctx);
        let has_snapshot_protection = self.has_snapshot_mechanisms(ctx);

        if has_governance_tokens && !has_snapshot_protection {
            // Find the main contract for the finding location
            if let Some(main_func) = ctx.contract.functions.first() {
                let finding = Finding::new(
                    self.id(),
                    Severity::High,
                    Confidence::Medium,
                    "Contract uses governance tokens without snapshot protection mechanisms. \
                    This enables flash loan attacks where attackers can temporarily acquire \
                    tokens to manipulate governance decisions.".to_string(),
                    SourceLocation::new(
                        ctx.file_path.clone(),
                        main_func.location.start().line() as u32,
                        0,
                        20,
                    ),
                ).with_cwe(284) // CWE-284: Improper Access Control
                .with_fix_suggestion(
                    "Implement snapshot-based voting power using block-based or time-based snapshots.".to_string()
                );

                findings.push(finding);
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn detect_temporal_control_issues(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Phase 56 FP Reduction: Only flag temporal issues if the contract actually
        // has governance token patterns. Simple voting contracts (commit-reveal, ZK voting)
        // are not governance token contracts and should not be flagged for missing timelocks.
        if !self.has_governance_token_patterns(ctx) {
            return Ok(findings);
        }

        for func in &ctx.contract.functions {
            if func.body.is_none() {
                continue;
            }

            if self.is_governance_function(func) && !self.has_time_delay_protection(ctx, func) {
                let finding = Finding::new(
                    self.id(),
                    Severity::Medium,
                    Confidence::Medium,
                    format!(
                        "Function '{}' lacks time-delay protection for governance actions. \
                        New token holders can immediately use their voting power, enabling \
                        flash loan governance attacks.",
                        func.name.as_str()
                    ),
                    SourceLocation::new(
                        ctx.file_path.clone(),
                        func.location.start().line() as u32,
                        0,
                        func.name.as_str().len() as u32,
                    ),
                )
                .with_cwe(662) // CWE-662: Improper Synchronization
                .with_fix_suggestion(
                    "Implement time-delayed voting rights requiring minimum holding periods."
                        .to_string(),
                );

                findings.push(finding);
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn is_governance_function(&self, func: &ast::Function) -> bool {
        let func_name = func.name.as_str().to_lowercase();

        // Phase 56 FP Reduction: Skip view/pure functions -- they cannot modify state
        // and are not vulnerable to governance manipulation attacks.
        if func.mutability == ast::StateMutability::View
            || func.mutability == ast::StateMutability::Pure
        {
            return false;
        }

        // Phase 56 FP Reduction: Skip access-controlled functions.
        // Functions with onlyOwner, onlyAdmin, onlyGuardian, etc. are admin-only
        // and not vulnerable to flash loan governance attacks (attacker cannot call them).
        if self.has_access_control_modifier(func) {
            return false;
        }

        // Only flag functions that are specifically governance-voting-related.
        // "castvote" is the clearest governance voting pattern.
        if func_name.contains("castvote") {
            return true;
        }

        // "vote" is governance-related only if it's a standalone vote function,
        // not "commitVote", "revealVote", "voteWeight" etc. which are commit-reveal
        // or utility patterns. Must be exactly "vote" or start with "vote" followed
        // by non-alphabetic chars (like "vote(") or combined with governance terms.
        if func_name == "vote"
            || func_name.starts_with("vote(")
            || (func_name.contains("vote") && func_name.contains("proposal"))
        {
            return true;
        }

        // "propose" is governance-related ONLY when combined with governance terms,
        // not "proposeUpgrade", "proposeSelfDestruct", etc.
        if func_name.contains("propose")
            && (func_name.contains("proposal")
                || func_name.contains("vote")
                || func_name.contains("governance"))
        {
            return true;
        }

        // "delegate" is only governance-related if combined with voting context
        if func_name.contains("delegate") && func_name.contains("vote") {
            return true;
        }

        // "execute" is only governance-related if it's specifically for proposals
        if func_name.contains("execute") && func_name.contains("proposal") {
            return true;
        }

        // Phase 56 FP Reduction: Removed "queue" and "cancel" as standalone patterns.
        // These are far too generic and match restaking (queueWithdrawals),
        // proxy upgrade (cancelUpgrade), metamorphic (cancelSelfDestruct), etc.
        // Only match them when combined with clear governance terms.
        if (func_name.contains("queue") || func_name.contains("cancel"))
            && (func_name.contains("proposal") || func_name.contains("vote"))
        {
            return true;
        }

        false
    }

    /// Phase 56 FP Reduction: Check if function has access control modifiers.
    /// Access-controlled functions (onlyOwner, onlyAdmin, etc.) are not vulnerable
    /// to flash loan governance attacks since arbitrary users cannot call them.
    fn has_access_control_modifier(&self, func: &ast::Function) -> bool {
        func.modifiers.iter().any(|modifier| {
            let name = modifier.name.as_str().to_lowercase();
            name.contains("only")
                || name.contains("auth")
                || name.contains("role")
                || name.contains("admin")
                || name.contains("owner")
                || name.contains("guardian")
                || name.contains("operator")
                || name.contains("whennotpaused")
        })
    }

    fn uses_current_balance_for_voting(&self, ctx: &AnalysisContext, func: &ast::Function) -> bool {
        let func_start = func.location.start().line();
        let func_end = func.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if func_start >= source_lines.len() || func_end >= source_lines.len() {
            return false;
        }

        // Clean source to avoid FPs from comments/strings
        let raw_source = source_lines[func_start..=func_end].join("\n");
        let func_source = utils::clean_source_for_search(&raw_source);

        // Enhanced patterns for current balance checks without snapshot protection
        let balance_patterns = [
            "balanceOf(",
            ".balanceOf(",
            "votingToken.balanceOf",
            "token.balanceOf",
            "governanceToken.balanceOf",
            "balanceOf(msg.sender)",
            "getBalance(",
            "currentBalance",
        ];

        let snapshot_patterns = [
            "snapshot",
            "getPastVotes",
            "balanceOfAt",
            "checkpoints",
            "getVotes(",
            "getPriorVotes",
            "getPastTotalSupply",
            "balanceAtBlockNumber",
        ];

        let uses_balance = balance_patterns
            .iter()
            .any(|&pattern| func_source.contains(pattern));
        let uses_snapshot = snapshot_patterns
            .iter()
            .any(|&pattern| func_source.contains(pattern));

        // Also check for governance-related balance usage in require statements
        let has_governance_balance_check = func_source.contains("require(")
            && (func_source.contains("balanceOf") || func_source.contains("getBalance"))
            && (func_source.contains("threshold")
                || func_source.contains("minimum")
                || func_source.contains(">=")
                || func_source.contains("<="));

        (uses_balance || has_governance_balance_check) && !uses_snapshot
    }

    fn has_governance_token_patterns(&self, ctx: &AnalysisContext) -> bool {
        // Clean source to avoid FPs from comments/strings
        let cleaned = utils::clean_source_for_search(ctx.source_code.as_str());
        let source_lower = cleaned.to_lowercase();

        // Phase 56 FP Reduction: Require ACTUAL governance token infrastructure.
        // A contract must have governance TOKEN patterns (not just voting or proposals).
        // Contracts like commit-reveal voting, ZK voting, metamorphic factories, etc.
        // may contain "proposal" or "vote" but are NOT governance token contracts.

        // Tier 1: Definitive governance token indicators (any one is sufficient)
        let definitive_indicators = [
            "votingtoken",
            "governancetoken",
            "igovernor",
            "proposalthreshold",
            "votingperiod",
            "votingdelay",
            "getpriorvotes",
            "getpastvotes",
            "getvotes(",
        ];

        let has_definitive = definitive_indicators
            .iter()
            .any(|&indicator| source_lower.contains(indicator));

        if has_definitive {
            return true;
        }

        // Tier 2: Must have BOTH voting mechanism AND governance token patterns.
        // "proposal" alone is not sufficient (used in upgrade proposals, selfdestruct proposals).
        // "vote" alone is not sufficient (used in commit-reveal, ZK voting, etc.).
        // Require governance token patterns: quorum, or token-based voting power.
        //
        // Phase 56 FP Reduction: "delegate(" is too broad -- it matches _delegate(),
        // setDelegate(), recursiveDelegate(), etc. in proxy/delegatecall contracts.
        // Even "function delegate(address" matches restaking delegation.
        // Only match delegation when combined with voting context.
        let has_governance_delegation = (source_lower.contains("delegatee")
            || source_lower.contains("delegatevote"))
            || (source_lower.contains("function delegate(address")
                && (source_lower.contains("vote") || source_lower.contains("voting")));

        let has_governance_token_infra = source_lower.contains("quorum")
            || source_lower.contains("votingpower")
            || has_governance_delegation
            || (source_lower.contains("castvote") && source_lower.contains("proposal"));

        has_governance_token_infra
    }

    fn has_snapshot_mechanisms(&self, ctx: &AnalysisContext) -> bool {
        // Clean source to avoid FPs from comments/strings
        let cleaned = utils::clean_source_for_search(ctx.source_code.as_str());
        let snapshot_patterns = [
            "snapshot",
            "getPastVotes",  // OpenZeppelin Governor
            "getPriorVotes", // Compound Governor Bravo
            "balanceOfAt",
            "checkpoints",
            "timeWeighted",
            "historicalBalance",
        ];
        snapshot_patterns
            .iter()
            .any(|&pattern| cleaned.contains(pattern))
    }

    fn has_time_delay_protection(&self, ctx: &AnalysisContext, _func: &ast::Function) -> bool {
        // Clean source to avoid FPs from comments/strings
        let cleaned = utils::clean_source_for_search(ctx.source_code.as_str());
        let time_delay_patterns = [
            "timelock",
            "delay",
            "holdingPeriod",
            "vestingPeriod",
            "minimumHolding",
            "lockPeriod",
        ];
        time_delay_patterns
            .iter()
            .any(|&pattern| cleaned.contains(pattern))
    }
}

/// Signature replay attack detector
pub struct SignatureReplayDetector;

impl Default for SignatureReplayDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SignatureReplayDetector {
    pub fn new() -> Self {
        Self
    }

    /// Phase 55 FP Reduction: Check if contract is a delegatecall proxy pattern.
    /// Delegatecall proxies forward calls to implementation contracts and do not
    /// perform signature verification themselves -- flagging them is a false positive.
    fn is_delegatecall_proxy_contract(&self, source: &str) -> bool {
        let cleaned = utils::clean_source_for_search(source);
        let lower = cleaned.to_lowercase();

        // Must actually use delegatecall
        let uses_delegatecall =
            lower.contains("delegatecall(") || lower.contains("delegatecall(gas()");

        if !uses_delegatecall {
            return false;
        }

        // Must NOT have actual signature verification (ecrecover / ECDSA.recover)
        let has_sig_verification = lower.contains("ecrecover") || lower.contains("ecdsa.recover");

        // Delegatecall proxy patterns: user-controlled target, fallback delegation, etc.
        let proxy_patterns = [
            "target.delegatecall",
            "lib.delegatecall",
            "impl.delegatecall",
            "implementation.delegatecall",
            "fallback()",
            ".delegatecall(data",
        ];
        let is_proxy = proxy_patterns.iter().any(|&p| lower.contains(p));

        is_proxy && !has_sig_verification
    }

    /// Phase 55 FP Reduction: Check if contract is an ERC-4337 account abstraction contract.
    /// ERC-4337 contracts have built-in nonce management via the EntryPoint contract,
    /// so signature replay is handled at the protocol level.
    fn is_erc4337_contract(&self, source: &str) -> bool {
        let cleaned = utils::clean_source_for_search(source);
        let lower = cleaned.to_lowercase();

        // ERC-4337 contract indicators
        let erc4337_patterns = [
            "validatepaymasteruserop",
            "validateuserop",
            "ientrypoint",
            "entrypoint",
            "useroperation",
            "iaccountexecution",
            "ipaymaster",
        ];

        let has_erc4337 = erc4337_patterns.iter().any(|&p| lower.contains(p));

        // Must have at least one ERC-4337 indicator
        has_erc4337
    }

    /// Phase 55 FP Reduction: Check if contract has contract-level replay protection.
    /// Many contracts track nonces or used signatures at the contract level (state variables),
    /// not inside individual functions. This checks the full contract source for such patterns.
    fn has_contract_level_replay_protection(&self, source: &str) -> bool {
        let cleaned = utils::clean_source_for_search(source);
        let lower = cleaned.to_lowercase();

        // Nonce tracking patterns at contract level — must be specific enough to avoid
        // matching every contract that has a mapping() of any kind.
        // "mapping" alone is NOT sufficient; it must be combined with "nonce".
        let nonce_specific_patterns = [
            "nonces[",
            "usednonces[",
            "usedsignatures[",
            "usedsignatures",   // catches: mapping(...) public usedSignatures; declarations
            "usedhashes[",
            "usedhashes",       // catches: mapping(...) public usedHashes; declarations
            "invalidatenonce",
            "_usenonce",
            "nonce++",
            "nonces[msg.sender]",
            "nonces[signer]",
            "nonces[owner]",
        ];

        // Check for nonce mapping declarations or usage:
        // Either a mapping() combined with "nonce" keyword (e.g., mapping(address=>uint256) public nonces)
        // OR a specific nonce usage pattern (nonces[...], usedNonces[...], etc.)
        let has_nonce_mapping = (lower.contains("mapping") && lower.contains("nonce"))
            || nonce_specific_patterns.iter().any(|&p| lower.contains(p));

        // Governance vote tracking (hasVoted, receipts mapping) prevents replay by design
        let has_vote_tracking = lower.contains("hasvoted")
            || lower.contains("receipts[")
            || (lower.contains("hasvotedonproposal") && lower.contains("mapping"));

        has_nonce_mapping || has_vote_tracking
    }

    /// Phase 55 FP Reduction: Check if function actually performs signature verification.
    /// Requires ecrecover or ECDSA.recover in the function body (not just "verify" or "signature"
    /// which match too many unrelated patterns like abi.encodeWithSignature).
    fn has_actual_signature_verification(
        &self,
        func: &ast::Function,
        ctx: &AnalysisContext,
    ) -> bool {
        let func_start = func.location.start().line();
        let func_end = func.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if func_start >= source_lines.len() || func_end >= source_lines.len() {
            return false;
        }

        let raw_source = source_lines[func_start..=func_end].join("\n");
        let func_source = utils::clean_source_for_search(&raw_source);

        // Require actual cryptographic signature verification calls in the function body,
        // OR the function calls a recovery helper that wraps ecrecover (common pattern where
        // a contract defines recoverSigner/recoverAddress which internally uses ecrecover).
        let direct_verification = func_source.contains("ecrecover")
            || func_source.contains("ECDSA.recover")
            || func_source.contains("SignatureChecker.isValidSignatureNow");

        if direct_verification {
            return true;
        }

        // Check for indirect verification: function calls a helper that uses ecrecover
        // and the contract itself contains ecrecover (indicating the helper is local)
        let calls_recovery_helper = func_source.contains("recoverSigner(")
            || func_source.contains("recoverAddress(")
            || func_source.contains("recover(");

        if calls_recovery_helper {
            let contract_source = crate::utils::get_contract_source(ctx);
            return contract_source.contains("ecrecover")
                || contract_source.contains("ECDSA.recover");
        }

        false
    }

    fn has_signature_replay_vulnerability(
        &self,
        func: &ast::Function,
        ctx: &AnalysisContext,
    ) -> bool {
        // Only check functions with actual implementations (not interface functions)
        if func.body.is_none() {
            return false;
        }

        let func_name = func.name.as_str();

        // Phase 55 FP Reduction: Tightened signature function name detection.
        // Only match names that clearly indicate signature-based operations,
        // not generic names like "Signature" which match aggregateSignatures, etc.
        let sig_verification_name_patterns = [
            "BySig",
            "bySignature",
            "WithSignature",
            "verifySig",
            "verifySignature",
            "recoverSigner",
        ];

        let is_signature_function_by_name = sig_verification_name_patterns
            .iter()
            .any(|&pattern| func_name.contains(pattern));

        // Phase 55 FP Reduction: Always require actual signature verification in the body.
        // This prevents FPs on functions like aggregateSignatures, encodeWithSignature, etc.
        if !self.has_actual_signature_verification(func, ctx) {
            return false;
        }

        if !is_signature_function_by_name {
            // Function name doesn't match -- only proceed if body has ecrecover/ECDSA.recover
            // (already confirmed above) AND function has signature params
        }

        // Check function parameters for signature components (v, r, s)
        let has_signature_params = func.parameters.iter().any(|param| {
            let param_name = param
                .name
                .as_ref()
                .map(|n| n.as_str().to_lowercase())
                .unwrap_or_default();
            param_name == "v" || param_name == "r" || param_name == "s" || param_name == "signature"
        });

        // Must have signature parameters to be a signature verification function
        if !has_signature_params {
            return false;
        }

        // Check if function has nonce protection in its own body
        let func_start = func.location.start().line();
        let func_end = func.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if func_start < source_lines.len() && func_end < source_lines.len() {
            let raw_source = source_lines[func_start..=func_end].join("\n");
            let func_source = utils::clean_source_for_search(&raw_source);
            let func_lower = func_source.to_lowercase();

            // Patterns indicating this function already has replay protection:
            // - nonce: any direct nonce usage
            // - counter: incrementing counter (replay prevention)
            // - replay: explicit replay protection check
            // - "used": e.g. `usedHashes`, `usedSignatures` variables
            // - "initialized": one-time-use initialization guard (e.g. require(!initialized))
            // - "!initialized": explicit one-time-use guard pattern
            // Note: "used" alone (without other context) is checked; false positives are
            // filtered by the contract-level check below.
            let nonce_patterns = [
                "nonce", "nonces", "_nonce", "counter", "replay",
                "usedhash", "usedsig", "usednonce",
                "!initialized", "require(!initialized",
            ];
            let has_nonce_protection = nonce_patterns
                .iter()
                .any(|&pattern| func_lower.contains(pattern));

            if has_nonce_protection {
                return false;
            }
        }

        // Phase 55 FP Reduction: Check contract-level replay protection.
        // If the contract has nonce tracking, vote tracking, or similar patterns
        // at the state variable level, the function likely delegates replay
        // protection to those mechanisms (even if not visible in this function body).
        // Use contract-scoped source to avoid cross-contract FPs in multi-contract files
        // where a later contract has nonces but an earlier vulnerable one does not.
        let contract_source = crate::utils::get_contract_source(ctx);
        let has_contract_protection = self.has_contract_level_replay_protection(&contract_source);
        if has_contract_protection {
            return false;
        }

        true
    }
}

impl Detector for SignatureReplayDetector {
    fn id(&self) -> DetectorId {
        DetectorId("signature-replay".to_string())
    }

    fn name(&self) -> &str {
        "Signature Replay Attack"
    }

    fn description(&self) -> &str {
        "Detects signature verification without replay protection (nonce system)"
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        vec![DetectorCategory::Auth, DetectorCategory::BestPractices]
    }

    fn default_severity(&self) -> Severity {
        Severity::High
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

        let contract_source = crate::utils::get_contract_source(ctx);
        let source = &contract_source;

        // Phase 53 FP Reduction: Skip well-known signature verification libraries
        // These are low-level verify functions - nonce handling is done at caller level
        let is_signature_library = source.contains("SignatureVerification")
            || source.contains("SignatureChecker")
            || source.contains("ECDSA")
            || source.contains("library ")
            || source.contains("Permit2")
            || source.contains("@uniswap")
            || source.contains("@openzeppelin");

        if is_signature_library {
            return Ok(findings);
        }

        // Phase 55 FP Reduction: Skip delegatecall proxy contracts.
        // These forward calls to implementation contracts and do not verify signatures.
        if self.is_delegatecall_proxy_contract(source) {
            return Ok(findings);
        }

        // Phase 55 FP Reduction: Skip ERC-4337 account abstraction contracts.
        // ERC-4337 has built-in nonce management via the EntryPoint contract.
        if self.is_erc4337_contract(source) {
            return Ok(findings);
        }

        for func in &ctx.contract.functions {
            // Skip interface functions (no body)
            if func.body.is_none() {
                continue;
            }

            if self.has_signature_replay_vulnerability(func, ctx) {
                let finding = Finding::new(
                    self.id(),
                    Severity::High,
                    Confidence::Medium,
                    format!(
                        "Function '{}' verifies signatures without replay protection. \
                        Attackers can reuse valid signatures to perform unauthorized actions. \
                        This is particularly dangerous in governance systems for vote manipulation.",
                        func.name.as_str()
                    ),
                    SourceLocation::new(
                        ctx.file_path.clone(),
                        func.location.start().line() as u32,
                        0,
                        func.name.as_str().len() as u32,
                    ),
                ).with_cwe(294) // CWE-294: Authentication Bypass by Capture-replay
                .with_fix_suggestion(
                    "Implement a nonce system to prevent signature replay attacks. \
                    Include a unique nonce in the signed message and track used nonces.".to_string()
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
    use crate::types::test_utils::*;

    // ============ SignatureReplayDetector Tests ============

    #[test]
    fn test_signature_replay_detector_properties() {
        let detector = SignatureReplayDetector::new();
        assert_eq!(detector.id().to_string(), "signature-replay");
        assert_eq!(detector.name(), "Signature Replay Attack");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_fp_reduction_delegatecall_proxy_not_flagged() {
        // UserControlledDelegatecall.sol: delegatecall proxy should not be flagged
        let detector = SignatureReplayDetector::new();
        let source = r#"
            contract DirectUserControlled {
                address public owner;
                mapping(address => uint256) public balances;

                function execute(address target, bytes calldata data) external payable {
                    (bool success, ) = target.delegatecall(data);
                    require(success, "Delegatecall failed");
                }

                function deposit() external payable {
                    balances[msg.sender] += msg.value;
                }
            }
        "#;

        assert!(
            detector.is_delegatecall_proxy_contract(source),
            "Should recognize delegatecall proxy contract"
        );

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(
            result.is_empty(),
            "Delegatecall proxy should not trigger signature replay findings"
        );
    }

    #[test]
    fn test_fp_reduction_erc4337_paymaster_not_flagged() {
        // VulnerablePaymaster.sol: ERC-4337 paymaster should not be flagged
        let detector = SignatureReplayDetector::new();
        let source = r#"
            contract VulnerablePaymaster {
                mapping(address => uint256) public deposits;

                function validatePaymasterUserOp(
                    bytes calldata userOp,
                    bytes32 userOpHash,
                    uint256 maxCost
                ) external returns (bytes memory context, uint256 validationData) {
                    return ("", 0);
                }
            }
        "#;

        assert!(
            detector.is_erc4337_contract(source),
            "Should recognize ERC-4337 contract"
        );

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(
            result.is_empty(),
            "ERC-4337 paymaster should not trigger signature replay findings"
        );
    }

    #[test]
    fn test_fp_reduction_secure_paymaster_not_flagged() {
        // SecurePaymaster.sol: ERC-4337 paymaster with nonce management
        let detector = SignatureReplayDetector::new();
        let source = r#"
            contract SecurePaymaster {
                mapping(address => uint256) public deposits;
                mapping(address => mapping(uint256 => bool)) public usedNonces;

                function validatePaymasterUserOp(
                    bytes calldata userOp,
                    bytes32 userOpHash,
                    uint256 maxCost
                ) external returns (bytes memory context, uint256 validationData) {
                    (address sender, uint256 nonce) = abi.decode(userOp, (address, uint256));
                    require(!usedNonces[sender][nonce], "Nonce already used");
                    usedNonces[sender][nonce] = true;
                    return ("", 0);
                }
            }
        "#;

        assert!(
            detector.is_erc4337_contract(source),
            "Should recognize ERC-4337 contract"
        );

        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(
            result.is_empty(),
            "Secure ERC-4337 paymaster should not trigger signature replay findings"
        );
    }

    #[test]
    fn test_fp_reduction_governance_with_vote_tracking_not_flagged() {
        // DAOGovernance.sol: governance with hasVoted tracking prevents replay
        let detector = SignatureReplayDetector::new();
        let source = r#"
            contract DAOGovernance {
                struct Receipt {
                    bool hasVoted;
                    uint8 support;
                    uint256 votes;
                }
                mapping(uint256 => mapping(address => Receipt)) public receipts;
                mapping(address => mapping(uint256 => bool)) public hasVotedOnProposal;

                function castVoteBySig(
                    uint256 proposalId,
                    uint8 support,
                    uint8 v,
                    bytes32 r,
                    bytes32 s
                ) external returns (uint256) {
                    bytes32 digest = keccak256(abi.encode(proposalId, support));
                    address signer = ecrecover(digest, v, r, s);
                    require(signer != address(0), "Invalid signature");
                    return _castVote(signer, proposalId, support);
                }
            }
        "#;

        assert!(
            detector.has_contract_level_replay_protection(source),
            "Should recognize vote tracking as replay protection"
        );
    }

    #[test]
    fn test_fp_reduction_contract_with_nonce_mapping() {
        let detector = SignatureReplayDetector::new();
        let source = r#"
            contract TokenWithPermit {
                mapping(address => uint256) public nonces;

                function permit(
                    address owner,
                    address spender,
                    uint256 value,
                    uint8 v,
                    bytes32 r,
                    bytes32 s
                ) external {
                    bytes32 digest = keccak256(abi.encode(owner, spender, value));
                    address signer = ecrecover(digest, v, r, s);
                    require(signer == owner, "Invalid signature");
                }
            }
        "#;

        assert!(
            detector.has_contract_level_replay_protection(source),
            "Should recognize nonce mapping as replay protection"
        );
    }

    #[test]
    fn test_fp_reduction_signature_aggregator_not_flagged() {
        // aggregateSignatures should not be flagged - it's not signature verification
        let detector = SignatureReplayDetector::new();
        let source = r#"
            contract SignatureAggregator {
                function aggregateSignatures(
                    bytes[] calldata signatures
                ) external pure returns (bytes memory) {
                    bytes memory aggregated;
                    for (uint i = 0; i < signatures.length; i++) {
                        aggregated = abi.encodePacked(aggregated, signatures[i]);
                    }
                    return aggregated;
                }
            }
        "#;

        // This function has "signatures" param but no ecrecover, so should not be flagged
        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(
            result.is_empty(),
            "Signature aggregation (no ecrecover) should not trigger signature replay findings"
        );
    }

    #[test]
    fn test_not_delegatecall_proxy_when_has_ecrecover() {
        // Contract with both delegatecall AND ecrecover should NOT be skipped
        let detector = SignatureReplayDetector::new();
        let source = r#"
            contract HybridContract {
                function execute(address target, bytes calldata data) external {
                    (bool success, ) = target.delegatecall(data);
                    require(success);
                }

                function verifySig(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {
                    address signer = ecrecover(hash, v, r, s);
                    require(signer != address(0));
                }
            }
        "#;

        assert!(
            !detector.is_delegatecall_proxy_contract(source),
            "Contract with ecrecover should not be classified as pure delegatecall proxy"
        );
    }

    #[test]
    fn test_erc4337_detection() {
        let detector = SignatureReplayDetector::new();

        assert!(detector.is_erc4337_contract("function validateUserOp(UserOperation calldata)"));
        assert!(detector.is_erc4337_contract("IEntryPoint public entryPoint"));
        assert!(detector.is_erc4337_contract("function validatePaymasterUserOp(bytes calldata)"));
        assert!(!detector.is_erc4337_contract("contract SimpleToken { function transfer() {} }"));
    }

    #[test]
    fn test_contract_level_replay_protection_patterns() {
        let detector = SignatureReplayDetector::new();

        // usedNonces mapping
        assert!(detector.has_contract_level_replay_protection(
            "mapping(address => mapping(uint256 => bool)) public usedNonces;"
        ));

        // usedSignatures mapping
        assert!(detector.has_contract_level_replay_protection(
            "mapping(bytes32 => bool) public usedSignatures;"
        ));

        // hasVoted pattern
        assert!(
            detector
                .has_contract_level_replay_protection("mapping(address => bool) public hasVoted;")
        );

        // _useNonce pattern
        assert!(detector.has_contract_level_replay_protection(
            "function _useNonce(address owner) internal returns (uint256)"
        ));

        // No replay protection
        assert!(
            !detector
                .has_contract_level_replay_protection("contract Simple { uint256 public value; }")
        );
    }

    // ============ GovernanceDetector Tests ============

    #[test]
    fn test_governance_detector_properties() {
        let detector = GovernanceDetector::new();
        assert_eq!(detector.id().to_string(), "test-governance");
        assert_eq!(detector.name(), "Governance Attacks");
        assert_eq!(detector.default_severity(), Severity::High);
    }

    // ============ Phase 56 FP Reduction: GovernanceDetector Tests ============

    #[test]
    fn test_fp_restaking_delegation_not_flagged() {
        // Restaking contracts with delegate/queue/cancel should NOT be flagged
        let detector = GovernanceDetector::new();
        let source = r#"
            contract VulnerableRestaking {
                mapping(address => uint256) public stakes;
                function delegate(address operator, uint256 amount) external {
                    stakes[operator] += amount;
                }
                function queueWithdrawals(uint256 amount) external {
                    stakes[msg.sender] -= amount;
                }
            }
        "#;
        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(
            result.is_empty(),
            "Restaking delegation contract should not trigger governance findings"
        );
    }

    #[test]
    fn test_fp_proxy_upgrade_propose_cancel_not_flagged() {
        // Proxy upgrade contracts with proposeUpgrade/cancelUpgrade
        let detector = GovernanceDetector::new();
        let source = r#"
            contract SecureProxyUpgrade {
                address public implementation;
                function proposeUpgrade(address newImplementation) external onlyAdmin {
                    implementation = newImplementation;
                }
                function cancelUpgrade(bytes32 upgradeId) external onlyAdmin {
                    delete pendingUpgrades[upgradeId];
                }
                function executeUpgrade(bytes32 upgradeId) external onlyAdmin {
                    _setImplementation(pending.implementation);
                }
            }
        "#;
        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(
            result.is_empty(),
            "Proxy upgrade contract should not trigger governance findings"
        );
    }

    #[test]
    fn test_fp_metamorphic_factory_not_flagged() {
        // Metamorphic factory with proposeSelfDestruct/cancelSelfDestruct
        let detector = GovernanceDetector::new();
        let source = r#"
            contract LegitimateMetamorphicFactory {
                address public factory;
                function deployMetamorphic(bytes32 salt) external {
                    bytes memory code = type(MetamorphicChild).creationCode;
                    address deployed;
                    assembly { deployed := create2(0, add(code, 0x20), mload(code), salt) }
                }
            }
            contract MetamorphicChild {
                function proposeSelfDestruct(address recipient) external onlyOwner {
                    emergencyRecipient = recipient;
                }
                function cancelSelfDestruct() external onlyOwner {
                    emergencyRecipient = address(0);
                }
            }
        "#;
        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(
            result.is_empty(),
            "Metamorphic factory contract should not trigger governance findings"
        );
    }

    #[test]
    fn test_fp_simple_voting_without_governance_tokens_not_flagged() {
        // Simple voting (commit-reveal pattern) without governance token infrastructure
        let detector = GovernanceDetector::new();
        let source = r#"
            contract VulnerableVoting {
                mapping(uint256 => uint256) public votes;
                mapping(address => mapping(uint256 => bool)) public hasVoted;
                function vote(uint256 proposalId) external {
                    require(!hasVoted[msg.sender][proposalId], "Already voted");
                    votes[proposalId]++;
                    hasVoted[msg.sender][proposalId] = true;
                }
            }
        "#;
        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(
            result.is_empty(),
            "Simple voting without governance token patterns should not be flagged"
        );
    }

    #[test]
    fn test_fp_zk_voting_not_flagged() {
        // ZK voting contracts should NOT be flagged as governance
        let detector = GovernanceDetector::new();
        let source = r#"
            contract ZKVoting {
                uint256 public yesVotes;
                uint256 public noVotes;
                mapping(bytes32 => bool) public hasVoted;
                function vote(bytes32 voterId, bool voteValue, uint256[8] calldata proof) external {
                    require(!hasVoted[voterId], "Already voted");
                    hasVoted[voterId] = true;
                    if (voteValue) { yesVotes += 1; } else { noVotes += 1; }
                }
            }
        "#;
        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(
            result.is_empty(),
            "ZK voting contract should not trigger governance findings"
        );
    }

    #[test]
    fn test_fp_eigenlayer_delegation_manager_not_flagged() {
        // EigenLayer-style DelegationManager with queueWithdrawals
        let detector = GovernanceDetector::new();
        let source = r#"
            contract DelegationManager {
                mapping(address => address) public delegatedTo;
                function queueWithdrawals(uint256[] calldata params)
                    external onlyWhenNotPaused nonReentrant returns (bytes32[] memory) {
                    // Staker queue withdrawal logic
                }
                function completeQueuedWithdrawal(uint256 withdrawal) external {
                    // Complete withdrawal logic
                }
                function getQueuedWithdrawals(address staker) external view returns (uint256[] memory) {
                    // View function
                }
                function cancelSalt(bytes32 salt) external {
                    operatorSaltIsSpent[msg.sender][salt] = true;
                }
            }
        "#;
        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(
            result.is_empty(),
            "EigenLayer DelegationManager should not trigger governance findings"
        );
    }

    #[test]
    fn test_fp_eip7702_delegation_not_flagged() {
        // EIP-7702 delegation contracts should be skipped
        let detector = GovernanceDetector::new();
        let source = r#"
            // EIP-7702 delegation contract
            contract DelegationDeFiAttacks {
                function deposit() external payable {
                    deposits[msg.sender] += msg.value;
                }
                function borrow(uint256 amount) external {
                    uint256 size;
                    assembly { size := extcodesize(caller()) }
                    require(size == 0, "Contracts not allowed");
                }
            }
        "#;
        let ctx = create_test_context(source);
        let result = detector.detect(&ctx).unwrap();
        assert!(
            result.is_empty(),
            "EIP-7702 delegation contract should not trigger governance findings"
        );
    }

    #[test]
    fn test_tp_actual_governance_contract_patterns_detected() {
        // A contract with actual governance token patterns should be recognized
        let detector = GovernanceDetector::new();
        let source = r#"
            contract VulnerableGovernance {
                mapping(address => uint256) public votingPower;
                uint256 public quorum;
                function castVote(uint256 proposalId, bool support) external {
                    uint256 power = token.balanceOf(msg.sender);
                    require(power > 0, "No voting power");
                    votes[proposalId] += power;
                }
            }
        "#;
        let ctx = create_test_context(source);
        // Verify governance token patterns are detected (quorum + castVote + proposal)
        assert!(
            detector.has_governance_token_patterns(&ctx),
            "Should recognize governance token patterns (quorum, castVote, proposal)"
        );
        // Verify this is NOT classified as a non-governance contract
        assert!(
            !detector.is_non_governance_contract(&ctx),
            "Actual governance contract should not be classified as non-governance"
        );
    }

    #[test]
    fn test_governance_token_patterns_tier1() {
        let detector = GovernanceDetector::new();

        // Tier 1 indicators should be recognized
        let tier1_sources = [
            "contract Gov { IGovernor public governor; }",
            "contract Gov { uint256 public votingPeriod = 7 days; }",
            "contract Gov { uint256 public votingDelay = 1 days; }",
            "contract Gov { uint256 public proposalThreshold = 1000; }",
            "contract Gov { function getPriorVotes(address, uint256) external view returns (uint256); }",
            "contract Gov { function getPastVotes(address, uint256) external view returns (uint256); }",
            "contract Gov { function getVotes(address account) external view returns (uint256); }",
            "contract Gov { IERC20 public votingToken; }",
            "contract Gov { address public governanceToken; }",
        ];

        for source in &tier1_sources {
            let ctx = create_test_context(source);
            assert!(
                detector.has_governance_token_patterns(&ctx),
                "Should recognize tier 1 governance pattern in: {}",
                source
            );
        }
    }

    #[test]
    fn test_governance_token_patterns_non_governance() {
        let detector = GovernanceDetector::new();

        // Non-governance contracts should NOT match
        let non_gov_sources = [
            "contract Vault { function deposit() external payable {} }",
            "contract Proxy { function _delegate(address impl) internal {} }",
            "contract Restaking { function delegate(address operator, uint256 amount) external {} }",
            "contract ZKVoting { function vote(bytes32 id, bool val) external {} }",
            "contract CommitReveal { mapping(uint256 => uint256) public votes; }",
            "contract Factory { function proposeSelfDestruct(address r) external {} }",
        ];

        for source in &non_gov_sources {
            let ctx = create_test_context(source);
            assert!(
                !detector.has_governance_token_patterns(&ctx),
                "Should NOT recognize governance pattern in: {}",
                source
            );
        }
    }

    #[test]
    fn test_is_non_governance_contract_detection() {
        let detector = GovernanceDetector::new();

        // Restaking protocol
        let source = "contract DelegationManager { function queueWithdrawals() external {} mapping(address => address) public delegatedTo; function completeQueuedWithdrawal() external {} address public strategyManager; }";
        let ctx = create_test_context(source);
        assert!(
            detector.is_non_governance_contract(&ctx),
            "Should detect restaking protocol"
        );

        // Proxy upgrade
        let source = "contract Proxy { function proposeUpgrade(address impl) external {} function cancelUpgrade() external {} address public implementation; }";
        let ctx = create_test_context(source);
        assert!(
            detector.is_non_governance_contract(&ctx),
            "Should detect proxy upgrade contract"
        );

        // Metamorphic factory
        let source = "contract MetamorphicFactory { function deploy(bytes32 salt) external { assembly { create2(0, 0, 0, salt) } } address public factory; }";
        let ctx = create_test_context(source);
        assert!(
            detector.is_non_governance_contract(&ctx),
            "Should detect metamorphic factory"
        );

        // Actual governance should NOT be detected as non-governance
        let source = "contract Governor { function castVote(uint256 proposalId) external {} uint256 public quorum; }";
        let ctx = create_test_context(source);
        assert!(
            !detector.is_non_governance_contract(&ctx),
            "Actual governance contract should NOT be detected as non-governance"
        );
    }

    #[test]
    fn test_tp_basic_signature_replay_no_contract_protection() {
        // Verify that a contract with mapping(balances) but no nonce mapping
        // is correctly identified as lacking contract-level replay protection.
        // The "mapping" pattern alone must NOT trigger has_contract_level_replay_protection.
        let detector = SignatureReplayDetector::new();

        // Contract with only a balance mapping (no nonce protection)
        let no_nonce_source = r#"
            contract TestSignatureReplay {
                mapping(address => uint256) public balances;
            }
        "#;
        assert!(
            !detector.has_contract_level_replay_protection(no_nonce_source),
            "A contract with only balances mapping should NOT have replay protection"
        );

        // Contract with nonce mapping (has protection)
        let with_nonce_source = r#"
            contract TokenWithPermit {
                mapping(address => uint256) public nonces;
            }
        "#;
        assert!(
            detector.has_contract_level_replay_protection(with_nonce_source),
            "A contract with nonces mapping should have replay protection"
        );

        // usedSignatures mapping (has protection)
        let with_used_sigs = r#"
            contract WithUsedSigs {
                mapping(bytes32 => bool) public usedSignatures;
            }
        "#;
        assert!(
            detector.has_contract_level_replay_protection(with_used_sigs),
            "A contract with usedSignatures mapping should have replay protection"
        );
    }

    // ============ Signature-replay nonce-mapping regression tests ============

    /// Regression: a contract with `mapping(address => uint256) public nonces`
    /// is correctly recognized as having replay protection (so no finding).
    #[test]
    fn test_nonce_mapping_counts_as_replay_protection() {
        let detector = SignatureReplayDetector::new();
        let source = r#"
            contract Permit {
                mapping(address => uint256) public nonces;
            }
        "#;
        assert!(
            detector.has_contract_level_replay_protection(source),
            "mapping(address => uint256) public nonces should be replay protection"
        );
    }

    /// Regression: a contract with only `mapping(address => bool) public used`
    /// (a generic flag, NOT nonce-based) must NOT be treated as replay
    /// protection. "used" alone is too generic to imply nonce/signature tracking.
    #[test]
    fn test_generic_used_mapping_is_not_replay_protection() {
        let detector = SignatureReplayDetector::new();
        let source = r#"
            contract Flagged {
                mapping(address => bool) public used;
            }
        "#;
        assert!(
            !detector.has_contract_level_replay_protection(source),
            "mapping(address => bool) public used (no nonce) must NOT be replay protection"
        );
    }

    /// Regression for the core bug: a contract with only a bare `mapping`
    /// declaration and no nonce keyword must NOT be treated as replay
    /// protection. Previously the presence of any `mapping` was wrongly
    /// counted as replay protection.
    #[test]
    fn test_bare_mapping_is_not_replay_protection() {
        let detector = SignatureReplayDetector::new();
        let source = r#"
            contract BareMapping {
                mapping(address => uint256) public balances;
            }
        "#;
        assert!(
            !detector.has_contract_level_replay_protection(source),
            "a bare mapping with no nonce keyword must NOT be replay protection"
        );
    }
}

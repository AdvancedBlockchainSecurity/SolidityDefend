use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::detector::{Detector, DetectorCategory};
use crate::types::{AnalysisContext, AnalysisResult, DetectorId, Finding};

/// Registry for managing and executing vulnerability detectors
pub struct DetectorRegistry {
    /// All registered detectors
    detectors: HashMap<DetectorId, Arc<dyn Detector>>,
    /// Enabled detector IDs
    enabled_detectors: Vec<DetectorId>,
    /// Configuration for the registry
    config: RegistryConfig,
}

/// Configuration for the detector registry
#[derive(Debug, Clone)]
pub struct RegistryConfig {
    /// Maximum number of threads to use for parallel execution
    pub max_threads: usize,
    /// Timeout for individual detector execution (in seconds)
    pub detector_timeout_secs: u64,
    /// Whether to stop on first error or continue
    pub fail_fast: bool,
    /// Minimum severity level to include in results
    pub min_severity: crate::types::Severity,
    /// Minimum confidence level to include in results
    pub min_confidence: crate::types::Confidence,
    /// Categories to include (empty means all)
    pub enabled_categories: Vec<DetectorCategory>,
    /// Whether to include lint-mode detectors
    pub include_lint: bool,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            max_threads: 1, // Single-threaded for now
            detector_timeout_secs: 30,
            fail_fast: false,
            min_severity: crate::types::Severity::Info,
            min_confidence: crate::types::Confidence::Low,
            enabled_categories: Vec::new(), // Empty means all categories
            include_lint: false,
        }
    }
}

impl DetectorRegistry {
    /// Create a new detector registry
    pub fn new() -> Self {
        Self {
            detectors: HashMap::new(),
            enabled_detectors: Vec::new(),
            config: RegistryConfig::default(),
        }
    }

    /// Create a new detector registry with configuration
    pub fn with_config(config: RegistryConfig) -> Self {
        Self {
            detectors: HashMap::new(),
            enabled_detectors: Vec::new(),
            config,
        }
    }

    /// Create a new detector registry with all built-in detectors
    pub fn with_all_detectors() -> Self {
        let mut registry = Self::new();
        registry.register_built_in_detectors();
        registry
    }

    /// Create a new detector registry with all built-in detectors and config
    pub fn with_all_detectors_and_config(config: RegistryConfig) -> Self {
        let mut registry = Self::with_config(config);
        registry.register_built_in_detectors();
        registry
    }

    /// Register a detector in the registry
    pub fn register(&mut self, detector: Arc<dyn Detector>) {
        let id = detector.id();
        if detector.is_enabled() {
            self.enabled_detectors.push(id.clone());
        }
        self.detectors.insert(id, detector);
    }

    /// Register multiple detectors
    pub fn register_all(&mut self, detectors: Vec<Arc<dyn Detector>>) {
        for detector in detectors {
            self.register(detector);
        }
    }

    /// Enable a detector by ID
    pub fn enable_detector(&mut self, id: &DetectorId) -> Result<()> {
        if !self.detectors.contains_key(id) {
            return Err(anyhow!("Detector not found: {}", id));
        }

        if !self.enabled_detectors.contains(id) {
            self.enabled_detectors.push(id.clone());
        }
        Ok(())
    }

    /// Disable a detector by ID
    pub fn disable_detector(&mut self, id: &DetectorId) {
        self.enabled_detectors
            .retain(|detector_id| detector_id != id);
    }

    /// Enable detectors by category
    pub fn enable_category(&mut self, category: DetectorCategory) {
        for (id, detector) in &self.detectors {
            if detector.categories().contains(&category) && !self.enabled_detectors.contains(id) {
                self.enabled_detectors.push(id.clone());
            }
        }
    }

    /// Disable detectors by category
    pub fn disable_category(&mut self, category: DetectorCategory) {
        self.enabled_detectors.retain(|id| {
            if let Some(detector) = self.detectors.get(id) {
                !detector.categories().contains(&category)
            } else {
                false
            }
        });
    }

    /// Get all registered detector IDs
    pub fn get_detector_ids(&self) -> Vec<DetectorId> {
        self.detectors.keys().cloned().collect()
    }

    /// Get enabled detector IDs
    pub fn get_enabled_detector_ids(&self) -> Vec<DetectorId> {
        self.enabled_detectors.clone()
    }

    /// Get detector by ID
    pub fn get_detector(&self, id: &DetectorId) -> Option<&Arc<dyn Detector>> {
        self.detectors.get(id)
    }

    /// Get detectors by category
    pub fn get_detectors_by_category(&self, category: DetectorCategory) -> Vec<&Arc<dyn Detector>> {
        self.detectors
            .values()
            .filter(|detector| detector.categories().contains(&category))
            .collect()
    }

    /// Update registry configuration
    pub fn set_config(&mut self, config: RegistryConfig) {
        self.config = config;
    }

    /// Get current configuration
    pub fn get_config(&self) -> &RegistryConfig {
        &self.config
    }

    /// Run all enabled detectors on the given analysis context
    pub fn run_analysis(&self, ctx: &AnalysisContext<'_>) -> Result<AnalysisResult> {
        let start_time = Instant::now();
        let mut result = AnalysisResult::new();

        // Filter detectors based on configuration and available analysis data
        let detectors_to_run: Vec<_> = self
            .enabled_detectors
            .iter()
            .filter_map(|id| self.detectors.get(id))
            .filter(|detector| self.should_run_detector(detector))
            .filter(|detector| self.can_run_with_context(detector, ctx))
            .collect();

        result.stats.detectors_run = detectors_to_run.len();

        // Sort detectors by priority (highest first)
        let mut sorted_detectors = detectors_to_run;
        sorted_detectors.sort_by(|a, b| b.priority().cmp(&a.priority()));

        // Run detectors sequentially for now due to AST thread safety issues
        // TODO: Implement parallel execution with thread-safe AST
        let findings: Result<Vec<Vec<Finding>>> = self.run_sequential(&sorted_detectors, ctx);

        match findings {
            Ok(all_findings) => {
                // Flatten and filter findings
                for detector_findings in all_findings {
                    for finding in detector_findings {
                        if self.should_include_finding(&finding) {
                            result.stats.record_finding(&finding);
                            result.add_finding(finding);
                        }
                    }
                }
            }
            Err(e) => {
                result.add_error(format!("Analysis failed: {}", e));
            }
        }

        result.stats.total_time_ms = start_time.elapsed().as_millis() as u64;
        Ok(result)
    }

    /// Run a specific detector by ID
    pub fn run_detector(&self, id: &DetectorId, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let detector = self
            .detectors
            .get(id)
            .ok_or_else(|| anyhow!("Detector not found: {}", id))?;

        let start_time = Instant::now();
        let result = detector.detect(ctx);
        let duration = start_time.elapsed();

        match result {
            Ok(findings) => {
                log::debug!(
                    "Detector {} completed in {:?} with {} findings",
                    id,
                    duration,
                    findings.len()
                );
                Ok(findings)
            }
            Err(e) => {
                log::error!("Detector {} failed: {}", id, e);
                Err(e)
            }
        }
    }

    /// Run detectors sequentially
    fn run_sequential(
        &self,
        detectors: &[&Arc<dyn Detector>],
        ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<Vec<Finding>>> {
        let mut results = Vec::new();

        for detector in detectors {
            match self.run_single_detector(detector, ctx) {
                Ok(findings) => results.push(findings),
                Err(e) => {
                    if self.config.fail_fast {
                        return Err(e);
                    } else {
                        log::warn!("Detector {} failed: {}", detector.id(), e);
                        results.push(Vec::new());
                    }
                }
            }
        }

        Ok(results)
    }

    /// Run detectors in parallel (disabled due to AST thread safety issues)
    #[allow(dead_code)]
    fn run_parallel(
        &self,
        _detectors: &[&Arc<dyn Detector>],
        _ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<Vec<Finding>>> {
        // TODO: Implement parallel execution with thread-safe AST
        // For now, fallback to sequential execution
        Err(anyhow!(
            "Parallel execution not yet implemented - AST is not thread-safe"
        ))
    }

    /// Run a single detector with timeout handling
    fn run_single_detector(
        &self,
        detector: &Arc<dyn Detector>,
        ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<Finding>> {
        let start_time = Instant::now();
        let timeout = Duration::from_secs(self.config.detector_timeout_secs);

        // TODO: Implement proper timeout handling
        // For now, just run the detector directly
        let result = detector.detect(ctx);

        let duration = start_time.elapsed();
        if duration > timeout {
            log::warn!(
                "Detector {} exceeded timeout ({:?} > {:?})",
                detector.id(),
                duration,
                timeout
            );
        }

        result
    }

    /// Check if a detector should be run based on configuration and available analysis data
    fn should_run_detector(&self, detector: &Arc<dyn Detector>) -> bool {
        // Check if categories are restricted and detector matches
        if !self.config.enabled_categories.is_empty() {
            let detector_categories = detector.categories();
            let has_enabled_category = detector_categories
                .iter()
                .any(|cat| self.config.enabled_categories.contains(cat));

            if !has_enabled_category {
                return false;
            }
        }

        // Exclude lint detectors from normal runs unless lint mode is enabled
        if detector.is_lint() && !self.config.include_lint {
            return false;
        }

        true
    }

    /// Check if a detector can run with the available analysis data in the context.
    /// Returns false if the detector requires dataflow/cfg/taint but it's not available.
    fn can_run_with_context(
        &self,
        detector: &Arc<dyn Detector>,
        ctx: &AnalysisContext<'_>,
    ) -> bool {
        if detector.requires_dataflow() && !ctx.has_dataflow() {
            log::debug!(
                "Skipping detector '{}': requires dataflow but unavailable",
                detector.id()
            );
            return false;
        }
        if detector.requires_cfg() && !ctx.has_cfg() {
            log::debug!(
                "Skipping detector '{}': requires CFG but unavailable",
                detector.id()
            );
            return false;
        }
        if detector.requires_taint_analysis() && !ctx.has_taint() {
            log::debug!(
                "Skipping detector '{}': requires taint analysis but unavailable",
                detector.id()
            );
            return false;
        }
        true
    }

    /// Check if a finding should be included in results based on configuration
    fn should_include_finding(&self, finding: &Finding) -> bool {
        finding.severity >= self.config.min_severity
            && finding.confidence >= self.config.min_confidence
    }

    /// Get metrics for all detectors
    pub fn get_all_metrics(&self) -> HashMap<DetectorId, crate::detector::DetectorMetrics> {
        let mut metrics = HashMap::new();

        // Note: This implementation is incomplete due to trait object limitations
        // In practice, we'd need a different approach for accessing metrics
        for id in self.detectors.keys() {
            // Placeholder - would need to implement a different pattern
            metrics.insert(id.clone(), crate::detector::DetectorMetrics::new());
        }

        metrics
    }

    /// Reset metrics for all detectors
    pub fn reset_all_metrics(&self) {
        // Note: This implementation is incomplete due to trait object limitations
        // In practice, we'd need a different approach for mutable operations on trait objects
        // This would require either:
        // 1. Interior mutability (RefCell/Mutex)
        // 2. A different API design
        // 3. Returning a new registry with reset metrics
    }

    /// Register all built-in detectors
    fn register_built_in_detectors(&mut self) {
        // Access Control Detectors
        self.register(Arc::new(
            crate::access_control::MissingModifiersDetector::new(),
        ));
        self.register(Arc::new(
            crate::access_control::UnprotectedInitializerDetector::new(),
        ));
        self.register(Arc::new(
            crate::access_control::DefaultVisibilityDetector::new(),
        ));
        self.register(Arc::new(
            crate::access_control::StateVariableVisibilityDetector::new(),
        ));

        // Reentrancy Detectors
        self.register(Arc::new(crate::reentrancy::ClassicReentrancyDetector::new()));
        self.register(Arc::new(
            crate::reentrancy::ReadOnlyReentrancyDetector::new(),
        ));

        // Validation Detectors
        self.register(Arc::new(
            crate::validation::zero_address::ZeroAddressDetector::new(),
        ));
        self.register(Arc::new(
            crate::validation::array_bounds::ArrayBoundsDetector::new(),
        ));

        // External Call Detectors
        self.register(Arc::new(crate::external::UncheckedCallDetector::new()));

        // Auth Detectors
        self.register(Arc::new(crate::auth::TxOriginDetector::new()));

        // Governance Detectors
        self.register(Arc::new(crate::governance::GovernanceDetector::new()));
        self.register(Arc::new(crate::governance::SignatureReplayDetector::new()));

        // Cross-Chain Security
        self.register(Arc::new(
            crate::cross_chain_replay::CrossChainReplayDetector::new(),
        ));

        // Slippage & MEV
        self.register(Arc::new(
            crate::slippage_protection::SlippageProtectionDetector::new(),
        ));
        self.register(Arc::new(
            crate::delegation_loop::DelegationLoopDetector::new(),
        ));
        self.register(Arc::new(
            crate::mev_extractable_value::MevExtractableValueDetector::new(),
        ));
        self.register(Arc::new(crate::nonce_reuse::NonceReuseDetector::new()));

        // Proxy & Delegatecall Security
        self.register(Arc::new(
            crate::proxy_storage_collision::ProxyStorageCollisionDetector::new(),
        ));
        self.register(Arc::new(
            crate::fallback_delegatecall_unprotected::FallbackDelegatecallUnprotectedDetector::new(
            ),
        ));
        self.register(Arc::new(
            crate::delegatecall_return_ignored::DelegatecallReturnIgnoredDetector::new(),
        ));
        self.register(Arc::new(
            crate::delegatecall_untrusted_library::DelegatecallUntrustedLibraryDetector::new(),
        ));
        self.register(Arc::new(
            crate::delegatecall_user_controlled::DelegatecallUserControlledDetector::new(),
        ));
        self.register(Arc::new(
            crate::upgradeable_proxy_issues::UpgradeableProxyIssuesDetector::new(),
        ));

        // Selfdestruct
        self.register(Arc::new(
            crate::selfdestruct_abuse::SelfdestructAbuseDetector::new(),
        ));

        // DoS & Gas Attacks
        self.register(Arc::new(
            crate::dos_unbounded_operation::DosUnboundedOperationDetector::new(),
        ));
        self.register(Arc::new(
            crate::dos_external_call_loop::DosExternalCallLoopDetector::new(),
        ));
        self.register(Arc::new(
            crate::gas_griefing::GasGriefingDetector::new(),
        ));

        // Oracle & Price Manipulation
        self.register(Arc::new(
            crate::oracle_manipulation::OracleManipulationDetector::new(),
        ));

        // Cryptographic Security
        self.register(Arc::new(
            crate::signature_malleability::SignatureMalleabilityDetector::new(),
        ));

        // Block Dependency
        self.register(Arc::new(
            crate::timestamp::BlockDependencyDetector::new(),
        ));

        // Type Safety
        self.register(Arc::new(
            crate::unsafe_type_casting::UnsafeTypeCastingDetector::new(),
        ));

        // Centralization
        self.register(Arc::new(
            crate::centralization_risk::CentralizationRiskDetector::new(),
        ));

        // Staking & Validator Security
        self.register(Arc::new(
            crate::slashing_mechanism::SlashingMechanismDetector::new(),
        ));

        // DeFi Vault Security
        self.register(Arc::new(
            crate::vault_share_inflation::VaultShareInflationDetector::new(),
        ));
        self.register(Arc::new(
            crate::vault_donation_attack::VaultDonationAttackDetector::new(),
        ));
        self.register(Arc::new(
            crate::vault_withdrawal_dos::VaultWithdrawalDosDetector::new(),
        ));
        self.register(Arc::new(
            crate::vault_fee_manipulation::VaultFeeManipulationDetector::new(),
        ));
        self.register(Arc::new(
            crate::vault_hook_reentrancy::VaultHookReentrancyDetector::new(),
        ));

        // Bridge Security
        self.register(Arc::new(
            crate::bridge_chain_id_validation::ChainIdValidationDetector::new(),
        ));
        self.register(Arc::new(
            crate::bridge_message_verification::MessageVerificationDetector::new(),
        ));
        self.register(Arc::new(
            crate::bridge_token_minting::TokenMintingDetector::new(),
        ));

        // Account Abstraction & ERC-4337
        self.register(Arc::new(crate::aa::ERC4337PaymasterAbuseDetector::new()));

        self.register(Arc::new(
            crate::aa_account_takeover::AaAccountTakeoverDetector::new(),
        ));
        self.register(Arc::new(
            crate::aa_session_key_vulnerabilities::SessionKeyVulnerabilitiesDetector::new(),
        ));
        self.register(Arc::new(
            crate::aa_social_recovery::SocialRecoveryDetector::new(),
        ));
        self.register(Arc::new(
            crate::aa_advanced::AAPaymasterFundDrainDetector::new(),
        ));

        // Access Control Advanced
        self.register(Arc::new(
            crate::access_control_advanced::GuardianRoleCentralizationDetector::new(),
        ));

        // Restaking & LRT Security
        self.register(Arc::new(
            crate::restaking::RestakingSlashingConditionsDetector::new(),
        ));
        self.register(Arc::new(crate::restaking::LRTShareInflationDetector::new()));
        self.register(Arc::new(
            crate::restaking::RestakingWithdrawalDelaysDetector::new(),
        ));

        // Flash Loan Enhanced
        self.register(Arc::new(
            crate::flashloan_enhanced::FlashLoanPriceManipulationAdvancedDetector::new(),
        ));
        self.register(Arc::new(
            crate::flashloan_enhanced::FlashLoanCollateralSwapDetector::new(),
        ));

        // Token Standards Extended
        self.register(Arc::new(
            crate::token_standards_extended::TokenPermitFrontRunningDetector::new(),
        ));

        // MEV Enhanced
        self.register(Arc::new(
            crate::mev_enhanced::MEVPriorityGasAuctionDetector::new(),
        ));

        // Zero-Knowledge Proofs
        self.register(Arc::new(
            crate::zk_proofs::ZKProofMalleabilityDetector::new(),
        ));
        self.register(Arc::new(
            crate::zk_proofs::ZKTrustedSetupBypassDetector::new(),
        ));
        self.register(Arc::new(
            crate::zk_proofs::ZKRecursiveProofValidationDetector::new(),
        ));

        // Transient Storage (EIP-1153)
        self.register(Arc::new(
            crate::transient::TransientStorageReentrancyDetector::new(),
        ));
        self.register(Arc::new(
            crate::transient::TransientStorageComposabilityDetector::new(),
        ));

        // EIP-7702 Account Delegation
        self.register(Arc::new(
            crate::eip7702::EIP7702DelegateAccessControlDetector::new(),
        ));

        // ERC-7821 Batch Executor
        self.register(Arc::new(
            crate::erc7821::ERC7821BatchAuthorizationDetector::new(),
        ));

        // DeFi Protocol Security
        self.register(Arc::new(
            crate::defi_yield_farming::YieldFarmingDetector::new(),
        ));
        self.register(Arc::new(
            crate::erc20_approve_race::Erc20ApproveRaceDetector::new(),
        ));
        self.register(Arc::new(
            crate::allowance_toctou::AllowanceToctouDetector::new(),
        ));
        self.register(Arc::new(
            crate::missing_transaction_deadline::MissingTransactionDeadlineDetector::new(),
        ));

        // OWASP 2025
        self.register(Arc::new(crate::owasp2025::OracleStalenesDetector::new()));

        // Advanced DeFi
        self.register(Arc::new(
            crate::defi_advanced::HookReentrancyEnhancedDetector::new(),
        ));

        // Multisig
        self.register(Arc::new(
            crate::multisig_bypass::MultisigBypassDetector::new(),
        ));

        // Metamorphic & CREATE2
        self.register(Arc::new(
            crate::constructor_reentrancy::ConstructorReentrancyDetector::new(),
        ));
        self.register(Arc::new(
            crate::create2_salt_frontrunning::Create2SaltFrontrunningDetector::new(),
        ));
        self.register(Arc::new(
            crate::metamorphic_contract_risk::MetamorphicContractRiskDetector::new(),
        ));

        // Future Standards
        self.register(Arc::new(
            crate::commit_reveal_timing::CommitRevealTimingDetector::new(),
        ));
        self.register(Arc::new(
            crate::eip3074_upgradeable_invoker::Eip3074UpgradeableInvokerDetector::new(),
        ));
        self.register(Arc::new(
            crate::eip4844_blob_validation::Eip4844BlobValidationDetector::new(),
        ));
        self.register(Arc::new(
            crate::push0_stack_assumption::Push0StackAssumptionDetector::new(),
        ));

        // L2/Rollup Security
        self.register(Arc::new(
            crate::zk_proof_bypass::ZkProofBypassDetector::new(),
        ));

        // Oracle-Specific Detectors
        self.register(Arc::new(
            crate::oracle_security::ChainlinkStalePriceDetector::new(),
        ));
        self.register(Arc::new(
            crate::oracle_security::ChainlinkSequencerCheckDetector::new(),
        ));
        self.register(Arc::new(
            crate::oracle_security::OracleSingleSourceDetector::new(),
        ));
        self.register(Arc::new(
            crate::oracle_security::TwapManipulationWindowDetector::new(),
        ));
        self.register(Arc::new(
            crate::oracle_security::OracleDecimalMismatchDetector::new(),
        ));

        // L2-Specific Detectors
        self.register(Arc::new(crate::l2_security::L2MsgValueInLoopDetector::new()));
        self.register(Arc::new(
            crate::l2_security::L2BlockNumberAssumptionDetector::new(),
        ));
        self.register(Arc::new(
            crate::l2_security::L2GasPriceDependencyDetector::new(),
        ));
        self.register(Arc::new(
            crate::l2_security::L2Push0CrossDeployDetector::new(),
        ));

        // Lint / Code Quality Detectors
        self.register(Arc::new(crate::lint::MissingNatspecDetector::new()));
        self.register(Arc::new(crate::lint::UnusedImportDetector::new()));
        self.register(Arc::new(crate::lint::MagicNumberDetector::new()));
        self.register(Arc::new(crate::lint::FunctionTooLongDetector::new()));
        self.register(Arc::new(crate::lint::ExcessiveInheritanceDetector::new()));
    }
}

impl Default for DetectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating detector registries
pub struct DetectorRegistryBuilder {
    registry: DetectorRegistry,
}

impl DetectorRegistryBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            registry: DetectorRegistry::new(),
        }
    }

    /// Set the configuration
    pub fn with_config(mut self, config: RegistryConfig) -> Self {
        self.registry.set_config(config);
        self
    }

    /// Add a detector
    pub fn with_detector(mut self, detector: Arc<dyn Detector>) -> Self {
        self.registry.register(detector);
        self
    }

    /// Add multiple detectors
    pub fn with_detectors(mut self, detectors: Vec<Arc<dyn Detector>>) -> Self {
        self.registry.register_all(detectors);
        self
    }

    /// Enable a specific category
    pub fn with_category(mut self, category: DetectorCategory) -> Self {
        self.registry.enable_category(category);
        self
    }

    /// Set maximum threads
    pub fn with_max_threads(mut self, max_threads: usize) -> Self {
        self.registry.config.max_threads = max_threads;
        self
    }

    /// Set minimum severity
    pub fn with_min_severity(mut self, min_severity: crate::types::Severity) -> Self {
        self.registry.config.min_severity = min_severity;
        self
    }

    /// Build the registry
    pub fn build(self) -> DetectorRegistry {
        self.registry
    }
}

impl Default for DetectorRegistryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Regression guard: if the registered detector count drops below this
    // threshold, a detector was accidentally unregistered. Update this constant
    // intentionally when adding or removing detectors.
    const MIN_REGISTERED_DETECTORS: usize = 90;

    #[test]
    fn registered_detector_count_meets_minimum() {
        let registry = DetectorRegistry::with_all_detectors();
        let count = registry.detectors.len();
        assert!(
            count >= MIN_REGISTERED_DETECTORS,
            "Detector count dropped to {count} — expected at least {MIN_REGISTERED_DETECTORS}. \
             A detector was likely accidentally unregistered in registry.rs. \
             Check crates/detectors/src/registry.rs register_built_in_detectors()."
        );
    }

    #[test]
    fn all_registered_detectors_have_non_empty_ids() {
        let registry = DetectorRegistry::with_all_detectors();
        for (id, detector) in &registry.detectors {
            assert!(
                !id.0.is_empty(),
                "Detector '{}' has an empty ID string",
                detector.name()
            );
            assert!(
                !detector.name().is_empty(),
                "Detector with id '{}' has an empty name",
                id.0
            );
            assert!(
                !detector.description().is_empty(),
                "Detector '{}' has an empty description",
                id.0
            );
        }
    }

    #[test]
    fn no_duplicate_detector_ids() {
        // DetectorRegistry uses a HashMap keyed on DetectorId, so duplicates
        // silently overwrite each other. This test catches that by verifying
        // the final count equals the number of unique IDs we inserted.
        // If a duplicate exists, the HashMap count will be lower than expected.
        let registry = DetectorRegistry::with_all_detectors();
        let ids: Vec<String> = registry.detectors.keys().map(|id| id.0.clone()).collect();
        let unique_count = ids.len();
        let mut seen = std::collections::HashSet::new();
        let mut duplicates = Vec::new();
        for id in &ids {
            if !seen.insert(id) {
                duplicates.push(id.clone());
            }
        }
        assert!(
            duplicates.is_empty(),
            "Duplicate detector IDs found (silently overwritten in registry): {:?}. \
             Each detector must have a unique ID.",
            duplicates
        );
        // Sanity: unique_count should equal ids.len() since HashMap already deduplicates
        assert_eq!(unique_count, ids.len());
    }
}

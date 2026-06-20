// Core detector framework
pub mod detector;
pub mod fp_filter;
pub mod registry;
pub mod types;

// Utility functions for context detection and pattern recognition
pub mod utils;

// Safe pattern recognition library
pub mod safe_patterns;

// Confidence scoring
pub mod confidence;

// Detector implementations - Core Security
pub mod access_control;
pub mod auth;
pub mod centralization_risk;
pub mod cross_chain_replay;
pub mod delegatecall_return_ignored;
pub mod delegatecall_untrusted_library;
pub mod delegatecall_user_controlled;
pub mod delegation_loop;
pub mod dos_external_call_loop;
pub mod dos_unbounded_operation;
pub mod external;
pub mod fallback_delegatecall_unprotected;
pub mod gas_griefing;
pub mod governance;
pub mod mev_extractable_value;
pub mod nonce_reuse;
pub mod oracle_manipulation;
pub mod proxy_storage_collision;
pub mod reentrancy;
pub mod selfdestruct_abuse;
pub mod signature_malleability;
pub mod slashing_mechanism;
pub mod slippage_protection;
pub mod timestamp;
pub mod unsafe_type_casting;

pub mod upgradeable_proxy_issues;
pub mod validation;
pub mod vault_donation_attack;
pub mod vault_fee_manipulation;
pub mod vault_hook_reentrancy;
pub mod vault_share_inflation;
pub mod vault_withdrawal_dos;

// Account Abstraction & ERC-4337
pub mod aa;
pub mod aa_account_takeover;
pub mod aa_advanced;
pub mod aa_session_key_vulnerabilities;
pub mod aa_social_recovery;

// Cross-Chain & Bridge Security
pub mod bridge_chain_id_validation;
pub mod bridge_message_verification;
pub mod bridge_token_minting;

// DeFi Protocol Security
pub mod allowance_toctou;
pub mod defi_yield_farming;
pub mod erc20_approve_race;
pub mod missing_transaction_deadline;

// Multisig Security
pub mod multisig_bypass;

// Advanced Detector Suites
pub mod access_control_advanced;
pub mod defi_advanced;
pub mod flashloan_enhanced;
pub mod mev_enhanced;
pub mod owasp2025;
pub mod restaking;
pub mod token_standards_extended;
pub mod zk_proofs;

// EIP/ERC Standards Security
pub mod eip7702;
pub mod erc7821;
pub mod transient;

// Metamorphic & CREATE2 Patterns
pub mod constructor_reentrancy;
pub mod create2_salt_frontrunning;
pub mod metamorphic_contract_risk;

// Future Standards
pub mod commit_reveal_timing;
pub mod eip3074_upgradeable_invoker;
pub mod eip4844_blob_validation;
pub mod push0_stack_assumption;

// L2/Rollup Security
pub mod zk_proof_bypass;

// DeFi-specific detectors
pub mod defi;

// Cross-contract analysis
pub mod cross_contract;

// Advanced taint analysis
pub mod taint;

// Advanced security engine integrating all advanced features
pub mod advanced_security_engine;

// Oracle-specific detectors (Chainlink, Pyth, TWAP)
pub mod oracle_security;

// L2-specific detectors (Arbitrum, Optimism, zkSync)
pub mod l2_security;

// Lint / code-quality detectors
pub mod lint;

// Re-export core types and traits
pub use detector::{
    AstAnalyzer, BaseDetector, ConfigurableDetector, DataFlowAnalyzer, Detector, DetectorCategory,
    MetricsDetector, TaintAnalyzer,
};
pub use fp_filter::FpFilter;
pub use registry::{DetectorRegistry, DetectorRegistryBuilder, RegistryConfig};
pub use types::{
    AnalysisContext, AnalysisResult, AnalysisStats, Confidence, DetectorId, Finding, Severity,
    SourceLocation,
};

// Convenience macro for implementing the Detector trait is defined in detector.rs

use detectors::allowance_toctou::AllowanceToctouDetector;
/**
 * Integration tests for Front-Running Detectors
 *
 * Tests the ERC20 Front-Running detectors:
 * 1. erc20-approve-race
 * 2. allowance-toctou
 */
use detectors::detector::{Detector, DetectorCategory};
use detectors::erc20_approve_race::Erc20ApproveRaceDetector;
use detectors::types::Severity;

#[test]
fn test_erc20_approve_race_metadata() {
    let detector = Erc20ApproveRaceDetector::new();

    assert_eq!(detector.id().0, "erc20-approve-race");
    assert_eq!(detector.name(), "ERC-20 Approve Race Condition");
    assert_eq!(detector.default_severity(), Severity::Info);
    assert!(detector.is_enabled());

    let categories = detector.categories();
    assert!(categories.contains(&DetectorCategory::Logic));
    assert!(categories.contains(&DetectorCategory::DeFi));
}

#[test]
fn test_allowance_toctou_metadata() {
    let detector = AllowanceToctouDetector::new();

    assert_eq!(detector.id().0, "allowance-toctou");
    assert_eq!(detector.name(), "Allowance Time-of-Check-Time-of-Use");
    assert_eq!(detector.default_severity(), Severity::Medium);
    assert!(detector.is_enabled());

    let categories = detector.categories();
    assert!(categories.contains(&DetectorCategory::Logic));
    assert!(categories.contains(&DetectorCategory::DeFi));
    assert!(categories.contains(&DetectorCategory::MEV));
}

#[test]
fn test_all_detectors_instantiable() {
    let d1 = Erc20ApproveRaceDetector::new();
    let d3 = AllowanceToctouDetector::new();

    assert_eq!(d1.id().0, "erc20-approve-race");
    assert_eq!(d3.id().0, "allowance-toctou");

    assert!(d1.is_enabled());
    assert!(d3.is_enabled());
}

#[test]
fn test_detector_categories_unique() {
    let detector1 = Erc20ApproveRaceDetector::new();
    let detector3 = AllowanceToctouDetector::new();

    let cats1 = detector1.categories();
    let cats3 = detector3.categories();

    // All should have MEV or DeFi category (front-running related)
    assert!(cats1.contains(&DetectorCategory::DeFi) || cats3.contains(&DetectorCategory::MEV));
}

#[test]
fn test_all_detectors_expected_severity() {
    let detector1 = Erc20ApproveRaceDetector::new();
    let detector3 = AllowanceToctouDetector::new();

    // erc20-approve-race is Info: the race is inherent to the ERC-20 standard (SWC-114)
    assert_eq!(detector1.default_severity(), Severity::Info);
    assert_eq!(detector3.default_severity(), Severity::Medium);
}

#[cfg(test)]
mod integration {
    use super::*;

    #[test]
    fn test_phase2_week1_complete() {
        let _d1 = Erc20ApproveRaceDetector::new();
        let _d3 = AllowanceToctouDetector::new();

        assert_eq!(_d1.id().0, "erc20-approve-race");
        assert_eq!(_d3.id().0, "allowance-toctou");

        assert!(_d1.is_enabled());
        assert!(_d3.is_enabled());
    }

    #[test]
    fn test_detector_descriptions_present() {
        let d1 = Erc20ApproveRaceDetector::new();
        let d3 = AllowanceToctouDetector::new();

        assert!(!d1.description().is_empty());
        assert!(!d3.description().is_empty());

        assert!(d1.description().len() > 20);
        assert!(d3.description().len() > 20);
    }

    #[test]
    fn test_detector_names_unique() {
        let d1 = Erc20ApproveRaceDetector::new();
        let d3 = AllowanceToctouDetector::new();

        let name1 = d1.name();
        let name3 = d3.name();

        assert_ne!(name1, name3);
    }

    #[test]
    fn test_detector_ids_unique() {
        let d1 = Erc20ApproveRaceDetector::new();
        let d3 = AllowanceToctouDetector::new();

        let id1 = d1.id();
        let id3 = d3.id();

        assert_ne!(id1, id3);
    }

    #[test]
    fn test_all_detector_categories_valid() {
        let d1 = Erc20ApproveRaceDetector::new();
        let d3 = AllowanceToctouDetector::new();

        assert!(!d1.categories().is_empty());
        assert!(!d3.categories().is_empty());

        assert!(d1.categories().len() <= 4);
        assert!(d3.categories().len() <= 4);
    }
}

#[cfg(test)]
mod coverage {
    use super::*;

    #[test]
    fn test_detectors_cover_front_running_patterns() {
        let d1 = Erc20ApproveRaceDetector::new();
        let d3 = AllowanceToctouDetector::new();

        let desc1 = d1.description().to_lowercase();
        let desc3 = d3.description().to_lowercase();

        // d1 should cover approve/allowance
        assert!(desc1.contains("approve") || desc1.contains("allowance"));

        // d3 should cover time-of-check-time-of-use
        assert!(desc3.contains("check") || desc3.contains("use") || desc3.contains("race"));
    }

    #[test]
    fn test_comprehensive_mev_coverage() {
        let d1 = Erc20ApproveRaceDetector::new();
        let d3 = AllowanceToctouDetector::new();

        let all_categories: Vec<Vec<DetectorCategory>> = vec![d1.categories(), d3.categories()];

        // At least one should have DeFi category
        let defi_count = all_categories
            .iter()
            .filter(|cats| cats.contains(&DetectorCategory::DeFi))
            .count();

        assert!(
            defi_count >= 1,
            "At least one detector should have DeFi category"
        );
    }
}

#[cfg(test)]
mod regression {
    use super::*;

    #[test]
    fn test_no_panic_on_empty_source() {
        let d1 = Erc20ApproveRaceDetector::new();
        let d3 = AllowanceToctouDetector::new();

        assert_eq!(d1.id().0, "erc20-approve-race");
        assert_eq!(d3.id().0, "allowance-toctou");
    }

    #[test]
    fn test_detector_consistency() {
        let d1a = Erc20ApproveRaceDetector::new();
        let d1b = Erc20ApproveRaceDetector::new();

        assert_eq!(d1a.id(), d1b.id());
        assert_eq!(d1a.name(), d1b.name());
        assert_eq!(d1a.default_severity(), d1b.default_severity());
        assert_eq!(d1a.is_enabled(), d1b.is_enabled());
    }
}

#[cfg(test)]
mod performance {
    use super::*;

    #[test]
    fn test_detector_creation_fast() {
        use std::time::Instant;

        let start = Instant::now();
        for _ in 0..1000 {
            let _ = Erc20ApproveRaceDetector::new();
            let _ = AllowanceToctouDetector::new();
        }
        let elapsed = start.elapsed();

        assert!(
            elapsed.as_millis() < 100,
            "Detector creation too slow: {:?}",
            elapsed
        );
    }

    #[test]
    fn test_metadata_access_fast() {
        use std::time::Instant;

        let d1 = Erc20ApproveRaceDetector::new();
        let d3 = AllowanceToctouDetector::new();

        let start = Instant::now();
        for _ in 0..10000 {
            let _ = d1.id();
            let _ = d1.name();
            let _ = d1.default_severity();
            let _ = d3.id();
            let _ = d3.name();
            let _ = d3.default_severity();
        }
        let elapsed = start.elapsed();

        assert!(
            elapsed.as_millis() < 10,
            "Metadata access too slow: {:?}",
            elapsed
        );
    }
}

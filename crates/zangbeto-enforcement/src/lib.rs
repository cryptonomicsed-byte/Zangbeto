//! 🕯 ZÀNGBÉTÒ ENFORCEMENT KERNEL v0.1
//!
//! Deterministic enforcement daemon for Reality VM.
//! Watches, quarantines, arbitrates, and corrects reality deviations.

pub mod action_ladder;
pub mod anomaly;
pub mod arbitration;
pub mod daemon;
pub mod http;
pub mod quarantine;
pub mod receipts;
pub mod rollback;
pub mod server;

pub use action_ladder::{EnforcementAction, HaltScope, QuarantineScope, ReleaseCondition};
pub use anomaly::{Anomaly, AnomalyClassification, AnomalySeverity, AnomalySource};
pub use arbitration::{ArbitrationEngine, ArbitrationGraph, ResolutionStrategy};
pub use daemon::{DaemonConfig, EnforcementEvent, EnforcementReceipt, ZangbetoDaemon};
pub use quarantine::{QuarantineId, QuarantineManager};

/// 🜂 Quick-start: create enforcement daemon with default policy
pub fn create_default_enforcer(
    replay_engine: std::sync::Arc<replay_engine::ReplayEngine>,
    policy_host: std::sync::Arc<policy_runtime::WasmpolicyHost>,
) -> ZangbetoDaemon {
    use action_ladder::{
        ActionLadder, AnomalyClassificationMatcher, EnforcementPolicy, EscalationRule,
    };

    let policy = EnforcementPolicy {
        default_severity_threshold: AnomalySeverity::Warning,
        escalation_rules: vec![
            EscalationRule {
                match_classification: AnomalyClassificationMatcher::Exact(
                    AnomalyClassification::EconomicAnomaly {
                        metric: "balance".into(),
                        deviation: 0.0,
                    },
                ),
                min_severity: AnomalySeverity::Critical,
                action: EnforcementAction::RollbackTransition {
                    to_state: [0u8; 32], // Resolved at runtime
                    preserve_audit_trail: true,
                    compensation_required: true,
                },
                requires_consensus: vec!["ṣàngó".into()],
            },
            EscalationRule {
                match_classification: AnomalyClassificationMatcher::Pattern {
                    r#type: "concurrency_conflict".into(),
                    field_pattern: None,
                },
                min_severity: AnomalySeverity::Critical,
                action: EnforcementAction::QuarantineState {
                    scope: QuarantineScope::Branch {
                        branch_id: "unknown".into(),
                    },
                    duration_ms: Some(600_000),
                    release_conditions: vec![ReleaseCondition::OrishaApproval {
                        required: vec!["yemọja".into(), "èṣù".into()],
                    }],
                },
                requires_consensus: vec!["yemọja".into()],
            },
        ],
        orisha_weights: [
            ("èṣù".into(), 10),
            ("ọbàtálá".into(), 9),
            ("ṣàngó".into(), 10),
            ("yemọja".into(), 8),
            ("ọ̀ṣun".into(), 7),
            ("ògún".into(), 6),
            ("ọya".into(), 7),
        ]
        .into_iter()
        .collect(),
        auto_quarantine_enabled: true,
        rollback_authority_threshold: 0.7,
    };

    let action_ladder = ActionLadder::new(policy);
    let quarantine_mgr = QuarantineManager::new();

    let arbitration_graph = ArbitrationGraph {
        defer_edges: [
            ("ògún".into(), vec!["èṣù".into(), "ọbàtálá".into()]),
            ("yemọja".into(), vec!["ṣàngó".into()]),
        ]
        .into_iter()
        .collect(),
        resolution_strategies: [
            (
                ("èṣù".into(), "ọbàtálá".into()),
                ResolutionStrategy::WeightedVote {
                    weights: [("èṣù".into(), 10), ("ọbàtálá".into(), 9)]
                        .into_iter()
                        .collect(),
                },
            ),
            (
                ("ṣàngó".into(), "yemọja".into()),
                ResolutionStrategy::Hierarchical {
                    superior: "ṣàngó".into(),
                },
            ),
        ]
        .into_iter()
        .collect(),
        default_strategy: ResolutionStrategy::ConsensusRequired {
            quorum: vec!["èṣù".into(), "ọbàtálá".into(), "ṣàngó".into()],
        },
    };

    let arbitration_engine = ArbitrationEngine::new(0.7, arbitration_graph);

    let config = DaemonConfig {
        anomaly_check_interval_ms: 1000,
        quarantine_eval_interval_ms: 5000,
        max_pending_anomalies: 100,
        auto_enforce: true,
        require_human_approval_for: vec![EnforcementAction::EmergencyHalt {
            scope: HaltScope::Global,
            require_quorum: vec![],
            auto_resume_condition: None,
        }],
    };

    ZangbetoDaemon::new(
        config,
        replay_engine,
        policy_host,
        action_ladder,
        quarantine_mgr,
        arbitration_engine,
    )
}

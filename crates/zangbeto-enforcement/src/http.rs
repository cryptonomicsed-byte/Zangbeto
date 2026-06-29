//! HTTP enforcement bridge.
//!
//! Exposes the [`ActionLadder`] over `POST /enforce` and `POST /review` so the
//! Ọmọ Kọ́dà runtime (`omokoda-core`'s `bus::zangbeto`) can obtain a verdict for
//! a reported anomaly or a *proposed* act. The response `action` field is one of
//! the keywords the runtime's `verdict_blocks()` recognizes, so a blocking
//! verdict (`quarantine` / `block` / `deny` / `halt`) gates the act while
//! permissive ones (`observe` / `review`) let it proceed.
//!
//! The default ladder carries no explicit escalation rules, so
//! [`ActionLadder::determine_action`] falls back to severity-based escalation:
//! observational/warning → allow, critical (conflict/economic) → block,
//! catastrophic → halt. Mirrors the daemon's default posture (permissive unless
//! a real, severe anomaly is reported).

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::action_ladder::{ActionLadder, EnforcementAction, EnforcementPolicy, LogLevel};
use crate::anomaly::{
    Anomaly, AnomalyClassification, AnomalyEvidence, AnomalySeverity, AnomalySource,
};

/// Build the default permissive enforcement ladder (no explicit escalation
/// rules — severity-based fallback only).
pub fn default_ladder() -> ActionLadder {
    ActionLadder::new(EnforcementPolicy {
        default_severity_threshold: AnomalySeverity::Warning,
        escalation_rules: vec![],
        orisha_weights: HashMap::new(),
        auto_quarantine_enabled: true,
        rollback_authority_threshold: 0.7,
    })
}

/// Router for the enforcement bridge, with a shared default ladder as state.
pub fn router() -> Router {
    router_with(Arc::new(default_ladder()))
}

/// Router over a caller-supplied ladder (used by tests).
pub fn router_with(ladder: Arc<ActionLadder>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/enforce", post(enforce))
        .route("/review", post(review))
        .with_state(ladder)
}

async fn health() -> Json<Value> {
    Json(json!({ "ok": true, "service": "zangbeto-enforcement" }))
}

#[derive(Deserialize)]
struct EnforceReq {
    #[serde(default)]
    agent_id: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    classification: String,
    #[serde(default)]
    detail: String,
}

async fn enforce(
    State(ladder): State<Arc<ActionLadder>>,
    Json(req): Json<EnforceReq>,
) -> Json<Value> {
    let anomaly = build_anomaly(
        parse_severity(&req.severity),
        parse_classification(&req.classification, &req.detail),
        &req.detail,
    );
    let decision = ladder.determine_action(&anomaly);
    let (action, blocking) = action_verdict(&decision.action);
    Json(json!({
        "agent_id": req.agent_id,
        "action": action,
        "blocking": blocking,
        "rationale": decision.rationale,
    }))
}

#[derive(Deserialize)]
struct ReviewReq {
    #[serde(default)]
    agent_id: String,
    #[serde(default)]
    tool: String,
    // `detail` may be sent by the runtime but isn't needed to review a proposed
    // act; serde ignores the extra field.
}

async fn review(
    State(ladder): State<Arc<ActionLadder>>,
    Json(req): Json<ReviewReq>,
) -> Json<Value> {
    // A proposed act is reviewed as a Warning-level capability use; the default
    // ladder flags it for review (non-blocking) unless policy escalates.
    let anomaly = build_anomaly(
        AnomalySeverity::Warning,
        AnomalyClassification::CapabilityEscape {
            granted_ops: vec![],
            attempted: req.tool.clone(),
        },
        &req.tool,
    );
    let decision = ladder.determine_action(&anomaly);
    let (action, blocking) = action_verdict(&decision.action);
    Json(json!({
        "agent_id": req.agent_id,
        "tool": req.tool,
        "action": action,
        "blocking": blocking,
    }))
}

fn parse_severity(s: &str) -> AnomalySeverity {
    match s.trim().to_ascii_lowercase().as_str() {
        "observational" | "observation" | "info" => AnomalySeverity::Observational,
        "critical" => AnomalySeverity::Critical,
        "catastrophic" | "fatal" => AnomalySeverity::Catastrophic,
        _ => AnomalySeverity::Warning,
    }
}

fn parse_classification(s: &str, detail: &str) -> AnomalyClassification {
    match s.trim().to_ascii_lowercase().as_str() {
        "economic_anomaly" | "economic" => AnomalyClassification::EconomicAnomaly {
            metric: detail.to_string(),
            deviation: 0.0,
        },
        "concurrency_conflict" | "concurrency" => AnomalyClassification::ConcurrencyConflict {
            nodes: vec![],
            conflict_type: detail.to_string(),
        },
        "temporal_inconsistency" | "temporal" => {
            AnomalyClassification::TemporalInconsistency { clock_skew_ms: 0 }
        }
        "schema_drift" | "schema" => AnomalyClassification::SchemaDrift {
            expected_schema: String::new(),
            observed_schema: detail.to_string(),
        },
        // capability_escape and anything unrecognized fall here.
        _ => AnomalyClassification::CapabilityEscape {
            granted_ops: vec![],
            attempted: detail.to_string(),
        },
    }
}

/// Map an [`EnforcementAction`] to a `(verdict_keyword, is_blocking)` pair. The
/// keyword set aligns with `omokoda-core`'s `verdict_blocks()`: `quarantine` /
/// `block` / `deny` / `halt` gate; `observe` / `review` do not.
fn action_verdict(action: &EnforcementAction) -> (&'static str, bool) {
    match action {
        EnforcementAction::Observe { .. } => ("observe", false),
        EnforcementAction::FlagForReview { .. } => ("review", false),
        EnforcementAction::QuarantineState { .. } => ("quarantine", true),
        EnforcementAction::RollbackTransition { .. } => ("block", true),
        EnforcementAction::PunishAgent { .. } => ("deny", true),
        EnforcementAction::EmergencyHalt { .. } => ("halt", true),
    }
}

fn build_anomaly(
    severity: AnomalySeverity,
    classification: AnomalyClassification,
    attempted: &str,
) -> Anomaly {
    Anomaly {
        anomaly_id: Uuid::nil(),
        detection_timestamp: 0,
        source: AnomalySource::CapabilityBreach {
            token_id: Uuid::nil(),
            attempted_op: attempted.to_string(),
        },
        severity,
        classification,
        evidence: AnomalyEvidence {
            trace_snapshot: None,
            state_before: [0u8; 32],
            state_after: [0u8; 32],
            crdt_conflict: None,
            policy_reports: vec![],
            cryptographic_proof: None,
        },
        affected_paths: vec![],
        recommended_action: EnforcementAction::Observe {
            log_level: LogLevel::Info,
            retain_evidence: true,
        },
        confidence: 1.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict_for(sev: AnomalySeverity, cls: AnomalyClassification) -> (&'static str, bool) {
        let ladder = default_ladder();
        let decision = ladder.determine_action(&build_anomaly(sev, cls, "op"));
        action_verdict(&decision.action)
    }

    #[test]
    fn permissive_levels_do_not_block() {
        assert_eq!(
            verdict_for(
                AnomalySeverity::Observational,
                AnomalyClassification::CapabilityEscape {
                    granted_ops: vec![],
                    attempted: "x".into()
                }
            ),
            ("observe", false)
        );
        assert_eq!(
            verdict_for(
                AnomalySeverity::Warning,
                AnomalyClassification::CapabilityEscape {
                    granted_ops: vec![],
                    attempted: "x".into()
                }
            ),
            ("review", false)
        );
    }

    #[test]
    fn severe_anomalies_block() {
        assert_eq!(
            verdict_for(
                AnomalySeverity::Critical,
                AnomalyClassification::ConcurrencyConflict {
                    nodes: vec![],
                    conflict_type: "merge".into()
                }
            ),
            ("quarantine", true)
        );
        assert_eq!(
            verdict_for(
                AnomalySeverity::Critical,
                AnomalyClassification::EconomicAnomaly {
                    metric: "balance".into(),
                    deviation: 9.0
                }
            ),
            ("block", true)
        );
        assert_eq!(
            verdict_for(
                AnomalySeverity::Catastrophic,
                AnomalyClassification::TemporalInconsistency { clock_skew_ms: 1 }
            ),
            ("halt", true)
        );
    }

    #[test]
    fn parsers_have_sane_defaults() {
        assert_eq!(parse_severity("CRITICAL"), AnomalySeverity::Critical);
        assert_eq!(parse_severity("nonsense"), AnomalySeverity::Warning);
        assert!(matches!(
            parse_classification("economic_anomaly", "balance"),
            AnomalyClassification::EconomicAnomaly { .. }
        ));
        assert!(matches!(
            parse_classification("unknown", "op"),
            AnomalyClassification::CapabilityEscape { .. }
        ));
    }
}

//! Minimal HTTP enforcement bridge.
//!
//! Gives ZÀNGBÉTÒ a network surface so a remote Ọmọ Kọ́dà runtime can submit an
//! anomaly for an agent and receive the enforcement action — without embedding
//! this Rust workspace in-process. Intentionally tiny (tokio only, no web
//! framework): two routes.
//!
//! - `GET  /health`  → `{"status":"ok"}`
//! - `POST /enforce` → body `{agent_id, severity, classification, detail?, confidence?}`
//!   returns `{agent_id, action_kind, rationale, action}` where `action` is the
//!   full serialized [`EnforcementAction`] from the [`ActionLadder`].
//!
//! `severity` ∈ observational | warning | critical | catastrophic.
//! `classification` ∈ schema_drift | economic_anomaly | temporal_inconsistency |
//!   capability_escape | concurrency_conflict (default for unknowns).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

use crate::action_ladder::{ActionLadder, EnforcementAction, EnforcementPolicy, LogLevel};
use crate::anomaly::{
    Anomaly, AnomalyClassification, AnomalyEvidence, AnomalySeverity, AnomalySource,
};

const MAX_REQUEST_BYTES: usize = 64 * 1024;

#[derive(Debug, Deserialize)]
struct EnforceRequest {
    agent_id: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    classification: String,
    #[serde(default)]
    detail: String,
    #[serde(default)]
    confidence: f64,
}

#[derive(Debug, Serialize)]
struct EnforceResponse {
    agent_id: String,
    action_kind: String,
    rationale: String,
    action: serde_json::Value,
}

fn parse_severity(s: &str) -> AnomalySeverity {
    match s {
        "observational" => AnomalySeverity::Observational,
        "critical" => AnomalySeverity::Critical,
        "catastrophic" => AnomalySeverity::Catastrophic,
        _ => AnomalySeverity::Warning,
    }
}

fn parse_classification(kind: &str, detail: &str) -> AnomalyClassification {
    match kind {
        "schema_drift" => AnomalyClassification::SchemaDrift {
            expected_schema: "expected".into(),
            observed_schema: detail.to_string(),
        },
        "economic_anomaly" => AnomalyClassification::EconomicAnomaly {
            metric: detail.to_string(),
            deviation: 1.0,
        },
        "temporal_inconsistency" => {
            AnomalyClassification::TemporalInconsistency { clock_skew_ms: 0 }
        }
        "capability_escape" => AnomalyClassification::CapabilityEscape {
            granted_ops: vec![],
            attempted: detail.to_string(),
        },
        // Default (incl. "concurrency_conflict" and unknowns): drives the
        // Critical → quarantine branch of the ladder.
        _ => AnomalyClassification::ConcurrencyConflict {
            nodes: vec![],
            conflict_type: if detail.is_empty() {
                kind.to_string()
            } else {
                detail.to_string()
            },
        },
    }
}

fn default_policy() -> EnforcementPolicy {
    EnforcementPolicy {
        default_severity_threshold: AnomalySeverity::Warning,
        escalation_rules: vec![],
        orisha_weights: HashMap::new(),
        auto_quarantine_enabled: true,
        rollback_authority_threshold: 0.66,
    }
}

/// Run the severity/classification through the ActionLadder and return the
/// enforcement decision for an agent.
fn decide(req: &EnforceRequest) -> EnforceResponse {
    let anomaly = Anomaly {
        anomaly_id: Uuid::new_v4(),
        detection_timestamp: 0,
        source: AnomalySource::ReplayMismatch {
            trace_id: Uuid::new_v4(),
        },
        severity: parse_severity(&req.severity),
        classification: parse_classification(&req.classification, &req.detail),
        evidence: AnomalyEvidence {
            trace_snapshot: None,
            state_before: [0u8; 32],
            state_after: [0u8; 32],
            crdt_conflict: None,
            policy_reports: vec![],
            cryptographic_proof: None,
        },
        affected_paths: vec![format!("agent:{}", req.agent_id)],
        recommended_action: EnforcementAction::Observe {
            log_level: LogLevel::Debug,
            retain_evidence: true,
        },
        confidence: if req.confidence > 0.0 {
            req.confidence
        } else {
            0.5
        },
    };

    let ladder = ActionLadder::new(default_policy());
    let decision = ladder.determine_action(&anomaly);
    let action = serde_json::to_value(&decision.action).unwrap_or(serde_json::Value::Null);
    let action_kind = action
        .as_object()
        .and_then(|o| o.keys().next().cloned())
        .unwrap_or_else(|| "unknown".to_string());

    EnforceResponse {
        agent_id: req.agent_id.clone(),
        action_kind,
        rationale: decision.rationale,
        action,
    }
}

/// Pure router: maps a parsed request to an HTTP status + JSON body. Kept
/// separate from the socket plumbing so it can be unit-tested directly.
fn route(method: &str, path: &str, body: &[u8]) -> (u16, String) {
    match (method, path) {
        ("GET", "/health") => (
            200,
            r#"{"status":"ok","service":"zangbeto-enforcement"}"#.to_string(),
        ),
        ("POST", "/enforce") => match serde_json::from_slice::<EnforceRequest>(body) {
            Ok(req) if !req.agent_id.trim().is_empty() => {
                let resp = decide(&req);
                (
                    200,
                    serde_json::to_string(&resp).unwrap_or_else(|_| "{}".into()),
                )
            }
            _ => (400, r#"{"error":"invalid enforce request"}"#.to_string()),
        },
        _ => (404, r#"{"error":"not found"}"#.to_string()),
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn content_length(head: &str) -> usize {
    head.lines()
        .find_map(|line| {
            let lower = line.to_ascii_lowercase();
            lower
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
        })
        .unwrap_or(0)
}

async fn write_response(socket: &mut TcpStream, status: u16, body: &str) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        413 => "Payload Too Large",
        _ => "OK",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    socket.write_all(response.as_bytes()).await?;
    socket.flush().await
}

async fn handle_conn(socket: &mut TcpStream) -> std::io::Result<()> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];

    // Read until the end of headers.
    let header_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > MAX_REQUEST_BYTES {
            return write_response(socket, 413, r#"{"error":"too large"}"#).await;
        }
        let n = socket.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
    };

    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut request_line = head.lines().next().unwrap_or("").split_whitespace();
    let method = request_line.next().unwrap_or("").to_string();
    let path = request_line.next().unwrap_or("").to_string();
    let want = header_end + content_length(&head);

    // Read the remaining body.
    while buf.len() < want && buf.len() <= MAX_REQUEST_BYTES {
        let n = socket.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let body = &buf[header_end..want.min(buf.len())];

    let (status, resp_body) = route(&method, &path, body);
    write_response(socket, status, &resp_body).await
}

/// Serve the enforcement bridge on an already-bound listener (used by tests).
pub async fn serve_listener(listener: TcpListener) -> std::io::Result<()> {
    loop {
        let (mut socket, _) = listener.accept().await?;
        tokio::spawn(async move {
            let _ = handle_conn(&mut socket).await;
        });
    }
}

/// Bind `addr` and serve the enforcement bridge forever.
pub async fn serve(addr: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    serve_listener(listener).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enforce(body: &str) -> (u16, serde_json::Value) {
        let (status, resp) = route("POST", "/enforce", body.as_bytes());
        (
            status,
            serde_json::from_str(&resp).unwrap_or(serde_json::Value::Null),
        )
    }

    #[test]
    fn health_ok() {
        let (status, body) = route("GET", "/health", b"");
        assert_eq!(status, 200);
        assert!(body.contains("\"status\":\"ok\""));
    }

    #[test]
    fn catastrophic_halts() {
        let (status, v) =
            enforce(r#"{"agent_id":"agent-1","severity":"catastrophic","classification":"x"}"#);
        assert_eq!(status, 200);
        assert_eq!(v["agent_id"], "agent-1");
        assert_eq!(v["action_kind"], "emergency_halt");
    }

    #[test]
    fn observational_observes_and_warning_flags() {
        let (_, obs) =
            enforce(r#"{"agent_id":"a","severity":"observational","classification":"x"}"#);
        assert_eq!(obs["action_kind"], "observe");
        let (_, warn) = enforce(r#"{"agent_id":"a","severity":"warning","classification":"x"}"#);
        assert_eq!(warn["action_kind"], "flag_for_review");
    }

    #[test]
    fn critical_concurrency_quarantines() {
        let (_, v) = enforce(
            r#"{"agent_id":"a","severity":"critical","classification":"concurrency_conflict"}"#,
        );
        assert_eq!(v["action_kind"], "quarantine_state");
    }

    #[test]
    fn missing_agent_id_is_rejected() {
        let (status, _) = route("POST", "/enforce", br#"{"severity":"warning"}"#);
        assert_eq!(status, 400);
    }

    #[test]
    fn unknown_route_404() {
        let (status, _) = route("GET", "/nope", b"");
        assert_eq!(status, 404);
    }
}

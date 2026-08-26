//! Minimal HTTP enforcement bridge.
//!
//! Gives ZÀNGBÉTÒ a network surface so a remote Ọmọ Kọ́dà runtime can submit an
//! anomaly for an agent and receive the enforcement action — without embedding
//! this Rust workspace in-process. Intentionally tiny (tokio only, no web
//! framework): two routes.
//!
//! - `GET  /health`  → `{"status":"ok"}`
//! - `POST /enforce` → body `{agent_id, severity, classification, detail?, confidence?}`
//!   returns `{agent_id, action_kind, block, rationale, action}` where `action` is
//!   the full serialized [`EnforcementAction`] and `block` is the boolean the
//!   Ọmọ Kọ́dà runtime reads to gate the act.
//! - `POST /review`  → body `{agent_id, tool}` — review a *proposed* act before
//!   it runs (Warning-level capability use); same response shape.
//! - `GET  /guardian/pubkey` → `{"guardian_pubkey": "<hex>"}` — the Ed25519
//!   public key callers need to verify `zangbeto_sig` on any receipt.
//! - `POST /diagnostics` → body is an arbitrary JSON diagnostic payload;
//!   returns `{"receipt_id", "zangbeto_sig"}`, a real Ed25519 signature over
//!   the receipt id and the payload's canonical (sorted-key) JSON bytes.
//! - `POST /receipt` → body `{kind, actor, subject, detail?}` — persists a
//!   signed [`crate::receipts::Receipt`] for any receiptable event (an Ọmọ
//!   Kọ́dà state transition, an ares-control daemon toggle, ...); returns
//!   the full stored receipt including `id`, `timestamp`, and `signature`.
//! - `GET  /receipts?since=<unix_ts>` → `{"receipts": [...]}`, all receipts
//!   with `timestamp` strictly greater than `since` (default `0` = all),
//!   oldest first.
//!
//! `severity` ∈ observational | warning | critical | catastrophic.
//! `classification` ∈ schema_drift | economic_anomaly | temporal_inconsistency |
//!   capability_escape | concurrency_conflict (default for unknowns).

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

use crate::action_ladder::{ActionLadder, EnforcementAction, EnforcementPolicy, LogLevel};
use crate::anomaly::{
    Anomaly, AnomalyClassification, AnomalyEvidence, AnomalySeverity, AnomalySource,
};
use crate::guardian::{default_seed_path, Guardian};
use crate::receipts::{default_db_path, make_receipt, ReceiptStore};

/// Loaded once, lazily, on first use -- every route in this pure-function
/// router shares the same guardian identity for the life of the process.
static GUARDIAN: OnceLock<Guardian> = OnceLock::new();

fn guardian() -> &'static Guardian {
    GUARDIAN.get_or_init(|| {
        Guardian::load_or_create(&default_seed_path())
            .expect("failed to load or create guardian signing identity")
    })
}

/// Same lazy-singleton pattern as [`guardian`]. Path override via
/// `ZANGBETO_RECEIPTS_DB` (tests/alternate deployments); default matches
/// the guardian seed's convention (relative to the daemon's working dir).
static RECEIPT_STORE: OnceLock<ReceiptStore> = OnceLock::new();

fn receipt_store() -> &'static ReceiptStore {
    RECEIPT_STORE.get_or_init(|| {
        let path = std::env::var("ZANGBETO_RECEIPTS_DB")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| default_db_path());
        ReceiptStore::open(&path).expect("failed to open receipt store")
    })
}

/// Canonical bytes for signing: `serde_json::Value`'s object variant is a
/// `BTreeMap` by default (this workspace does not enable the
/// `preserve_order` feature), so re-serializing a parsed `Value` always
/// yields the same byte sequence regardless of the original field order in
/// the caller's JSON -- independent implementations verifying a receipt
/// will derive identical bytes as long as they parse-then-reserialize the
/// same way, rather than hashing the raw request body verbatim.
fn canonical_json(value: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap_or_default()
}

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
    /// Whether the verdict gates the act. Mirrors the keyword in `action_kind`
    /// into the boolean field the Ọmọ Kọ́dà runtime reads (`verdict_blocks()`
    /// honors `{"block": true}`), so `quarantine_state` / `rollback_transition`
    /// / `punish_agent` / `emergency_halt` deny the act and the rest allow it.
    block: bool,
    rationale: String,
    action: serde_json::Value,
    /// Unique id for this verdict, bound into `zangbeto_sig` -- a caller can
    /// verify authenticity via `GET /guardian/pubkey` without trusting the
    /// transport.
    receipt_id: String,
    zangbeto_sig: String,
}

/// `POST /receipt` request body. Generalized beyond the original Ọmọ Kọ́dà
/// state-transition shape -- see [`crate::receipts::Receipt`]'s doc comment
/// for the field semantics and both real use cases (state transition,
/// daemon toggle).
#[derive(Debug, Deserialize)]
struct ReceiptRequest {
    kind: String,
    actor: String,
    subject: String,
    #[serde(default = "default_detail")]
    detail: serde_json::Value,
}

fn default_detail() -> serde_json::Value {
    serde_json::json!({})
}

/// `GET /receipts?since=<ts>` query param. `since` defaults to 0 (all
/// receipts) when absent or unparsable, rather than erroring -- this is a
/// read/query endpoint, not a validated write, so a malformed `since` is
/// treated the same as an absent one.
fn parse_since_query(query: &str) -> u64 {
    query
        .split('&')
        .find_map(|kv| kv.strip_prefix("since="))
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0)
}

/// Does this `action_kind` (the serialized [`EnforcementAction`] variant tag)
/// gate the act?
fn blocks(action_kind: &str) -> bool {
    matches!(
        action_kind,
        "quarantine_state" | "rollback_transition" | "punish_agent" | "emergency_halt"
    )
}

/// Pre-act review request: the runtime asks whether a *proposed* act should run.
#[derive(Debug, Deserialize)]
struct ReviewRequest {
    agent_id: String,
    #[serde(default)]
    tool: String,
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
    let block = blocks(&action_kind);

    let receipt_id = Uuid::new_v4().to_string();
    let signable = serde_json::json!({
        "agent_id": req.agent_id,
        "action_kind": action_kind,
        "block": block,
        "rationale": decision.rationale,
        "action": action,
    });
    let zangbeto_sig = guardian().sign_receipt(&receipt_id, &canonical_json(&signable));

    EnforceResponse {
        agent_id: req.agent_id.clone(),
        block,
        action_kind,
        rationale: decision.rationale,
        action,
        receipt_id,
        zangbeto_sig,
    }
}

/// Pure router: maps a parsed request to an HTTP status + JSON body. Kept
/// separate from the socket plumbing so it can be unit-tested directly.
fn route(method: &str, path: &str, body: &[u8]) -> (u16, String) {
    // Every existing route below is matched on the bare path with no query
    // string, and no existing caller ever sent one -- splitting it off
    // here is a no-op for all of them and only changes behavior for the
    // new /receipts?since=... route, which needs it.
    let (route_path, query) = match path.split_once('?') {
        Some((p, q)) => (p, q),
        None => (path, ""),
    };
    match (method, route_path) {
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
        // Review a *proposed* act before it runs: treated as a Warning-level
        // capability use, so the default ladder flags it for review (non-blocking)
        // unless policy escalates. Same response shape as /enforce.
        ("POST", "/review") => match serde_json::from_slice::<ReviewRequest>(body) {
            Ok(req) if !req.agent_id.trim().is_empty() => {
                let enforce_req = EnforceRequest {
                    agent_id: req.agent_id,
                    severity: "warning".into(),
                    classification: "capability_escape".into(),
                    detail: req.tool,
                    confidence: 0.5,
                };
                let resp = decide(&enforce_req);
                (
                    200,
                    serde_json::to_string(&resp).unwrap_or_else(|_| "{}".into()),
                )
            }
            _ => (400, r#"{"error":"invalid review request"}"#.to_string()),
        },
        ("GET", "/guardian/pubkey") => (
            200,
            serde_json::json!({ "guardian_pubkey": guardian().public_key_hex() }).to_string(),
        ),
        // Sign an arbitrary diagnostic payload (Ọmọ Kọ́dà's diagnostic
        // pipeline posts here). Accepts any JSON object; rejects anything
        // else (an empty body, a bare string/number/array) so a caller can't
        // get a signature over something that doesn't round-trip through
        // `canonical_json` predictably.
        ("POST", "/diagnostics") => match serde_json::from_slice::<serde_json::Value>(body) {
            Ok(payload) if payload.is_object() => {
                let receipt_id = Uuid::new_v4().to_string();
                let zangbeto_sig = guardian().sign_receipt(&receipt_id, &canonical_json(&payload));
                (
                    200,
                    serde_json::json!({
                        "receipt_id": receipt_id,
                        "zangbeto_sig": zangbeto_sig,
                    })
                    .to_string(),
                )
            }
            _ => (400, r#"{"error":"diagnostic payload must be a JSON object"}"#.to_string()),
        },
        // Persist a signed receipt for any receiptable event. Generalized
        // (kind/actor/subject/detail) rather than a fixed state-transition
        // shape -- see ReceiptRequest's doc comment.
        ("POST", "/receipt") => match serde_json::from_slice::<ReceiptRequest>(body) {
            Ok(req)
                if !req.kind.trim().is_empty()
                    && !req.actor.trim().is_empty()
                    && !req.subject.trim().is_empty() =>
            {
                let receipt = make_receipt(guardian(), req.kind, req.actor, req.subject, req.detail);
                match receipt_store().emit(&receipt) {
                    Ok(()) => (
                        200,
                        serde_json::to_string(&receipt).unwrap_or_else(|_| "{}".into()),
                    ),
                    Err(e) => (
                        500,
                        serde_json::json!({ "error": format!("failed to persist receipt: {e}") })
                            .to_string(),
                    ),
                }
            }
            Ok(_) => (
                400,
                r#"{"error":"kind, actor, and subject are all required and must be non-empty"}"#
                    .to_string(),
            ),
            Err(e) => (
                400,
                serde_json::json!({ "error": format!("invalid receipt request: {e}") }).to_string(),
            ),
        },
        // Query persisted receipts. since=<unix_ts> defaults to 0 (all).
        ("GET", "/receipts") => {
            let since = parse_since_query(query);
            match receipt_store().since(since) {
                Ok(receipts) => (
                    200,
                    serde_json::json!({ "receipts": receipts }).to_string(),
                ),
                Err(e) => (
                    500,
                    serde_json::json!({ "error": format!("failed to query receipts: {e}") })
                        .to_string(),
                ),
            }
        }
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

    #[test]
    fn enforce_response_carries_block_flag() {
        // The runtime's verdict_blocks() honors {"block": true}; a quarantine /
        // halt must set it, a permissive verdict must not.
        let (_, q) = enforce(
            r#"{"agent_id":"a","severity":"critical","classification":"concurrency_conflict"}"#,
        );
        assert_eq!(q["action_kind"], "quarantine_state");
        assert_eq!(q["block"], true);

        let (_, halt) =
            enforce(r#"{"agent_id":"a","severity":"catastrophic","classification":"x"}"#);
        assert_eq!(halt["block"], true);

        let (_, obs) =
            enforce(r#"{"agent_id":"a","severity":"observational","classification":"x"}"#);
        assert_eq!(obs["block"], false);
    }

    #[test]
    fn review_of_normal_act_is_non_blocking() {
        // A proposed act reviewed at Warning level → flag_for_review → allowed.
        let (status, resp) = route(
            "POST",
            "/review",
            br#"{"agent_id":"a","tool":"web_search"}"#,
        );
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(status, 200);
        assert_eq!(v["action_kind"], "flag_for_review");
        assert_eq!(v["block"], false);
    }

    #[test]
    fn review_missing_agent_id_is_rejected() {
        let (status, _) = route("POST", "/review", br#"{"tool":"x"}"#);
        assert_eq!(status, 400);
    }

    #[test]
    fn enforce_receipt_is_really_signed() {
        let (_, v) = enforce(r#"{"agent_id":"agent-1","severity":"warning","classification":"x"}"#);
        let receipt_id = v["receipt_id"].as_str().unwrap();
        let sig = v["zangbeto_sig"].as_str().unwrap();
        assert!(!receipt_id.is_empty());
        assert!(!sig.is_empty());

        let (status, pk_body) = route("GET", "/guardian/pubkey", b"");
        assert_eq!(status, 200);
        let pk: serde_json::Value = serde_json::from_str(&pk_body).unwrap();
        let pubkey_hex = pk["guardian_pubkey"].as_str().unwrap();

        // Re-derive exactly what /enforce signed and confirm it verifies --
        // proves this isn't a stub that returns Ok(true) unconditionally.
        let signable = serde_json::json!({
            "agent_id": v["agent_id"],
            "action_kind": v["action_kind"],
            "block": v["block"],
            "rationale": v["rationale"],
            "action": v["action"],
        });
        assert!(crate::guardian::verify_receipt(
            pubkey_hex,
            receipt_id,
            &canonical_json(&signable),
            sig,
        ));

        // A different receipt_id (as if replayed against another receipt)
        // must NOT verify.
        assert!(!crate::guardian::verify_receipt(
            pubkey_hex,
            "not-the-real-receipt-id",
            &canonical_json(&signable),
            sig,
        ));
    }

    #[test]
    fn diagnostics_endpoint_signs_arbitrary_payload() {
        let (status, resp) = route(
            "POST",
            "/diagnostics",
            br#"{"code":"D001","severity":2,"agent_id":"agent-1"}"#,
        );
        assert_eq!(status, 200);
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
        let receipt_id = v["receipt_id"].as_str().unwrap();
        let sig = v["zangbeto_sig"].as_str().unwrap();

        let (_, pk_body) = route("GET", "/guardian/pubkey", b"");
        let pk: serde_json::Value = serde_json::from_str(&pk_body).unwrap();
        let pubkey_hex = pk["guardian_pubkey"].as_str().unwrap();

        let payload: serde_json::Value =
            serde_json::from_str(r#"{"code":"D001","severity":2,"agent_id":"agent-1"}"#).unwrap();
        assert!(crate::guardian::verify_receipt(
            pubkey_hex,
            receipt_id,
            &canonical_json(&payload),
            sig,
        ));
    }

    #[test]
    fn diagnostics_rejects_non_object_payload() {
        let (status, _) = route("POST", "/diagnostics", b"\"just a string\"");
        assert_eq!(status, 400);
    }

    // ── /receipt + /receipts ────────────────────────────────────────────
    //
    // receipt_store() is a process-wide OnceLock singleton (same pattern as
    // guardian()), shared across every test in this binary running in
    // parallel -- these tests tag their own receipts with a unique kind
    // per test and search for that tag in the response, rather than
    // asserting exact counts, so they're correct regardless of what other
    // tests emit concurrently. The store's own isolated logic (real
    // persistence across reopens, real signature verification) is tested
    // directly against an in-memory store in receipts.rs; these test the
    // HTTP contract on top of it.

    #[test]
    fn receipt_requires_kind_actor_subject() {
        let (status, _) = route("POST", "/receipt", br#"{"kind":"","actor":"a","subject":"b"}"#);
        assert_eq!(status, 400);

        let (status, _) = route("POST", "/receipt", br#"{"actor":"a","subject":"b"}"#);
        assert_eq!(status, 400, "kind is a required field, not just non-empty-if-present");
    }

    #[test]
    fn receipt_post_returns_a_real_signed_receipt() {
        let tag = format!("test-state-transition-{}", Uuid::new_v4());
        let (status, resp) = route(
            "POST",
            "/receipt",
            format!(
                r#"{{"kind":"{tag}","actor":"agent-abc","subject":"agent-abc","detail":{{"pre_hash":"aaa","post_hash":"bbb","ops_count":3}}}}"#
            )
            .as_bytes(),
        );
        assert_eq!(status, 200);
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["kind"], tag);
        assert_eq!(v["actor"], "agent-abc");
        assert_eq!(v["subject"], "agent-abc");
        assert_eq!(v["detail"]["ops_count"], 3);
        let id = v["id"].as_str().unwrap();
        let sig = v["signature"].as_str().unwrap();
        assert!(!id.is_empty());
        assert!(!sig.is_empty());

        // The signature must actually verify -- not just be present.
        let (_, pk_body) = route("GET", "/guardian/pubkey", b"");
        let pk: serde_json::Value = serde_json::from_str(&pk_body).unwrap();
        let pubkey_hex = pk["guardian_pubkey"].as_str().unwrap();
        let payload = crate::receipts::signable_payload(
            v["timestamp"].as_u64().unwrap(),
            v["kind"].as_str().unwrap(),
            v["actor"].as_str().unwrap(),
            v["subject"].as_str().unwrap(),
            &v["detail"],
        );
        assert!(crate::guardian::verify_receipt(pubkey_hex, id, &payload, sig));
    }

    #[test]
    fn receipt_covers_the_daemon_toggle_shape_not_just_state_transitions() {
        // The generalization this was actually built for: ares-control's
        // "toggled a daemon" event, structurally nothing like an Ọmọ Kọ́dà
        // state transition, through the exact same endpoint.
        let tag = format!("daemon_toggle-{}", Uuid::new_v4());
        let (status, resp) = route(
            "POST",
            "/receipt",
            format!(
                r#"{{"kind":"{tag}","actor":"claude-orchestration-batch","subject":"ares-jupiter-signer.service","detail":{{"action":"start","result":"ok"}}}}"#
            )
            .as_bytes(),
        );
        assert_eq!(status, 200);
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["subject"], "ares-jupiter-signer.service");
        assert_eq!(v["detail"]["action"], "start");
        assert_eq!(v["detail"]["result"], "ok");
    }

    #[test]
    fn receipt_detail_defaults_to_empty_object_when_absent() {
        let tag = format!("no-detail-{}", Uuid::new_v4());
        let (status, resp) = route(
            "POST",
            "/receipt",
            format!(r#"{{"kind":"{tag}","actor":"a","subject":"b"}}"#).as_bytes(),
        );
        assert_eq!(status, 200);
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["detail"], serde_json::json!({}));
    }

    #[test]
    fn receipts_get_finds_what_was_just_posted() {
        let tag = format!("findme-{}", Uuid::new_v4());
        let (post_status, post_resp) = route(
            "POST",
            "/receipt",
            format!(r#"{{"kind":"{tag}","actor":"a","subject":"b"}}"#).as_bytes(),
        );
        assert_eq!(post_status, 200);
        let posted: serde_json::Value = serde_json::from_str(&post_resp).unwrap();
        let posted_id = posted["id"].as_str().unwrap();

        let (status, resp) = route("GET", "/receipts?since=0", b"");
        assert_eq!(status, 200);
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
        let receipts = v["receipts"].as_array().unwrap();
        assert!(
            receipts.iter().any(|r| r["id"] == posted_id),
            "the receipt just posted must appear in /receipts?since=0"
        );
    }

    #[test]
    fn receipts_get_since_excludes_older_receipts() {
        let tag = format!("future-{}", Uuid::new_v4());
        let (_, post_resp) = route(
            "POST",
            "/receipt",
            format!(r#"{{"kind":"{tag}","actor":"a","subject":"b"}}"#).as_bytes(),
        );
        let posted: serde_json::Value = serde_json::from_str(&post_resp).unwrap();
        let posted_id = posted["id"].as_str().unwrap();
        let posted_ts = posted["timestamp"].as_u64().unwrap();

        // since = the receipt's own timestamp (strictly greater than,
        // per the documented contract) must exclude it.
        let (status, resp) = route(
            "GET",
            &format!("/receipts?since={}", posted_ts),
            b"",
        );
        assert_eq!(status, 200);
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
        let receipts = v["receipts"].as_array().unwrap();
        assert!(
            !receipts.iter().any(|r| r["id"] == posted_id),
            "since=<receipt's own timestamp> must exclude that receipt (strictly greater than)"
        );
    }

    #[test]
    fn receipts_get_since_malformed_defaults_to_zero_not_an_error() {
        let (status, _) = route("GET", "/receipts?since=not-a-number", b"");
        assert_eq!(status, 200);
        let (status, _) = route("GET", "/receipts", b"");
        assert_eq!(status, 200);
    }
}

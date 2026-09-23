//! Signed, persisted enforcement receipts.
//!
//! Was a dead-code stub: `TransitionReceipt` + an in-memory `Vec`-backed
//! `ReceiptStore`, `.emit()` never called anywhere in the real codebase, no
//! signing, no persistence (a process restart silently discarded every
//! receipt). This is the real thing: SQLite-backed (survives restart,
//! matching the rest of the ecosystem's SQLite-everywhere pattern), signed
//! with the same Guardian Ed25519 identity `/enforce` and `/diagnostics`
//! already use (`crate::guardian` -- no second signing scheme invented).
//!
//! Generalized beyond the original Ọmọ Kọ́dà state-transition shape
//! (`agent_id` / `pre_hash` / `post_hash` / `ops_count`) to cover any
//! receiptable event -- e.g. ares-control's "toggled a daemon"
//! (`unit_name` / `action` / `result` / `requested_by`). `kind` is the
//! caller-chosen event type; `actor` and `subject` are the two identity
//! fields every receiptable event has in common (who did it / what it was
//! done to), and `detail` is free-form JSON for whatever else is specific
//! to that `kind`.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// An immutable, signed record of one receiptable event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub id: String,
    /// Unix epoch seconds.
    pub timestamp: u64,
    /// Caller-chosen event type, e.g. "state_transition", "daemon_toggle".
    pub kind: String,
    /// Who/what performed the action (an agent_id, a "requested_by", ...).
    pub actor: String,
    /// What the action was performed on (an agent_id target, a unit_name, ...).
    pub subject: String,
    /// Event-specific payload. For a state transition:
    /// `{"pre_hash": "...", "post_hash": "...", "ops_count": N}`. For a
    /// daemon toggle: `{"action": "start", "result": "ok"}`. Whatever the
    /// `kind` needs -- this store doesn't interpret it.
    pub detail: serde_json::Value,
    /// Hex Ed25519 signature from the guardian, over `sha256(id ||
    /// canonical_json({timestamp, kind, actor, subject, detail}))` -- see
    /// [`crate::guardian::Guardian::sign_receipt`]. Binds every field; a
    /// caller can verify with [`crate::guardian::verify_receipt`] using
    /// only the guardian's public key (`GET /guardian/pubkey`).
    pub signature: String,
}

/// SQLite-backed store for [`Receipt`]s. A `Mutex<Connection>` rather than
/// a connection pool: this is a low-throughput audit trail (one write per
/// enforcement/toggle event, not a hot path), and SQLite only supports one
/// writer at a time regardless -- a pool would add complexity without
/// adding real concurrency.
pub struct ReceiptStore {
    conn: Mutex<Connection>,
}

impl ReceiptStore {
    /// Open (creating if missing) a receipt store at `db_path`, creating
    /// the parent directory and the `receipts` table if needed. Idempotent
    /// -- safe to call on every process start.
    pub fn open(db_path: &Path) -> rusqlite::Result<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CANTOPEN),
                    Some(format!("failed to create {:?}: {e}", parent)),
                )
            })?;
        }
        let conn = Connection::open(db_path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS receipts (
                id        TEXT PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                kind      TEXT NOT NULL,
                actor     TEXT NOT NULL,
                subject   TEXT NOT NULL,
                detail    TEXT NOT NULL,
                signature TEXT NOT NULL
            )",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_receipts_timestamp ON receipts(timestamp)",
            [],
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Open an in-memory store -- tests only, never persists.
    #[cfg(test)]
    pub fn open_in_memory() -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS receipts (
                id        TEXT PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                kind      TEXT NOT NULL,
                actor     TEXT NOT NULL,
                subject   TEXT NOT NULL,
                detail    TEXT NOT NULL,
                signature TEXT NOT NULL
            )",
            [],
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Persist a receipt. `id` must be unique (it's the primary key) --
    /// callers generate it with `Uuid::new_v4()`, so a collision would
    /// indicate a real bug upstream, not a normal condition to retry past.
    pub fn emit(&self, receipt: &Receipt) -> rusqlite::Result<()> {
        let conn = self.conn.lock().expect("receipt store mutex poisoned");
        conn.execute(
            "INSERT INTO receipts (id, timestamp, kind, actor, subject, detail, signature)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                receipt.id,
                receipt.timestamp as i64,
                receipt.kind,
                receipt.actor,
                receipt.subject,
                receipt.detail.to_string(),
                receipt.signature,
            ],
        )?;
        Ok(())
    }

    /// Return all receipts whose `timestamp` is strictly greater than
    /// `after_timestamp`, oldest first.
    pub fn since(&self, after_timestamp: u64) -> rusqlite::Result<Vec<Receipt>> {
        let conn = self.conn.lock().expect("receipt store mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, kind, actor, subject, detail, signature
             FROM receipts WHERE timestamp > ?1 ORDER BY timestamp ASC",
        )?;
        let rows = stmt.query_map(params![after_timestamp as i64], |row| {
            let detail_str: String = row.get(5)?;
            let detail = serde_json::from_str(&detail_str).unwrap_or(serde_json::Value::Null);
            Ok(Receipt {
                id: row.get(0)?,
                timestamp: row.get::<_, i64>(1)? as u64,
                kind: row.get(2)?,
                actor: row.get(3)?,
                subject: row.get(4)?,
                detail,
                signature: row.get(6)?,
            })
        })?;
        rows.collect()
    }

    /// Return all receipts of a specific `kind` whose `timestamp` is strictly
    /// greater than `after_timestamp`, oldest first. Added for the canary-trip
    /// surface: `/canary-trips` must return only intrusion events, not every
    /// receipt kind, so the kernel pulls incidents without the rest of the
    /// audit trail.
    pub fn since_kind(
        &self,
        after_timestamp: u64,
        kind: &str,
    ) -> rusqlite::Result<Vec<Receipt>> {
        let conn = self.conn.lock().expect("receipt store mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, kind, actor, subject, detail, signature
             FROM receipts WHERE kind = ?1 AND timestamp > ?2 ORDER BY timestamp ASC",
        )?;
        let rows = stmt.query_map(params![kind, after_timestamp as i64], |row| {
            let detail_str: String = row.get(5)?;
            let detail = serde_json::from_str(&detail_str).unwrap_or(serde_json::Value::Null);
            Ok(Receipt {
                id: row.get(0)?,
                timestamp: row.get::<_, i64>(1)? as u64,
                kind: row.get(2)?,
                actor: row.get(3)?,
                subject: row.get(4)?,
                detail,
                signature: row.get(6)?,
            })
        })?;
        rows.collect()
    }
}

/// Default on-disk location for the receipt store, relative to the
/// daemon's working directory -- same convention as
/// [`crate::guardian::default_seed_path`] (`.guardian/seed`).
pub fn default_db_path() -> std::path::PathBuf {
    std::path::PathBuf::from(".receipts").join("receipts.db")
}

/// Builds an unsigned receipt's canonical signable bytes: everything
/// except `id` and `signature` themselves, so the signature can't be
/// replayed onto a different id/content. Shared by the HTTP handler (which
/// signs before persisting) and tests (which need to re-derive the same
/// bytes to verify).
pub fn signable_payload(timestamp: u64, kind: &str, actor: &str, subject: &str, detail: &serde_json::Value) -> Vec<u8> {
    let value = serde_json::json!({
        "timestamp": timestamp,
        "kind": kind,
        "actor": actor,
        "subject": subject,
        "detail": detail,
    });
    serde_json::to_vec(&value).unwrap_or_default()
}

/// Build and sign a new receipt (does not persist it -- callers call
/// `ReceiptStore::emit` separately, so a test can construct+sign without
/// needing a store, and the HTTP handler can persist the same value it
/// returns).
pub fn make_receipt(
    guardian: &crate::guardian::Guardian,
    kind: String,
    actor: String,
    subject: String,
    detail: serde_json::Value,
) -> Receipt {
    let id = Uuid::new_v4().to_string();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let payload = signable_payload(timestamp, &kind, &actor, &subject, &detail);
    let signature = guardian.sign_receipt(&id, &payload);
    Receipt {
        id,
        timestamp,
        kind,
        actor,
        subject,
        detail,
        signature,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guardian::{verify_receipt, Guardian};

    fn test_guardian() -> Guardian {
        let dir = std::env::temp_dir().join(format!(
            "zangbeto-receipts-guardian-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        Guardian::load_or_create(&dir.join("seed")).unwrap()
    }

    fn make_test_receipt(guardian: &Guardian, ts_override: Option<u64>) -> Receipt {
        let mut r = make_receipt(
            guardian,
            "state_transition".into(),
            "agent-1".into(),
            "agent-1".into(),
            serde_json::json!({"pre_hash": "aaa", "post_hash": "bbb", "ops_count": 1}),
        );
        if let Some(ts) = ts_override {
            // Re-sign under the overridden timestamp so tests can control
            // ordering without a real sleep -- must stay consistent with
            // what emit() actually persists.
            let payload = signable_payload(ts, &r.kind, &r.actor, &r.subject, &r.detail);
            r.timestamp = ts;
            r.signature = guardian.sign_receipt(&r.id, &payload);
        }
        r
    }

    #[test]
    fn emit_and_since_real_sqlite() {
        let store = ReceiptStore::open_in_memory().unwrap();
        let guardian = test_guardian();

        store.emit(&make_test_receipt(&guardian, Some(100))).unwrap();
        store.emit(&make_test_receipt(&guardian, Some(200))).unwrap();
        store.emit(&make_test_receipt(&guardian, Some(300))).unwrap();

        let recent = store.since(150).unwrap();
        assert_eq!(recent.len(), 2);
        assert!(recent.iter().all(|r| r.timestamp > 150));
        // Oldest first.
        assert_eq!(recent[0].timestamp, 200);
        assert_eq!(recent[1].timestamp, 300);
    }

    #[test]
    fn since_kind_returns_only_that_kind() {
        let store = ReceiptStore::open_in_memory().unwrap();
        let guardian = test_guardian();

        // Two canary_trip receipts interleaved with an unrelated kind.
        store
            .emit(&make_receipt(
                &guardian,
                "canary_trip".into(),
                "aaa".into(),
                "aws_keys".into(),
                serde_json::json!({"src_ip": "1.2.3.4"}),
            ))
            .unwrap();
        store
            .emit(&make_receipt(
                &guardian,
                "state_transition".into(),
                "x".into(),
                "y".into(),
                serde_json::json!({}),
            ))
            .unwrap();
        store
            .emit(&make_receipt(
                &guardian,
                "canary_trip".into(),
                "bbb".into(),
                "ms_word".into(),
                serde_json::json!({"src_ip": "5.6.7.8"}),
            ))
            .unwrap();

        let trips = store.since_kind(0, "canary_trip").unwrap();
        assert_eq!(trips.len(), 2);
        assert!(trips.iter().all(|r| r.kind == "canary_trip"));
        // The unrelated receipt is excluded, not returned.
        assert!(trips.iter().all(|r| r.kind != "state_transition"));
    }

    #[test]
    fn since_kind_respects_the_since_bound() {
        let store = ReceiptStore::open_in_memory().unwrap();
        let guardian = test_guardian();

        store
            .emit(&make_test_receipt(&guardian, Some(100)))
            .unwrap();
        // A canary_trip at ts 200.
        let mut trip = make_receipt(
            &guardian,
            "canary_trip".into(),
            "a".into(),
            "aws_keys".into(),
            serde_json::json!({}),
        );
        let payload = signable_payload(200, &trip.kind, &trip.actor, &trip.subject, &trip.detail);
        trip.timestamp = 200;
        trip.signature = guardian.sign_receipt(&trip.id, &payload);
        store.emit(&trip).unwrap();

        // since=150 includes the trip; since=200 excludes it (strictly greater).
        assert_eq!(store.since_kind(150, "canary_trip").unwrap().len(), 1);
        assert_eq!(store.since_kind(200, "canary_trip").unwrap().len(), 0);
    }

    #[test]
    fn receipt_signature_is_real_and_verifiable() {
        let guardian = test_guardian();
        let receipt = make_test_receipt(&guardian, Some(42));

        let payload = signable_payload(
            receipt.timestamp,
            &receipt.kind,
            &receipt.actor,
            &receipt.subject,
            &receipt.detail,
        );
        assert!(verify_receipt(
            &guardian.public_key_hex(),
            &receipt.id,
            &payload,
            &receipt.signature,
        ));

        // Tampering with any field must break verification.
        let tampered = signable_payload(
            receipt.timestamp,
            &receipt.kind,
            &receipt.actor,
            "someone-else",
            &receipt.detail,
        );
        assert!(!verify_receipt(
            &guardian.public_key_hex(),
            &receipt.id,
            &tampered,
            &receipt.signature,
        ));
    }

    #[test]
    fn generalized_schema_covers_daemon_toggle_shape() {
        // The ares-control use case: unit_name/action/result/requested_by,
        // not an Ọmọ Kọ́dà state transition at all -- same store, same
        // signing path, different `kind` + `detail` shape.
        let store = ReceiptStore::open_in_memory().unwrap();
        let guardian = test_guardian();

        let receipt = make_receipt(
            &guardian,
            "daemon_toggle".into(),
            "claude-orchestration-batch".into(), // requested_by
            "ares-jupiter-signer.service".into(), // unit_name
            serde_json::json!({"action": "start", "result": "ok"}),
        );
        store.emit(&receipt).unwrap();

        let all = store.since(0).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].kind, "daemon_toggle");
        assert_eq!(all[0].subject, "ares-jupiter-signer.service");
        assert_eq!(all[0].detail["action"], "start");
    }

    #[test]
    fn persistence_survives_reopening_the_same_file() {
        let dir = std::env::temp_dir().join(format!(
            "zangbeto-receipts-persist-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        let db_path = dir.join("receipts.db");
        let guardian = test_guardian();

        {
            let store = ReceiptStore::open(&db_path).unwrap();
            store.emit(&make_test_receipt(&guardian, Some(1))).unwrap();
        } // store (and its Connection) dropped here

        {
            let store = ReceiptStore::open(&db_path).unwrap();
            let all = store.since(0).unwrap();
            assert_eq!(all.len(), 1, "receipt did not survive reopening the store");
        }

        std::fs::remove_dir_all(&dir).ok();
    }
}

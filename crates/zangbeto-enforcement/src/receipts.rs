// Enforcement receipts for Zàngbétò Enforcement
use uuid::Uuid;

/// An immutable record of a single state-transition enforcement action.
#[derive(Debug, Clone)]
pub struct TransitionReceipt {
    pub id: Uuid,
    pub agent_id: String,
    /// SHA-256 hex of state before the transition.
    pub pre_hash: String,
    /// SHA-256 hex of state after the transition.
    pub post_hash: String,
    /// Number of discrete operations applied.
    pub ops_count: usize,
    /// Unix epoch seconds.
    pub timestamp: u64,
}

/// In-memory store for `TransitionReceipt`s.
#[derive(Debug, Default)]
pub struct ReceiptStore {
    inner: Vec<TransitionReceipt>,
}

impl ReceiptStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a receipt to the store.
    pub fn emit(&mut self, receipt: TransitionReceipt) {
        self.inner.push(receipt);
    }

    /// Return all receipts whose `timestamp` is strictly greater than
    /// `after_timestamp`.
    pub fn since(&self, after_timestamp: u64) -> Vec<&TransitionReceipt> {
        self.inner
            .iter()
            .filter(|r| r.timestamp > after_timestamp)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_receipt(ts: u64) -> TransitionReceipt {
        TransitionReceipt {
            id: Uuid::new_v4(),
            agent_id: "agent-1".into(),
            pre_hash: "aaa".into(),
            post_hash: "bbb".into(),
            ops_count: 1,
            timestamp: ts,
        }
    }

    #[test]
    fn emit_and_since() {
        let mut store = ReceiptStore::new();
        store.emit(make_receipt(100));
        store.emit(make_receipt(200));
        store.emit(make_receipt(300));

        let recent = store.since(150);
        assert_eq!(recent.len(), 2);
        assert!(recent.iter().all(|r| r.timestamp > 150));
    }
}

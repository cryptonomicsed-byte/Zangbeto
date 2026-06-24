// Rollback logic for Zàngbétò Enforcement
use std::time::{SystemTime, UNIX_EPOCH};

/// A saved checkpoint that the system can roll back to.
#[derive(Debug, Clone)]
pub struct RollbackPoint {
    pub id: String,
    pub state_hash: String,
    /// Unix epoch seconds at checkpoint creation.
    pub timestamp: u64,
    pub reason: String,
}

/// Manages an ordered list of rollback checkpoints.
#[derive(Debug, Default)]
pub struct RollbackManager {
    checkpoints: Vec<RollbackPoint>,
}

impl RollbackManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Persist a new checkpoint and return its generated id.
    pub fn create_point(&mut self, state_hash: &str, reason: &str) -> String {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let id = format!("rbp-{}-{}", timestamp, self.checkpoints.len());
        self.checkpoints.push(RollbackPoint {
            id: id.clone(),
            state_hash: state_hash.to_string(),
            timestamp,
            reason: reason.to_string(),
        });
        id
    }

    /// Return a reference to the most-recently created checkpoint, if any.
    pub fn latest(&self) -> Option<&RollbackPoint> {
        self.checkpoints.last()
    }

    /// Look up a checkpoint by its id.
    pub fn find(&self, id: &str) -> Option<&RollbackPoint> {
        self.checkpoints.iter().find(|p| p.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_retrieve() {
        let mut mgr = RollbackManager::new();
        let id = mgr.create_point("deadbeef", "pre-upgrade");
        assert!(mgr.latest().is_some());
        assert_eq!(mgr.latest().unwrap().state_hash, "deadbeef");
        assert!(mgr.find(&id).is_some());
        assert!(mgr.find("nonexistent").is_none());
    }

    #[test]
    fn latest_returns_most_recent() {
        let mut mgr = RollbackManager::new();
        mgr.create_point("hash1", "first");
        mgr.create_point("hash2", "second");
        assert_eq!(mgr.latest().unwrap().state_hash, "hash2");
    }
}

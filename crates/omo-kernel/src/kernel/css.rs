use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use uuid::Uuid;
use std::collections::HashMap;

use crate::kernel::orisha::OrishaMask;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub wallet: String,
    pub tier: u8,
    pub orisha_alignment: OrishaMask,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Memory {
    pub public_hive: HashMap<String, serde_json::Value>,
    pub private_seal_ref: Option<String>, // walrus:// or ipfs://
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: Uuid,
    pub intent: String,
    pub status: TaskStatus,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaskStatus {
    Pending,
    Validating,
    Executing,
    Completed,
    Rejected(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Economy {
    pub balance: i64,
    pub reputation: f64, // 0.0 - 1.0
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Constraints {
    pub privacy_mode: bool,
    pub sabbath: bool,
    pub max_diff_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalSystemState {
    pub agent_id: String,
    pub identity: Identity,
    pub memory: Memory,
    pub tasks: Vec<Task>,
    pub diagnostics: Vec<String>,
    pub economy: Economy,
    pub constraints: Constraints,
    pub state_hash: String, // sha256 hex
    pub version: u64,
    #[serde(skip)]
    pub _cache: Option<serde_json::Value>, // for fast access
}

impl CanonicalSystemState {
    pub fn compute_hash(&self) -> String {
        let mut state_clone = self.clone();
        state_clone.state_hash = String::new(); // exclude hash from hash
        let serialized = serde_cbor::to_vec(&state_clone)
            .expect("CBOR serialization of CanonicalSystemState must not fail");
        let mut hasher = Sha256::new();
        hasher.update(serialized);
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    pub fn validate_hash(&self) -> bool {
        self.state_hash == self.compute_hash()
    }

    pub fn apply_diff(&mut self, diff: &crate::kernel::diff::StateDiff) -> Result<(), StateError> {
        diff.apply_to(self)
    }
}

impl Default for CanonicalSystemState {
    fn default() -> Self {
        Self {
            agent_id: "omo-0".into(),
            identity: Identity {
                wallet: "0x0".into(),
                tier: 0,
                orisha_alignment: OrishaMask::Eshu,
            },
            memory: Memory {
                public_hive: HashMap::new(),
                private_seal_ref: None,
            },
            tasks: vec![],
            diagnostics: vec![],
            economy: Economy::default(),
            constraints: Constraints::default(),
            state_hash: String::new(),
            version: 0,
            _cache: None,
        }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum StateError {
    #[error("Hash mismatch")]
    HashMismatch,
    #[error("Invalid diff: {0}")]
    InvalidDiff(String),
    #[error("Constraint violation: {0}")]
    ConstraintViolation(String),
    #[error("Validator rejection: {0}")]
    ValidatorRejection(String),
}

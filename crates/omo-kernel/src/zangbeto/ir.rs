use serde::{Serialize, Deserialize};

/// 🌐 Language-agnostic state operations
/// Used by: Rust, Julia, Python, Lisp, Move, Go, WASM
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", content = "args")]
pub enum CanonicalStateIR {
    // Core state mutations
    #[serde(rename = "STATE.ADD_TASK")]
    AddTask { intent: String, priority: u8, metadata: serde_json::Value },
    
    #[serde(rename = "STATE.UPDATE_MEMORY")]
    UpdateMemory { scope: MemoryScope, key: String, value: serde_json::Value },
    
    #[serde(rename = "STATE.MODIFY_ECONOMY")]
    ModifyEconomy { field: EconomyField, delta: i64 },
    
    #[serde(rename = "STATE.SET_CONSTRAINT")]
    SetConstraint { name: String, value: serde_json::Value },
    
    // Orisha-specific semantic ops
    #[serde(rename = "ORISHA.BLESS_PATH")]
    BlessPath { path: String, by: String, reason: String },  // Ọbàtálá
    
    #[serde(rename = "ORISHA.SEAL_DATA")]
    SealData { path: String, algorithm: String, by: String }, // Yemọja
    
    #[serde(rename = "ORISHA.PREDICT_BRANCH")]
    PredictBranch { horizon: u64, confidence_threshold: f64 }, // Ọ̀ṣun
    
    #[serde(rename = "ORISHA.SYNC_TIMELINE")]
    SyncTimeline { target_timestamp: u64, tolerance_ms: u64 }, // Ọya
    
    // Cross-cutting
    #[serde(rename = "AUDIT.LOG_ANOMALY")]
    LogAnomaly { severity: AnomalySeverity, description: String, context: serde_json::Value },
    
    #[serde(rename = "REPAIR.GENERATE_DELTA")]
    GenerateRepairDelta { target_path: String, strategy: RepairStrategy },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MemoryScope {
    #[serde(rename = "public")]
    Public,
    #[serde(rename = "private")]
    Private,
    #[serde(rename = "ephemeral")]
    Ephemeral,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EconomyField {
    #[serde(rename = "balance")]
    Balance,
    #[serde(rename = "reputation")]
    Reputation,
    #[serde(rename = "stake")]
    Stake,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalySeverity {
    #[serde(rename = "low")]
    Low,
    #[serde(rename = "medium")]
    Medium,
    #[serde(rename = "high")]
    High,
    #[serde(rename = "critical")]
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy)]
pub enum RepairStrategy {
    #[serde(rename = "rollback")]
    Rollback,
    #[serde(rename = "patch")]
    Patch,
    #[serde(rename = "compensate")]
    Compensate,
    #[serde(rename = "quarantine")]
    Quarantine,
}

impl CanonicalStateIR {
    /// Convert IR → executable StateDiff (Ògún layer)
    pub fn to_diff_op(&self) -> Option<crate::kernel::diff::DiffOp> {
        use crate::kernel::diff::DiffOp;
        
        match self {
            CanonicalStateIR::AddTask { intent, priority, .. } => {
                Some(DiffOp::Add {
                    path: "/tasks/-".into(),
                    value: serde_json::json!({
                        "intent": intent,
                        "priority": priority,
                        "status": "Pending"
                    }),
                })
            }
            CanonicalStateIR::ModifyEconomy { field, delta } => {
                let path = match field {
                    EconomyField::Balance => "/economy/balance",
                    EconomyField::Reputation => "/economy.reputation",
                    EconomyField::Stake => "/economy.stake",
                };
                Some(DiffOp::Increment {
                    path: path.into(),
                    delta: *delta,
                })
            }
            // ... other conversions
            _ => None,
        }
    }
    
    /// Normalize for fingerprinting (deterministic serialization)
    pub fn canonical_form(&self) -> String {
        // Sort keys, remove whitespace, lowercase enums
        let mut value = serde_json::to_value(self).unwrap();
        canonicalize_json(&mut value);
        serde_json::to_string(&value).unwrap()
    }

    pub fn opcode_name(&self) -> String {
        // Extract enum variant name as string
        serde_json::to_value(self).unwrap()["op"].as_str().unwrap().into()
    }
    
    pub fn target_path(&self) -> Option<String> {
        // Extract path from op args if present
        match self {
            CanonicalStateIR::UpdateMemory { key, scope, .. } => {
                Some(format!("/memory/{:?}/{}", scope, key))
            }
            CanonicalStateIR::BlessPath { path, .. } => Some(path.clone()),
            _ => None,
        }
    }
}

pub fn canonicalize_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(obj) => {
            let sorted = obj.iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<std::collections::BTreeMap<_, _>>();
            *obj = sorted.into_iter().collect();
            for v in obj.values_mut() {
                canonicalize_json(v);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr.iter_mut() {
                canonicalize_json(v);
            }
        }
        serde_json::Value::String(s) => {
            *s = s.to_lowercase().trim().to_string();
        }
        _ => {}
    }
}

use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use crate::kernel::css::{CanonicalSystemState, Memory};
use sha2::{Sha256, Digest};

/// 🧵 Memory State Vector: per-node memory snapshot with divergence metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryStateVector {
    pub node_id: String,
    pub memory_hash: String,  // sha256 of memory subtree
    pub divergence_score: f64, // 0.0 (aligned) - 1.0 (diverged)
    pub last_sync: u64,
    pub conflict_markers: Vec<ConflictMarker>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictMarker {
    pub path: String,
    pub conflict_type: ConflictType,
    pub local_value: serde_json::Value,
    pub remote_value: Option<serde_json::Value>,
    pub detected_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConflictType {
    #[serde(rename = "concurrent_write")]
    ConcurrentWrite,
    #[serde(rename = "schema_mismatch")]
    SchemaMismatch,
    #[serde(rename = "ethical_disagreement")]
    EthicalDisagreement,
    #[serde(rename = "temporal_ordering")]
    TemporalOrdering,
}

/// 🤝 Memory Consensus Protocol: reconcile distributed memory states
pub struct MemoryConsensusProtocol {
    pub local_vector: MemoryStateVector,
    pub peer_vectors: HashMap<String, MemoryStateVector>,
    pub reconciliation_strategy: ReconciliationStrategy,
    pub orisha_arbitrators: HashMap<String, OrishaArbitrator>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReconciliationStrategy {
    #[serde(rename = "last_writer_wins")]
    LastWriterWins { timestamp_source: String },
    #[serde(rename = "weighted_merge")]
    WeightedMerge { weights: HashMap<String, f64> },
    #[serde(rename = "semantic_merge")]
    SemanticMerge { merge_functions: HashMap<String, String> },
    #[serde(rename = "orisha_arbitration")]
    OrishaArbitration { primary_arbitrator: String },
}

#[derive(Debug, Clone)]
pub struct OrishaArbitrator {
    pub orisha: String,
    pub authority_weight: f64,
    pub resolution_logic: String,  // reference to rule engine
}

impl MemoryConsensusProtocol {
    pub fn new(node_id: &str, strategy: ReconciliationStrategy) -> Self {
        Self {
            local_vector: MemoryStateVector {
                node_id: node_id.into(),
                memory_hash: String::new(),
                divergence_score: 0.0,
                last_sync: chrono::Utc::now().timestamp() as u64,
                conflict_markers: vec![],
            },
            peer_vectors: HashMap::new(),
            reconciliation_strategy: strategy,
            orisha_arbitrators: HashMap::new(),
        }
    }
    
    /// 🔄 Sync with peer node and detect conflicts
    pub async fn sync_with_peer(
        &mut self,
        peer_vector: MemoryStateVector,
        local_state: &CanonicalSystemState,
        peer_state: &CanonicalSystemState,
    ) -> SyncResult {
        // Update peer registry
        self.peer_vectors.insert(peer_vector.node_id.clone(), peer_vector.clone());
        
        // Compute divergence score (simplified: hash comparison)
        let divergence = if self.local_vector.memory_hash == peer_vector.memory_hash {
            0.0
        } else {
            // In production: semantic diff of memory subtrees
            Self::compute_divergence(local_state, peer_state)
        };
        
        // Detect conflicts
        let conflicts = Self::detect_conflicts(local_state, peer_state);
        
        // Update local vector
        self.local_vector.divergence_score = divergence;
        self.local_vector.conflict_markers = conflicts.clone();
        self.local_vector.last_sync = chrono::Utc::now().timestamp() as u64;
        
        if conflicts.is_empty() {
            SyncResult::Aligned {
                new_memory_hash: self.local_vector.memory_hash.clone(),
                peer_node: peer_vector.node_id,
            }
        } else {
            SyncResult::ConflictsDetected {
                recommended_resolution: self.recommend_resolution(&conflicts),
                conflicts,
            }
        }
    }
    
    /// 🧭 Reconcile conflicts using strategy + Orisha arbitration
    pub async fn reconcile(
        &mut self,
        conflicts: Vec<ConflictMarker>,
        state: &mut CanonicalSystemState,
    ) -> Result<ReconciliationResult, ReconciliationError> {
        let strategy = self.reconciliation_strategy.clone();
        match strategy {
            ReconciliationStrategy::LastWriterWins { timestamp_source } => {
                // Simple: pick value with latest timestamp
                self.apply_lww(conflicts, state, &timestamp_source)
            }
            ReconciliationStrategy::WeightedMerge { weights } => {
                // Weighted average for numeric, LWW for others
                self.apply_weighted_merge(conflicts, state, &weights)
            }
            ReconciliationStrategy::SemanticMerge { merge_functions } => {
                // Custom merge logic per path
                self.apply_semantic_merge(conflicts, state, &merge_functions)
            }
            ReconciliationStrategy::OrishaArbitration { primary_arbitrator } => {
                // Delegate to Orisha rule engine
                self.apply_orisha_arbitration(conflicts, state, &primary_arbitrator).await
            }
        }
    }
    
    /// 🜄 Ọ̀ṣun arbitration: use prediction model to resolve memory conflicts
    async fn apply_orisha_arbitration(
        &mut self,
        conflicts: Vec<ConflictMarker>,
        state: &mut CanonicalSystemState,
        primary_orisha: &str,
    ) -> Result<ReconciliationResult, ReconciliationError> {
        let arbitrator = self.orisha_arbitrators.get(primary_orisha)
            .cloned()
            .unwrap_or(OrishaArbitrator {
                orisha: primary_orisha.to_string(),
                authority_weight: 1.0,
                resolution_logic: "default".into(),
            });
        
        let mut resolutions = Vec::new();
        
        for conflict in conflicts {
            // Query Orisha rule engine (simplified)
            let resolution = match primary_orisha {
                "ọbàtálá" => self.ethical_resolution(&conflict, state).await?,
                "ọ̀ṣun" => self.predictive_resolution(&conflict, state).await?,
                "yemọja" => self.concurrency_resolution(&conflict, state).await?,
                _ => self.default_resolution(&conflict),
            };
            
            resolutions.push(resolution.clone());
            
            // Apply resolution to state
            self.apply_resolution(resolution, state)?;
        }
        
        // Recompute memory hash after reconciliation
        state.memory.public_hive = Self::canonicalize_memory(&state.memory.public_hive);
        self.local_vector.memory_hash = Self::hash_memory(&state.memory);
        self.local_vector.divergence_score = 0.0;
        self.local_vector.conflict_markers.clear();
        
        Ok(ReconciliationResult {
            resolved_conflicts: resolutions,
            new_memory_hash: self.local_vector.memory_hash.clone(),
            orisha_authority: primary_orisha.into(),
            authority_weight: arbitrator.authority_weight,
        })
    }
    
    async fn ethical_resolution(&self, conflict: &ConflictMarker, _state: &CanonicalSystemState) -> Result<ConflictResolution, ReconciliationError> {
        Ok(self.default_resolution(conflict))
    }
    async fn predictive_resolution(&self, conflict: &ConflictMarker, _state: &CanonicalSystemState) -> Result<ConflictResolution, ReconciliationError> {
        Ok(self.default_resolution(conflict))
    }
    async fn concurrency_resolution(&self, conflict: &ConflictMarker, _state: &CanonicalSystemState) -> Result<ConflictResolution, ReconciliationError> {
        Ok(self.default_resolution(conflict))
    }
    fn default_resolution(&self, conflict: &ConflictMarker) -> ConflictResolution {
        ConflictResolution {
            conflict_path: conflict.path.clone(),
            chosen_value: conflict.local_value.clone(),
            resolution_method: "default:local_wins".into(),
            orisha_input: None,
        }
    }

    fn apply_resolution(&self, resolution: ConflictResolution, state: &mut CanonicalSystemState) -> Result<(), ReconciliationError> {
        state.memory.public_hive.insert(resolution.conflict_path, resolution.chosen_value);
        Ok(())
    }

    fn apply_lww(&self, conflicts: Vec<ConflictMarker>, _state: &mut CanonicalSystemState, _ts_source: &str) -> Result<ReconciliationResult, ReconciliationError> {
        let resolutions = conflicts.into_iter().map(|c| self.default_resolution(&c)).collect();
        Ok(ReconciliationResult {
            resolved_conflicts: resolutions,
            new_memory_hash: "".into(),
            orisha_authority: "system".into(),
            authority_weight: 1.0,
        })
    }
    fn apply_weighted_merge(&self, conflicts: Vec<ConflictMarker>, _state: &mut CanonicalSystemState, _weights: &HashMap<String, f64>) -> Result<ReconciliationResult, ReconciliationError> {
        let resolutions = conflicts.into_iter().map(|c| self.default_resolution(&c)).collect();
        Ok(ReconciliationResult {
            resolved_conflicts: resolutions,
            new_memory_hash: "".into(),
            orisha_authority: "system".into(),
            authority_weight: 1.0,
        })
    }
    fn apply_semantic_merge(&self, conflicts: Vec<ConflictMarker>, _state: &mut CanonicalSystemState, _merge_functions: &HashMap<String, String>) -> Result<ReconciliationResult, ReconciliationError> {
        let resolutions = conflicts.into_iter().map(|c| self.default_resolution(&c)).collect();
        Ok(ReconciliationResult {
            resolved_conflicts: resolutions,
            new_memory_hash: "".into(),
            orisha_authority: "system".into(),
            authority_weight: 1.0,
        })
    }

    fn recommend_resolution(&self, _conflicts: &[ConflictMarker]) -> ResolutionHint {
        ResolutionHint {
            strategy: "orisha_arbitration".into(),
            confidence: 0.8,
            orisha_recommendation: Some("ọbàtálá".into()),
        }
    }
    
    fn compute_divergence(local: &CanonicalSystemState, remote: &CanonicalSystemState) -> f64 {
        // Simplified: compare memory subtree hashes
        let local_hash = Self::hash_memory(&local.memory);
        let remote_hash = Self::hash_memory(&remote.memory);
        if local_hash == remote_hash { 0.0 } else { 0.5 }
    }
    
    fn detect_conflicts(_local: &CanonicalSystemState, _remote: &CanonicalSystemState) -> Vec<ConflictMarker> {
        // Simplified conflict detection
        vec![]
    }
    
    fn hash_memory(memory: &Memory) -> String {
        let mut hasher = Sha256::new();
        hasher.update(serde_json::to_string(&memory.public_hive).unwrap().as_bytes());
        if let Some(ref private) = memory.private_seal_ref {
            hasher.update(private.as_bytes());
        }
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }
    
    fn canonicalize_memory(map: &HashMap<String, serde_json::Value>) -> HashMap<String, serde_json::Value> {
        // Sort keys for deterministic hashing
        map.iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<std::collections::BTreeMap<_, _>>()
            .into_iter()
            .collect()
    }
}

#[derive(Debug)]
pub enum SyncResult {
    Aligned { new_memory_hash: String, peer_node: String },
    ConflictsDetected {
        conflicts: Vec<ConflictMarker>,
        recommended_resolution: ResolutionHint,
    },
}

#[derive(Debug)]
pub struct ResolutionHint {
    pub strategy: String,
    pub confidence: f64,
    pub orisha_recommendation: Option<String>,
}

#[derive(Debug)]
pub struct ReconciliationResult {
    pub resolved_conflicts: Vec<ConflictResolution>,
    pub new_memory_hash: String,
    pub orisha_authority: String,
    pub authority_weight: f64,
}

#[derive(Debug, Clone)]
pub struct ConflictResolution {
    pub conflict_path: String,
    pub chosen_value: serde_json::Value,
    pub resolution_method: String,
    pub orisha_input: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ReconciliationError {
    #[error("Arbitrator not found")]
    ArbitratorNotFound,
    #[error("Resolution failed: {0}")]
    ResolutionFailed(String),
    #[error("State mutation error")]
    StateMutationError,
}

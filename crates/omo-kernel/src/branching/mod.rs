use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use crate::zangbeto::drift::DriftType;
use std::collections::HashMap;

/// 🌿 Reality Branch: a forked timeline with its own state head
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealityBranch {
    pub branch_id: String,          // hash(branch_seed + parent_hash)
    pub parent_hash: String,        // sha256 of parent CSS
    pub fork_reason: ForkReason,
    pub confidence: f64,            // 0.0 - 1.0 (Ọ̀ṣun prediction strength)
    pub state_head: String,         // sha256 of latest CSS in this branch
    pub created_at: u64,
    pub is_speculative: bool,       // true = not yet committed to mainline
    pub merge_policy: MergePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "details")]
pub enum ForkReason {
    #[serde(rename = "PREDICTION")]
    Prediction { horizon_events: u64 },  // Ọ̀ṣun forecast
    #[serde(rename = "DRIFT_RECOVERY")]
    DriftRecovery { drift_type: DriftType },  // Zàngbétò repair fork
    #[serde(rename = "SPECULATIVE_EXEC")]
    SpeculativeExecution { intent_hash: String },  // Shadow VM trial
    #[serde(rename = "CONSENSUS_SPLIT")]
    ConsensusSplit { dissenting_validators: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MergePolicy {
    #[serde(rename = "auto_merge")]
    AutoMerge { confidence_threshold: f64 },
    #[serde(rename = "orisha_arbitration")]
    OrishaArbitration { required_validators: Vec<String> },
    #[serde(rename = "human_review")]
    HumanReview,
    #[serde(rename = "abandon")]
    AbandonIfNotConfirmed,
}

/// 🕸️ Branch DAG: tracks all parallel realities
pub struct RealityDAG {
    pub branches: HashMap<String, RealityBranch>,
    pub mainline_tip: String,  // branch_id of canonical reality
    pub branch_index: HashMap<String, Vec<String>>,  // parent_hash → child_branches
}

impl RealityDAG {
    pub fn new(genesis_branch: RealityBranch) -> Self {
        let tip = genesis_branch.branch_id.clone();
        let mut index = HashMap::new();
        index.insert(genesis_branch.parent_hash.clone(), vec![tip.clone()]);
        
        Self {
            branches: [(tip.clone(), genesis_branch)].into_iter().collect(),
            mainline_tip: tip,
            branch_index: index,
        }
    }
    
    /// 🌱 Fork a new branch from existing state
    pub fn fork(
        &mut self,
        parent_branch_id: &str,
        reason: ForkReason,
        confidence: f64,
        merge_policy: MergePolicy,
    ) -> Result<String, BranchError> {
        let (parent_state_head, _parent_branch_id_str) = {
            let parent = self.branches.get(parent_branch_id)
                .ok_or(BranchError::ParentNotFound)?;
            (parent.state_head.clone(), parent_branch_id.to_string())
        };
            
        let branch_id = Self::compute_branch_id(&parent_state_head, &reason);
        
        let new_branch = RealityBranch {
            branch_id: branch_id.clone(),
            parent_hash: parent_state_head.clone(),
            fork_reason: reason,
            confidence,
            state_head: parent_state_head.clone(),  // starts identical
            created_at: chrono::Utc::now().timestamp() as u64,
            is_speculative: matches!(merge_policy, MergePolicy::AutoMerge { .. }),
            merge_policy,
        };
        
        self.branches.insert(branch_id.clone(), new_branch);
        self.branch_index
            .entry(parent_state_head)
            .or_default()
            .push(branch_id.clone());
            
        Ok(branch_id)
    }
    
    /// 🔀 Merge branch back into mainline (Yemọja logic)
    pub fn merge_branch(
        &mut self,
        branch_id: &str,
        validator_consensus: &ValidatorConsensus,
    ) -> Result<MergeResult, BranchError> {
        let branch_info = {
            let branch = self.branches.get(branch_id)
                .ok_or(BranchError::BranchNotFound)?;
            (branch.confidence, branch.merge_policy.clone(), branch.state_head.clone())
        };
            
        // Check merge policy
        match &branch_info.1 {
            MergePolicy::AutoMerge { confidence_threshold } => {
                if branch_info.0 < *confidence_threshold {
                    return Ok(MergeResult::Rejected("Confidence too low".into()));
                }
            }
            MergePolicy::OrishaArbitration { required_validators } => {
                if !validator_consensus.has_quorum(required_validators) {
                    return Ok(MergeResult::Rejected("Insufficient Orisha approval".into()));
                }
            }
            MergePolicy::HumanReview => {
                return Ok(MergeResult::PendingReview);
            }
            MergePolicy::AbandonIfNotConfirmed => {
                // Auto-abandon if not explicitly confirmed
                return Ok(MergeResult::Abandoned);
            }
        }
        
        // Perform merge: update mainline tip to branch head
        let old_tip = self.mainline_tip.clone();
        self.mainline_tip = branch_id.to_string();
        
        // Mark branch as merged
        if let Some(b) = self.branches.get_mut(branch_id) {
            b.is_speculative = false;
        }
        
        Ok(MergeResult::Merged {
            old_mainline: old_tip,
            new_mainline: branch_id.to_string(),
            state_transition: branch_info.2,
        })
    }
    
    /// 🧭 Get all active speculative branches
    pub fn speculative_branches(&self) -> Vec<&RealityBranch> {
        self.branches.values()
            .filter(|b| b.is_speculative)
            .collect()
    }
    
    fn compute_branch_id(state_head: &str, reason: &ForkReason) -> String {
        let mut hasher = Sha256::new();
        hasher.update(state_head.as_bytes());
        hasher.update(serde_json::to_string(reason).unwrap().as_bytes());
        format!("branch:{}", hex::encode(hasher.finalize()))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BranchError {
    #[error("Parent branch not found")]
    ParentNotFound,
    #[error("Branch not found")]
    BranchNotFound,
    #[error("Merge conflict")]
    MergeConflict,
}

#[derive(Debug)]
pub enum MergeResult {
    Merged { old_mainline: String, new_mainline: String, state_transition: String },
    Rejected(String),
    PendingReview,
    Abandoned,
}

pub struct ValidatorConsensus {
    pub approvals: HashMap<String, bool>,  // orisha_name → approved
}

impl ValidatorConsensus {
    pub fn has_quorum(&self, required: &[String]) -> bool {
        required.iter().all(|orisha| 
            self.approvals.get(orisha).copied().unwrap_or(false)
        )
    }
}

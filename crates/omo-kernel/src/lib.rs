//! 🧿 ÒGÚN'S FORGE: Reality VM Core v3
//! 
//! A Byzantine fault-tolerant, capability-gated, temporally-branching
//! state machine with mythic consensus semantics.

pub mod capability;
pub mod branching;
pub mod consensus;
pub mod sandbox;
pub mod memory;
pub mod kernel;   // CSS + Diff + Engine
pub mod zangbeto; // Event + Drift + Ledger
pub mod audit;

use std::collections::HashMap;
use capability::CapabilityToken;
use branching::{RealityDAG, RealityBranch, ForkReason, MergePolicy};
use consensus::temporal::TemporalConsensusEngine;
use sandbox::ShadowVM;
use memory::consensus::{MemoryConsensusProtocol, ReconciliationStrategy};
use zangbeto::event::RealityEvent;
use zangbeto::ir::CanonicalStateIR;
use kernel::css::{CanonicalSystemState, StateError};
use kernel::engine::{StateTransitionEngine, EnvironmentContext};

/// 🜂 RealityVM: unified interface to the sovereign compute system
pub struct RealityVM {
    pub capabilities: CapabilityRegistry,
    pub branches: RealityDAG,
    pub consensus: TemporalConsensusEngine,
    pub shadow_vm: ShadowVM,
    pub memory_protocol: MemoryConsensusProtocol,
    pub config: VMConfig,
    pub engine: StateTransitionEngine,
}

#[derive(Debug, Clone)]
pub struct VMConfig {
    pub chain_id: String,
    pub default_quorum_threshold: f64,
    pub shadow_execution_required: bool,
    pub auto_repair_enabled: bool,
    pub max_speculative_branches: usize,
}

pub struct CapabilityRegistry {
    pub tokens: HashMap<uuid::Uuid, CapabilityToken>,
}
impl CapabilityRegistry {
    pub fn new() -> Self {
        Self { tokens: HashMap::new() }
    }
}

impl RealityVM {
    pub fn new(config: VMConfig, initial_state: CanonicalSystemState) -> Self {
        let genesis_branch = RealityBranch {
            branch_id: "genesis".into(),
            parent_hash: "0".repeat(64),
            fork_reason: ForkReason::Prediction { horizon_events: 0 },
            confidence: 1.0,
            state_head: initial_state.state_hash.clone(),
            created_at: chrono::Utc::now().timestamp() as u64,
            is_speculative: false,
            merge_policy: MergePolicy::HumanReview,
        };

        Self {
            capabilities: CapabilityRegistry::new(),
            branches: RealityDAG::new(genesis_branch),
            consensus: TemporalConsensusEngine::new(config.default_quorum_threshold),
            shadow_vm: ShadowVM::new(),
            memory_protocol: MemoryConsensusProtocol::new(
                &config.chain_id,
                ReconciliationStrategy::OrishaArbitration {
                    primary_arbitrator: "ọbàtálá".into(),
                },
            ),
            config,
            engine: StateTransitionEngine::new(),
        }
    }
    
    /// ⚡ Execute intent with full Reality VM pipeline
    pub async fn execute(
        &mut self,
        intent: String,
        agent_token: CapabilityToken,
        mut context: ExecutionContext,
    ) -> Result<ExecutionResult, VMError> {
        // 1. Capability check (Èṣù gate)
        let ir_ops = self.intent_to_ir(&intent)?;
        for op in &ir_ops {
            match agent_token.permits(op, context.timestamp) {
                capability::PermissionResult::Permitted => {},
                capability::PermissionResult::Denied(reason) => {
                    return Err(VMError::CapabilityDenied(reason));
                }
                capability::PermissionResult::Conditional { requires_blessing_from, reason } => {
                    // Request blessing from specified Orisha
                    if !self.request_blessing(&requires_blessing_from, op, &context).await? {
                        return Err(VMError::BlessingDenied(reason));
                    }
                }
            }
        }
        
        // 2. Shadow execution (if configured)
        if self.config.shadow_execution_required {
            let simulation = self.shadow_vm.simulate(
                context.current_state.clone(),
                ir_ops.clone(),
                sandbox::SimulationContext {
                    intent_metadata: context.metadata.clone(),
                    resource_limits: context.resource_limits.clone(),
                    time_budget_ms: 5000,
                },
            ).await?;
            
            match simulation.risk_assessment.recommended_action {
                sandbox::SandboxAction::Proceed => {},
                sandbox::SandboxAction::ProceedWithMonitoring { checkpoints } => {
                    context.add_checkpoints(checkpoints);
                }
                sandbox::SandboxAction::RequireValidation { ref from_orisha } => {
                    // Request additional validation
                    if !self.request_validation(from_orisha, &simulation).await? {
                        return Err(VMError::ValidationFailed);
                    }
                }
                sandbox::SandboxAction::Abort { reason } => {
                    return Err(VMError::ShadowAbort(reason));
                }
            }
        }
        
        // 3. Execute transition (Ògún layer)
        let before = context.current_state.clone();
        let env_ctx = EnvironmentContext {
            timestamp: context.timestamp,
            external_signals: if let Some(obj) = context.metadata.as_object() {
                obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
            } else {
                HashMap::new()
            },
        };
        
        let mut after = self.engine.transition(before.clone(), intent.clone(), env_ctx)
            .await.map_err(VMError::KernelError)?;
        
        // 4. Branch management (if speculative)
        let mut branch_id_opt = None;
        if context.speculative {
            let tip = self.branches.mainline_tip.clone();
            let branch_id = self.branches.fork(
                &tip,
                branching::ForkReason::SpeculativeExecution {
                    intent_hash: self.hash_intent(&intent),
                },
                0.85, // confidence
                branching::MergePolicy::AutoMerge { confidence_threshold: 0.9 },
            ).map_err(VMError::BranchingError)?;
            branch_id_opt = Some(branch_id);
        }
        
        // 5. Memory reconciliation (Yemọja layer)
        if context.distributed {
            if let Some(peer_vector) = context.peer_memory_vector.clone() {
                let sync_result = self.memory_protocol.sync_with_peer(
                    peer_vector,
                    &before,
                    &after,
                ).await;
                
                if let memory::consensus::SyncResult::ConflictsDetected { conflicts, .. } = sync_result {
                    self.memory_protocol.reconcile(conflicts, &mut after).await?;
                }
            }
        }
        
        // 6. Zàngbétò audit + ledger anchor
        // Simplified: would use zangbeto pipeline or manual append
        let event = RealityEvent {
            event_id: uuid::Uuid::new_v4(),
            pre_state_hash: before.state_hash.clone(),
            post_state_hash: after.state_hash.clone(),
            fingerprint: zangbeto::event::TransitionFingerprint::compute(
                &intent,
                &["èṣù", "ọbàtálá"],
                &ir_ops,
                &context.metadata,
            ),
            diff: kernel::diff::StateDiff {
                transition_id: uuid::Uuid::new_v4(),
                input_state_hash: before.state_hash,
                ops: vec![], // would be computed
                validators_required: vec![],
                validators_approved: vec![],
                execution_plan: None,
                final_state_hash: Some(after.state_hash.clone()),
                timestamp: context.timestamp,
            },
            validators: vec![],
            expected_state: None,
            drift_analysis: None,
            repair_delta: None,
            finality_receipt: None,
            timestamp: context.timestamp,
            metadata: context.metadata,
        };
        
        Ok(ExecutionResult {
            event_id: event.event_id,
            final_state_hash: event.post_state_hash,
            drift_detected: false,
            branch_id: branch_id_opt,
            memory_hash: self.memory_protocol.local_vector.memory_hash.clone(),
        })
    }
    
    fn intent_to_ir(&self, intent: &str) -> Result<Vec<CanonicalStateIR>, VMError> {
        Ok(vec![CanonicalStateIR::AddTask {
            intent: intent.to_string(),
            priority: 1,
            metadata: serde_json::json!({}),
        }])
    }

    async fn request_blessing(&self, _orisha: &str, _op: &CanonicalStateIR, _ctx: &ExecutionContext) -> Result<bool, VMError> {
        Ok(true)
    }

    async fn request_validation(&self, _orishas: &[String], _sim: &sandbox::ShadowExecution) -> Result<bool, VMError> {
        Ok(true)
    }

    fn hash_intent(&self, intent: &str) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(intent.as_bytes());
        hex::encode(hasher.finalize())
    }
}

#[derive(Debug, Clone)]
pub struct ExecutionContext {
    pub timestamp: u64,
    pub current_state: CanonicalSystemState,
    pub metadata: serde_json::Value,
    pub resource_limits: sandbox::ResourceLimits,
    pub speculative: bool,
    pub distributed: bool,
    pub peer_memory_vector: Option<memory::consensus::MemoryStateVector>,
    pub checkpoints: Vec<String>,
}

impl ExecutionContext {
    pub fn add_checkpoints(&mut self, cps: Vec<String>) {
        self.checkpoints.extend(cps);
    }
}

#[derive(Debug)]
pub struct ExecutionResult {
    pub event_id: uuid::Uuid,
    pub final_state_hash: String,
    pub drift_detected: bool,
    pub branch_id: Option<String>,
    pub memory_hash: String,
}

#[derive(Debug, thiserror::Error)]
pub enum VMError {
    #[error("Capability denied: {0}")]
    CapabilityDenied(String),
    #[error("Blessing denied: {0}")]
    BlessingDenied(String),
    #[error("Shadow execution aborted: {0}")]
    ShadowAbort(String),
    #[error("Validation failed")]
    ValidationFailed,
    #[error("Branching error: {0}")]
    BranchingError(#[from] branching::BranchError),
    #[error("Consensus error: {0}")]
    ConsensusError(String),
    #[error("Memory reconciliation error: {0}")]
    MemoryReconciliationError(#[from] memory::consensus::ReconciliationError),
    #[error("Kernel error: {0}")]
    KernelError(#[from] StateError),
    #[error("Zangbeto error: {0}")]
    ZangbetoError(#[from] zangbeto::ZangbetoError),
    #[error("Simulation error: {0}")]
    SimulationError(#[from] sandbox::SimulationError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_vm_smoke() {
        let config = VMConfig {
            chain_id: "test-chain".into(),
            default_quorum_threshold: 7.0,
            shadow_execution_required: true,
            auto_repair_enabled: true,
            max_speculative_branches: 5,
        };
        let initial_state = CanonicalSystemState::default();
        let mut vm = RealityVM::new(config, initial_state.clone());

        let token = CapabilityToken {
            token_id: uuid::Uuid::new_v4(),
            agent_id: "test-agent".into(),
            allowed_ops: vec![capability::OpCapability {
                ir_opcode: "*".into(),
                max_frequency: None,
                resource_budget: None,
                requires_blessing: None,
            }],
            denied_paths: vec![],
            expiry: chrono::Utc::now().timestamp() as u64 + 3600,
            authority_source: capability::AuthoritySource::EsuSystem,
            delegation_chain: vec![],
            signature: b"valid".to_vec(),
        };

        let context = ExecutionContext {
            timestamp: chrono::Utc::now().timestamp() as u64,
            current_state: initial_state,
            metadata: serde_json::json!({}),
            resource_limits: sandbox::ResourceLimits {
                max_cpu_ms: 1000,
                max_memory_bytes: 1024 * 1024,
                max_economic_delta: 1000,
            },
            speculative: true,
            distributed: false,
            peer_memory_vector: None,
            checkpoints: vec![],
        };

        let result = vm.execute("Search for Yoruba oral histories".into(), token, context).await;
        assert!(result.is_ok());
        let res = result.unwrap();
        assert!(!res.final_state_hash.is_empty());
        assert!(res.branch_id.is_some());
    }
}

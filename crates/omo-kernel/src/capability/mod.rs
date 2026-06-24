use serde::{Serialize, Deserialize};
use uuid::Uuid;
use crate::zangbeto::ir::CanonicalStateIR;

/// 🔐 Capability Token: what an agent is ALLOWED to attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityToken {
    pub token_id: Uuid,
    pub agent_id: String,
    pub allowed_ops: Vec<OpCapability>,
    pub denied_paths: Vec<String>,  // e.g., "/memory/private"
    pub expiry: u64,                // UNIX timestamp
    pub authority_source: AuthoritySource,
    pub delegation_chain: Vec<Uuid>, // parent tokens
    pub signature: Vec<u8>,         // cryptographic proof (Ed25519)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpCapability {
    pub ir_opcode: String,          // e.g., "STATE.ADD_TASK"
    pub max_frequency: Option<u64>, // ops per minute
    pub resource_budget: Option<ResourceBudget>,
    pub requires_blessing: Option<String>, // Orisha name
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceBudget {
    pub max_memory_bytes: Option<u64>,
    pub max_cpu_ms: Option<u64>,
    pub max_economic_delta: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthoritySource {
    #[serde(rename = "èṣù:system")]
    EsuSystem,
    #[serde(rename = "ṣàngó:ledger")]
    SangoLedger,
    #[serde(rename = "human:admin")]
    HumanAdmin,
    #[serde(rename = "delegate:{agent_id}")]
    Delegated { agent_id: String },
}

impl CapabilityToken {
    /// 🔍 Check if token permits an operation
    pub fn permits(&self, op: &CanonicalStateIR, timestamp: u64) -> PermissionResult {
        if timestamp > self.expiry {
            return PermissionResult::Denied("Token expired".into());
        }
        
        let op_name = op.opcode_name();
        
        // Check allowed ops
        let cap = self.allowed_ops.iter()
            .find(|c| c.ir_opcode == op_name)
            .or_else(|| self.allowed_ops.iter().find(|c| c.ir_opcode == "*"));
            
        let Some(cap) = cap else {
            return PermissionResult::Denied(format!("Op {} not permitted", op_name));
        };
        
        // Check denied paths
        if let Some(path) = op.target_path() {
            if self.denied_paths.iter().any(|p| path.starts_with(p)) {
                return PermissionResult::Denied(format!("Path {} denied", path));
            }
        }
        
        // Check blessing requirement
        if let Some(orisha) = &cap.requires_blessing {
            return PermissionResult::Conditional {
                requires_blessing_from: orisha.clone(),
                reason: format!("{} requires {} approval", op_name, orisha),
            };
        }
        
        PermissionResult::Permitted
    }
    
    /// 🧬 Derive child token with reduced permissions
    pub fn delegate(&self, child_agent: &str, restrictions: DelegationRestrictions) -> Self {
        Self {
            token_id: Uuid::new_v4(),
            agent_id: child_agent.into(),
            allowed_ops: restrictions.allowed_ops
                .unwrap_or_else(|| self.allowed_ops.clone()),
            denied_paths: [self.denied_paths.clone(), restrictions.extra_denied_paths]
                .concat(),
            expiry: restrictions.expiry.unwrap_or(self.expiry),
            authority_source: AuthoritySource::Delegated { 
                agent_id: self.agent_id.clone() 
            },
            delegation_chain: {
                let mut chain = self.delegation_chain.clone();
                chain.push(self.token_id);
                chain
            },
            signature: vec![], // caller must re-sign via crypto-kernel
        }
    }

    /// Whether this token carries a cryptographic signature
    pub fn is_signed(&self) -> bool {
        !self.signature.is_empty()
    }
}

#[derive(Debug, Clone)]
pub enum PermissionResult {
    Permitted,
    Denied(String),
    Conditional { requires_blessing_from: String, reason: String },
}

#[derive(Debug, Clone, Default)]
pub struct DelegationRestrictions {
    pub allowed_ops: Option<Vec<OpCapability>>,
    pub extra_denied_paths: Vec<String>,
    pub expiry: Option<u64>,
}

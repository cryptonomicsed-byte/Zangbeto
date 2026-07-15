pub mod glyph_audit;

use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey};
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use vm_core::ir::{StateHash, OrishaId};
use rand_core::OsRng;

/// 🔐 Key hierarchy: root → agent → capability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyHierarchy {
    pub root_key_id: KeyId,
    pub agent_key_id: KeyId,
    pub capability_key_id: Option<KeyId>,
    pub delegation_path: Vec<KeyId>,
}

pub type KeyId = String;

/// 🔑 Key Registry: verifiable public key store
#[derive(Debug, Clone)]
pub struct KeyRegistry {
    pub keys: std::collections::HashMap<KeyId, VerifyingKey>,
    pub root_trust_anchor: VerifyingKey,
}

impl KeyRegistry {
    pub fn new(root_public_key: VerifyingKey) -> Self {
        let mut keys = std::collections::HashMap::new();
        keys.insert(hex::encode(root_public_key.to_bytes()), root_public_key);
        Self {
            keys,
            root_trust_anchor: root_public_key,
        }
    }
    
    pub fn register_key(&mut self, key_id: KeyId, public_key: VerifyingKey, signature: ed25519_dalek::Signature) -> Result<(), CryptoError> {
        // Verify key registration is signed by trusted authority
        let message = format!("register_key:{}", key_id);
        self.root_trust_anchor.verify(message.as_bytes(), &signature)
            .map_err(|_| CryptoError::InvalidSignature)?;
        
        self.keys.insert(key_id, public_key);
        Ok(())
    }
    
    pub fn get_key(&self, key_id: &KeyId) -> Option<&VerifyingKey> {
        self.keys.get(key_id)
    }

    pub fn get_key_by_hash(&self, hash: &[u8; 32]) -> Option<&VerifyingKey> {
        for key in self.keys.values() {
            let h: [u8; 32] = Sha256::digest(key.to_bytes()).into();
            if &h == hash {
                return Some(key);
            }
        }
        None
    }

    pub fn dummy() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self::new(signing_key.verifying_key())
    }
}

/// 🪙 CapabilityToken: now cryptographically signed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityToken {
    pub token_id: Uuid,
    pub agent_id: String,
    pub allowed_ops: Vec<OpCapability>,
    pub denied_paths: Vec<String>,
    pub expiry: u64,
    pub authority_source: AuthoritySource,
    pub delegation_chain: Vec<Uuid>,
    
    // 🔐 Cryptographic fields
    pub payload_hash: StateHash,      // hash of above fields (canonical)
    pub signature: Vec<u8>,           // Ed25519 signature over payload_hash
    pub signer_key_id: KeyId,         // which key signed this
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpCapability {
    pub ir_opcode: String,
    pub max_frequency: Option<u64>,
    pub resource_budget: Option<ResourceBudget>,
    pub requires_blessing: Option<OrishaId>,
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
    pub fn sign(
        token_data: UnsignedCapabilityToken,
        signing_key: &SigningKey,
        key_id: KeyId,
    ) -> Result<Self, CryptoError> {
        let payload = token_data.encode_canonical_payload();
        let payload_hash: [u8; 32] = Sha256::digest(&payload).into();
        let signature = signing_key.sign(&payload_hash);
        
        Ok(Self {
            token_id: token_data.token_id,
            agent_id: token_data.agent_id,
            allowed_ops: token_data.allowed_ops,
            denied_paths: token_data.denied_paths,
            expiry: token_data.expiry,
            authority_source: token_data.authority_source,
            delegation_chain: token_data.delegation_chain,
            payload_hash,
            signature: signature.to_bytes().to_vec(),
            signer_key_id: key_id,
        })
    }
    
    pub fn verify(&self, registry: &KeyRegistry) -> Result<(), CryptoError> {
        let signer_key = registry.get_key(&self.signer_key_id)
            .ok_or(CryptoError::KeyNotFound(self.signer_key_id.clone()))?;
        
        let signature = ed25519_dalek::Signature::from_slice(&self.signature)
            .map_err(|_| CryptoError::InvalidSignature)?;

        signer_key.verify(&self.payload_hash, &signature)
            .map_err(|_| CryptoError::InvalidSignature)?;
        
        let recomputed_hash: [u8; 32] = Sha256::digest(self.encode_canonical_payload()).into();
        if self.payload_hash != recomputed_hash {
            return Err(CryptoError::PayloadTampered);
        }
        
        if current_timestamp() > self.expiry {
            return Err(CryptoError::TokenExpired);
        }
        
        Ok(())
    }
    
    pub fn encode_canonical_payload(&self) -> Vec<u8> {
        #[derive(Serialize)]
        struct Payload<'a> {
            token_id: &'a Uuid,
            agent_id: &'a String,
            allowed_ops: &'a Vec<OpCapability>,
            denied_paths: &'a Vec<String>,
            expiry: &'a u64,
            authority_source: &'a AuthoritySource,
            delegation_chain: &'a Vec<Uuid>,
        }
        
        let payload = Payload {
            token_id: &self.token_id,
            agent_id: &self.agent_id,
            allowed_ops: &self.allowed_ops,
            denied_paths: &self.denied_paths,
            expiry: &self.expiry,
            authority_source: &self.authority_source,
            delegation_chain: &self.delegation_chain,
        };
        
        let mut buf = Vec::new();
        let mut serializer = serde_cbor::ser::Serializer::new(&mut buf);
        payload.serialize(&mut serializer).unwrap();
        buf
    }

    pub fn dummy() -> Self {
        Self {
            token_id: Uuid::new_v4(),
            agent_id: "dummy".into(),
            allowed_ops: vec![],
            denied_paths: vec![],
            expiry: current_timestamp() + 3600,
            authority_source: AuthoritySource::EsuSystem,
            delegation_chain: vec![],
            payload_hash: [0; 32],
            signature: vec![],
            signer_key_id: "root".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedCapabilityToken {
    pub token_id: Uuid,
    pub agent_id: String,
    pub allowed_ops: Vec<OpCapability>,
    pub denied_paths: Vec<String>,
    pub expiry: u64,
    pub authority_source: AuthoritySource,
    pub delegation_chain: Vec<Uuid>,
}

impl UnsignedCapabilityToken {
    pub fn encode_canonical_payload(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut serializer = serde_cbor::ser::Serializer::new(&mut buf);
        self.serialize(&mut serializer).unwrap();
        buf
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Key not found: {0}")]
    KeyNotFound(KeyId),
    #[error("Payload tampered")]
    PayloadTampered,
    #[error("Token expired")]
    TokenExpired,
    #[error("Key registration failed")]
    RegistrationFailed,
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

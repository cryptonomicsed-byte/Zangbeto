use serde::{Serialize, Deserialize};
use crate::{Diagnostic};

pub struct ZangbetoClient {
    pub http: reqwest::Client,
    pub endpoint: String,
    pub guardian_pubkey: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ZangbetoPayload {
    pub code: String,
    pub severity: u8,
    pub category: u8,
    pub message_hash: String,
    pub agent_id: String,
    pub birth_epoch: u64,
    pub tier: u8,
    pub sabbath_active: bool,
    pub repair_id: String,
    pub repair_strategy: u8,
    pub witness_quorum: Vec<String>,
    pub constitutional_class: String,
    pub economic_impact: Option<u64>,
    pub seal_policy: Option<String>,
    pub sovereign_scope: String,
}

impl ZangbetoPayload {
    pub fn from_diagnostic(diag: &Diagnostic, hash: &str) -> Self {
        Self {
            code: diag.diagnostic.code.clone(),
            severity: diag.diagnostic.severity as u8,
            category: diag.diagnostic.category,
            message_hash: hash.to_string(),
            agent_id: diag.diagnostic.context.agent_id.clone().unwrap_or_default(),
            birth_epoch: diag.diagnostic.context.birth_timestamp.unwrap_or(0),
            tier: diag.diagnostic.context.tier.unwrap_or(0),
            sabbath_active: diag.diagnostic.context.sabbath_active,
            repair_id: diag.repair.as_ref().map(|r| r.id.clone()).unwrap_or_default(),
            repair_strategy: diag.repair.as_ref().map(|r| r.strategy as u8).unwrap_or(2),
            witness_quorum: diag.witness_quorum.clone(),
            constitutional_class: diag.constitutional_class.clone(),
            economic_impact: diag.economic_impact,
            seal_policy: diag.seal_policy.clone(),
            sovereign_scope: diag.sovereign_scope.clone(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ZangbetoReceipt {
    pub receipt_id: String,
    pub zangbeto_sig: String,
}

impl ZangbetoClient {
    pub fn new(endpoint: String, guardian_pubkey: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            endpoint,
            guardian_pubkey,
        }
    }

    pub async fn submit_diagnostic(&self, payload: ZangbetoPayload) -> Result<ZangbetoReceipt, reqwest::Error> {
        let response = self.http
            .post(&format!("{}/diagnostics", self.endpoint))
            .header("X-Guardian-Pubkey", &self.guardian_pubkey)
            .json(&payload)
            .send()
            .await?
            .json::<ZangbetoReceipt>()
            .await?;
        
        Ok(response)
    }

    /// Verify a receipt signature stub.
    ///
    /// Returns `false` immediately for empty signatures or empty receipt ids,
    /// preventing trivially unsigned tokens from passing verification.
    /// Full cryptographic verification is deferred to a future milestone.
    pub async fn verify_signature(
        &self,
        receipt_id: &str,
        sig: &str,
    ) -> Result<bool, crate::DiagnosticError> {
        if sig.is_empty() {
            return Ok(false);
        }
        if receipt_id.is_empty() {
            return Ok(false);
        }
        // Stub: real Ed25519 verification against self.guardian_pubkey goes here.
        Ok(true)
    }
}

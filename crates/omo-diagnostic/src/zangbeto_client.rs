use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Serialize, Deserialize};
use sha2::{Digest, Sha256};
use crate::{Diagnostic};

pub struct ZangbetoClient {
    pub http: reqwest::Client,
    pub endpoint: String,
    pub guardian_pubkey: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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

    /// Fetch the guardian's current Ed25519 public key (hex) directly from
    /// the daemon, rather than trusting whatever `self.guardian_pubkey` was
    /// constructed with -- callers that hardcoded a placeholder (or an
    /// out-of-date key) get the real one instead of silently failing every
    /// verification.
    pub async fn fetch_guardian_pubkey(&self) -> Result<String, reqwest::Error> {
        #[derive(Deserialize)]
        struct PubkeyResponse {
            guardian_pubkey: String,
        }
        let resp = self
            .http
            .get(&format!("{}/guardian/pubkey", self.endpoint))
            .send()
            .await?
            .json::<PubkeyResponse>()
            .await?;
        Ok(resp.guardian_pubkey)
    }

    /// Verify a receipt's Ed25519 signature against the guardian's public
    /// key. `payload` must be the exact payload that was submitted to
    /// `/diagnostics` to produce this receipt -- the signature binds both
    /// the receipt id and the payload contents, so a receipt replayed
    /// against a different payload (or a different receipt id) fails to
    /// verify. Mirrors zangbeto-enforcement's `guardian::verify_receipt`
    /// exactly: `sha256(receipt_id || canonical_json(payload))`, where
    /// `canonical_json` is `serde_json::to_vec` on a `Value` (parse-then-
    /// reserialize normalizes key order via `Value`'s `BTreeMap`, so it
    /// matches regardless of the wire order `payload` happened to encode
    /// in).
    pub fn verify_signature(
        &self,
        receipt_id: &str,
        payload: &ZangbetoPayload,
        sig: &str,
    ) -> Result<bool, crate::DiagnosticError> {
        if sig.is_empty() || receipt_id.is_empty() {
            return Ok(false);
        }

        let Ok(pubkey_bytes) = hex::decode(&self.guardian_pubkey) else {
            return Ok(false);
        };
        let Ok(pubkey_arr): Result<[u8; 32], _> = pubkey_bytes.try_into() else {
            return Ok(false);
        };
        let Ok(verifying_key) = VerifyingKey::from_bytes(&pubkey_arr) else {
            return Ok(false);
        };

        let Ok(sig_bytes) = hex::decode(sig) else {
            return Ok(false);
        };
        let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.try_into() else {
            return Ok(false);
        };
        let signature = Signature::from_bytes(&sig_arr);

        let canonical_value = serde_json::to_value(payload).unwrap_or(serde_json::Value::Null);
        let canonical_bytes = serde_json::to_vec(&canonical_value).unwrap_or_default();

        let mut hasher = Sha256::new();
        hasher.update(receipt_id.as_bytes());
        hasher.update(&canonical_bytes);
        let digest = hasher.finalize();

        Ok(verifying_key.verify(&digest, &signature).is_ok())
    }
}

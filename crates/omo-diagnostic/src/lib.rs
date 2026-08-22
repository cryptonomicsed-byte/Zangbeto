pub mod zangbeto_client;
pub mod agent;

use serde::{Serialize, Deserialize};
use schemars::JsonSchema;
use uuid::Uuid;
use chrono::{DateTime, Utc};
pub use omo_kernel::kernel::orisha::OrishaMask;

// ─────────────────────────────────────────────────────
// Canonical Enums (Bitmask-Compatible)
// ─────────────────────────────────────────────────────
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Copy, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum Severity {
    #[default]
    Info = 0,
    Warning = 1,
    Error = 2,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Copy, PartialEq)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum Category {
    Type = 1,
    Logic = 2,
    Security = 4,
    Receipt = 8,
    Identity = 16,
    Rhythm = 32,
}

impl Category {
    pub fn as_bitmask(categories: &[Category]) -> u8 {
        categories.iter().map(|c| *c as u8).fold(0, |acc, bit| acc | bit)
    }
    
    pub fn from_bitmask(mask: u8) -> Vec<Category> {
        [Category::Type, Category::Logic, Category::Security, 
         Category::Receipt, Category::Identity, Category::Rhythm]
            .iter()
            .filter(|&&c| (mask & c as u8) != 0)
            .copied()
            .collect()
    }
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Copy, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum RepairStrategy {
    Auto = 1,
    #[default]
    Manual = 2,
    Hybrid = 3,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Copy, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum ReceiptStatus {
    #[default]
    Pending = 0,
    Verified = 1,
    Disputed = 2,
    Fixed = 3,
    RiskAccepted = 4,
}

// ─────────────────────────────────────────────────────
// Core Structs (Aligned with Move DiagnosticReceipt)
// ─────────────────────────────────────────────────────
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Default)]
pub struct SourceLocation {
    pub language: String,  // rust|julia|elixir|lisp|python|go|move|wasm|ts
    pub role: OrishaMask, // Access|History|Spawn|Policy|Run|Sync|Score
    pub file: String,
    pub line: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span: Option<Span>,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Default)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Default)]
pub struct DiagnosticContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub birth_timestamp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<u8>,
    pub sabbath_active: bool,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Default)]
pub struct DiagnosticInfo {
    pub code: String,
    pub severity: Severity,
    pub category: u8,
    pub message: String,
    pub context: DiagnosticContext,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Default)]
pub struct RepairStep {
    pub action: String,
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub payload: serde_json::Value,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Default)]
pub struct RepairValidation {
    pub pre_check: Vec<String>,
    pub post_check: Vec<String>,
    pub rollback_safe: bool,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Default)]
pub struct RepairPlan {
    pub id: String,
    pub strategy: RepairStrategy,
    pub steps: Vec<RepairStep>,
    pub validation: RepairValidation,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Default)]
pub struct AuditTrail {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zangbeto_sig: Option<String>,
    pub ts: DateTime<Utc>,
}

// ─────────────────────────────────────────────────────
// Top-Level Diagnostic
// ─────────────────────────────────────────────────────
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone, Default)]
pub struct Diagnostic {
    pub version: String,
    #[serde(default = "Uuid::new_v4")]
    pub trace_id: Uuid,
    pub language: String,
    pub role: OrishaMask,
    pub source: SourceLocation,
    pub diagnostic: DiagnosticInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repair: Option<RepairPlan>,
    pub audit_trail: AuditTrail,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub red_team_round: Option<u64>,

    // ─────────────────────────────────────────────────────
    // Constitutional Receipt Fields
    // ─────────────────────────────────────────────────────
    pub witness_quorum: Vec<String>,
    pub constitutional_class: String,
    pub economic_impact: Option<u64>,
    pub seal_policy: Option<String>,
    pub sovereign_scope: String,
}

#[derive(thiserror::Error, Debug)]
pub enum DiagnosticError {
    #[error("Invalid schema: {0}")]
    SchemaInvalid(String),
    #[error("Signature verification failed")]
    SignatureInvalid,
}

impl Diagnostic {
    pub fn new(
        language: String,
        role: OrishaMask,
        file: String,
        line: u32,
        code: String,
        severity: Severity,
        categories: &[Category],
        message: String,
        context: DiagnosticContext,
    ) -> Self {
        Self {
            version: "1.1".into(),
            trace_id: Uuid::new_v4(),
            language: language.clone(),
            role,
            source: SourceLocation {
                language,
                role,
                file,
                line,
                column: None,
                span: None,
            },
            diagnostic: DiagnosticInfo {
                code,
                severity,
                category: Category::as_bitmask(categories),
                message,
                context,
            },
            repair: None,
            audit_trail: AuditTrail {
                zangbeto_sig: None,
                ts: Utc::now(),
            },
            red_team_round: None,
            witness_quorum: vec![],
            constitutional_class: "general".into(),
            economic_impact: None,
            seal_policy: None,
            sovereign_scope: "global".into(),
        }
    }

    pub fn with_repair(mut self, plan: RepairPlan) -> Self {
        self.repair = Some(plan);
        self
    }

    pub fn with_heartbeat_round(mut self, round: u64) -> Self {
        self.red_team_round = Some(round);
        self
    }

    pub fn emit_to_stderr(&self) -> Result<(), serde_json::Error> {
        let json = serde_json::to_string(self)?;
        eprintln!("{}", json);
        Ok(())
    }

    pub fn compute_message_hash(&self) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(self.diagnostic.message.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diagnostic_creation() {
        let context = DiagnosticContext {
            agent_id: Some("agent-1".into()),
            birth_timestamp: Some(1000),
            tier: Some(1),
            sabbath_active: false,
        };
        let diag = Diagnostic::new(
            "rust".into(),
            OrishaMask::Eshu,
            "main.rs".into(),
            10,
            "ERR-001".into(),
            Severity::Error,
            &[Category::Security, Category::Logic],
            "Security breach".into(),
            context,
        );

        assert_eq!(diag.role, OrishaMask::Eshu);
        assert_eq!(diag.diagnostic.category, (Category::Security as u8 | Category::Logic as u8));
        assert_eq!(diag.constitutional_class, "general");
        assert_eq!(diag.sovereign_scope, "global");
    }

    #[test]
    fn test_category_bitmask() {
        let categories = vec![Category::Type, Category::Security];
        let mask = Category::as_bitmask(&categories);
        assert_eq!(mask, 1 | 4);
        
        let decoded = Category::from_bitmask(mask);
        assert!(decoded.contains(&Category::Type));
        assert!(decoded.contains(&Category::Security));
        assert!(!decoded.contains(&Category::Logic));
    }
}

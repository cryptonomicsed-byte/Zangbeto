use crate::zangbeto_client::{ZangbetoClient, ZangbetoPayload};
use crate::{Diagnostic, Severity, Category, RepairStrategy};
use crate::agent::sandbox::Sandbox;
use tokio::sync::mpsc;
use tracing::{info, error};
use std::path::Path;

pub struct DiagnosticHandler {
    pub zangbeto: ZangbetoClient,
    pub diag_tx: mpsc::Sender<Diagnostic>,
    pub auto_merge_threshold: Severity,
    pub security_categories: u8,
    pub workspace_root: std::path::PathBuf,
}

impl DiagnosticHandler {
    pub fn new(
        zangbeto: ZangbetoClient,
        diag_tx: mpsc::Sender<Diagnostic>,
        auto_merge_threshold: Severity,
        workspace_root: std::path::PathBuf,
    ) -> Self {
        Self {
            zangbeto,
            diag_tx,
            auto_merge_threshold,
            security_categories: Category::as_bitmask(&[Category::Security, Category::Identity]),
            workspace_root,
        }
    }

    pub async fn handle_line(&self, line: &str) -> Result<HandlerAction, crate::DiagnosticError> {
        let diag: Diagnostic = serde_json::from_str(line)
            .map_err(|e| crate::DiagnosticError::SchemaInvalid(e.to_string()))?;

        // ⚪ White Court Arbitration
        match crate::agent::courts::WhiteCourt::arbitrate(&diag).await {
            crate::agent::courts::CourtDecision::Approve => info!("⚪ White Court: Approved"),
            crate::agent::courts::CourtDecision::Reject(reason) => {
                info!("⚪ White Court: REJECTED - {}", reason);
                return Ok(HandlerAction::Rejected(reason));
            }
            crate::agent::courts::CourtDecision::Escalate => {
                info!("⚪ White Court: ESCALATED to Twelve Thrones");
                return Ok(HandlerAction::EscalateToTwelveThrones);
            }
            crate::agent::courts::CourtDecision::NeedsMoreInfo => {
                return Ok(HandlerAction::EscalateToHuman);
            }
        }

        self.diag_tx.send(diag.clone()).await
            .map_err(|_| crate::DiagnosticError::SchemaInvalid("Channel closed".into()))?;

        if (diag.diagnostic.category & self.security_categories) != 0 {
            info!("🔐 Security diagnostic: awaiting Zangbeto verification");
            let hash = diag.compute_message_hash();
            let payload = ZangbetoPayload::from_diagnostic(&diag, &hash);
            let receipt = self.zangbeto.submit_diagnostic(payload.clone()).await
                .map_err(|e| crate::DiagnosticError::SchemaInvalid(e.to_string()))?;

            if !self.zangbeto.verify_signature(&receipt.receipt_id, &payload, &receipt.zangbeto_sig)? {
                return Err(crate::DiagnosticError::SignatureInvalid);
            }
            
            Ok(HandlerAction::VerifiedOnChain(receipt))
        } else {
            // Local repair check
            if self.should_auto_merge(&diag) {
                info!("🛠  Local repair eligible for: {}", diag.diagnostic.code);
                Ok(HandlerAction::LocalRepairEligible)
            } else {
                Ok(HandlerAction::EscalateToHuman)
            }
        }
    }

    pub async fn execute_repair(&self, diag: &Diagnostic) -> Result<bool, Box<dyn std::error::Error>> {
        let _sandbox = Sandbox::new(&self.workspace_root).await?;
        
        if let Some(ref plan) = diag.repair {
            // In a real scenario, we'd apply the steps
            info!("🚀 Executing repair plan: {}", plan.id);
            
            // For now, simulate success
            for step in &plan.steps {
                info!("   - Step: {} on {}", step.action, step.target);
            }
            
            // Run pre-checks
            for check in &plan.validation.pre_check {
                info!("   - Running pre-check: {}", check);
            }
            
            // Run post-checks
            for check in &plan.validation.post_check {
                info!("   - Running post-check: {}", check);
            }
            
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn should_auto_merge(&self, diag: &Diagnostic) -> bool {
        // Must pass White Court first (implied as it's called in handle_line)
        if diag.diagnostic.severity as u8 > self.auto_merge_threshold as u8 {
            return false;
        }
        if (diag.diagnostic.category & self.security_categories) != 0 {
            return false;
        }
        if let Some(ref plan) = diag.repair {
            plan.strategy == RepairStrategy::Auto
        } else {
            false
        }
    }
}

pub enum HandlerAction {
    VerifiedOnChain(crate::zangbeto_client::ZangbetoReceipt),
    LocalRepairEligible,
    EscalateToHuman,
    EscalateToTwelveThrones,
    Rejected(String),
}

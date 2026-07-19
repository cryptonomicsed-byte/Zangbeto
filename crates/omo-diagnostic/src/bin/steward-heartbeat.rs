//! Minimal self-healing heartbeat engine with mock Red/Blue agents
use clap::Parser;
use tokio::time::{interval, Duration};
use omo_diagnostic::{Diagnostic, Severity, Category, DiagnosticContext, RepairPlan, RepairStrategy, RepairStep, RepairValidation, OrishaMask};
use omo_diagnostic::agent::courts::{WhiteCourt, CourtDecision};
use std::collections::HashMap;

#[derive(Parser, Debug)]
#[command(author, version, about = "Omo-Koda Self-Healing Heartbeat")]
struct Args {
    #[arg(short, long, default_value = "5")]
    rounds: u64,
    #[arg(short, long, default_value = "10")]
    interval: u64,
    #[arg(long, default_value = "warning")]
    auto_merge: String,
}

// ─────────────────────────────────────────────────────
// Mock Red Agent (Generates Safe Test Mutations)
// ─────────────────────────────────────────────────────
struct MockRedAgent;

impl MockRedAgent {
    async fn generate_attack(&self, round: u64) -> Option<Diagnostic> {
        match round % 4 {
            0 => Some(Diagnostic::new(
                "rust".into(),
                OrishaMask::Eshu,
                "src/interpreter.rs".into(),
                142,
                "OMO-ERR-017".into(),
                Severity::Warning,
                &[Category::Logic],
                "Tier gate missing before tool execution".into(),
                DiagnosticContext {
                    agent_id: Some("0xtest".into()),
                    birth_timestamp: Some(1716234567),
                    tier: Some(2),
                    sabbath_active: false,
                },
            ).with_heartbeat_round(round).with_repair(RepairPlan {
                id: "fix-tier-gate".into(),
                strategy: RepairStrategy::Auto,
                steps: vec![RepairStep {
                    action: "insert".into(),
                    target: "code".into(),
                    path: Some("src/interpreter.rs".into()),
                    payload: serde_json::json!({"check": "agent.tier >= required_tier"}),
                }],
                validation: RepairValidation {
                    pre_check: vec!["cargo check".into()],
                    post_check: vec!["cargo test --package omokoda-core".into()],
                    rollback_safe: true,
                },
            })),
            1 => Some(Diagnostic::new(
                "python".into(),
                OrishaMask::Ogun,
                "tools/data_fetcher.py".into(),
                27,
                "OMO-ERR-023".into(),
                Severity::Error,
                &[Category::Receipt, Category::Security], // Trigger escalation
                "Receipt validation missing null check".into(),
                DiagnosticContext {
                    agent_id: Some("0xtest".into()),
                    birth_timestamp: Some(1716234567),
                    tier: Some(1),
                    sabbath_active: false,
                },
            ).with_heartbeat_round(round).with_repair(RepairPlan {
                id: "patch-python-tool".into(),
                strategy: RepairStrategy::Auto,
                steps: vec![],
                validation: RepairValidation {
                    pre_check: vec!["python -m pytest tools/".into()],
                    post_check: vec!["python -m pytest tools/".into()],
                    rollback_safe: true,
                },
            })),
            2 => Some(Diagnostic::new(
                "lisp".into(),
                OrishaMask::Obatala,
                "ritual/core.lisp".into(),
                108,
                "OMO-ERR-666".into(),
                Severity::Warning,
                &[Category::Rhythm],
                "Sabbath violation: active thought during rest".into(),
                DiagnosticContext {
                    agent_id: Some("0xrest".into()),
                    birth_timestamp: Some(1716234567),
                    tier: Some(4),
                    sabbath_active: true, // Trigger Sabbath rejection
                },
            ).with_heartbeat_round(round)),
            _ => Some(Diagnostic::new(
                "move".into(),
                OrishaMask::Shango,
                "shrine/sources/example.move".into(),
                33,
                "OMO-ERR-042".into(),
                Severity::Warning,
                &[Category::Type],
                "Balance check missing before transfer".into(),
                DiagnosticContext {
                    agent_id: Some("0xtest".into()),
                    birth_timestamp: Some(1716234567),
                    tier: Some(3),
                    sabbath_active: false,
                },
            ).with_heartbeat_round(round).with_repair(RepairPlan {
                id: "fix-balance-check".into(),
                strategy: RepairStrategy::Auto,
                steps: vec![],
                validation: RepairValidation {
                    pre_check: vec!["sui move test".into()],
                    post_check: vec!["sui move test".into()],
                    rollback_safe: true,
                },
            })),
        }
    }
}

// ─────────────────────────────────────────────────────
// Mock Blue Agents (Propose Minimal Fixes)
// ─────────────────────────────────────────────────────
struct MockBlueAgent {
    id: u8,
    success_rate: f64,
}

impl MockBlueAgent {
    fn new(id: u8) -> Self {
        Self { id, success_rate: 0.9 }
    }

    async fn handle_diagnostic(&self, diag: &Diagnostic) -> Result<FixProposal, String> {
        if rand::random::<f64>() > self.success_rate {
            return Err("Validation failed".into());
        }

        Ok(FixProposal {
            repair_id: diag.repair.as_ref().map(|r| r.id.clone()).unwrap_or_default(),
            patch_diff: format!("@@ -{},6 +{},8 @@\n+    // Auto-fix by Blue-{}\n+    assert!(condition, E_FIX);", 
                               diag.source.line, diag.source.line, self.id),
            validation: diag.repair.as_ref().map(|r| r.validation.clone()).unwrap_or_default(),
        })
    }
}

struct FixProposal {
    repair_id: String,
    patch_diff: String,
    validation: RepairValidation,
}

// ─────────────────────────────────────────────────────
// Minimal Repair Registry (Demo Only)
// ─────────────────────────────────────────────────────
struct DemoRepairRegistry {
    strategies: HashMap<String, bool>,
}

impl DemoRepairRegistry {
    fn new() -> Self {
        let mut reg = Self { strategies: HashMap::new() };
        reg.strategies.insert("fix-tier-gate".into(), true);
        reg.strategies.insert("patch-python-tool".into(), true);
        reg.strategies.insert("fix-balance-check".into(), true);
        reg
    }

    fn can_execute(&self, repair_id: &str) -> bool {
        self.strategies.get(repair_id).copied().unwrap_or(false)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let auto_merge_threshold = match args.auto_merge.as_str() {
        "info" => Severity::Info,
        "warning" => Severity::Warning,
        "error" => Severity::Error,
        _ => Severity::Warning,
    };

    println!("⚔️  Starting Omo-Koda Self-Healing Heartbeat");
    let red = MockRedAgent;
    let blues = vec![MockBlueAgent::new(1), MockBlueAgent::new(2), MockBlueAgent::new(3)];
    let registry = DemoRepairRegistry::new();

    let mut kernel_engine = omo_kernel::kernel::engine::StateTransitionEngine::new();
    let mut current_state = omo_kernel::kernel::css::CanonicalSystemState::default();
    let env_ctx = omo_kernel::kernel::engine::EnvironmentContext {
        timestamp: chrono::Utc::now().timestamp() as u64,
        external_signals: std::collections::HashMap::new(),
    };

    println!("🌐 Reality VM initialized: {}", current_state.state_hash);

    let (diag_tx, mut diag_rx) = tokio::sync::mpsc::channel::<Diagnostic>(100);

    // Port 8787 is the real Zàngbétò enforcement bridge; fetch its guardian's
    // real public key rather than a hardcoded placeholder (see steward.rs
    // for the same fix and rationale).
    let zangbeto_endpoint =
        std::env::var("ZANGBETO_URL").unwrap_or_else(|_| "http://localhost:8787".into());
    let bootstrap_client =
        omo_diagnostic::zangbeto_client::ZangbetoClient::new(zangbeto_endpoint.clone(), String::new());
    let guardian_pubkey = match bootstrap_client.fetch_guardian_pubkey().await {
        Ok(pk) => pk,
        Err(e) => {
            eprintln!("⚠️  failed to fetch Zàngbétò guardian pubkey from {zangbeto_endpoint}: {e}");
            String::new()
        }
    };

    let handler = omo_diagnostic::agent::diagnostic_handler::DiagnosticHandler::new(
        omo_diagnostic::zangbeto_client::ZangbetoClient::new(zangbeto_endpoint, guardian_pubkey),
        diag_tx.clone(),
        auto_merge_threshold,
        std::env::current_dir().unwrap(),
    );

    let _listener_handle = tokio::spawn(async move {
        while let Some(diag) = diag_rx.recv().await {
            println!("📡 Diagnostic received: {} (round={:?})", 
                     diag.diagnostic.code, diag.red_team_round);
        }
    });

    let mut ticker = interval(Duration::from_secs(args.interval));
    let mut round: u64 = 0;

    while round < args.rounds {
        ticker.tick().await;
        round += 1;
        println!("\n🔴 Round #{}", round);

        if let Some(diag) = red.generate_attack(round).await {
            println!("   🔍 Found: {} (severity={:?}, category=0x{:x})", 
                     diag.diagnostic.code, diag.diagnostic.severity, diag.diagnostic.category);

            // ⚪ White Court Arbitration
            match WhiteCourt::arbitrate(&diag).await {
                CourtDecision::Approve => println!("   ⚪ White Court: Approved"),
                CourtDecision::Reject(reason) => {
                    println!("   ⚪ White Court: REJECTED - {}", reason);
                    continue;
                }
                CourtDecision::Escalate => {
                    println!("   ⚪ White Court: ESCALATED to Twelve Thrones");
                    continue;
                }
                CourtDecision::NeedsMoreInfo => {
                    println!("   ⚪ White Court: Needs more info");
                    continue;
                }
            }

            let blue = &blues[(round as usize) % blues.len()];
            match blue.handle_diagnostic(&diag).await {
                Ok(fix) => {
                    println!("   🔵 Blue-{} proposed fix: {}", blue.id, fix.repair_id);

                    // Update Reality VM state with the fix intent
                    let intent = format!("Apply fix {} for {}", fix.repair_id, diag.diagnostic.code);
                    match kernel_engine.transition(current_state.clone(), intent, env_ctx.clone()).await {
                        Ok(new_state) => {
                            current_state = new_state;
                            println!("   🜂 Reality updated: {}", current_state.state_hash);
                        }
                        Err(e) => println!("   ⚠️ Reality transition failed: {}", e),
                    }
                    
                    if registry.can_execute(&fix.repair_id) {
                        let can_auto = diag.diagnostic.severity as u8 <= auto_merge_threshold as u8
                            && (diag.diagnostic.category & (Category::Security as u8 | Category::Identity as u8)) == 0
                            && diag.repair.as_ref().map(|r| r.strategy == RepairStrategy::Auto).unwrap_or(false);
                        
                        if can_auto {
                            println!("   ✅ Auto-merge eligible: applying patch");
                            println!("   📝 Patch preview:\n{}", fix.patch_diff);
                            let _ = diag_tx.send(diag).await;
                        } else {
                            println!("   ⚠️  Requires human review (security category or high severity)");
                        }
                    } else {
                        println!("   ❌ No registered strategy for {}", fix.repair_id);
                    }
                }
                Err(e) => println!("   ❌ Blue fix failed: {}", e),
            }
        } else {
            println!("   ℹ️  No anomaly detected");
        }
    }

    println!("\n✅ Heartbeat complete.");
    Ok(())
}

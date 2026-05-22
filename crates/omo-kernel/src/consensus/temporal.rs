use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use crate::zangbeto::event::ValidatorReport;

/// ⏳ Temporal Weight: authority that evolves over time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalWeight {
    pub orisha: String,
    pub base_weight: u8,           // 1-10 initial authority
    pub weight_function: WeightFunction,
    pub last_updated: u64,
    pub trust_history: Vec<TrustEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "params")]
pub enum WeightFunction {
    #[serde(rename = "exponential_decay")]
    ExponentialDecay { half_life_hours: f64, min_weight: u8 },
    
    #[serde(rename = "harmonic_accumulation")]
    HarmonicAccumulation { max_weight: u8, convergence_rate: f64 },
    
    #[serde(rename = "event_triggered")]
    EventTriggered { trigger_events: Vec<String>, weight_on_trigger: u8 },
    
    #[serde(rename = "consensus_dependent")]
    ConsensusDependent { depends_on: Vec<String>, correlation_factor: f64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEvent {
    pub timestamp: u64,
    pub event_type: TrustEventType,
    pub impact_delta: i8,  // -5 to +5
    pub context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrustEventType {
    #[serde(rename = "correct_validation")]
    CorrectValidation,
    #[serde(rename = "false_positive")]
    FalsePositive,
    #[serde(rename = "false_negative")]
    FalseNegative,
    #[serde(rename = "drift_detected")]
    DriftDetected,
    #[serde(rename = "successful_repair")]
    SuccessfulRepair,
}

impl TemporalWeight {
    /// 📈 Compute current weight based on time + history
    pub fn current_weight(&self, now: u64) -> f64 {
        let elapsed_hours = (now.saturating_sub(self.last_updated)) as f64 / 3600.0;
        
        let base = self.base_weight as f64;
        
        let dynamic = match &self.weight_function {
            WeightFunction::ExponentialDecay { half_life_hours, min_weight } => {
                let decay = 0.5f64.powf(elapsed_hours / half_life_hours);
                let computed = base * decay;
                computed.max(*min_weight as f64)
            }
            WeightFunction::HarmonicAccumulation { max_weight, convergence_rate } => {
                let history_score = self.trust_history.iter()
                    .map(|e| e.impact_delta as f64 * 0.1)
                    .sum::<f64>();
                let accumulated = base + history_score * convergence_rate;
                accumulated.min(*max_weight as f64)
            }
            WeightFunction::EventTriggered { trigger_events, weight_on_trigger } => {
                // Check if any trigger event occurred recently
                let recent_triggers = self.trust_history.iter()
                    .filter(|e| trigger_events.iter().any(|t| format!("{:?}", e.event_type).to_lowercase().contains(&t.to_lowercase())))
                    .count();
                if recent_triggers > 0 {
                    *weight_on_trigger as f64
                } else {
                    base
                }
            }
            WeightFunction::ConsensusDependent { correlation_factor, .. } => {
                // In production: query other Orisha weights and correlate
                // Simplified: assume positive correlation
                base * (1.0 + correlation_factor * 0.1)
            }
        };
        
        dynamic.clamp(0.0, 10.0)
    }
    
    /// 📝 Record a trust event
    pub fn record_event(&mut self, event: TrustEvent) {
        self.trust_history.push(event);
        // Keep history bounded
        if self.trust_history.len() > 1000 {
            self.trust_history.drain(0..100);
        }
        self.last_updated = chrono::Utc::now().timestamp() as u64;
    }
}

/// 🗳️ Temporal Consensus: weighted vote with time-aware resolution
pub struct TemporalConsensusEngine {
    pub weights: HashMap<String, TemporalWeight>,  // orisha_name → weight
    pub quorum_threshold: f64,  // e.g., 7.0 out of 10.0 max
}

impl TemporalConsensusEngine {
    pub fn new(quorum_threshold: f64) -> Self {
        Self {
            weights: HashMap::new(),
            quorum_threshold,
        }
    }
    
    /// Register an Orisha validator with temporal weight config
    pub fn register_orisha(&mut self, orisha: &str, config: TemporalWeight) {
        self.weights.insert(orisha.to_string(), config);
    }
    
    /// 🗳️ Compute weighted consensus from validator reports
    pub fn compute_consensus(
        &self,
        reports: &[ValidatorReport],
        timestamp: u64,
    ) -> ConsensusDecision {
        let mut total_weight = 0.0;
        let mut approved_weight = 0.0;
        let mut dissent_details = Vec::new();
        
        for report in reports {
            if let Some(weight_config) = self.weights.get(&report.orisha) {
                let weight = weight_config.current_weight(timestamp);
                total_weight += weight;
                
                if report.passed {
                    approved_weight += weight;
                } else {
                    dissent_details.push(DissentDetail {
                        orisha: report.orisha.clone(),
                        weight,
                        reasons: report.reasons.clone(),
                    });
                }
            }
        }
        
        let quorum_met = if total_weight > 0.0 {
             approved_weight >= (total_weight * self.quorum_threshold / 10.0)
        } else {
            false
        };
        
        ConsensusDecision {
            approved: quorum_met,
            total_weight,
            approved_weight,
            dissent_details,
            confidence: if total_weight > 0.0 {
                approved_weight / total_weight
            } else {
                0.0
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConsensusDecision {
    pub approved: bool,
    pub total_weight: f64,
    pub approved_weight: f64,
    pub dissent_details: Vec<DissentDetail>,
    pub confidence: f64,
}

#[derive(Debug, Clone)]
pub struct DissentDetail {
    pub orisha: String,
    pub weight: f64,
    pub reasons: Vec<String>,
}

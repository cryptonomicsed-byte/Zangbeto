module zbt::zbt_v2 {
    use std::vector;
    use std::string;
    use std::option::{Self, Option};
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID, ID};
    use sui::event;

    /// 🟥 Ṣàngó: Final authority on committed reality events
    public struct RealityEventReceipt has key, store {
        id: UID,
        event_id: vector<u8>,           // UUID bytes
        pre_state_hash: vector<u8>,     // sha256 hex as bytes
        post_state_hash: vector<u8>,
        fingerprint: TransitionFingerprint,
        drift_detected: bool,
        drift_type: Option<DriftType>,
        repair_applied: bool,
        role_consensus: vector<ValidatorSignature>,
        committed_epoch: u64,
    }

    public struct TransitionFingerprint has store {
        intent_hash: vector<u8>,
        validator_set_hash: vector<u8>,
        op_signature: vector<u8>,
        environment_hash: vector<u8>,
    }

    public struct ValidatorSignature has store {
        role: string::String,
        signature: vector<u8>,
        public_key: vector<u8>,
        authority_weight: u8,
    }

    public enum DriftType has store {
        Schema { field: vector<u8> },
        Ethical { violation: vector<u8> },
        Memory { deviation: u64, confidence: u64 },
        Economic { balance_anomaly: u64, is_negative: bool, reputation_shift: u64 },
        Temporal { expected: u64, actual: u64 },
        Execution { tool_failure: vector<u8>, rollback_triggered: bool },
    }

    /// Emit event when reality transition is anchored
    public struct RealityAnchored has copy, drop {
        receipt_id: ID,
        event_id: vector<u8>,
        final_state_hash: vector<u8>,
        drift_detected: bool,
        epoch: u64,
    }

    /// Commit verified event to on-chain ledger
    public entry fun commit_event(
        event_id: vector<u8>,
        pre_hash: vector<u8>,
        post_hash: vector<u8>,
        fingerprint_intent: vector<u8>,
        fingerprint_validators: vector<u8>,
        fingerprint_op: vector<u8>,
        fingerprint_env: vector<u8>,
        drift_detected: bool,
        repair_applied: bool,
        ctx: &mut TxContext
    ) {
        let fingerprint = TransitionFingerprint {
            intent_hash: fingerprint_intent,
            validator_set_hash: fingerprint_validators,
            op_signature: fingerprint_op,
            environment_hash: fingerprint_env,
        };

        let receipt = RealityEventReceipt {
            id: object::new(ctx),
            event_id,
            pre_state_hash: pre_hash,
            post_state_hash: post_hash,
            fingerprint,
            drift_detected,
            drift_type: option::none(),
            repair_applied,
            role_consensus: vector::empty(),
            committed_epoch: tx_context::epoch(ctx),
        };
        
        let receipt_id = object::id(&receipt);
        
        event::emit(RealityAnchored {
            receipt_id,
            event_id: event_id.clone(),
            final_state_hash: post_hash,
            drift_detected,
            epoch: tx_context::epoch(ctx),
        });
        
        sui::transfer::public_transfer(receipt, tx_context::sender(ctx));
    }

    /// Query: verify event was anchored
    public fun verify_anchored(receipt: &RealityEventReceipt, expected_hash: vector<u8>): bool {
        receipt.post_state_hash == expected_hash
    }
}

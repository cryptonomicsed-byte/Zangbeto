module zbt::guard {
    use 0x2::event;
    use 0x2::tx_context::TxContext;
    use 0x2::object::{Self, ID};

    struct InvariantBreach has drop, store { rule: vector<u8>, code: u64 }
    struct ReceiptEvent has drop, store { tag: vector<u8>, severity: u8, rule: vector<u8>, evidence_hash: vector<u8> }
    struct FixEvent has drop, store { receipt_id: u64, fix_hash: vector<u8> }
    struct DiagnosticEmitted has drop, store {
        receipt_id: ID,
        code: vector<u8>,
        severity: u8,
        category: u8,
        agent_id: vector<u8>,
        repair_id: vector<u8>,
    }
    struct AutoRepairExecuted has drop, store {
        receipt_id: ID,
        repair_id: vector<u8>,
        result: bool,
        gas_used: u64,
    }

    public fun invariant_true(cond: bool, code: u64) {
        if (!cond) {
            event::emit<InvariantBreach>(InvariantBreach{ rule: b"runtime", code });
            abort code;
        }
    }

    public fun receipt(tag: vector<u8>, severity: u8, rule: vector<u8>, evidence_hash: vector<u8>, _ctx: &mut TxContext) {
        event::emit<ReceiptEvent>(ReceiptEvent{ tag, severity, rule, evidence_hash });
    }

    public fun mark_fixed(receipt_id: u64, fix_hash: vector<u8>) {
        event::emit<FixEvent>(FixEvent{ receipt_id, fix_hash });
    }

    public fun emit_diagnostic_event(
        receipt_id: ID,
        code: vector<u8>,
        severity: u8,
        category: u8,
        agent_id: vector<u8>,
        repair_id: vector<u8>,
    ) {
        event::emit<DiagnosticEmitted>(DiagnosticEmitted {
            receipt_id,
            code,
            severity,
            category,
            agent_id,
            repair_id,
        });
    }

    public fun emit_auto_repair_event(
        receipt_id: ID,
        repair_id: vector<u8>,
        result: bool,
        gas_used: u64,
    ) {
        event::emit<AutoRepairExecuted>(AutoRepairExecuted {
            receipt_id,
            repair_id,
            result,
            gas_used,
        });
    }
}

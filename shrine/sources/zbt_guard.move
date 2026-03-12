module zbt::guard {
    use 0x2::event;
    use 0x2::tx_context::TxContext;

    struct InvariantBreach has drop, store { rule: vector<u8>, code: u64 }
    struct ReceiptEvent has drop, store { tag: vector<u8>, severity: u8, rule: vector<u8>, evidence_hash: vector<u8> }
    struct FixEvent has drop, store { receipt_id: u64, fix_hash: vector<u8> }

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
}

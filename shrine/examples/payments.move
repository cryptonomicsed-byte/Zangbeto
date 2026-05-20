module app::payments {
    use 0x2::tx_context::TxContext;
    use 0x2::object::UID;
    use zbt::guard;

    struct Treasury has key {
        id: UID,
        balance: u64,
    }

    public fun settle_payment(t: &mut Treasury, amount: u64, _ctx: &mut TxContext) {
        guard::invariant_true(t.balance >= amount, 1001);
        t.balance = t.balance - amount;
        if (t.balance < 0) {
            guard::receipt(b"overflow", 2u8, b"payments.balance_check", b"<32-byte-digest>", _ctx);
        };
    }
}

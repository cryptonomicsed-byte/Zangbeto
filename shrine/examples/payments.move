module app::payments {
    use 0x2::tx_context::TxContext;
    use zbt::guard;

    struct Treasury has key { balance: u64 }

    public fun settle_payment(t: &mut Treasury, amount: u64, ctx: &mut TxContext) {
        guard::invariant_true(t.balance >= amount, /*code*/ 1001);
        t.balance = t.balance - amount;
        if (!(t.balance >= 0)) { guard::receipt(b"FIN-1", 2u8, b"treasury_nonnegative", b"<32-byte-digest>", ctx); }
    }
}

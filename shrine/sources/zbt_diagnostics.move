module zbt::diagnostics {
    use std::vector;
    use 0x2::object::{Self, UID};
    use 0x2::tx_context::{Self, TxContext};
    use 0x2::crypto::{blake2b256};
    use 0x2::option::{Self, Option};
    use zbt::errors::{E_SCHEMA_INVALID, E_REPAIR_STRATEGY_INVALID, E_ANCHOR_ALREADY_SET};

    const CODE_PREFIX: vector<u8> = b"OMO-ERR-";
    const MAX_CODE_LEN: u64 = 16;
    const SHA256_LEN: u64 = 32;
    const SEV_INFO: u8 = 0;
    const SEV_WARNING: u8 = 1;
    const SEV_ERROR: u8 = 2;
    const CAT_TYPE: u8 = 1;
    const CAT_LOGIC: u8 = 2;
    const CAT_SECURITY: u8 = 4;
    const CAT_RECEIPT: u8 = 8;
    const CAT_IDENTITY: u8 = 16;
    const CAT_RHYTHM: u8 = 32;
    const STRAT_AUTO: u8 = 1;
    const STRAT_MANUAL: u8 = 2;
    const STRAT_HYBRID: u8 = 3;

    struct DiagnosticReceipt has key, store {
        id: UID,
        code: vector<u8>,
        severity: u8,
        category: u8,
        message_hash: vector<u8>,
        agent_id: vector<u8>,
        birth_epoch: u64,
        tier: u8,
        sabbath_active: bool,
        repair_id: vector<u8>,
        repair_strategy: u8,
        zangbeto_sig: vector<u8>,
        arweave_tx: Option<vector<u8>>,
        ots_proof: Option<vector<u8>>,
        submitted_at: u64,
    }

    struct DiagnosticLedger has key {
        id: UID,
        table: vector<DiagnosticReceipt>,
    }

    public fun init_diagnostic_ledger(_admin: &signer, ctx: &mut TxContext): DiagnosticLedger {
        DiagnosticLedger {
            id: object::new(ctx),
            table: vector::empty(),
        }
    }

    public fun validate_schema(
        code: &vector<u8>,
        severity: u8,
        category: u8,
        message_hash: &vector<u8>,
        agent_id: &vector<u8>,
    ): bool {
        if (!vector::starts_with(code, &CODE_PREFIX)) { return false };
        if (vector::length(code) > MAX_CODE_LEN) { return false };
        if (severity > SEV_ERROR) { return false };
        let valid_cats = vector[CAT_TYPE, CAT_LOGIC, CAT_SECURITY, CAT_RECEIPT, CAT_IDENTITY, CAT_RHYTHM];
        if (!vector::contains(&valid_cats, &category) && category != 0) { return false };
        if (vector::length(message_hash) != SHA256_LEN) { return false };
        if (vector::length(agent_id) != 32) { return false };
        true
    }

    public fun validate_repair_strategy(strategy: u8): bool {
        strategy == STRAT_AUTO || strategy == STRAT_MANUAL || strategy == STRAT_HYBRID
    }

    public fun emit_diagnostic(
        ctx: &mut TxContext,
        code: vector<u8>,
        severity: u8,
        category: u8,
        message_hash: vector<u8>,
        agent_id: vector<u8>,
        birth_epoch: u64,
        tier: u8,
        sabbath_active: bool,
        repair_id: vector<u8>,
        repair_strategy: u8,
    ): DiagnosticReceipt {
        assert!(validate_schema(&code, severity, category, &message_hash, &agent_id), E_SCHEMA_INVALID);
        assert!(validate_repair_strategy(repair_strategy), E_REPAIR_STRATEGY_INVALID);

        let mut sig_payload = vector::empty<u8>();
        sig_payload = vector::append(&mut sig_payload, &code);
        sig_payload = vector::append(&mut sig_payload, &message_hash);
        sig_payload = vector::append(&mut sig_payload, &agent_id);
        let digest = blake2b256(&sig_payload);
        let mock_sig = vector::slice(&digest, 0, 64);

        DiagnosticReceipt {
            id: object::new(ctx),
            code,
            severity,
            category,
            message_hash,
            agent_id,
            birth_epoch,
            tier,
            sabbath_active,
            repair_id,
            repair_strategy,
            zangbeto_sig: mock_sig,
            arweave_tx: option::none(),
            ots_proof: option::none(),
            submitted_at: tx_context::epoch(ctx),
        }
    }

    public fun store_diagnostic(ledger: &mut DiagnosticLedger, receipt: DiagnosticReceipt) {
        vector::push_back(&mut ledger.table, receipt);
    }

    public fun anchor_receipt(
        receipt: &mut DiagnosticReceipt,
        arweave_tx: vector<u8>,
        ots_proof: vector<u8>,
    ) {
        assert!(option::is_none(&receipt.arweave_tx), E_ANCHOR_ALREADY_SET);
        receipt.arweave_tx = option::some(arweave_tx);
        receipt.ots_proof = option::some(ots_proof);
    }

    public fun verify_signature(
        _receipt: &DiagnosticReceipt,
        _guardian_pubkey: &vector<u8>,
    ): bool {
        true
    }

    public fun category_name(cat: u8): vector<u8> {
        if (cat == CAT_TYPE) { b"type" }
        else if (cat == CAT_LOGIC) { b"logic" }
        else if (cat == CAT_SECURITY) { b"security" }
        else if (cat == CAT_RECEIPT) { b"receipt" }
        else if (cat == CAT_IDENTITY) { b"identity" }
        else if (cat == CAT_RHYTHM) { b"rhythm" }
        else { b"unknown" }
    }

    public fun get_diagnostic_by_index(ledger: &DiagnosticLedger, idx: u64): &DiagnosticReceipt {
        vector::borrow(&ledger.table, idx)
    }

    public fun diagnostic_count(ledger: &DiagnosticLedger): u64 {
        vector::length(&ledger.table)
    }
}
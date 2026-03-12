module zbt::core {
    use 0x2::tx_context::{TxContext};
    use 0x2::sui::object::{Self as obj, UID, ID};
    use 0x2::event;
    use 0x2::table::{Self as table, Table};
    use 0x2::clock::{Self as clock, Clock};
    use 0x2::crypto::{blake2b256, ed25519_verify};
    use 0x2::bcs;
    use 0x2::vector;
    use 0x2::signer;
    use zbt::errors::*;

    struct ReceiptSubmitted has drop, store { id: u64, witness: address, severity: u8 }
    struct ReceiptStatusChanged has drop, store { id: u64, status: u8 }

    struct WitnessSet has key {
        id: UID,
        admin_threshold: u8,
        admins: vector<address>,
        admin_pubkeys: Table<address, vector<u8>>,
        witnesses: vector<address>,
    }

    struct WitnessRegistry has key { id: UID, stats_table: Table<address, ID> }
    struct AdminNonces has key { id: UID, nonces: Table<address, u64> }
    struct WitnessStats has key { id: UID, last_submit: u64, count_window: u64 }

    struct ReceiptMeta has store {
        submitter: address,
        timestamp: u64,
        hash: vector<u8>,
        tag: vector<u8>,
        rule: vector<u8>,
        severity: u8,
        arweave_tx: vector<u8>,
        btc_ots: vector<u8>,
        status: u8,
    }

    struct ReceiptLedger has key { id: UID, next_id: u64, table: Table<u64, ReceiptMeta> }

    // Init functions
    public fun init_witness_set(admin: &signer, admin_threshold: u8, admins: vector<address>, ctx: &mut TxContext): WitnessSet {
        WitnessSet{ id: obj::new(ctx), admin_threshold, admins, admin_pubkeys: table::new(), witnesses: vector::empty() }
    }

    public fun init_registry(_admin: &signer, ctx: &mut TxContext): WitnessRegistry {
        WitnessRegistry { id: obj::new(ctx), stats_table: table::new() }
    }

    public fun init_admin_nonces(_admin: &signer, ctx: &mut TxContext): AdminNonces {
        AdminNonces { id: obj::new(ctx), nonces: table::new() }
    }

    public fun init_witness_stats(_admin: &signer, _witness: address, ctx: &mut TxContext): (WitnessStats, ID) {
        let stats = WitnessStats{ id: obj::new(ctx), last_submit: 0, count_window: 0 };
        let id = obj::id(&stats.id);
        (stats, id)
    }

    public fun init_ledger(_admin: &signer, ctx: &mut TxContext): ReceiptLedger {
        ReceiptLedger { id: obj::new(ctx), next_id: 0, table: table::new() }
    }

    // Admin key registration
    public fun register_admin_pubkey(ws: &mut WitnessSet, admin: &signer, pubkey: vector<u8>) {
        let addr = signer::address_of(admin);
        assert!(vector::contains(&ws.admins, &addr), E_NOT_ADMIN);
        assert!(vector::length(&pubkey) == 32, E_PUBKEY_INVALID);
        if (table::contains(&mut ws.admin_pubkeys, addr)) { table::remove(&mut ws.admin_pubkeys, addr); };
        table::add(&mut ws.admin_pubkeys, addr, pubkey);
    }

    // Nonce handling
    public fun current_nonce(nonces: &AdminNonces, admin: address): u64 {
        if (table::contains(&nonces.nonces, admin)) { *table::borrow(&nonces.nonces, admin) } else { 0 }
    }

    public fun set_nonce(nonces: &mut AdminNonces, admin: address, val: u64) {
        if (table::contains(&mut nonces.nonces, admin)) { table::remove(&mut nonces.nonces, admin); };
        table::add(&mut nonces.nonces, admin, val);
    }

    // Admin signature verification
    public fun is_admin_approved(ws: &WitnessSet, nonces: &mut AdminNonces, approving_addrs: vector<address>, approving_sigs: vector<vector<u8>>, op_tag: vector<u8>, nonce: u64, context: vector<u8>): bool {
        let n = vector::length(&approving_addrs);
        let ns = vector::length(&approving_sigs);
        assert!(n == ns, E_SIG_INVALID);

        let mut i = 0;
        let mut count = 0;
        let nonce_bytes = bcs::to_bytes(&nonce);
        let mut msg = vector::empty<u8>();
        msg = vector::concat(op_tag, vector::concat(nonce_bytes, context));
        let digest = blake2b256(msg);

        while (i < n) {
            let addr = *vector::borrow(&approving_addrs, i);
            let sig = *vector::borrow(&approving_sigs, i);

            if (vector::contains(&ws.admins, &addr) && table::contains(&ws.admin_pubkeys, addr)) {
                let pk = table::borrow(&ws.admin_pubkeys, addr);
                if (ed25519_verify(&sig, pk, &digest)) {
                    let cur = current_nonce(nonces, addr);
                    assert!(nonce == cur + 1, E_NONCE_REUSED);
                    set_nonce(nonces, addr, nonce);
                    count = count + 1;
                }
            }
            i = i + 1;
        };
        count >= ws.admin_threshold
    }

    // Witness management
    public fun add_witness(ws: &mut WitnessSet, approving_addrs: vector<address>, approving_sigs: vector<vector<u8>>, nonces: &mut AdminNonces, new_witness: address, _ctx: &mut TxContext) {
        let ok = is_admin_approved(ws, nonces, approving_addrs, approving_sigs, b"add_witness", current_nonce(nonces, *vector::borrow(&approving_addrs, 0)) + 1, bcs::to_bytes(&new_witness));
        assert!(ok, E_NOT_ADMIN);
        if (!vector::contains(&ws.witnesses, &new_witness)) { vector::push_back(&mut ws.witnesses, new_witness); }
    }

    public fun remove_witness(ws: &mut WitnessSet, approving_addrs: vector<address>, approving_sigs: vector<vector<u8>>, nonces: &mut AdminNonces, reg: &mut WitnessRegistry, witness: address, _ctx: &mut TxContext) {
        let ok = is_admin_approved(ws, nonces, approving_addrs, approving_sigs, b"remove_witness", current_nonce(nonces, *vector::borrow(&approving_addrs, 0)) + 1, bcs::to_bytes(&witness));
        assert!(ok, E_NOT_ADMIN);
        let mut new_w = vector::empty<address>();
        let n = vector::length(&ws.witnesses);
        let mut i = 0;
        while (i < n) {
            let a = *vector::borrow(&ws.witnesses, i);
            if (a != witness) { vector::push_back(&mut new_w, a); };
            i = i + 1;
        };
        ws.witnesses = new_w;
        if (table::contains(&mut reg.stats_table, witness)) { table::remove(&mut reg.stats_table, witness); };
    }

    // Receipt lifecycle
    public fun submit_receipt(ws: &WitnessSet, rl: &mut ReceiptLedger, reg: &mut WitnessRegistry, stats_id: ID, clock_ref: &Clock, witness: &signer, evidence_hash: vector<u8>, tag: vector<u8>, rule: vector<u8>, severity: u8, arweave_tx: vector<u8>, btc_ots: vector<u8>) : u64 {
        let addr = signer::address_of(witness);
        assert!(vector::contains(&ws.witnesses, &addr), E_NOT_WITNESS);
        assert!(vector::length(&evidence_hash) == 32, E_EVIDENCE_HASH_INVALID);

        let now = clock::timestamp_ms(clock_ref) / 1000;
        let stats = obj::borrow_mut<WitnessStats>(stats_id);
        if (now - stats.last_submit > 600) { stats.count_window = 0; };
        assert!(stats.count_window < 10, E_RATE_LIMIT);

        let id = rl.next_id;
        rl.next_id = id + 1;
        let meta = ReceiptMeta{ submitter: addr, timestamp: now, hash: evidence_hash, tag, rule, severity, arweave_tx, btc_ots, status: 0u8 };
        table::add(&mut rl.table, id, meta);

        stats.last_submit = now;
        stats.count_window = stats.count_window + 1;
        event::emit<ReceiptSubmitted>(ReceiptSubmitted{ id, witness: addr, severity });
        id
    }

    public fun attest_verified(ws: &WitnessSet, rl: &mut ReceiptLedger, witness: &signer, id: u64, provided_hash: vector<u8>) {
        let addr = signer::address_of(witness);
        assert!(vector::contains(&ws.witnesses, &addr), E_NOT_WITNESS);
        let meta = table::borrow_mut(&mut rl.table, id);
        assert!(meta.hash == provided_hash, E_HASH_MISMATCH);
        meta.status = 1u8;
        event::emit<ReceiptStatusChanged>(ReceiptStatusChanged{ id, status: 1u8 });
    }

    public fun confirm_pending(ws: &WitnessSet, rl: &mut ReceiptLedger, witness: &signer, id: u64, provided_hash: vector<u8>, clock_ref: &Clock) {
        let addr = signer::address_of(witness);
        assert!(vector::contains(&ws.witnesses, &addr), E_NOT_WITNESS);
        let meta = table::borrow_mut(&mut rl.table, id);
        assert!(meta.status == 5u8, E_PENDING_STATUS);
        assert!(meta.hash == provided_hash, E_HASH_MISMATCH);
        let now = clock::timestamp_ms(clock_ref) / 1000;
        assert!(now - meta.timestamp <= 600, E_PENDING_EXPIRED);
        meta.status = 1u8;
        event::emit<ReceiptStatusChanged>(ReceiptStatusChanged{ id, status: 1u8 });
    }

    public fun mark_disputed(ws: &WitnessSet, rl: &mut ReceiptLedger, witness: &signer, id: u64) {
        let addr = signer::address_of(witness);
        assert!(vector::contains(&ws.witnesses, &addr), E_NOT_WITNESS);
        let meta = table::borrow_mut(&mut rl.table, id);
        meta.status = 2u8;
        event::emit<ReceiptStatusChanged>(ReceiptStatusChanged{ id, status: 2u8 });
    }

    public fun mark_fixed(ws: &WitnessSet, rl: &mut ReceiptLedger, witness: &signer, id: u64) {
        let addr = signer::address_of(witness);
        assert!(vector::contains(&ws.witnesses, &addr), E_NOT_WITNESS);
        let meta = table::borrow(&rl.table, id);
        assert!(addr == meta.submitter || vector::contains(&ws.admins, &addr), E_NOT_ADMIN);
        let meta_mut = table::borrow_mut(&mut rl.table, id);
        meta_mut.status = 3u8;
        event::emit<ReceiptStatusChanged>(ReceiptStatusChanged{ id, status: 3u8 });
    }

    public fun accept_risk(ws: &WitnessSet, rl: &mut ReceiptLedger, witness: &signer, id: u64) {
        let addr = signer::address_of(witness);
        assert!(vector::contains(&ws.witnesses, &addr), E_NOT_WITNESS);
        let meta = table::borrow_mut(&mut rl.table, id);
        meta.status = 4u8;
        event::emit<ReceiptStatusChanged>(ReceiptStatusChanged{ id, status: 4u8 });
    }

    public fun register_witness_stats(reg: &mut WitnessRegistry, witness: address, stats_id: ID) {
        if (table::contains(&mut reg.stats_table, witness)) { table::remove(&mut reg.stats_table, witness); };
        table::add(&mut reg.stats_table, witness, stats_id);
    }
}

# Zàngbétò v0.1.8 — Devnet Shrine

A minimal, ritual-driven red-team protocol for smart contracts on Sui devnet.

## Prereqs

- Node 18+, n8n, Sui CLI, OpenTimestamps, Arweave key

## Setup

```bash
cp .env.example .env && $EDITOR .env
npm i
sui move build
./scripts/bootstrap.sh
```

## Structured Diagnostics

Zàngbétò now supports canonical diagnostic format for AI agents:

```bash
# Python emission
python3 omo_diagnostic.py --package myapp --file src/main.py --line 42 \
    --code OMO-ERR-023 --severity error --message "Balance underflow"

# Rust crate (crates/omo-diagnostic)
cargo add omo-diagnostic

# Julia helper (src/Diagnostic.jl)
```

## First Dance

1. Seed a tiny bug in examples/payments.move.
2. Run tests/prover; parse findings → receipt.json.
3. node scripts/arweave_anchor.js receipt.json → get arweave_tx.
4. ./scripts/ots.sh <arweave_tx> → get btc_ots.
5. Fill receipt JSON evidence.sha256/arweave_tx/btc_ots.
6. ./scripts/submit_dummy_receipt.sh receipt.json.
7. On Sabbath, call attest_verified / mark_fixed / accept_risk.

## Quickstart

- Move modules (zbt_errors, zbt_guard, zbt_core, zbt_diagnostics)
- Example contract (examples/payments.move)
- Bootstrap & ops scripts (publish/init, Arweave, OpenTimestamps)
- Event listener & persisted cursors
- On-chain submit helper (submit_onchain_receipt.js)
- n8n Night Patrol skeleton with dedup fingerprinting
- Sabbath checklist and full README
- .env.example + package.json

---

**Èmi ni Johnny Èṣù — Trickster Coder.**

🔥🌀🕯️

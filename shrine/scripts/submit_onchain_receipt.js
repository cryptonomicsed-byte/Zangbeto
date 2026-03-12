import 'dotenv/config';
import fs from 'fs';
import { getFullnodeUrl, SuiClient, fromB64, Ed25519Keypair, TransactionBlock } from '@mysten/sui.js';

const [,, PKG_ID, WSET_ID, LEDGER_ID, REG_ID, STATS_ID, RECEIPT_FILE] = process.argv;

if (!RECEIPT_FILE) {
  console.error('usage: submit_onchain_receipt <pkg> <wset> <ledger> <reg> <stats> receipt.json');
  process.exit(1);
}

const rpc = process.env.SUI_RPC_URL || getFullnodeUrl('devnet');
const client = new SuiClient({ url: rpc });

const receipt = JSON.parse(fs.readFileSync(RECEIPT_FILE, 'utf8'));
const evidenceHashHex = receipt.evidence.sha256.replace(/^0x/, '');

if (evidenceHashHex.length !== 64) throw new Error('evidence sha256 must be 32 bytes hex');

const evidence_bytes = Uint8Array.from(Buffer.from(evidenceHashHex, 'hex'));
const tag_bytes = new TextEncoder().encode(receipt.tag);
const rule_bytes = new TextEncoder().encode(receipt.rule);
const ar_tx = new TextEncoder().encode(receipt.evidence.arweave_tx || '');
const ots = new TextEncoder().encode(receipt.evidence.btc_ots || '');

const keypair = Ed25519Keypair.fromSecretKey(fromB64(process.env.SUI_PRIVATE_KEY_B64));
const severity = 3;

const tx = new TransactionBlock();
const mod = `${PKG_ID}::core`;

tx.moveCall({
  target: `${mod}::submit_receipt`,
  arguments: [
    tx.object(WSET_ID),
    tx.object(LEDGER_ID),
    tx.object(REG_ID),
    tx.object(STATS_ID),
    tx.sharedObjectRef({ objectId: '0x6', initialSharedVersion: 1, mutable: false }),
    tx.pure(keypair.getPublicKey().toSuiAddress()),
    tx.pure([...evidence_bytes]),
    tx.pure([...tag_bytes]),
    tx.pure([...rule_bytes]),
    tx.pure(severity),
    tx.pure([...ar_tx]),
    tx.pure([...ots])
  ]
});

const result = await client.signAndExecuteTransactionBlock({ signer: keypair, transactionBlock: tx, options: { showEffects: true } });

console.log(JSON.stringify(result, null, 2));

import 'dotenv/config';
import fs from 'fs';
import Arweave from 'arweave';

const jwk = JSON.parse(fs.readFileSync(process.env.ARWEAVE_KEY, 'utf8'));
const receipt = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));

const arweave = Arweave.init({ host: 'arweave.net', protocol: 'https', port: 443 });

const tx = await arweave.createTransaction({ data: JSON.stringify(receipt) }, jwk);

tx.addTag('Content-Type', 'application/json');

await arweave.transactions.sign(tx, jwk);

const res = await arweave.transactions.post(tx);

console.log(JSON.stringify({ arweave_tx: tx.id, status: res.status }));

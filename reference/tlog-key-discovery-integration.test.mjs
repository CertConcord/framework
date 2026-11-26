import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createPublicKey } from 'node:crypto';
import { checkpointBody, verifyNote } from './transparency.mjs';
import { selectMlDsa87Key } from './vendor/tlog-cosignature-ml-dsa/extension.mjs';

const read = (path) => JSON.parse(readFileSync(new URL('../' + path, import.meta.url)));
const discovery = read('spec/external/tlog-cosignature-ml-dsa/vectors/key-discovery.json');
const prefix = read('spec/external/tlog-cosignature-ml-dsa/vectors/prefix.json');
const keys = Object.fromEntries(
  Object.entries(discovery.keys).map(([id, hex]) => [
    id,
    createPublicKey({ key: Buffer.from(hex, 'hex'), format: 'der', type: 'spki' }),
  ]),
);
const root = Buffer.from(prefix.context.root, 'hex');
const timestamp = Buffer.alloc(8);
timestamp.writeBigUInt64BE(BigInt(prefix.context.timestamp));
const witnessBytes = Buffer.concat([
  Buffer.from(prefix.keyHint, 'hex'),
  timestamp,
  Buffer.from(prefix.signature, 'hex'),
]);
const witnessLine = `— ${discovery.name} ${witnessBytes.toString('base64')}\n`;
const body = checkpointBody(prefix.context.origin, prefix.context.end, root);
const note = body + '\n' + witnessLine;

test('selected component key discovery feeds Framework witness-note verification', () => {
  assert.equal(discovery.profile, 'CERTCONCORD-MLDSA87-SUBTREE-v1');
  assert.equal(discovery.name, prefix.context.name);
  assert.equal(discovery.keys.primary, prefix.spki);
  assert.equal(discovery.keyHint, prefix.keyHint);
  const key = selectMlDsa87Key(discovery.name, Buffer.from(discovery.keyHint, 'hex'), [
    { name: discovery.name, publicKey: keys.legacy44 },
    { name: discovery.name, publicKey: keys.second },
    { name: discovery.name, publicKey: keys.primary },
  ]);
  assert.equal(key, keys.primary);
  const signer = { name: discovery.name, scheme: discovery.profile, publicKey: key };
  assert.equal(verifyNote(note, signer, { knowledgeTime: prefix.context.timestamp, maxFutureSkew: 0 }).size,
    BigInt(prefix.context.end));
  const altered = checkpointBody(prefix.context.origin, prefix.context.end, Buffer.alloc(32)) +
    '\n' + witnessLine;
  assert.throws(() => verifyNote(altered, signer, {
    knowledgeTime: prefix.context.timestamp,
    maxFutureSkew: 0,
  }), { code: 'NOTE_UNTRUSTED_SIGNATURE' });
});

for (const item of discovery.cases) {
  test('selected component discovery vector: ' + item.id, () => {
    const candidates = item.candidates.map((candidate) => ({
      name: candidate.name,
      publicKey: keys[candidate.key],
    }));
    const select = () => selectMlDsa87Key(
      item.name ?? discovery.name,
      Buffer.from(item.keyHint ?? discovery.keyHint, 'hex'),
      candidates,
    );
    if (item.expected === 'primary') assert.equal(select(), keys.primary);
    else assert.throws(select, { code: item.expected });
  });
}

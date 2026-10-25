import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as c from './core.mjs';
import { createAuthorityResolver } from './authority-history.mjs';
import { authenticateRetainedAuthorityEntry } from './retained-authorities.mjs';
import { verifyTimestampToken } from './timestamp.mjs';

const vectors = JSON.parse(readFileSync(new URL('./vectors/direct-authority-key-incidents.json', import.meta.url)));
const raw = (entry) => {
  const bytes = Buffer.from(entry.cbor, 'base64');
  assert.equal(bytes.length, entry.bytes);
  assert.equal(c.sha256(bytes).toString('hex'), entry.sha256);
  const value = c.decodeCBOR(bytes);
  assert.deepEqual(c.dcbor(value), bytes);
  return value;
};
const materials = new Map(vectors.materials.map((entry) => [entry.id, raw(entry)]));
const clone = (value) => c.decodeCBOR(c.dcbor(value));

function configuration(fixture) {
  return { trustDomainID: fixture.trustDomainID, governance: fixture.governance,
    algorithmDeadlines: fixture.algorithmDeadlines, validationTime: fixture.validationTime,
    verifyPublication: ({ proof, imprint, at }) => ({ overall: 'VALID', ...verifyTimestampToken(proof,
      { certificate: fixture.tsaCertificate, issuerKey: c.publicFromDER(fixture.governance.roots[0].publicKeyDER),
        policy: fixture.tsaPolicy, imprint, at, maxFutureSkew: 0 }) }) };
}

test('equivalent authority points keep distinct wire IDs and verify the same signature', () => {
  const f = materials.get('original');
  const u = c.publicFromDER(f.uncompressed), z = c.publicFromDER(f.compressed);
  assert.equal(u.equals(z), true);
  assert.equal(z.equals(u), true);
  assert.equal(u.equals(c.publicFromDER(f.other)), false);
  assert.equal(c.keyID(u).toString('hex'), vectors.identity.uncompressedKeyID);
  assert.equal(c.keyID(z).toString('hex'), vectors.identity.compressedKeyID);
  assert.notDeepEqual(c.keyID(u), c.keyID(z));
  assert.deepEqual(c.spki(u), f.uncompressed);
  assert.deepEqual(c.spki(z), f.compressed);
  assert.equal(c.verify(f.message, f.signature, u), true);
  assert.equal(c.verify(f.message, f.signature, z), true);
  assert.equal(c.verify(f.message, f.signature, c.publicFromDER(f.other)), false);
  const others = materials.get('additional').comparatorPublicKeys;
  for (const value of [others.p384, others.ed25519, others.mldsa87]) {
    const key = c.publicFromDER(value);
    assert.equal(u.equals(key), false);
    assert.equal(key.equals(u), false);
  }
  assert.equal(c.publicFromDER(others.mldsa87).equals(c.publicFromDER(others.mldsa87)), true);
});

test('direct authority vectors authenticate their frozen selected policy publications', () => {
  for (const f of materials.values()) {
    for (const entry of Object.values(f.policies).filter((entry) => entry.manifest)) {
      const before = c.dcbor(entry);
      const admitted = authenticateRetainedAuthorityEntry({ ...configuration(f), entry,
        knowledgeTime: f.validationTime, strictRecords: true });
      assert.equal(admitted.serial, 0);
      assert.deepEqual(admitted.hash, c.H('RootTrustManifest', entry.manifest));
      assert.equal(admitted.published, entry.manifest.issuedAt);
      assert.deepEqual(c.dcbor(entry), before);
    }
  }
});

for (const row of vectors.cases) {
  test('direct authority key incident: ' + row.name, () => {
    const f = materials.get(row.material), query = raw(row.query);
    const records = row.kind === 'selected-policy'
      ? clone(f.policies[row.entry].manifest.authorities) : raw(row.records);
    const beforeQuery = c.dcbor(query), beforeRecords = c.dcbor(records), calls = [];
    let outputs, beforeOutputs;
    if (row.kind === 'callbacks') {
      outputs = raw(row.outputs);
      beforeOutputs = c.dcbor(outputs);
      records.forEach((record, index) => {
        const originalID = c.keyID(c.publicFromDER(record.publicKeyDER));
        record.status = (received) => {
          calls.push({ index, originalID, received });
          return clone(outputs[index]);
        };
      });
    }
    const resolve = createAuthorityResolver({ trustDomainID: f.trustDomainID, authorities: records });
    const actual = resolve(query);
    assert.deepEqual(actual, row.expected);
    assert.equal(Object.isFrozen(actual), true);
    assert.deepEqual(c.dcbor(query), beforeQuery);
    if (row.kind === 'callbacks') {
      assert.deepEqual(calls.map((call) => call.index), row.expectedCallbackOrder);
      for (const { originalID, received } of calls) {
        assert.deepEqual(received.authorityID, originalID);
        assert.deepEqual(c.dcbor(received.scope), c.dcbor(query.scope));
        assert.equal(received.role, query.role);
        assert.equal(received.stateTime, query.stateTime);
        assert.equal(received.knowledgeTime, query.knowledgeTime);
      }
      assert.deepEqual(c.dcbor(outputs), beforeOutputs);
    } else assert.deepEqual(c.dcbor(records), beforeRecords);
  });
}

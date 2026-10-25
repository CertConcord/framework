import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as c from './core.mjs';
import { createRetainedAuthorityResolver, authenticateRetainedAuthorityEntry } from './retained-authorities.mjs';
import { verifyTimestampToken } from './timestamp.mjs';

const vectors = JSON.parse(readFileSync(new URL('./vectors/retained-authority-key-incidents.json', import.meta.url)));
const raw = (entry) => {
  const bytes = Buffer.from(entry.cbor, 'base64');
  assert.equal(bytes.length, entry.bytes);
  assert.equal(c.sha256(bytes).toString('hex'), entry.sha256);
  const value = c.decodeCBOR(bytes);
  assert.deepEqual(c.dcbor(value), bytes);
  return value;
};
const materials = new Map(vectors.materials.map((entry) => [entry.id, raw(entry)]));
function configuration(fixture, calls = []) {
  return { trustDomainID: fixture.trustDomainID, governance: fixture.governance,
    algorithmDeadlines: fixture.algorithmDeadlines, validationTime: fixture.validationTime,
    verifyPublication: ({ proof, imprint, at }) => {
      const result = verifyTimestampToken(proof, { certificate: fixture.tsaCertificate,
        issuerKey: c.publicFromDER(fixture.governance.roots[0].publicKeyDER),
        policy: fixture.tsaPolicy, imprint, at, maxFutureSkew: 0 });
      calls.push({ proof: Buffer.from(proof), imprint: Buffer.from(imprint), at, published: result.poeUpperBound });
      return { overall: 'VALID', ...result };
    } };
}

test('retained authority vectors authenticate every frozen publication and hash chain', () => {
  for (const fixture of materials.values()) {
    for (const history of Object.values(fixture.histories)) {
      const before = c.dcbor(history);
      let previous;
      for (const [serial, entry] of history.entries()) {
        const admitted = authenticateRetainedAuthorityEntry({ ...configuration(fixture), entry,
          previous, knowledgeTime: fixture.validationTime, strictRecords: true });
        assert.equal(admitted.serial, serial);
        assert.deepEqual(admitted.hash, c.H('RootTrustManifest', entry.manifest));
        assert.equal(admitted.published, entry.manifest.issuedAt);
        previous = admitted;
      }
      assert.deepEqual(c.dcbor(history), before);
    }
  }
});

for (const row of vectors.cases) {
  test('retained authority key incident: ' + row.name, () => {
    const fixture = materials.get(row.material), history = fixture.histories[row.history], query = raw(row.query);
    const beforeHistory = c.dcbor(history), beforeQuery = c.dcbor(query), calls = [];
    const resolve = createRetainedAuthorityResolver({ ...configuration(fixture, calls), history });
    assert.deepEqual(resolve(query), row.expected);
    const unseen = history.findIndex((entry) => entry.manifest.issuedAt > query.knowledgeTime);
    const traversed = history.slice(0, unseen === -1 ? history.length : unseen + 1);
    assert.deepEqual(calls, traversed.map((entry) => ({ proof: entry.publicationProof,
      imprint: c.H('RootTrustManifestPublication', { manifest: entry.manifest, signatures: entry.signatures }),
      at: fixture.validationTime, published: entry.manifest.issuedAt })));
    assert.deepEqual(c.dcbor(history), beforeHistory);
    assert.deepEqual(c.dcbor(query), beforeQuery);
  });
}

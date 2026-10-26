import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as c from './core.mjs';
import { createRetainedAuthorityResolver, authenticateRetainedAuthorityEntry } from './retained-authorities.mjs';
import { verifyTimestampToken } from './timestamp.mjs';

const vectors = JSON.parse(readFileSync(new URL('./vectors/retained-query-snapshot.json', import.meta.url)));
const raw = Buffer.from(vectors.material.cbor, 'base64');
assert.equal(raw.length, vectors.material.bytes);
assert.equal(c.sha256(raw).toString('hex'), vectors.material.sha256);
assert.deepEqual(c.dcbor(c.decodeCBOR(raw)), raw);
const digest = (bytes) => c.sha256(bytes).toString('hex');
function configuration(fixture, observe = () => {}) {
  return { trustDomainID: fixture.trustDomainID, governance: fixture.governance,
    algorithmDeadlines: fixture.algorithmDeadlines, validationTime: fixture.validationTime,
    verifyPublication: ({ proof, imprint, at }) => {
      const checked = verifyTimestampToken(proof, { certificate: fixture.tsaCertificate,
        issuerKey: c.publicFromDER(fixture.governance.roots[0].publicKeyDER),
        policy: fixture.tsaPolicy, imprint, at, maxFutureSkew: 0 });
      observe({ published: checked.poeUpperBound, at, proofSHA256: digest(proof),
        imprintSHA256: digest(imprint) });
      return { overall: 'VALID', ...checked };
    } };
}

test('retained query vectors authenticate every frozen publication and raw hash binding', () => {
  const fixture = c.decodeCBOR(raw); let previous;
  assert.equal(fixture.history.length, vectors.publications.length);
  for (const [serial, entry] of fixture.history.entries()) {
    const declared = vectors.publications[serial];
    assert.equal(digest(c.dcbor(entry.manifest)), declared.manifestSHA256);
    assert.equal(digest(c.dcbor(entry.signatures)), declared.signaturesSHA256);
    assert.equal(digest(entry.publicationProof), declared.proofSHA256);
    const accepted = authenticateRetainedAuthorityEntry({ ...configuration(fixture), entry, previous,
      knowledgeTime: fixture.validationTime, strictRecords: true });
    assert.equal(accepted.serial, serial);
    assert.equal(accepted.published, declared.published);
    assert.deepEqual(accepted.hash, c.H('RootTrustManifest', entry.manifest));
    previous = accepted;
  }
  assert.deepEqual(c.dcbor(fixture), raw);
});

for (const row of vectors.cases) {
  test('retained query fixed replay: ' + row.name, () => {
    const fixture = c.decodeCBOR(raw), query = fixture.baseQuery, calls = [];
    const historyBefore = c.dcbor(fixture.history);
    const selectedKey = Buffer.from(query.publicKeyDER), selectedPurpose = query.scope.purpose;
    let hooks = 0;
    if (Object.hasOwn(row, 'stateTime')) query.stateTime = row.stateTime;
    if (Object.hasOwn(row, 'knowledgeTime')) query.knowledgeTime = row.knowledgeTime;
    switch (row.prepare) {
      case undefined: break;
      case 'wrong-purpose': query.scope.purpose = 'not-selected-purpose'; break;
      case 'wrong-domain': query.scope.trustDomainID.fill(0); break;
      case 'alternate-key': query.publicKeyDER = Buffer.from(fixture.alternatePublicKeyDER); break;
      case 'knowledge-getter': Object.defineProperty(query, 'knowledgeTime', {
        get() { hooks++; return 1800000110; }, enumerable: true }); break;
      default: assert.fail('Unknown local input preparation: ' + row.prepare);
    }
    const before = row.callerUnchanged ? c.dcbor(query) : undefined;
    const resolve = createRetainedAuthorityResolver({ ...configuration(fixture, (observed) => {
      calls.push(observed);
      if (row.action === 'knowledge-window') {
        query.knowledgeTime = calls.length === 1 ? 1800000080 : 1800000110;
        return;
      }
      if (calls.length !== 1) return;
      switch (row.action) {
        case undefined: break;
        case 'restore-purpose': query.scope.purpose = selectedPurpose; break;
        case 'restore-domain': fixture.trustDomainID.copy(query.scope.trustDomainID); break;
        case 'restore-key': query.publicKeyDER = selectedKey; break;
        case 'corrupt-key': query.publicKeyDER.fill(0); break;
        case 'replace-scope': query.scope = { trustDomainID: Buffer.alloc(32) }; break;
        case 'replace-role-time': query.role = 'ISSUER'; query.stateTime = 1799999999; break;
        default: assert.fail('Unknown local callback action: ' + row.action);
      }
    }), history: fixture.history });
    assert.deepEqual(resolve(query), row.expected);
    assert.deepEqual(calls, row.published.map((published) => {
      const entry = fixture.history.find((entry) => entry.manifest.issuedAt === published);
      return { published, at: fixture.validationTime, proofSHA256: digest(entry.publicationProof),
        imprintSHA256: digest(c.H('RootTrustManifestPublication', {
          manifest: entry.manifest, signatures: entry.signatures })) };
    }));
    assert.equal(hooks, row.hooks ?? 0);
    if (before) assert.deepEqual(c.dcbor(query), before);
    assert.deepEqual(c.dcbor(fixture.history), historyBefore);
  });
}

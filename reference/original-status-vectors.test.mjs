import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { decodeCBOR } from './core.mjs';
import { createRetainedAuthorityResolver } from './retained-authorities.mjs';
import { verifyTimestampToken } from './timestamp.mjs';
import { loadVectorCorpus, runDocumentVectors, runRetainedVectors } from './verify-vectors.mjs';

const directory = fileURLToPath(
  new URL('./vectors/original-status-proof-mtc07-rar2/', import.meta.url),
);
const S = 1792454400,
  Ps = S + 1,
  P = S + 2,
  H = P,
  R = P,
  D = S + 100,
  K = 1792627202;
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const inputFor = (corpus, id) =>
  corpus.config(
    corpus.manifest.retained.find((entry) => entry.id === 'original-status-' + id).options,
  );
const resolverFor = (input) =>
  createRetainedAuthorityResolver({
    ...input.historyTrust,
    history: decodeCBOR(input.history),
    verifyPublication: ({ imprint, proof, at }) => ({
      overall: 'VALID',
      ...verifyTimestampToken(proof, { ...input.publicationTSA, imprint, at, maxFutureSkew: 0 }),
    }),
  });
const decision = (result) => ({ overall: result.overall, reason: result.reason });

test('fixed original status corpus retains exact public CMS and ERS with a three-field selection', () => {
  const corpus = loadVectorCorpus(directory);
  const previous = loadVectorCorpus(
    fileURLToPath(new URL('./vectors/cms-retirement-mtc07-rar2/', import.meta.url)),
  );
  const prior = previous.config(
    previous.manifest.retained.find((entry) => entry.id === 'cms-retirement-successor').options,
  );
  const positive = inputFor(corpus, 'early-status-proof');
  assert.equal(corpus.manifest.retained.length, 21);
  assert.equal(corpus.manifest.documents.length, 1);
  assert.equal(corpus.manifest.files.length, 85);
  assert.deepEqual(positive.originalBytes, prior.originalBytes);
  assert.deepEqual(positive.evidenceRecord, prior.evidenceRecord);
  assert.deepEqual(corpus.config(positive.historicalTrust), previous.config(prior.historicalTrust));
  assert.equal(
    hash(positive.originalBytes),
    '09e93450939c93b3dce9daa2ab8f278a357701b46d2d93f0c4fba3c9a0839133',
  );
  assert.equal(
    hash(positive.evidenceRecord),
    '148c25cb9fb9c16846eb14ece6bc8927bdf442444d7ff76168b680236b343050',
  );
  const cms = decodeCBOR(positive.originalBytes).objects.find(
    (entry) => entry.type === 'CertificateStatus',
  ).payload;
  assert.equal(hash(cms), '65f5d18908b652ac34182411a19b96bf8f1bc1f0c951da74365dd3c7fe92b99e');
  assert.equal(
    hash(positive.originalStatusProof.evidenceRecord),
    '59d7e66f2170e58d6d9dfa3f22e0c088cc8c743634802eec054ebeaec14d6b3d',
  );
  assert.notDeepEqual(positive.historyTrust.governance.roots, prior.historyTrust.governance.roots);
  for (const entry of corpus.manifest.retained) {
    const input = corpus.config(entry.options);
    assert.deepEqual(input.originalBytes, positive.originalBytes, entry.id);
    assert.equal(input.currentKnowledgeTime, K, entry.id);
    if (Object.hasOwn(input, 'originalStatusProof'))
      assert.deepEqual(
        Object.keys(input.originalStatusProof).sort(),
        ['evidenceRecord', 'preservationPolicy', 'protectionTrust'],
        entry.id,
      );
    else assert.equal(entry.id, 'original-status-without-status-proof');
  }
  assert.equal(runDocumentVectors({ directory })[0].actual.overall, 'VALID');
});

test('signed history admits S and Ps before exclusive R=P retirement without changing other old-key roles', () => {
  const corpus = loadVectorCorpus(directory),
    input = inputFor(corpus, 'early-status-proof');
  const trust = corpus.config(input.historicalTrust).trust,
    resolver = resolverFor(input);
  const query = {
    certificate: trust.statusCertificate,
    role: 'STATUS_AUTHORITY',
    scope: { trustDomainID: trust.trustDomainID },
    knowledgeTime: H,
  };
  for (const stateTime of [S, Ps]) assert.equal(resolver({ ...query, stateTime }).overall, 'VALID');
  assert.deepEqual(decision(resolver({ ...query, stateTime: P })), {
    overall: 'INVALID',
    reason: 'AUTHORITY_EXPIRED',
  });
  for (const role of ['PERMIT_AUTHORITY', 'RECEIPT_AUTHORITY'])
    assert.equal(resolver({ ...query, role, stateTime: P }).overall, 'VALID', role);
  assert(S < Ps && Ps < R && R === P);
});

test('fixed status proof replay is offline and independent of the current wall clock', (t) => {
  const network = t.mock.method(globalThis, 'fetch', () => {
    throw Error('Unexpected network');
  });
  let now = 0;
  t.mock.method(Date, 'now', () => now);
  const first = runRetainedVectors({ directory });
  now = 4102444800000;
  assert.deepEqual(runRetainedVectors({ directory }), first);
  assert.equal(network.mock.callCount(), 0);
  const rows = new Map(
    first.map((entry) => [entry.id.slice('original-status-'.length), entry.details]),
  );
  assert.equal(rows.size, 21);
  const positive = rows.get('early-status-proof'),
    baseline = rows.get('without-status-proof');
  assert.equal(positive.overall, 'VALID');
  assert.deepEqual(positive.preservation, baseline.preservation);
  assert.deepEqual(positive.currentAdmissibility, baseline.currentAdmissibility);
  assert.equal(baseline.historicalAuthorization.reason, 'AUTHORITY_EXPIRED');
  assert.equal(Object.hasOwn(baseline, 'originalStatusProof'), false);
  assert.equal(Object.hasOwn(baseline, 'originalStatusAdmission'), false);
  assert.equal(positive.originalStatusAdmission.length, 2);
  for (const admission of positive.originalStatusAdmission) {
    assert.deepEqual([admission.S, admission.B, admission.H], [S, Ps, H]);
    assert.deepEqual(admission.authority, {
      overall: 'VALID',
      reason: 'ORIGINAL_STATUS_AUTHORITY_ADMITTED',
    });
  }
  for (const name of [
    'expired-status-proof',
    'late-status-renewal',
    'status-proof-after-h',
    'missing-status-proof',
    'empty-status-proof',
    'missing-status-policy',
    'wrong-role-missing-proof',
    'wrong-scope-missing-proof',
    'unknown-authority-missing-proof',
    'revoked-authority-missing-proof',
    'unadmitted-revocation',
    'original-proof-after-h',
    'missing-original-proof',
    'original-tsa-revoked-at-h',
    'status-tsa-stale-at-h',
  ]) {
    const result = rows.get(name);
    assert.ok(result.originalStatusAdmission.length > 0, name);
    assert.ok(
      result.originalStatusAdmission.every((entry) => entry.B === null && entry.S === S),
      name,
    );
  }
  for (const [name, reason] of [
    ['wrong-role-missing-proof', 'AUTHORITY_ROLE'],
    ['wrong-scope-missing-proof', 'AUTHORITY_SCOPE'],
    ['revoked-authority-missing-proof', 'AUTHORITY_REVOKED'],
  ]) {
    const result = rows.get(name);
    assert.deepEqual(decision(result.historicalAuthorization), { overall: 'INVALID', reason });
    for (const admission of result.originalStatusAdmission) {
      assert.deepEqual(admission.authority, { overall: 'INVALID', reason });
      assert.deepEqual(admission.proof, {
        overall: 'INDETERMINATE',
        reason: 'ORIGINAL_STATUS_EVIDENCE_UNAVAILABLE',
      });
    }
  }
  const packageIncident = rows.get('original-tsa-revoked-at-h');
  assert.equal(packageIncident.originalProof.overall, 'VALID');
  assert.equal(packageIncident.originalProof.proofOfExistenceUpperBound, P);
  assert.deepEqual(packageIncident.historicalBytesVisibility, {
    overall: 'INVALID',
    reason: 'AUTHORITY_REVOKED',
  });
  assert.equal(packageIncident.originalStatusProof.overall, 'VALID');
  assert.equal(
    rows.get('unadmitted-revocation').historicalAuthorization.reason,
    'TSA_REQUEST_BINDING',
  );
  assert.deepEqual(decision(rows.get('stale-current-status').currentAdmissibility), {
    overall: 'INDETERMINATE',
    reason: 'ECP_STATUS_STALE',
  });
  assert.deepEqual(decision(rows.get('wrong-current-target').currentAdmissibility), {
    overall: 'INVALID',
    reason: 'ECP_STATUS_BINDING',
  });
  for (const name of ['stale-current-status', 'wrong-current-target'])
    assert.equal(rows.get(name).historicalAuthorization.overall, 'VALID', name);
});

test('retained initial status TSA has distinct Ps, H and K evidence cutoffs', () => {
  const corpus = loadVectorCorpus(directory);
  const positive = inputFor(corpus, 'status-tsa-h-covered');
  const negative = inputFor(corpus, 'status-tsa-stale-at-h');
  assert.deepEqual(positive.originalStatusProof, negative.originalStatusProof);
  const firstTSA = positive.originalStatusProof.preservationPolicy.timestampAuthorities.find(
    (entry) => entry.validUntil === D,
  );
  assert.ok(firstTSA);
  const query = {
    certificate: firstTSA.certificate,
    role: 'TIMESTAMP_AUTHORITY',
    scope: { trustDomainID: positive.historyTrust.trustDomainID },
    stateTime: Ps,
  };
  const resolve = resolverFor(negative);
  for (const knowledgeTime of [Ps, K])
    assert.equal(resolve({ ...query, knowledgeTime }).overall, 'VALID');
  assert.deepEqual(decision(resolve({ ...query, knowledgeTime: H })), {
    overall: 'INDETERMINATE',
    reason: 'AUTHORITY_STATUS_STALE',
  });
  assert.equal(resolverFor(positive)({ ...query, knowledgeTime: H }).overall, 'VALID');
  const oldRecord = decodeCBOR(positive.history)[0].manifest.authorities.find(
    (entry) => entry.roles.includes('TIMESTAMP_AUTHORITY') && entry.validUntil === D,
  );
  const staleRecord = decodeCBOR(negative.history)[0].manifest.authorities.find(
    (entry) => entry.roles.includes('TIMESTAMP_AUTHORITY') && entry.validUntil === D,
  );
  assert.ok(oldRecord && staleRecord);
  assert.equal(oldRecord.status.nextUpdate, H + 300);
  assert.equal(staleRecord.status.nextUpdate, H);
});

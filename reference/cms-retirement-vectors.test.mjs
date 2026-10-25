import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dcbor, decodeCBOR, keyID, spki } from './core.mjs';
import { parseCertificate, verifyCMS } from './pki.mjs';
import { createRetainedAuthorityResolver } from './retained-authorities.mjs';
import { verifyTimestampToken } from './timestamp.mjs';
import { loadVectorCorpus, runDocumentVectors, runRetainedVectors } from './verify-vectors.mjs';

const directory = fileURLToPath(new URL('./vectors/cms-retirement-mtc07-rar2/', import.meta.url));
const S = 1792454400,
  P = 1792454402,
  R = 1792454502,
  K = 1792627202;
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const optionsFor = (corpus, name) =>
  corpus.config(corpus.manifest.retained.find(({ id }) => id === 'cms-retirement-' + name).options);
const statusLeaf = (bytes) =>
  decodeCBOR(bytes).objects.find(({ type }) => type === 'CertificateStatus');

test('fixed CMS retirement corpus preserves the original and limits current changes to status', () => {
  const corpus = loadVectorCorpus(directory),
    previous = loadVectorCorpus();
  const input = optionsFor(corpus, 'successor');
  const old = previous.config(
    previous.manifest.retained.find(({ id }) => id === 'cms-retained-renewed').options,
  );
  assert.equal(corpus.manifest.documents.length, 1);
  assert.equal(corpus.manifest.retained.length, 14);
  assert.deepEqual(input.originalBytes, old.originalBytes);
  assert.deepEqual(input.evidenceRecord, old.evidenceRecord);
  assert.equal(
    hash(input.originalBytes),
    '09e93450939c93b3dce9daa2ab8f278a357701b46d2d93f0c4fba3c9a0839133',
  );
  assert.equal(
    hash(input.evidenceRecord),
    '148c25cb9fb9c16846eb14ece6bc8927bdf442444d7ff76168b680236b343050',
  );
  const original = decodeCBOR(input.originalBytes),
    current = decodeCBOR(input.currentBytes);
  assert.deepEqual(
    current.objects.filter(({ type }) => type !== 'CertificateStatus'),
    original.objects.filter(({ type }) => type !== 'CertificateStatus'),
  );
  assert.equal(
    hash(statusLeaf(input.originalBytes).payload),
    '65f5d18908b652ac34182411a19b96bf8f1bc1f0c951da74365dd3c7fe92b99e',
  );
  for (const entry of corpus.manifest.retained) {
    const variant = corpus.config(entry.options);
    assert.deepEqual(variant.originalBytes, input.originalBytes, entry.id);
    assert.deepEqual(
      corpus.config(variant.historicalTrust),
      corpus.config(input.historicalTrust),
      entry.id,
    );
  }
  const result = runDocumentVectors({ directory })[0].actual;
  assert.equal(result.overall, 'VALID');
  for (const name of [
    'integrity',
    'issuerTrust',
    'qualification',
    'keyBinding',
    'authorization',
    'status',
    'time',
    'transparency',
  ])
    assert.equal(result.dimensions[name].overall, 'VALID', name);
});

test('fixed successor and wrong-target status have valid signatures from the same distinct key', () => {
  const corpus = loadVectorCorpus(directory),
    input = optionsFor(corpus, 'successor');
  const oldCertificate = corpus.config(input.historicalTrust).trust.statusCertificate;
  const newCertificate = corpus.config(input.currentTrust).trust.statusCertificate;
  assert.notDeepEqual(
    keyID(parseCertificate(oldCertificate).publicKey),
    keyID(parseCertificate(newCertificate).publicKey),
  );
  const oldStatus = decodeCBOR(
    verifyCMS(statusLeaf(input.originalBytes).payload, { expectedCertificate: oldCertificate })
      .content,
  )[3];
  const payload = statusLeaf(input.currentBytes).payload;
  const currentStatus = decodeCBOR(
    verifyCMS(payload, { expectedCertificate: newCertificate }).content,
  )[3];
  assert.equal(oldStatus.publishedAt, S);
  assert.deepEqual(
    dcbor(currentStatus),
    dcbor({ ...oldStatus, publishedAt: K, nextUpdate: K + 300 }),
  );
  const wrong = optionsFor(corpus, 'wrong-target');
  const wrongStatus = decodeCBOR(
    verifyCMS(statusLeaf(wrong.currentBytes).payload, { expectedCertificate: newCertificate })
      .content,
  )[3];
  assert.notDeepEqual(wrongStatus.certificateID, currentStatus.certificateID);
  assert.deepEqual(
    dcbor({ ...wrongStatus, certificateID: currentStatus.certificateID }),
    dcbor(currentStatus),
  );
  const corrupted = Buffer.from(payload);
  corrupted[corrupted.length - 1] ^= 1;
  assert.throws(() => verifyCMS(corrupted, { expectedCertificate: newCertificate }));
});

test('authenticated retirement ends the old roles and admits the successor at the exact boundary', () => {
  const corpus = loadVectorCorpus(directory),
    input = optionsFor(corpus, 'successor');
  const oldTrust = corpus.config(input.historicalTrust).trust;
  const newTrust = corpus.config(input.currentTrust).trust;
  const resolver = createRetainedAuthorityResolver({
    ...input.historyTrust,
    history: decodeCBOR(input.history),
    verifyPublication: ({ imprint, proof, at }) => ({
      overall: 'VALID',
      ...verifyTimestampToken(proof, { ...input.publicationTSA, imprint, at, maxFutureSkew: 0 }),
    }),
  });
  const scope = { trustDomainID: input.historyTrust.trustDomainID };
  for (const authority of [
    { certificate: oldTrust.statusCertificate, role: 'STATUS_AUTHORITY' },
    { publicKeyDER: spki(oldTrust.mtc.caPublicKey), role: 'ISSUER' },
  ]) {
    for (const stateTime of [S, P])
      assert.equal(resolver({ ...authority, scope, stateTime, knowledgeTime: P }).overall, 'VALID');
    for (const stateTime of [S, P, R - 1])
      assert.equal(resolver({ ...authority, scope, stateTime, knowledgeTime: K }).overall, 'VALID');
    for (const stateTime of [R, K]) {
      const decision = resolver({ ...authority, scope, stateTime, knowledgeTime: K });
      assert.equal(decision.overall, 'INVALID');
      assert.equal(decision.reason, 'AUTHORITY_EXPIRED');
    }
  }
  const successor = {
    certificate: newTrust.statusCertificate,
    role: 'STATUS_AUTHORITY',
    scope,
    knowledgeTime: K,
  };
  assert.equal(resolver({ ...successor, stateTime: R - 1 }).overall, 'INVALID');
  assert.equal(resolver({ ...successor, stateTime: R - 1 }).reason, 'AUTHORITY_NOT_YET_VALID');
  for (const stateTime of [R, K])
    assert.equal(resolver({ ...successor, stateTime }).overall, 'VALID');
  for (const role of ['PERMIT_AUTHORITY', 'RECEIPT_AUTHORITY'])
    assert.equal(
      resolver({
        certificate: oldTrust.statusCertificate,
        role,
        scope,
        stateTime: K,
        knowledgeTime: K,
      }).overall,
      'VALID',
      role,
    );
  assert.equal(input.historicalKnowledgeTime, P);
  assert.equal(input.currentKnowledgeTime, K);
  assert(S < P && P < R && R < K);
});

test('fixed retirement replay separates all three decisions offline at explicit knowledge times', async (t) => {
  const network = t.mock.method(globalThis, 'fetch', () => {
    throw Error('Unexpected network');
  });
  let wallClock = 0;
  t.mock.method(Date, 'now', () => wallClock);
  const first = runRetainedVectors({ directory });
  wallClock = 4102444800000;
  assert.deepEqual(runRetainedVectors({ directory }), first);
  assert.equal(network.mock.callCount(), 0);
  const rows = new Map(
    first.map(({ id, actual, details }) => [
      id.slice('cms-retirement-'.length),
      { actual, details },
    ]),
  );
  const cases = [
    ['successor', 'VALID', 'VALID', 'VALID', 'VALID'],
    [
      'missing',
      'INDETERMINATE',
      'VALID',
      'VALID',
      'INDETERMINATE',
      'currentAdmissibility',
      'AUTHORITY_MISSING',
    ],
    [
      'wrong-role',
      'INVALID',
      'VALID',
      'VALID',
      'INVALID',
      'currentAdmissibility',
      'AUTHORITY_ROLE',
    ],
    [
      'wrong-scope',
      'INVALID',
      'VALID',
      'VALID',
      'INVALID',
      'currentAdmissibility',
      'AUTHORITY_SCOPE',
    ],
    [
      'stale-current',
      'INDETERMINATE',
      'VALID',
      'VALID',
      'INDETERMINATE',
      'currentAdmissibility',
      'ECP_STATUS_STALE',
    ],
    [
      'missing-proof',
      'INVALID',
      'INVALID',
      'INDETERMINATE',
      'VALID',
      'historicalAuthorization',
      'HISTORICAL_BYTES_UNPROVEN',
    ],
    [
      'before-first-proof',
      'INDETERMINATE',
      'VALID',
      'INDETERMINATE',
      'VALID',
      'historicalAuthorization',
      'HISTORICAL_BYTES_NOT_YET_PROVEN',
    ],
    [
      'missing-renewal',
      'INVALID',
      'INVALID',
      'VALID',
      'VALID',
      'preservation',
      'ERS_FINAL_PROTECTION_EXPIRED',
    ],
    [
      'late-renewal',
      'INVALID',
      'INVALID',
      'VALID',
      'VALID',
      'preservation',
      'ERS_HASH_RENEWAL_LATE',
    ],
    [
      'later-compromise',
      'INVALID',
      'VALID',
      'VALID',
      'INVALID',
      'currentAdmissibility',
      'AUTHORITY_REVOKED',
    ],
    [
      'later-historical-compromise',
      'INVALID',
      'VALID',
      'INVALID',
      'INVALID',
      'historicalAuthorization',
      'AUTHORITY_REVOKED',
    ],
    [
      'history-conflict',
      'INVALID',
      'INVALID',
      'VALID',
      'INVALID',
      'preservation',
      'HISTORY_MANIFEST_CHAIN',
    ],
    [
      'wrong-target',
      'INVALID',
      'VALID',
      'VALID',
      'INVALID',
      'currentAdmissibility',
      'ECP_STATUS_BINDING',
    ],
    [
      'changed-operation',
      'INVALID',
      'VALID',
      'VALID',
      'INVALID',
      'currentAdmissibility',
      'HISTORICAL_OPERATION_CHANGED',
    ],
  ];
  assert.equal(rows.size, cases.length);
  for (const [name, overall, preservation, historical, current, part, reason] of cases)
    await t.test(name, () => {
      const { actual, details } = rows.get(name);
      assert.deepEqual(
        [
          actual.overall,
          actual.preservation.overall,
          actual.historicalAuthorization.overall,
          actual.currentAdmissibility.overall,
        ],
        [overall, preservation, historical, current],
      );
      if (part) assert.equal(actual[part].reason, reason);
      assert.equal(actual.currentKnowledgeTime, K);
      assert.equal(
        actual.historicalKnowledgeTime,
        name === 'before-first-proof' ? P - 1 : name === 'later-historical-compromise' ? K : P,
      );
      if (name !== 'missing-proof')
        assert.equal(details.originalProof.proofOfExistenceUpperBound, P);
    });
  const positive = rows.get('successor').details;
  assert.equal(positive.preservation.chains, 2);
  assert.equal(positive.preservation.timestamps, 3);
  assert.equal(positive.preservation.latestRenewalUpperBound, 1792456402);
  assert.equal(positive.historicalAuthorization.proofOfExistenceUpperBound, S);
  assert.equal(positive.originalProof.proofOfExistenceUpperBound, P);
  assert.equal(rows.get('missing-proof').actual.preservation.reason, 'MALFORMED_EVIDENCE');
  assert.equal(
    rows.get('history-conflict').actual.currentAdmissibility.reason,
    'HISTORY_MANIFEST_CHAIN',
  );
});

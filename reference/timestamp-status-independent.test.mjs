import test from 'node:test';
import assert from 'node:assert/strict';
import { setImmediate as immediate } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { Journal } from './state.mjs';
import { TimestampAuthority, timestampRequest, tokenFromResponse, verifyTimestampToken } from './timestamp.mjs';
import { createERS, renewERS, verifyERSPreservation } from './archive.mjs';
import { VerificationError, verificationOutcome } from './verification-result.mjs';
import { createAuthorityResolver } from './authority-history.mjs';
import { createRetainedAuthorityResolver } from './retained-authorities.mjs';
import { createEvidencePackage, evidenceLeaf } from './evidence-plan.mjs';
import { createVerifier } from './sdk/index.mjs';
import { verifyPreservedDocument } from './historical-validation.mjs';
import { loadVectorCorpus } from './verify-vectors.mjs';

const statusBoundary = () => import('./status-result.mjs');
const at = 1_800_000_000;
const negative = [
  ['missing', 'INDETERMINATE', 'AUTHORITY_STATUS_MISSING'],
  ['stale', 'INDETERMINATE', 'AUTHORITY_STATUS_STALE'],
  ['unknown', 'INDETERMINATE', 'AUTHORITY_STATUS_UNKNOWN'],
  ['coverage', 'INDETERMINATE', 'HISTORY_KNOWLEDGE_COVERAGE'],
  ['revoked', 'INVALID', 'AUTHORITY_REVOKED'],
  ['unsupported', 'UNSUPPORTED', 'AUTHORITY_STATUS_CRITICAL_UNSUPPORTED'],
];
const checkError = (operation, overall, reason) => assert.throws(operation, (error) => {
  assert(error instanceof VerificationError);
  assert.equal(error.overall, overall);
  assert.equal(error.code, reason);
  assert.equal(error.dimension, 'time');
  return true;
});

test('timestamp status boundary preserves explicit typed decisions and legacy booleans', async () => {
  const { requireStatusDecision } = await statusBoundary();
  const query = { stateTime: at, knowledgeTime: at + 1 };
  assert.doesNotThrow(() => requireStatusDecision(() => true, query, 'TEST_TSA'));
  assert.doesNotThrow(() => requireStatusDecision(() => ({ overall: 'VALID', reason: 'AUTHORITY_ADMITTED' }), query, 'TEST_TSA'));
  checkError(() => requireStatusDecision(() => false, query, 'TEST_TSA'), 'INVALID', 'TEST_TSA');
  for (const [, overall, reason] of negative)
    checkError(() => requireStatusDecision(() => ({ overall, reason }), query, 'TEST_TSA'), overall, reason);
});

test('timestamp status boundary rejects malformed, inherited, asynchronous and accessor decisions', async () => {
  const { requireStatusDecision } = await statusBoundary();
  let getterCalls = 0;
  const accessor = { overall: 'VALID', get reason() { getterCalls++; return 'FORGED'; } };
  const hiddenThen = { overall: 'VALID', reason: 'FORGED', get then() { getterCalls++; return undefined; } };
  const values = [undefined, null, 1, 'VALID', [], {}, { overall: 'VALID' },
    { overall: 'VALID', reason: '' }, { overall: 'INDETERMINATE', reason: 12 },
    { overall: 'UNKNOWN', reason: 'FORGED' }, Object.create({ overall: 'VALID', reason: 'FORGED' }),
    { overall: 'VALID', reason: 'FORGED', then() {} }, Promise.resolve(true), accessor, hiddenThen];
  for (const value of values)
    checkError(() => requireStatusDecision(() => value, {}, 'TEST_TSA'), 'INVALID', 'TEST_TSA_DECISION');
  assert.equal(getterCalls, 0);
  const rejected = Promise.reject(new Error('Unavailable remote status'));
  checkError(() => requireStatusDecision(() => rejected, {}, 'TEST_TSA'), 'INVALID', 'TEST_TSA_DECISION');
  await immediate();
});

test('timestamp status callback exceptions cannot select a forged result or reason', async () => {
  const { requireStatusDecision } = await statusBoundary();
  for (const thrown of [
    Object.assign(new Error('bad dependency'), { overall: 'VALID', code: 'FORGED_ACCEPTANCE' }),
    { overall: 'UNSUPPORTED', code: 'FORGED_UNSUPPORTED' },
    new VerificationError('FORGED_TYPED_EXCEPTION', 'INVALID', 'authorization'),
  ]) checkError(() => requireStatusDecision(() => { throw thrown; }, {}, 'TEST_TSA'),
    'INDETERMINATE', 'TEST_TSA_UNAVAILABLE');
});

test('a rejected native status Promise is observed without terminating a separate verifier process', () => {
  const moduleURL = new URL('./status-result.mjs', import.meta.url).href;
  const script = `
    import assert from 'node:assert/strict';
    import { setImmediate as immediate } from 'node:timers/promises';
    const { requireStatusDecision } = await import(${JSON.stringify(moduleURL)});
    assert.throws(() => requireStatusDecision(() => Promise.reject(new Error('Rejected status source')), {}, 'CHILD_TSA'),
      (error) => error.overall === 'INVALID' && error.code === 'CHILD_TSA_DECISION');
    await immediate();
    await immediate();
    process.stdout.write('STATUS_REJECTION_OBSERVED\\n');
  `;
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8', timeout: 10000 });
  assert.equal(child.error, undefined);
  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.signal, null);
  assert.equal(child.stdout, 'STATUS_REJECTION_OBSERVED\n');
  assert.equal(child.stderr, '');
});

async function archiveFixture() {
  const root = c.generate('ml-dsa-87'), key = c.generate('ml-dsa-87'), journal = new Journal();
  let clock = at;
  const certificate = p.issueCertificate({ publicKey: key.publicKey, serial: 711,
    issuer: p.name('Status decision fixture'), subject: p.name('Status decision TSA'),
    profileID: 'CERTCONCORD-TSA-v1', notBefore: at - 60, notAfter: at + 1000 }, root.privateKey);
  const service = new TimestampAuthority({ certificate, privateKey: key.privateKey, journal,
    policy: '1.3.6.1.4.1.32473.77.2', clock: () => clock, accuracySeconds: 0 });
  const issue = (imprint, hashOID = p.OID.sha512) => tokenFromResponse(service.issue(timestampRequest(imprint, {
    policy: service.policy, hashOID,
  }).der));
  const data = Buffer.from('Original evidence with independently evaluated timestamp status');
  const first = await createERS(data, { tsa: issue });
  clock = at + 10;
  const renewed = await renewERS(first, data, { tsa: issue });
  const policy = (status) => ({ at: at + 20, dataValidUntil: at + 100,
    hashValidUntil: { [p.OID.sha512]: at + 1000 }, resolveTimestamp: () => ({
      certificate, issuerKey: root.publicKey, policy: service.policy, validUntil: at + 1000, status,
    }) });
  return { data, first, renewed, policy, close() { journal.close(); } };
}

test('real ERS accepts legacy true and typed VALID, and retains legacy false rejection', async () => {
  const f = await archiveFixture();
  try {
    for (const status of [() => true, () => ({ overall: 'VALID', reason: 'AUTHORITY_ADMITTED' })]) {
      const result = verifyERSPreservation(f.renewed, f.data, f.policy(status));
      assert.equal(result.preservation, 'VALID');
      assert.equal(result.timestamps, 2);
      assert.equal(result.proofOfExistenceUpperBound, at);
    }
    checkError(() => verifyERSPreservation(f.renewed, f.data, f.policy(() => false)), 'INVALID', 'ERS_TSA_STATUS');
  } finally { f.close(); }
});

for (const [name, overall, reason] of negative)
  test(`real ERS preserves ${name} TSA status as ${overall}`, async () => {
    const f = await archiveFixture();
    try {
      const queries = [];
      checkError(() => verifyERSPreservation(f.first, f.data, f.policy((query) => {
        queries.push(query); return { overall, reason };
      })), overall, reason);
      assert.equal(queries.length, 1);
      assert.equal(queries[0].stateTime, at);
      assert.equal(queries[0].knowledgeTime, at + 20);
    } finally { f.close(); }
  });

test('real ERS rejects corrupted timestamp mathematics before consulting its status callback', async () => {
  const f = await archiveFixture();
  try {
    const bad = Buffer.from(f.first); bad[bad.length - 1] ^= 1;
    let calls = 0;
    assert.throws(() => verifyERSPreservation(bad, f.data, f.policy(() => {
      calls++; return { overall: 'INDETERMINATE', reason: 'HISTORY_KNOWLEDGE_COVERAGE' };
    })), (error) => { assert.equal(verificationOutcome(error).overall, 'INVALID'); return true; });
    assert.equal(calls, 0);
  } finally { f.close(); }
});

test('real ERS later corrupted mathematics remains INVALID when an earlier TSA status is unavailable', async () => {
  const f = await archiveFixture();
  try {
    const bad = Buffer.from(f.renewed); bad[bad.length - 1] ^= 1;
    assert.throws(() => verifyERSPreservation(bad, f.data, f.policy(() => ({
      overall: 'INDETERMINATE', reason: 'HISTORY_KNOWLEDGE_COVERAGE',
    }))), (error) => { assert.equal(verificationOutcome(error).overall, 'INVALID'); return true; });
  } finally { f.close(); }
});

test('real ERS known revocation remains INVALID when the hash protection deadline is unavailable', async () => {
  const f = await archiveFixture();
  try {
    const policy = f.policy(() => ({ overall: 'INVALID', reason: 'AUTHORITY_REVOKED' }));
    policy.hashValidUntil = {};
    checkError(() => verifyERSPreservation(f.renewed, f.data, policy), 'INVALID', 'AUTHORITY_REVOKED');
  } finally { f.close(); }
});

test('real ERS unsupported status remains UNSUPPORTED when later timestamp trust is unavailable', async () => {
  const f = await archiveFixture();
  try {
    const policy = f.policy(() => ({ overall: 'UNSUPPORTED', reason: 'AUTHORITY_STATUS_CRITICAL_UNSUPPORTED' }));
    const resolve = policy.resolveTimestamp;
    let calls = 0;
    policy.resolveTimestamp = () => ++calls === 1 ? resolve() : undefined;
    checkError(() => verifyERSPreservation(f.renewed, f.data, policy),
      'UNSUPPORTED', 'AUTHORITY_STATUS_CRITICAL_UNSUPPORTED');
    assert.equal(calls, 2);
  } finally { f.close(); }
});

const corpus = loadVectorCorpus(fileURLToPath(new URL('./vectors/document-acceptance-mtc07-rar2-mdoc2', import.meta.url)));
function documentInput(format, status) {
  const entry = corpus.manifest.documents.find((item) => item.id === format.toLowerCase() + '-valid');
  const input = corpus.config(entry.trust);
  input.trust.authorityResolver = createAuthorityResolver({ trustDomainID: input.trust.trustDomainID,
    authorities: input.authorities });
  input.trust.timestamp.status = status;
  return { entry, trust: input.trust, bytes: corpus.read(entry.bytes) };
}

for (const format of ['CMS', 'MDOC']) {
  for (const [name, overall, reason] of negative)
    test(`${format} public document preserves ${name} timestamp status as ${overall}`, () => {
      const queries = [];
      const input = documentInput(format, (query) => { queries.push(query); return { overall, reason }; });
      const result = createVerifier({ format, trust: input.trust }).verify(input.bytes);
      assert.equal(result.overall, overall, JSON.stringify(result));
      assert.equal(result.reason, reason);
      assert.deepEqual(result.dimensions.time, { overall, reason });
      assert(queries.length > 0);
      assert(queries.every((query) => query.knowledgeTime === input.trust.knowledgeTime));
    });

  test(`${format} public document rejects a malformed timestamp decision and a forged callback exception`, () => {
    for (const [callback, overall, reason] of [
      [() => ({ overall: 'VALID' }), 'INVALID', 'DOCUMENT_TIMESTAMP_STATUS_DECISION'],
      [() => { throw { overall: 'VALID', code: 'FORGED' }; }, 'INDETERMINATE', 'DOCUMENT_TIMESTAMP_STATUS_UNAVAILABLE'],
      [() => false, 'INVALID', 'DOCUMENT_TIMESTAMP_STATUS'],
      [() => true, 'VALID', null],
    ]) {
      const input = documentInput(format, callback);
      const result = createVerifier({ format, trust: input.trust }).verify(input.bytes);
      assert.equal(result.overall, overall, JSON.stringify(result));
      if (reason) assert.equal(result.reason, reason);
    }
  });

  test(`${format} corrupted public timestamp remains INVALID with unavailable current status`, () => {
    const input = documentInput(format, () => ({ overall: 'INDETERMINATE', reason: 'HISTORY_KNOWLEDGE_COVERAGE' }));
    const bundle = c.decodeCBOR(input.bytes);
    const objects = bundle.objects.map((leaf) => {
      if (leaf.type !== 'DocumentTimestamp') return leaf;
      const payload = Buffer.from(leaf.payload); payload[payload.length - 1] ^= 1;
      return evidenceLeaf(leaf.type, payload);
    });
    const result = createVerifier({ format, trust: input.trust }).verify(c.dcbor(createEvidencePackage(bundle.plan.profile, objects)));
    assert.equal(result.overall, 'INVALID', JSON.stringify(result));
    assert.equal(result.dimensions.time.overall, 'INVALID');
  });

  test(`${format} retained public archive keeps missing current history INDETERMINATE`, () => {
    const entry = corpus.manifest.retained.find((item) => item.id === format.toLowerCase() + '-retained-renewed');
    const input = corpus.config(entry.options), history = c.decodeCBOR(input.history), decisions = [];
    const authorityResolver = createRetainedAuthorityResolver({ ...input.historyTrust, history: [history[0]],
      verifyPublication: ({ imprint, proof, at }) => ({ overall: 'VALID', ...verifyTimestampToken(proof,
        { ...input.publicationTSA, imprint, at, maxFutureSkew: 0 }) }),
    });
    const trust = (name) => {
      const configured = corpus.config(name);
      configured.trust.timestamp.status = () => ({ overall: 'VALID', reason: 'EXTERNAL_TSA_STATUS_GOOD' });
      return configured.trust;
    };
    const result = verifyPreservedDocument({ ...input, authorityResolver,
      preservationPolicy: { ...input.preservationPolicy, resolveTimestamp(token) {
        const certificate = p.verifyCMS(token, { expectedContentType: p.OID.tstInfo }).certificate;
        const selected = input.preservationPolicy.timestampAuthorities.find((candidate) => candidate.certificate.equals(certificate));
        return { ...selected, status(query) {
          const decision = authorityResolver({ ...query, role: 'TIMESTAMP_AUTHORITY',
            scope: { trustDomainID: input.historyTrust.trustDomainID } });
          decisions.push(decision); return decision;
        } };
      } }, historicalTrust: trust(input.historicalTrust), currentTrust: trust(input.currentTrust),
    });
    assert.equal(decisions[0].overall, 'INDETERMINATE');
    assert.equal(result.preservation.overall, 'INDETERMINATE', JSON.stringify(result));
    assert.equal(result.preservation.reason, decisions[0].reason);
    assert.equal(result.overall, 'INDETERMINATE');
  });
}

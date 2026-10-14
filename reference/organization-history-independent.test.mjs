import test from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { readControl } from './state.mjs';
import { createIndependentOrganizationHistoryFixture } from './fixtures-history-independent.mjs';

const historyAPI = () => import('./sdk/index.mjs');
const fixedDimensions = new Set(['integrity', 'issuerTrust', 'qualification', 'keyBinding',
  'authorization', 'status', 'time', 'transparency']);
async function usingFixture(action, options) {
  const f = await createIndependentOrganizationHistoryFixture(options);
  try { return await action(f, (await historyAPI()).createOrganizationHistoryVerifier); }
  finally { f.close(); }
}
function verdict(result, expected) {
  assert.equal(result.overall, expected, JSON.stringify(result));
  assert.equal(result.coreRevision, 'draft-03');
  assert.equal(result.profile, 'certconcord-ecp-cms-organization-delegation-v1');
  assert.equal(typeof result.reason, 'string');
  assert(result.reason.length > 0);
  assert(Object.isFrozen(result));
  assert(Object.isFrozen(result.dimensions));
  for (const [dimension, decision] of Object.entries(result.dimensions)) {
    assert(fixedDimensions.has(dimension));
    assert(['VALID', 'INVALID', 'UNSUPPORTED', 'INDETERMINATE'].includes(decision.overall));
    assert.equal(typeof decision.reason, 'string');
    assert(decision.reason.length > 0);
    assert(Object.isFrozen(decision));
  }
  return result;
}
const rejected = (result) => {
  assert.notEqual(result.overall, 'VALID', JSON.stringify(result));
  for (const name of ['signature', 'receipt', 'cms', 'bundle', 'permit', 'authorization'])
    assert.equal(Object.hasOwn(result, name), false, name);
};
const targetIndex = (f, type = 'GRANT') => f.originalStatusMembers.findIndex((member) =>
  readControl(member.cms, 'OrganizationDelegationStatus', member.issuerCertificate).objectType === type);
function withResolver(f, authorityResolver) {
  const resolveTimestamp = f.options.preservationPolicy.resolveTimestamp;
  return { ...f.options, authorityResolver, preservationPolicy: { ...f.options.preservationPolicy,
    resolveTimestamp(token) {
      const trust = resolveTimestamp(token);
      return trust && { ...trust, status: ({ certificate, stateTime, knowledgeTime }) => authorityResolver({
        certificate, stateTime, knowledgeTime, role: 'TIMESTAMP_AUTHORITY',
        scope: { trustDomainID: f.source.trustDomainID },
      }) };
    },
  } };
}

test('historical organization acceptance preserves original bytes after issuer expiry and scoped succession', async () => usingFixture((f, create) => {
  const result = verdict(create(f.options).verify(f.input), 'VALID');
  assert.equal(result.purpose, 'RETAINED_EVIDENCE_VERIFICATION');
  assert.equal(result.operationTime, f.A);
  assert.equal(result.proofOfExistenceUpperBound, f.P);
  assert.equal(result.knowledgeTime, f.K);
  assert.equal(result.historicalAuthorization.overall, 'VALID');
  assert.equal(result.historicalAuthorization.scope, 'AS_KNOWN_AT_PROOF_TIME');
  assert.equal(result.historicalAuthorization.stateTime, f.P);
  assert.equal(result.historicalAuthorization.knowledgeTime, f.P);
  assert.equal(result.currentAdmissibility.overall, 'VALID');
  assert.equal(result.currentAdmissibility.scope, 'HISTORICAL_EVIDENCE_UNDER_CURRENT_KNOWLEDGE');
  assert.equal(result.currentAdmissibility.stateTime, f.P);
  assert.equal(result.currentAdmissibility.knowledgeTime, f.K);
  assert.equal(result.preservation.overall, 'VALID');
  assert(result.limitations.includes('AUTHORITY_ATTESTED_WORKLOAD_PERMISSION'));
  assert(result.limitations.includes('NO_CURRENT_EXECUTION_PERMISSION'));
  assert(p.parseCertificate(f.source.keys.issuer.certificate).notAfter < f.K);
  assert(f.queries.some((query) => query.stateTime === f.P && query.knowledgeTime === f.P));
  assert(f.queries.some((query) => query.stateTime === f.P && query.knowledgeTime === f.K));
  assert(f.queries.some((query) => query.stateTime === f.A - 10 && query.knowledgeTime === f.K));
  assert(f.queries.every((query) => query.knowledgeTime === f.P || query.knowledgeTime === f.K));
  assert.equal(f.source.calls.sign, 1);
  assert.equal(Object.hasOwn(result.dimensions, 'transparency'), false);
}));

test('retrospective permission never releases a completed signature after current workload exit', async () => usingFixture(async (f, create) => {
  f.source.advance(f.K - f.A);
  f.source.context.operator.active = false;
  f.source.context.executionCurrent = null;
  verdict(create(f.options).verify(f.input), 'VALID');
  const denied = await f.app.reconcile({ operationID: f.source.operationID, signature: f.completed.signature });
  rejected(denied);
  assert.equal(f.source.calls.sign, 1);
  const record = f.app.getOperationResult({ operationID: f.source.operationID });
  assert.equal(record.admission, 'NOT_REEVALUATED');
  assert.equal(record.originalStatus, 'COMPLETED');
}));

for (const type of ['GRANT', 'APPROVER_REGISTRATION', 'FINAL_AUTHORIZATION']) {
  test(`historical ${type} remains admissible after ordinary later revocation`, async () => usingFixture((f, create) => {
    const i = targetIndex(f, type);
    f.knowledge.statusMaterial[i] = f.organizationStatus(f.originalStatusMembers[i], {
      status: 'REVOKED', effectiveTime: f.P + 1,
    });
    const result = verdict(create(f.options).verify(f.input), 'VALID');
    assert.equal(result.historicalAuthorization.overall, 'VALID');
    assert.equal(result.currentAdmissibility.overall, 'VALID');
  }));
  test(`later learned ${type} compromise at the proof bound denies current historical reliance`, async () => usingFixture((f, create) => {
    const i = targetIndex(f, type);
    f.knowledge.statusMaterial[i] = f.organizationStatus(f.originalStatusMembers[i], {
      status: 'REVOKED', effectiveTime: f.K - 1, compromiseStart: f.P,
    });
    const result = verdict(create(f.options).verify(f.input), 'INVALID');
    assert.equal(result.historicalAuthorization.overall, 'VALID');
    assert.equal(result.currentAdmissibility.overall, 'INVALID');
    assert.equal(result.preservation.overall, 'VALID');
    rejected(result);
  }));
}

test('later GOOD cannot erase a retained organization key compromise', async () => usingFixture((f, create) => {
  const i = targetIndex(f);
  f.knowledge.statusMaterial.push(f.organizationStatus(f.originalStatusMembers[i], {
    epoch: 3, status: 'REVOKED', effectiveTime: f.K - 1, compromiseStart: f.A,
  }), f.organizationStatus(f.originalStatusMembers[i], { epoch: 4 }));
  const result = verdict(create(f.options).verify(f.input), 'INVALID');
  assert.equal(result.currentAdmissibility.overall, 'INVALID');
}));

test('contradictory same-epoch original targets remain INVALID with a later GOOD head', async () => usingFixture((f, create) => {
  const i = targetIndex(f);
  f.knowledge.statusMaterial.push(f.organizationStatus(f.originalStatusMembers[i], {
    epoch: 2, status: 'REVOKED', effectiveTime: f.K - 1,
  }), f.organizationStatus(f.originalStatusMembers[i], { epoch: 3 }));
  const result = verdict(create(f.options).verify(f.input), 'INVALID');
  assert.equal(result.currentAdmissibility.overall, 'INVALID');
}));

for (const incident of ['compromise', 'same-epoch conflict'])
  test(`one verifier retains authenticated ${incident} when later knowledge supplies only newer GOOD`, async () => usingFixture((f, create) => {
    const i = targetIndex(f);
    const original = f.originalStatusMembers[i];
    f.knowledge.statusMaterial.push(f.organizationStatus(original, {
      epoch: incident === 'compromise' ? 3 : 2, status: 'REVOKED', effectiveTime: f.K - 1,
      ...(incident === 'compromise' ? { compromiseStart: f.A } : {}),
    }));
    const verifier = create(withResolver(f, f.resolver(f.history, f.K + 10)));
    const first = verdict(verifier.verify(f.input), 'INVALID');
    assert.equal(first.currentAdmissibility.overall, 'INVALID');
    f.knowledge.knowledgeTime = f.K + 1;
    f.knowledge.statusMaterial = f.originalStatusMembers.map((member) => f.organizationStatus(member,
      { epoch: 4, publishedAt: f.K }));
    const later = verdict(verifier.verify(f.input), 'INVALID');
    assert.equal(later.knowledgeTime, f.K + 1);
    assert.equal(later.historicalAuthorization.overall, 'VALID');
    assert.equal(later.currentAdmissibility.overall, 'INVALID');
    rejected(later);
  }));

test('one verifier retains authenticated credential compromise after a later GOOD-only refresh', async () => usingFixture((f, create) => {
  f.knowledge.certificateStatusMaterial = [f.certificateStatus({ status: 'REVOKED',
    effectiveTime: f.K - 1, compromiseStart: f.A })];
  const verifier = create(withResolver(f, f.resolver(f.history, f.K + 10)));
  verdict(verifier.verify(f.input), 'INVALID');
  f.knowledge.knowledgeTime = f.K + 1;
  f.knowledge.certificateStatusMaterial = [f.certificateStatus({ publishedAt: f.K })];
  const later = verdict(verifier.verify(f.input), 'INVALID');
  assert.equal(later.historicalAuthorization.overall, 'VALID');
  assert.equal(later.currentAdmissibility.overall, 'INVALID');
}));

test('current historical reliance requires latest organization and certificate coverage', async () => usingFixture((f, create) => {
  f.knowledge.statusMaterial = [];
  f.knowledge.certificateStatusMaterial = [];
  const result = verdict(create(f.options).verify(f.input), 'INDETERMINATE');
  assert.equal(result.historicalAuthorization.overall, 'VALID');
  assert.equal(result.preservation.overall, 'VALID');
  assert.equal(result.currentAdmissibility.overall, 'INDETERMINATE');
}));

test('missing latest retained authority coverage preserves an authenticated initial proof and historical view', async () => usingFixture((f, create) => {
  const result = verdict(create(withResolver(f, f.resolver([f.firstManifest]))).verify(f.input), 'INDETERMINATE');
  assert.equal(result.proofOfExistenceUpperBound, f.P);
  assert.equal(result.historicalAuthorization.overall, 'VALID');
  assert.equal(result.historicalAuthorization.knowledgeTime, f.P);
  assert.equal(result.currentAdmissibility.overall, 'INDETERMINATE');
  assert.equal(result.preservation.overall, 'INDETERMINATE');
  rejected(result);
}));

test('original organization authority admission without explicit knowledge coverage is INDETERMINATE', async () => usingFixture((f, create) => {
  let omitted = 0;
  const authorityResolver = (query) => {
    const decision = f.options.authorityResolver(query);
    if (query.role !== 'ORGANIZATION_AUTHORITY' || decision.overall !== 'VALID') return decision;
    const { coverageUntil, ...incomplete } = decision;
    assert(Number.isFinite(coverageUntil));
    omitted++;
    return incomplete;
  };
  const result = verdict(create({ ...f.options, authorityResolver }).verify(f.input), 'INDETERMINATE');
  assert(omitted > 0);
  assert.equal(result.historicalAuthorization.overall, 'INDETERMINATE');
  assert.equal(result.currentAdmissibility.overall, 'INDETERMINATE');
}));

test('a receipt authority first admitted at P cannot authorize a receipt declared earlier at A', async () => usingFixture((f, create) => {
  const shiftReceipt = (records) => records.map((record) => record.roles.includes('RECEIPT_AUTHORITY')
    ? { ...record, validFrom: f.P } : record);
  const first = f.manifest(shiftReceipt(f.initialAuthorities), f.A - 30);
  const latest = f.manifest(shiftReceipt(f.currentAuthorities), f.K - 1, first, { replacement: true });
  const result = verdict(create(withResolver(f, f.resolver([first, latest]))).verify(f.input), 'INVALID');
  assert.equal(result.operationTime, f.A);
  assert.equal(result.proofOfExistenceUpperBound, f.P);
  assert.equal(result.preservation.overall, 'VALID');
  assert.equal(result.historicalAuthorization.overall, 'INVALID');
  assert.equal(result.currentAdmissibility.overall, 'INVALID');
}));

test('known organization compromise dominates missing current credential coverage', async () => usingFixture((f, create) => {
  const i = targetIndex(f);
  f.knowledge.statusMaterial[i] = f.organizationStatus(f.originalStatusMembers[i], {
    status: 'REVOKED', effectiveTime: f.K - 1, compromiseStart: f.A,
  });
  f.knowledge.certificateStatusMaterial = [];
  const result = verdict(create(f.options).verify(f.input), 'INVALID');
  assert.equal(result.currentAdmissibility.overall, 'INVALID');
}));

test('an expired external status signer cannot borrow preservation of the original package', async () => usingFixture((f, create) => {
  const i = targetIndex(f);
  f.knowledge.statusMaterial[i] = f.organizationStatus(f.originalStatusMembers[i], {}, f.source.keys.status);
  const result = verdict(create(f.options).verify(f.input), 'INVALID');
  assert.equal(result.historicalAuthorization.overall, 'VALID');
  assert.equal(result.currentAdmissibility.overall, 'INVALID');
}));

test('current scoped successors cannot substitute a different original status target', async () => usingFixture((f, create) => {
  const i = targetIndex(f);
  f.knowledge.statusMaterial[i] = f.organizationStatus(f.originalStatusMembers[i], { objectHash: c.random(64) });
  const result = verdict(create(f.options).verify(f.input), 'INVALID');
  assert.equal(result.currentAdmissibility.overall, 'INVALID');
}));

test('current history rejects a successor whose organization status purpose was never admitted', async () => usingFixture((f, create) => {
  const records = f.currentAuthorities.map((record) => c.equal(record.certificate, f.statusSuccessor.certificate)
    ? { ...record, scopes: [f.source.scope('ORGANIZATION_FINAL_AUTHORIZATION')] } : record);
  const latest = f.manifest(records, f.K - 1, f.firstManifest, { replacement: true });
  const result = verdict(create({ ...f.options, authorityResolver: f.resolver([f.firstManifest, latest]) }).verify(f.input), 'INVALID');
  assert.equal(result.currentAdmissibility.overall, 'INVALID');
}));

test('retained history rejects a unilateral root successor without accepting current status', async () => usingFixture((f, create) => {
  const latest = f.manifest(f.currentAuthorities, f.K - 1, f.firstManifest, { replacement: true, signers: [f.root] });
  const result = create({ ...f.options, authorityResolver: f.resolver([f.firstManifest, latest]) }).verify(f.input);
  rejected(result);
  assert.equal(result.overall, 'INVALID');
}));

test('historical credential revocation is evaluated using current knowledge and original proof time', async () => usingFixture((f, create) => {
  f.knowledge.certificateStatusMaterial = [f.certificateStatus({ status: 'REVOKED',
    effectiveTime: f.K - 1, compromiseStart: f.A })];
  const result = verdict(create(f.options).verify(f.input), 'INVALID');
  assert.equal(result.historicalAuthorization.overall, 'VALID');
  assert.equal(result.currentAdmissibility.overall, 'INVALID');
}));

for (const type of ['Document', 'Certificate', 'RegistrationAuthorization', 'SIM', 'SignaturePolicy',
  'OperationPermit', 'ExecutionReceipt', 'CertificateStatus', 'CMS', 'ExecutionBindingEvidence',
  'OrganizationAuthorization', 'OrganizationDelegationPath', 'OrganizationApprovalSet', 'OrganizationDelegationStatus'])
  test(`missing original ${type} cannot be reconstructed from current knowledge`, async () => usingFixture(async (f, create) => {
    const missing = { ...f.bundle, objects: f.bundle.objects.filter((leaf) => leaf.type !== type) };
    const originalBytes = c.dcbor(missing), evidenceRecord = await f.preserve(originalBytes);
    const result = create(f.options).verify({ originalBytes, evidenceRecord });
    rejected(result);
    assert.equal(result.overall, 'INDETERMINATE', JSON.stringify(result));
  }));

test('damaged original approval is INVALID even when preservation and current knowledge are unavailable', async () => usingFixture((f, create) => {
  const approvalSet = c.decodeCBOR(f.leaves.OrganizationApprovalSet);
  approvalSet.approvals[0].assertion.signature[0] ^= 1;
  const originalBytes = f.replaceLeaf('OrganizationApprovalSet', c.dcbor(approvalSet));
  const result = verdict(create({ ...f.options, readKnowledge: () => { throw new Error('Offline'); } })
    .verify({ originalBytes, evidenceRecord: Buffer.from('missing archive') }), 'INVALID');
  assert.equal(result.dimensions.integrity.overall, 'INVALID');
  assert(result.checks.some((row) => row.reason === 'ASSERTION_SIGNATURE'));
}));

test('an available bad original approval remains INVALID when another required original is missing', async () => usingFixture(async (f, create) => {
  const approvalSet = c.decodeCBOR(f.leaves.OrganizationApprovalSet);
  approvalSet.approvals[0].assertion.signature[0] ^= 1;
  const changed = c.decodeCBOR(f.replaceLeaf('OrganizationApprovalSet', c.dcbor(approvalSet)));
  changed.objects = changed.objects.filter((leaf) => leaf.type !== 'SIM');
  const originalBytes = c.dcbor(changed), evidenceRecord = await f.preserve(originalBytes);
  const result = verdict(create(f.options).verify({ originalBytes, evidenceRecord }), 'INVALID');
  assert(result.checks.some((row) => row.reason === 'ASSERTION_SIGNATURE' && row.overall === 'INVALID'));
  assert.equal(result.dimensions.integrity.overall, 'INVALID');
}));

test('preservation of different original organization bytes does not authorize a changed operation', async () => usingFixture((f, create) => {
  const originalBytes = f.replaceLeaf('Document', Buffer.from('Changed organization document'));
  const result = verdict(create(f.options).verify({ originalBytes, evidenceRecord: f.evidenceRecord }), 'INVALID');
  assert.equal(result.dimensions.integrity.overall, 'INVALID');
}));

for (const [delay, expected] of [[29, 'VALID'], [30, 'INVALID'], [31, 'INVALID']])
  test(`first whole-package proof at authorization offset ${delay} has ${expected} permission`, async () => usingFixture((f, create) => {
    const result = verdict(create(f.options).verify(f.input), expected);
    assert.equal(result.proofOfExistenceUpperBound, f.P);
  }, { proofDelay: delay }));

for (const [delay, milliseconds, expected] of [[29, 999, 'VALID'], [30, 1, 'INVALID']])
  test(`fractional proof at ${delay} seconds plus ${milliseconds} milliseconds retains the exact exclusive bound`, async () => usingFixture((f, create) => {
    const result = verdict(create(f.options).verify(f.input), expected);
    assert.equal(result.proofOfExistenceUpperBound, f.P);
    assert.notEqual(f.P, Math.floor(f.P));
    assert.equal(result.historicalAuthorization.stateTime, f.P);
  }, { proofDelay: delay, firstAccuracyMillis: milliseconds }));

test('a loose caller data deadline cannot override the earliest raw approver key cutoff', async () => usingFixture((f, create) => {
  const key = c.keyID(f.source.keys.person0.publicKey).toString('hex');
  f.trust.keyDeadlines[key] = f.A + 1;
  const result = verdict(create({ ...f.options, preservationPolicy: { ...f.options.preservationPolicy,
    dataValidUntil: f.end } }).verify(f.input), 'INVALID');
  assert.equal(result.originalProtectionDeadline, f.A + 1);
  assert.equal(result.preservation.reason, 'ERS_INITIAL_PROTECTION_LATE');
}));

test('late archive renewal cannot restore an expired original protection interval', async () => usingFixture(async (f, create) => {
  const evidenceRecord = await f.preserve(f.originalBytes, { renewalAt: f.A + 80 });
  const result = verdict(create(f.options).verify({ originalBytes: f.originalBytes, evidenceRecord }), 'INVALID');
  assert.equal(result.preservation.reason, 'ERS_RENEWAL_LATE');
  assert.equal(result.proofOfExistenceUpperBound, f.P);
  assert.equal(result.historicalAuthorization.overall, 'VALID');
}));

test('an authenticated whole-package proof before the bound receipt time is INVALID', async () => usingFixture(async (f, create) => {
  const evidenceRecord = await f.preserve(f.originalBytes, { firstAt: f.A - 1 });
  const result = verdict(create(f.options).verify({ originalBytes: f.originalBytes, evidenceRecord }), 'INVALID');
  assert.equal(result.operationTime, f.A);
  assert.equal(result.proofOfExistenceUpperBound, f.A - 1);
  assert.equal(result.currentAdmissibility.overall, 'INVALID');
}));

for (const [name, change] of [
  ['missing certificate status collection', (value) => { delete value.certificateStatusMaterial; }],
  ['non-array certificate status collection', (value) => { value.certificateStatusMaterial = {}; }],
  ['over-limit certificate status collection', (value) => { value.certificateStatusMaterial = Array(65).fill(value.certificateStatusMaterial[0]); }],
  ['non-array organization status collection', (value) => { value.statusMaterial = {}; }],
  ['over-limit organization status collection', (value) => { value.statusMaterial = Array(65).fill(value.statusMaterial[0]); }],
]) test(`malformed knowledge with ${name} produces a typed rejection without escaping verify`, async () => usingFixture((f, create) => {
  const knowledge = { ...f.knowledge };
  change(knowledge);
  const verifier = create({ ...f.options, readKnowledge: () => knowledge });
  let result;
  assert.doesNotThrow(() => { result = verifier.verify(f.input); });
  rejected(result);
  verdict(result, result.overall);
  assert.equal(result.historicalAuthorization.overall, 'VALID');
  assert.notEqual(result.currentAdmissibility.overall, 'VALID');
}));

test('the historical verifier does not rewind its own latest knowledge watermark', async () => usingFixture((f, create) => {
  const verifier = create(f.options);
  verdict(verifier.verify(f.input), 'VALID');
  f.knowledge.knowledgeTime = f.K - 1;
  const result = verdict(verifier.verify(f.input), 'INVALID');
  assert.equal(result.reason, 'ORG_KNOWLEDGE_ROLLBACK');
}));

test('historical API rejects caller-supplied evaluation scope and time overrides', async () => usingFixture((f, create) => {
  const verifier = create(f.options);
  for (const extra of [{ stateTime: f.A }, { knowledgeTime: f.A }, { scope: 'CURRENT_EXECUTION' }, { operator: { active: true } }]) {
    const result = verdict(verifier.verify({ ...f.input, ...extra }), 'INVALID');
    rejected(result);
  }
}));

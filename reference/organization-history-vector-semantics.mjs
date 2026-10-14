import assert from 'node:assert/strict';
import {
  decodeCBOR,
  dcbor,
  equal,
  parseDER,
  publicFromDER,
  sha256,
  sha512,
  verify,
} from './core.mjs';
import { parseCertificate, verifyCMS, OID } from './pki.mjs';
import { readControl } from './state.mjs';
import { parseTSTInfo } from './timestamp.mjs';

// This independent oracle is used by authoring and tests, never by the replay
// runner or a verifier. These outcomes are specified before expected capture.
export const organizationHistoryVectorTime = 1_800_000_000;
const A = organizationHistoryVectorTime;
const K = A + 7200;
const profile = 'certconcord-ecp-cms-organization-delegation-v1';
const V = 'VALID',
  I = 'INVALID',
  U = 'INDETERMINATE';
const requiredOriginals = Object.freeze([
  'Document',
  'Certificate',
  'RegistrationAuthorization',
  'SIM',
  'SignaturePolicy',
  'OperationPermit',
  'ExecutionReceipt',
  'CertificateStatus',
  'CMS',
  'ExecutionBindingEvidence',
  'OrganizationAuthorization',
  'OrganizationDelegationPath',
  'OrganizationApprovalSet',
  'OrganizationDelegationStatus',
]);
const definition = (id, kind, description, outcomes = [V, V, V, V], details = {}) =>
  Object.freeze({
    id,
    kind,
    description,
    outcomes: Object.freeze(outcomes),
    proofOffset: 1,
    knowledgeTime: K,
    ...details,
  });
const slug = (name) =>
  name
    .replace(/([a-z])([A-Z])/g, '$1-$2')
    .replaceAll('_', '-')
    .toLowerCase();

export const organizationHistorySemantics = Object.freeze([
  definition(
    'expired-issuer-scoped-successor',
    'positive',
    'Expired original issuer and retired original roles retain valid historical evidence under scoped succession.',
  ),
  ...[
    [1, 500, V],
    [29, 0, V],
    [30, 0, I],
    [31, 0, I],
    [29, 999, V],
    [30, 1, I],
  ].map(([seconds, millis, overall]) =>
    definition(
      `proof-${seconds}-${millis}`,
      'proof-boundary',
      `The exact first proof at A + ${seconds} seconds + ${millis} milliseconds respects exclusive authorization expiry.`,
      [overall, overall, overall, V],
      { proofOffset: seconds + millis / 1000, seconds, millis },
    ),
  ),
  ...requiredOriginals.map((missing) =>
    definition(
      `missing-original-${slug(missing)}`,
      'missing-original',
      `Current knowledge cannot replace the absent original ${missing}.`,
      [U, U, U, missing === 'Certificate' ? U : V],
      { missing, proofUnavailable: missing === 'Certificate' },
    ),
  ),
  definition(
    'corrupt-approval',
    'corrupt-approval',
    'An available invalid raw ES256 approval is invalid despite valid preservation.',
    [I, I, I, V],
  ),
  definition(
    'corrupt-approval-missing-sim',
    'corrupt-approval-missing-sim',
    'An independently invalid approval dominates the missing original SIM.',
    [I, I, I, V],
  ),
  ...['GRANT', 'APPROVER_REGISTRATION', 'FINAL_AUTHORIZATION'].flatMap((target) => [
    definition(
      `ordinary-revocation-${slug(target)}`,
      'ordinary-revocation',
      `Ordinary ${target} revocation effective after P does not invalidate past authorization.`,
      [V, V, V, V],
      { target },
    ),
    definition(
      `retrospective-compromise-${slug(target)}`,
      'retrospective-compromise',
      `A later authenticated ${target} compromise effective at P denies current historical reliance.`,
      [I, V, I, V],
      { target },
    ),
  ]),
  definition(
    'credential-compromise',
    'credential-compromise',
    'A later authenticated credential compromise preserves the earlier view but denies current reliance.',
    [I, V, I, V],
  ),
  definition(
    'authority-compromise',
    'authority-compromise',
    'A later authenticated original non-TSA authority compromise denies current reliance.',
    [I, V, I, V],
  ),
  definition(
    'shared-key-target-compromise',
    'shared-key-target-compromise',
    'Different original target identifiers share a key, with a compromise and another GOOD target. This combined rejection alone does not isolate key-wide continuity.',
    [I, V, I, V],
  ),
  definition(
    'same-epoch-conflict-newer-good',
    'same-epoch-conflict',
    'Authenticated same-epoch disagreement cannot be erased by a newer GOOD head.',
    [I, V, I, V],
  ),
  definition(
    'compromise-newer-good',
    'compromise-newer-good',
    'An authenticated terminal compromise cannot be erased by a newer GOOD head.',
    [I, V, I, V],
  ),
  ...['organization', 'certificate', 'both'].map((category) =>
    definition(
      `missing-current-${category}`,
      'missing-current',
      `Current historical reliance requires current ${category} status coverage.`,
      [U, V, U, V],
      { category },
    ),
  ),
  definition(
    'missing-current-history',
    'missing-current-history',
    'Missing current RTM coverage does not erase the independently authenticated first proof.',
    [U, V, U, U],
  ),
  definition(
    'status-before-next-update',
    'status-coverage',
    'The last instant before current status nextUpdate remains covered.',
    [V, V, V, V],
    { knowledgeTime: K + 298 },
  ),
  definition(
    'status-at-next-update',
    'status-coverage',
    'Current status nextUpdate is exclusive.',
    [U, V, U, V],
    { knowledgeTime: K + 299 },
  ),
  definition(
    'history-before-coverage',
    'history-coverage',
    'The last instant before retained history coverageUntil remains covered.',
    [V, V, V, V],
    { knowledgeTime: K + 299 },
  ),
  definition(
    'history-at-coverage',
    'history-coverage',
    'Retained history coverageUntil is exclusive.',
    [U, V, U, U],
    { knowledgeTime: K + 300 },
  ),
  definition(
    'compromise-missing-coverage',
    'compromise-missing-coverage',
    'An authenticated applicable compromise dominates missing current credential coverage.',
    [I, V, I, V],
  ),
  definition(
    'late-renewal',
    'late-renewal',
    'A genuinely issued renewal at the previous deadline cannot repair expired preservation.',
    [I, V, V, I],
  ),
  definition(
    'early-raw-key-cutoff',
    'early-raw-key-cutoff',
    'A caller data deadline cannot extend the earliest used raw approver key deadline.',
    [I, I, I, I],
    { proofUnavailable: true },
  ),
  definition(
    'wrong-original-binding',
    'wrong-original-binding',
    'An existing EvidenceRecord does not bind substituted original document bytes.',
    [I, I, I, I],
    { proofUnavailable: true },
  ),
  definition(
    'wrong-status-target',
    'wrong-status-target',
    'A scoped successor cannot substitute a different original target commitment.',
    [I, V, I, V],
  ),
  definition(
    'wrong-successor-purpose',
    'wrong-successor-purpose',
    'A status signer admitted for a different purpose is not admitted for this operation.',
    [I, V, I, V],
  ),
  definition(
    'wrong-successor-domain',
    'wrong-successor-domain',
    'A status signer admitted in a different trust domain is not admitted here.',
    [I, V, I, V],
  ),
  definition(
    'unilateral-root-successor',
    'unilateral-root-successor',
    'A root transition requires the old and new governance quorum on the same manifest.',
    [I, V, I, I],
  ),
  definition(
    'receipt-authority-after-execution',
    'receipt-authority-after-execution',
    'An authority appointed only at P cannot authorize a receipt declared at earlier A.',
    [I, I, I, V],
  ),
  definition(
    'proof-before-execution',
    'proof-before-execution',
    'Authenticated P before the authenticated execution declaration A is invalid.',
    [I, I, I, V],
    { proofOffset: -1 },
  ),
]);

const definitions = new Map(organizationHistorySemantics.map((entry) => [entry.id, entry]));
assert.equal(definitions.size, organizationHistorySemantics.length);
const body = (member, label = 'OrganizationDelegationStatus') =>
  readControl(member.cms, label, member.issuerCertificate);
const targetID = (row) => row.objectType + ':' + row.objectID.toString('hex');
const originalLeaves = (bytes) =>
  Object.fromEntries(decodeCBOR(bytes).objects.map((leaf) => [leaf.type, leaf.payload]));
function timestampFacts(record) {
  const stamps = parseDER(record).children[2].children.flatMap((chain) => chain.children);
  return stamps.map((stamp) =>
    parseTSTInfo(
      verifyCMS(stamp.children.at(-1).raw, { expectedContentType: OID.tstInfo }).content,
    ),
  );
}
function facts(entry) {
  const spec = definitions.get(entry.id);
  assert(spec, `Unreviewed semantic case: ${entry.id}`);
  const leaves = originalLeaves(entry.originalBytes);
  const statuses = entry.knowledge.statusMaterial.map((member) => body(member));
  const certificates = entry.knowledge.certificateStatusMaterial.map((member) =>
    body(member, 'CertificateStatus'),
  );
  const history = entry.knowledge.authorityHistory.map((member) => {
    const manifest = decodeCBOR(member.manifest);
    assert(
      equal(dcbor(manifest), member.manifest),
      'RTM body must be the original canonical bytes',
    );
    return manifest;
  });
  const timestamps = timestampFacts(entry.evidenceRecord);
  return { spec, leaves, statuses, certificates, history, timestamps, P: A + spec.proofOffset };
}

/** Check public construction facts without asking a historical verifier for a verdict. */
export function assertOrganizationHistoryInput(entry) {
  const { spec, leaves, statuses, certificates, history, timestamps, P } = facts(entry);
  const { configuration, knowledge } = entry;
  assert.equal(configuration.schemaVersion, 1);
  assert.equal(configuration.trust.policy.organizationDelegation.mode, 'CURRENT_STATE_ONLY');
  assert.equal(knowledge.knowledgeTime, spec.knowledgeTime);
  assert.equal(timestamps[0].poeUpperBound, P);
  assert.equal(
    equal(timestamps[0].imprint, sha512(entry.originalBytes)),
    spec.kind !== 'wrong-original-binding',
  );
  assert.equal(history[0].serial, 0);
  assert.equal(history[0].previousHash, null);
  assert.equal(
    parseCertificate(configuration.trust.credentialTrust.issuerCertificate).notAfter < K,
    true,
  );
  if (leaves.ExecutionReceipt) {
    const cms = verifyCMS(leaves.ExecutionReceipt);
    assert.equal(
      readControl(leaves.ExecutionReceipt, 'ExecutionReceipt', cms.certificate).executedAt,
      A,
    );
  }
  if (spec.kind === 'missing-original') {
    assert.equal(Object.hasOwn(leaves, spec.missing), false);
    assert.deepEqual(
      requiredOriginals.filter((type) => !Object.hasOwn(leaves, type)),
      [spec.missing],
    );
  } else if (spec.kind === 'corrupt-approval-missing-sim') {
    assert.equal(Object.hasOwn(leaves, 'SIM'), false);
  } else {
    for (const type of requiredOriginals) assert(Object.hasOwn(leaves, type), type);
  }
  if (['positive', 'proof-boundary'].includes(spec.kind)) {
    const final = verifyCMS(leaves.OrganizationAuthorization);
    const authorization = readControl(
      leaves.OrganizationAuthorization,
      'OrganizationAuthorization',
      final.certificate,
    );
    assert.equal(authorization.expiresAt, A + 30);
    assert.equal(P < authorization.expiresAt, spec.outcomes[0] === V);
    assert(history.at(-1).successor);
    assert(knowledge.authorityHistory.at(-1).signatures.length >= 2);
    assert(
      history[0].authorities.some(
        (row) => !row.roles.includes('TIMESTAMP_AUTHORITY') && row.validUntil < K,
      ),
    );
    assert(
      history
        .at(-1)
        .authorities.some((row) => row.roles.includes('STATUS_AUTHORITY') && row.validFrom > P),
    );
  }
  if (spec.kind.startsWith('corrupt-approval')) {
    const approval = decodeCBOR(leaves.OrganizationApprovalSet).approvals[0];
    const registration = readControl(
      approval.registrationCMS,
      'OrganizationApproverRegistration',
      approval.registrationIssuerCertificate,
    );
    assert.equal(
      verify(
        Buffer.concat([
          approval.assertion.authenticatorData,
          sha256(approval.assertion.clientDataJSON),
        ]),
        approval.assertion.signature,
        publicFromDER(registration.publicKeyDER),
      ),
      false,
    );
  }
  if (['ordinary-revocation', 'retrospective-compromise'].includes(spec.kind)) {
    const incident = statuses.find(
      (row) => row.objectType === spec.target && row.status === 'REVOKED',
    );
    assert(incident);
    assert(incident.publishedAt > P);
    if (spec.kind === 'ordinary-revocation') {
      assert(incident.effectiveTime > P);
      assert.equal(Object.hasOwn(incident, 'compromiseStart'), false);
    } else assert.equal(incident.compromiseStart, P);
  }
  if (spec.kind === 'credential-compromise') {
    assert(
      certificates.some(
        (row) => row.status === 'REVOKED' && row.compromiseStart <= P && row.publishedAt > P,
      ),
    );
  }
  if (spec.kind === 'authority-compromise') {
    const receiptSigner = verifyCMS(leaves.ExecutionReceipt).certificate;
    const used = history
      .at(-1)
      .authorities.filter(
        (row) => equal(row.certificate, receiptSigner) && row.roles.includes('RECEIPT_AUTHORITY'),
      );
    assert(used.length > 0);
    assert(
      used.every(
        (row) =>
          !row.roles.includes('TIMESTAMP_AUTHORITY') &&
          row.status.status === 'REVOKED' &&
          row.status.compromiseStart <= P,
      ),
    );
  }
  if (spec.kind === 'shared-key-target-compromise') {
    const incident = statuses.find((row) => row.status === 'REVOKED' && row.compromiseStart <= P);
    assert(incident);
    assert(
      statuses.some(
        (row) =>
          targetID(row) !== targetID(incident) &&
          row.status === 'GOOD' &&
          equal(row.subjectKeyID, incident.subjectKeyID),
      ),
    );
    // Both targets belong to this original; the combined rejection must not be
    // presented as an isolated cross-original/durable key-wide test.
  }
  if (['same-epoch-conflict', 'compromise-newer-good'].includes(spec.kind)) {
    const incident = statuses.find((row) => row.status === 'REVOKED');
    assert(incident);
    assert(
      statuses.some(
        (row) =>
          targetID(row) === targetID(incident) &&
          row.status === 'GOOD' &&
          row.epoch > incident.epoch,
      ),
    );
    if (spec.kind === 'same-epoch-conflict') {
      assert(incident.effectiveTime > P);
      assert.equal(Object.hasOwn(incident, 'compromiseStart'), false);
      assert(
        statuses.some(
          (row) =>
            targetID(row) === targetID(incident) &&
            row.epoch === incident.epoch &&
            !equal(dcbor(row), dcbor(incident)),
        ),
      );
    } else {
      assert(incident.compromiseStart <= P);
      for (const row of statuses)
        assert(
          !statuses.some(
            (other) =>
              targetID(row) === targetID(other) &&
              row.epoch === other.epoch &&
              !equal(dcbor(row), dcbor(other)),
          ),
        );
    }
  }
  if (spec.kind === 'missing-current') {
    if (['organization', 'both'].includes(spec.category)) assert.equal(statuses.length, 0);
    if (['certificate', 'both'].includes(spec.category)) assert.equal(certificates.length, 0);
  }
  if (spec.kind === 'missing-current-history') {
    assert.equal(history.length, 1);
    assert(history[0].coverageUntil > P && history[0].coverageUntil < knowledge.knowledgeTime);
  }
  if (spec.kind === 'status-coverage') {
    assert(statuses.every((row) => row.nextUpdate === K + 299));
    assert(certificates.every((row) => row.nextUpdate === K + 299));
    assert.equal(knowledge.knowledgeTime < K + 299, spec.outcomes[0] === V);
  }
  if (spec.kind === 'history-coverage') {
    assert.equal(history.at(-1).coverageUntil, K + 300);
    assert(statuses.every((row) => row.nextUpdate > knowledge.knowledgeTime));
    assert(certificates.every((row) => row.nextUpdate > knowledge.knowledgeTime));
    assert.equal(knowledge.knowledgeTime < history.at(-1).coverageUntil, spec.outcomes[0] === V);
  }
  if (spec.kind === 'compromise-missing-coverage') {
    assert(statuses.some((row) => row.status === 'REVOKED' && row.compromiseStart <= P));
    assert.equal(certificates.length, 0);
  }
  if (spec.kind === 'late-renewal') {
    assert.equal(timestamps[1].genTime, A + 80);
    assert.equal(configuration.preservation.timestampAuthorities[0].validUntil, A + 80);
  }
  if (spec.kind === 'early-raw-key-cutoff') {
    const approvals = decodeCBOR(leaves.OrganizationApprovalSet).approvals;
    const reg = readControl(
      approvals[0].registrationCMS,
      'OrganizationApproverRegistration',
      approvals[0].registrationIssuerCertificate,
    );
    assert.equal(configuration.trust.keyDeadlines[reg.keyID.toString('hex')], P);
    assert(configuration.preservation.dataValidUntil > P);
  }
  if (spec.kind === 'wrong-status-target') {
    const original = decodeCBOR(leaves.OrganizationDelegationStatus).statements.map((member) =>
      body(member),
    );
    assert(
      statuses.some((row) =>
        original.some(
          (old) => targetID(row) === targetID(old) && !equal(row.objectHash, old.objectHash),
        ),
      ),
    );
  }
  if (['wrong-successor-purpose', 'wrong-successor-domain'].includes(spec.kind)) {
    const signer = knowledge.statusMaterial[0].issuerCertificate;
    const row = history
      .at(-1)
      .authorities.find((authority) => equal(authority.certificate, signer));
    assert(row);
    if (spec.kind === 'wrong-successor-domain')
      assert(
        row.scopes.every((scope) => !equal(scope.trustDomainID, configuration.trust.trustDomainID)),
      );
    else assert(row.scopes.every((scope) => scope.purpose !== 'ORGANIZATION_DELEGATION_STATUS'));
  }
  if (spec.kind === 'unilateral-root-successor') {
    assert(history.at(-1).successor);
    assert.equal(knowledge.authorityHistory.at(-1).signatures.length, 1);
    const newIDs = history.at(-1).successor.roots.map((root) => root.publicKeyDER);
    assert(
      newIDs.every(
        (der) =>
          !configuration.retainedAuthorities.governance.roots.some((root) =>
            equal(root.publicKeyDER, der),
          ),
      ),
    );
  }
  if (spec.kind === 'receipt-authority-after-execution') {
    const receiptSigner = verifyCMS(leaves.ExecutionReceipt).certificate;
    const used = history[0].authorities.filter(
      (row) => row.roles.includes('RECEIPT_AUTHORITY') && equal(row.certificate, receiptSigner),
    );
    assert(used.length > 0);
    assert(used.every((row) => row.validFrom === P && P > A));
  }
  if (spec.kind === 'proof-before-execution') assert(P < A);
  return spec;
}

/** This oracle has fixed expectations; it never learns them from actual output. */
export function assertOrganizationHistoryOutcome(entry, actual) {
  const spec = assertOrganizationHistoryInput(entry);
  assert.deepEqual(
    [
      actual.overall,
      actual.historicalAuthorization.overall,
      actual.currentAdmissibility.overall,
      actual.preservation.overall,
    ],
    spec.outcomes,
    entry.id,
  );
  assert.equal(actual.profile, profile);
  assert.equal(actual.coreRevision, 'draft-03');
  assert.equal(actual.purpose, 'RETAINED_EVIDENCE_VERIFICATION');
  assert.equal(actual.knowledgeTime, spec.knowledgeTime);
  const P = spec.proofUnavailable ? null : A + spec.proofOffset;
  assert.equal(actual.proofOfExistenceUpperBound, P);
  assert.equal(actual.historicalAuthorization.scope, 'AS_KNOWN_AT_PROOF_TIME');
  assert.equal(actual.currentAdmissibility.scope, 'HISTORICAL_EVIDENCE_UNDER_CURRENT_KNOWLEDGE');
  assert.equal(actual.historicalAuthorization.stateTime, P);
  assert.equal(actual.historicalAuthorization.knowledgeTime, P);
  assert.equal(actual.currentAdmissibility.stateTime, P);
  assert.equal(actual.currentAdmissibility.knowledgeTime, spec.knowledgeTime);
  assert(actual.limitations.includes('NO_CURRENT_EXECUTION_PERMISSION'));
  assert.equal(Object.hasOwn(actual, 'knowledgeReceipt'), false);
  for (const forbidden of ['signature', 'receipt', 'cms', 'bundle', 'permit', 'authorization'])
    assert.equal(Object.hasOwn(actual, forbidden), false, forbidden);
  for (const value of [
    actual,
    actual.historicalAuthorization,
    actual.currentAdmissibility,
    actual.preservation,
  ]) {
    assert.equal(typeof value.reason, 'string');
    assert(value.reason.length > 0);
    assert(Array.isArray(value.checks));
    assert.equal(Object.hasOwn(value.dimensions, 'transparency'), false);
  }
  if (spec.kind.startsWith('corrupt-approval')) {
    assert.equal(actual.dimensions.integrity.overall, I);
    assert(actual.checks.some((row) => row.reason === 'ASSERTION_SIGNATURE' && row.overall === I));
  }
  if (spec.kind === 'late-renewal') assert.equal(actual.preservation.reason, 'ERS_RENEWAL_LATE');
  if (spec.kind === 'same-epoch-conflict')
    assert.equal(actual.currentAdmissibility.reason, 'ORG_STATUS_CONFLICT');
  if (spec.kind === 'early-raw-key-cutoff') {
    assert.equal(actual.originalProtectionDeadline, A + 1);
    assert.equal(actual.preservation.reason, 'ERS_INITIAL_PROTECTION_LATE');
    assert(actual.protectionLedger.some((row) => row.kind === 'KEY' && row.validUntil === A + 1));
  }
  const executionTupleLeaves = new Set([
    'Document',
    'CMS',
    'SIM',
    'SignaturePolicy',
    'OperationPermit',
    'ExecutionReceipt',
    'ExecutionBindingEvidence',
  ]);
  const noAuthenticatedExecution =
    (spec.kind === 'missing-original' && executionTupleLeaves.has(spec.missing)) ||
    ['corrupt-approval-missing-sim', 'wrong-original-binding'].includes(spec.kind);
  assert.equal(actual.operationTime, noAuthenticatedExecution ? null : A);
}

/** Knowledge-only scenarios must retain the very same original signed bytes. */
export function assertOrganizationHistoryOriginalPairs(entries) {
  const base = entries.find((entry) => entry.id === 'expired-issuer-scoped-successor');
  assert(base);
  const changedOriginalKinds = new Set([
    'missing-original',
    'corrupt-approval',
    'corrupt-approval-missing-sim',
    'wrong-original-binding',
  ]);
  const changedArchiveKinds = new Set([
    ...changedOriginalKinds,
    'proof-boundary',
    'late-renewal',
    'proof-before-execution',
  ]);
  assert.deepEqual(
    entries.map((entry) => entry.id).sort(),
    organizationHistorySemantics.map((entry) => entry.id).sort(),
  );
  for (const entry of entries) {
    const spec = definitions.get(entry.id);
    if (!changedOriginalKinds.has(spec.kind))
      assert(equal(entry.originalBytes, base.originalBytes), entry.id);
    if (!changedArchiveKinds.has(spec.kind))
      assert(equal(entry.evidenceRecord, base.evidenceRecord), entry.id);
  }
}

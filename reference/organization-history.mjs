import { types } from 'node:util';
import {
  ALG,
  H,
  dcbor,
  decodeCBOR,
  equal,
  fields,
  keyID,
  publicFromDER,
  sha256,
  sha512,
  verify,
} from './core.mjs';
import { parseCertificate, validateCertificate, verifyCMS } from './pki.mjs';
import { readControl, evaluateStatus } from './state.mjs';
import { inspectEvidencePackage } from './evidence-plan.mjs';
import { verifyERSOriginalProof, verifyERSPreservation } from './archive.mjs';
import { verifyStatusPreservation } from './status-preservation.mjs';
import { verifyRegistrationBinding } from './document-evidence.mjs';
import { verifyOrganizationExecutionEvidence } from './execution-binding.mjs';
import {
  verifyOrganizationHistoricalEvidence,
  authenticateOrganizationHistoryMaterial,
} from './organization-delegation-evidence.mjs';
import { ORGANIZATION_PLAN, record, snapshot } from './organization-delegation-state.mjs';
import { connectOrganizationHistorySource } from './organization-history-source.mjs';
import {
  VerificationError,
  VerificationEvaluation,
  verificationOutcome,
  verificationResult,
} from './verification-result.mjs';

const SEAL = 'CERTCONCORD-ORG-SEAL-v1';
const SHA256 = '2.16.840.1.101.3.4.2.1',
  SHA512 = '2.16.840.1.101.3.4.2.3';
const integer = (n) => Number.isSafeInteger(n) && n >= 0;
const need = (ok, code, overall = 'INVALID', dimension) => {
  if (!ok) throw new VerificationError(code, overall, dimension);
};
const requiredTypes = [
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
];
const rank = ['INVALID', 'UNSUPPORTED', 'INDETERMINATE'];

function sync(callback, code) {
  let value;
  try {
    value = callback();
  } catch {
    throw new VerificationError(code, 'INDETERMINATE');
  }
  if (types.isPromise(value)) {
    Promise.prototype.then.call(value, undefined, () => {});
    throw new VerificationError(code, 'INDETERMINATE');
  }
  return value;
}
function resolver(callback) {
  return (query) => {
    const { stateTime, knowledgeTime, ...bound } = query;
    const value = sync(
      () => callback({ ...snapshot(bound), stateTime, knowledgeTime }),
      'ORG_AUTHORITY_UNAVAILABLE',
    );
    let answer;
    try {
      answer = snapshot(value);
    } catch {
      return { overall: 'INDETERMINATE', reason: 'ORG_AUTHORITY_DECISION' };
    }
    if (
      !answer ||
      !['VALID', ...rank].includes(answer.overall) ||
      typeof answer.reason !== 'string' ||
      !answer.reason.length ||
      Object.hasOwn(answer, 'then')
    )
      return { overall: 'INDETERMINATE', reason: 'ORG_AUTHORITY_DECISION' };
    return answer;
  };
}
class Checks {
  constructor() {
    this.checks = [];
    this.evaluation = new VerificationEvaluation();
  }
  add(check, dimension, action) {
    try {
      const value = action();
      this.checks.push({ check, overall: 'VALID', reason: 'ORG_HISTORY_CHECK_VALID' });
      return value;
    } catch (error) {
      const decision = verificationOutcome(error);
      this.checks.push({ check, ...decision });
      this.evaluation.observe(dimension, decision.overall, decision.reason);
    }
  }
  absorb(check, dimension, result) {
    this.checks.push({ check, overall: result.overall, reason: result.reason });
    this.evaluation.observe(dimension, result.overall, result.reason);
  }
  result(reason, details = {}) {
    const bad = rank.map((kind) => this.checks.find((r) => r.overall === kind)).find(Boolean);
    return verificationResult({
      ...details,
      overall: bad?.overall ?? 'VALID',
      reason: bad?.reason ?? reason,
      profile: ORGANIZATION_PLAN,
      dimensions: this.evaluation.result(),
      checks: this.checks,
    });
  }
}

function control(raw, label) {
  need(Buffer.isBuffer(raw), 'ORG_HISTORY_ORIGINAL_MISSING', 'INDETERMINATE');
  const { certificate } = verifyCMS(raw);
  return { cms: raw, issuerCertificate: certificate, body: readControl(raw, label, certificate) };
}

function inspectOriginal(raw, trust, checks) {
  need(
    Buffer.isBuffer(raw) && raw.length > 0 && raw.length <= 64 * 1024 * 1024,
    'ORG_HISTORY_INPUT',
  );
  const bundle = decodeCBOR(raw, { maxBytes: 64 * 1024 * 1024, maxItems: 100000 });
  const inspected = inspectEvidencePackage(bundle, { maxBytes: 64 * 1024 * 1024 });
  const values = inspected.values;
  checks.add('plan', 'integrity', () => {
    need(
      inspected.supportedSchema && bundle.schemaVersion === 2,
      'ECP_UNSUPPORTED_SCHEMA',
      'UNSUPPORTED',
    );
    need(inspected.plan?.profile === ORGANIZATION_PLAN, 'ORG_HISTORY_PROFILE', 'UNSUPPORTED');
    need(
      Object.keys(values).every((name) => requiredTypes.includes(name)),
      'ECP_PLAN',
    );
    need(
      requiredTypes.every((name) => Object.hasOwn(values, name)) && !inspected.missingTypes.length,
      'ORG_HISTORY_ORIGINAL_MISSING',
      'INDETERMINATE',
    );
  });
  const sim = values.SIM && checks.add('sim', 'integrity', () => decodeCBOR(values.SIM));
  const policy =
    values.SignaturePolicy &&
    checks.add('policy', 'authorization', () => {
      const value = decodeCBOR(values.SignaturePolicy);
      need(equal(dcbor(value), dcbor(trust.policy)), 'ORG_POLICY_BINDING');
      return value;
    });
  const signed =
    values.CMS &&
    values.Document &&
    checks.add('document', 'integrity', () =>
      verifyCMS(values.CMS, {
        content: values.Document,
        expectedCertificate: trust.credentialTrust.certificate,
        ...(sim && policy
          ? {
              simHash: H('SIM', sim),
              policyHash: H('SignaturePolicy', policy),
              context: {
                schemaVersion: 1,
                trustDomainID: trust.trustDomainID,
                profileID: SEAL,
                container: 'CMS',
                adapterID: 'certconcord-cms-v1',
              },
            }
          : {}),
      }),
    );
  const controls = {};
  for (const [name, label] of [
    ['OrganizationAuthorization', 'OrganizationAuthorization'],
    ['OperationPermit', 'OperationPermit'],
    ['ExecutionReceipt', 'ExecutionReceipt'],
  ])
    if (values[name])
      controls[name] = checks.add(name, 'integrity', () => control(values[name], label));
  const executionEvidence =
    values.ExecutionBindingEvidence &&
    checks.add('execution-leaf', 'integrity', () => decodeCBOR(values.ExecutionBindingEvidence));
  const binding =
    executionEvidence &&
    checks.add('execution-binding', 'integrity', () =>
      control(executionEvidence.binding, 'ExecutionBinding'),
    );
  const parsed = {};
  for (const name of [
    'OrganizationDelegationPath',
    'OrganizationApprovalSet',
    'OrganizationDelegationStatus',
  ])
    if (values[name]) parsed[name] = checks.add(name, 'integrity', () => decodeCBOR(values[name]));
  for (const [name, key, maximum] of [
    ['OrganizationDelegationPath', 'grants', 8],
    ['OrganizationApprovalSet', 'approvals', 16],
    ['OrganizationDelegationStatus', 'statements', 64],
  ])
    if (parsed[name]) {
      const value = parsed[name];
      const admitted = checks.add('collection-limit:' + name, 'integrity', () => {
        need(Array.isArray(value[key]), 'ORG_ARRAY');
        need(value[key].length <= maximum, 'ORG_ARRAY_LIMIT', 'UNSUPPORTED');
        return true;
      });
      if (!admitted) delete parsed[name];
    }
  // These original mathematics remain applicable even when the ERS or current knowledge is unavailable.
  for (const [i, member] of (parsed.OrganizationDelegationPath?.grants ?? []).entries())
    checks.add('grant-math:' + i, 'integrity', () =>
      readControl(member.cms, 'OrganizationDelegationGrant', member.issuerCertificate),
    );
  for (const [i, member] of (parsed.OrganizationApprovalSet?.approvals ?? []).entries()) {
    const registration = checks.add('registration-math:' + i, 'integrity', () =>
      readControl(
        member.registrationCMS,
        'OrganizationApproverRegistration',
        member.registrationIssuerCertificate,
      ),
    );
    if (registration)
      checks.add('assertion-math:' + i, 'integrity', () => {
        const assertion = member.assertion,
          key = publicFromDER(registration.publicKeyDER);
        need(
          key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails.namedCurve === 'prime256v1',
          'ORG_APPROVER_ALGORITHM',
          'UNSUPPORTED',
        );
        need(
          verify(
            Buffer.concat([assertion.authenticatorData, sha256(assertion.clientDataJSON)]),
            assertion.signature,
            key,
          ),
          'ASSERTION_SIGNATURE',
        );
      });
  }
  for (const [i, member] of (parsed.OrganizationDelegationStatus?.statements ?? []).entries())
    checks.add('status-math:' + i, 'integrity', () =>
      readControl(member.cms, 'OrganizationDelegationStatus', member.issuerCertificate),
    );
  const receipt = controls.ExecutionReceipt,
    permit = controls.OperationPermit;
  const A = receipt?.body.executedAt;
  let operation;
  if (signed && sim && policy && permit && receipt && binding)
    operation = checks.add('execution-tuple', 'authorization', () =>
      verifyOrganizationExecutionEvidence(
        {
          policy,
          sim,
          permit: permit.cms,
          tbs: signed.tbs,
          signature: signed.signature,
          publicKey: signed.cert.publicKey,
          receipt: receipt.cms,
          evidence: executionEvidence,
        },
        {
          bindingCertificate: binding.issuerCertificate,
          permitCertificate: permit.issuerCertificate,
          receiptCertificate: receipt.issuerCertificate,
          trustDomainID: trust.trustDomainID,
          at: A,
          knowledgeTime: A,
        },
      ),
    );
  return { values, sim, policy, signed, controls, binding, parsed, A: operation ? A : undefined };
}

function originalDeadline(original, trust) {
  const { values, controls, binding, parsed } = original;
  const certificates = [
    values.Certificate,
    trust.credentialTrust.issuerCertificate,
    trust.credentialTrust.raCertificate,
    trust.credentialTrust.statusCertificate,
  ];
  for (const value of Object.values(controls))
    if (value) certificates.push(value.issuerCertificate);
  if (binding) certificates.push(binding.issuerCertificate);
  for (const member of parsed.OrganizationDelegationPath?.grants ?? [])
    certificates.push(member.issuerCertificate, member.delegateCertificate);
  for (const member of parsed.OrganizationApprovalSet?.approvals ?? [])
    certificates.push(member.registrationIssuerCertificate);
  for (const member of parsed.OrganizationDelegationStatus?.statements ?? [])
    certificates.push(member.issuerCertificate);
  const cutoffs = [],
    ledger = [];
  const cutoff = (map, id, kind) => {
    need(
      integer(map?.[id]) && map[id] > 0,
      'ORG_HISTORY_' + kind + '_DEADLINE_MISSING',
      'INDETERMINATE',
    );
    cutoffs.push(map[id]);
    ledger.push({ kind, id, validUntil: map[id] });
  };
  const key = (publicKey) => {
    const alg = ALG[publicKey.asymmetricKeyType];
    need(alg, 'ORG_KEY_ALGORITHM', 'UNSUPPORTED');
    cutoff(trust.keyDeadlines, keyID(publicKey).toString('hex'), 'KEY');
    cutoff(trust.algorithmDeadlines, alg.oid, 'ALGORITHM');
    cutoff(trust.hashDeadlines, publicKey.asymmetricKeyType === 'ec' ? SHA256 : SHA512, 'HASH');
  };
  for (const raw of certificates) {
    need(Buffer.isBuffer(raw), 'ORG_HISTORY_ORIGINAL_MISSING', 'INDETERMINATE');
    const cert = parseCertificate(raw);
    key(cert.publicKey);
    cutoff(trust.algorithmDeadlines, cert.algorithm, 'CERTIFICATE_ALGORITHM');
    cutoffs.push(cert.notAfter);
    ledger.push({
      kind: 'CERTIFICATE',
      id: cert.representationHash.toString('hex'),
      validUntil: cert.notAfter,
    });
  }
  for (const member of parsed.OrganizationApprovalSet?.approvals ?? []) {
    const reg = readControl(
      member.registrationCMS,
      'OrganizationApproverRegistration',
      member.registrationIssuerCertificate,
    );
    key(publicFromDER(reg.publicKeyDER));
  }
  cutoff(trust.hashDeadlines, SHA512, 'HASH');
  return { validUntil: Math.min(...cutoffs), ledger };
}

function admit(authorityResolver, raw, role, scope, stateTime, knowledgeTime) {
  const result = authorityResolver({ certificate: raw, role, scope, stateTime, knowledgeTime });
  need(result.overall === 'VALID', result.reason, result.overall);
  need(
    Number.isFinite(result.coverageUntil) && knowledgeTime < result.coverageUntil,
    'ORG_AUTHORITY_COVERAGE',
    'INDETERMINATE',
  );
}

// These are authenticated negative/rollback observations, never positive status
// substitutes, a live journal projection, or permission to execute an operation.
class HistoricalKnowledge {
  constructor(durable = false) {
    this.targets = new Map();
    this.statuses = new Map();
    this.certificates = new Map();
    this.full = false;
    this.durable = durable;
  }
  keep(map, id, value) {
    if (map.has(id)) return;
    if (this.targets.size + this.statuses.size + this.certificates.size >= 4096) {
      this.full = true;
      return;
    }
    map.set(id, snapshot(value));
  }
  matchingTargets(original) {
    if (!this.durable) return [];
    const raw = [
      original.controls.OrganizationAuthorization?.cms,
      ...(original.parsed.OrganizationDelegationPath?.grants ?? []).map((v) => v.cms),
      ...(original.parsed.OrganizationApprovalSet?.approvals ?? []).map((v) => v.registrationCMS),
    ].filter(Buffer.isBuffer);
    const hashes = new Set(raw.map((v) => sha512(v).toString('hex')));
    return [...this.targets.values()].filter((v) => hashes.has(v.objectHash.toString('hex')));
  }
  organization(result, P, checks, retainedTargets = []) {
    const targetID = (v) => v.objectType + ':' + v.objectID.toString('hex');
    const usedKeys = new Set(result.usedKeyIDs ?? []);
    const targets = result.targetObservations ?? [],
      incoming = result.statusObservations ?? [];
    for (const target of retainedTargets) usedKeys.add(target.subjectKeyID.toString('hex'));
    for (const value of targets)
      this.keep(this.targets, targetID(value) + ':' + value.semanticHash.toString('hex'), value);
    for (const value of incoming)
      this.keep(
        this.statuses,
        targetID(value) + ':' + value.epoch + ':' + value.semanticHash.toString('hex'),
        value,
      );
    const rows = [...this.statuses.values()];
    checks.add('retained-organization-incidents', 'status', () => {
      const epochs = new Map();
      for (const row of rows) {
        const id = targetID(row) + ':' + row.epoch;
        need(!epochs.has(id) || equal(epochs.get(id), row.semanticHash), 'ORG_STATUS_CONFLICT');
        epochs.set(id, row.semanticHash);
        const relevant = [...targets, ...retainedTargets].some(
          (target) => targetID(target) === targetID(row),
        );
        if (row.status === 'REVOKED') {
          need(
            !relevant ||
              P < Math.min(row.effectiveTime ?? Infinity, row.compromiseStart ?? Infinity),
            'ORG_STATUS_REVOKED',
          );
          need(
            !(
              row.compromiseStart !== null &&
              row.compromiseStart <= P &&
              usedKeys.has(row.subjectKeyID.toString('hex'))
            ),
            'ORG_KEY_COMPROMISED',
          );
        }
      }
      for (const target of targets) {
        for (const old of this.targets.values())
          need(
            targetID(old) !== targetID(target) || equal(old.semanticHash, target.semanticHash),
            'ORG_TARGET_CONFLICT',
          );
        const prior = rows.filter((row) => targetID(row) === targetID(target));
        const presented = (
          this.durable ? (result.currentStatusObservations ?? []) : incoming
        ).filter((row) => targetID(row) === targetID(target));
        if (prior.length && presented.length)
          need(
            Math.max(...presented.map((row) => row.epoch)) >=
              Math.max(...prior.map((row) => row.epoch)),
            'ORG_STATUS_ROLLBACK',
          );
      }
    });
    if (this.full)
      checks.absorb('retained-knowledge-limit', 'status', {
        overall: 'UNSUPPORTED',
        reason: 'ORG_HISTORY_KNOWLEDGE_LIMIT',
      });
  }
  certificate(statements, P, K, checks, currentStatements = statements) {
    let publicationRollback = false;
    if (this.durable) {
      for (const body of currentStatements) {
        const incoming = currentStatements.filter((v) =>
          equal(v.certificateID, body.certificateID),
        );
        const old = [...this.certificates.values()].filter((v) =>
          equal(v.certificateID, body.certificateID),
        );
        if (
          old.length &&
          Math.max(...incoming.map((v) => v.publishedAt)) <
            Math.max(...old.map((v) => v.publishedAt))
        )
          publicationRollback = true;
      }
    }
    for (const body of statements)
      this.keep(this.certificates, H('CertificateStatus', body).toString('hex'), body);
    checks.add('retained-certificate-incidents', 'status', () => {
      need(!publicationRollback, 'ORG_CERTIFICATE_STATUS_ROLLBACK');
      const publications = new Map();
      for (const body of this.certificates.values()) {
        const id = body.certificateID.toString('hex') + ':' + body.publishedAt;
        const semantic = H('CertificateStatus', body);
        need(
          !publications.has(id) || equal(publications.get(id), semantic),
          'ORG_CERTIFICATE_STATUS_CONFLICT',
        );
        publications.set(id, semantic);
        const decision = evaluateStatus(body, {
          stateTime: P,
          knowledgeTime: K,
          scope: 'CERTIFICATE',
        });
        if (decision.overall === 'INVALID') throw new VerificationError(decision.reason, 'INVALID');
      }
    });
    if (this.full)
      checks.absorb('retained-knowledge-limit', 'status', {
        overall: 'UNSUPPORTED',
        reason: 'ORG_HISTORY_KNOWLEDGE_LIMIT',
      });
  }
}

function credentialView(
  original,
  trust,
  knowledge,
  P,
  authorityResolver,
  checks,
  onAdmission,
  preservation,
) {
  const { values, A } = original,
    t = trust.credentialTrust,
    K = knowledge.knowledgeTime,
    statusTime = Number.isFinite(P) ? P : K;
  const scope = {
    trustDomainID: trust.trustDomainID,
    profileID: SEAL,
    issuerID: t.issuanceScope.issuerID,
    representation: 'X509',
  };
  checks.add('original-credential', 'qualification', () => {
    need(integer(A), 'ORG_HISTORY_TIME_UNAVAILABLE', 'INDETERMINATE');
    need(
      Buffer.isBuffer(values.Certificate) && Buffer.isBuffer(values.RegistrationAuthorization),
      'ORG_HISTORY_ORIGINAL_MISSING',
      'INDETERMINATE',
    );
    need(
      equal(values.Certificate, t.certificate) &&
        equal(values.RegistrationAuthorization, t.registrationAuthorization),
      'ORG_CERTIFICATE_BINDING',
    );
    const issuer = parseCertificate(t.issuerCertificate);
    validateCertificate(t.certificate, issuer.publicKey, { at: A, profileID: SEAL });
    const cert = parseCertificate(t.certificate);
    need(cert.notBefore <= P && P < cert.notAfter, 'ORG_CERTIFICATE_TIME');
    const reg = verifyRegistrationBinding(t.registrationAuthorization, t.certificate, {
      raCertificate: t.raCertificate,
      issuanceScope: t.issuanceScope,
      subjectID: trust.organizationID,
      profileID: SEAL,
      policyHash: H('SignaturePolicy', trust.policy),
      at: A,
    });
    for (const [raw, role] of [
      [t.issuerCertificate, 'ISSUER'],
      [t.raCertificate, 'REGISTRATION_AUTHORITY'],
    ])
      for (const at of [reg.issuedAt, P]) admit(authorityResolver, raw, role, scope, at, K);
  });
  if (!values.CertificateStatus)
    checks.absorb('original-certificate-status', 'status', {
      overall: 'INDETERMINATE',
      reason: 'ORG_HISTORY_ORIGINAL_MISSING',
    });
  const members = [
    ...(values.CertificateStatus
      ? [{ cms: values.CertificateStatus, issuerCertificate: t.statusCertificate, original: true }]
      : []),
    ...knowledge.certificateStatusMaterial.map((m) => ({ ...m, original: false })),
  ];
  const statements = [],
    currentStatements = [];
  for (const [i, member] of members.entries())
    checks.add('certificate-status:' + i, 'status', () => {
      const body = readControl(member.cms, 'CertificateStatus', member.issuerCertificate);
      if (onAdmission) {
        fields(
          body,
          [
            'schemaVersion',
            'trustDomainID',
            'certificateID',
            'scope',
            'status',
            'publishedAt',
            'nextUpdate',
          ],
          ['effectiveTime', 'compromiseStart', 'critical'],
        );
        need(body.schemaVersion === 1, 'ORG_CERTIFICATE_STATUS_SCHEMA', 'UNSUPPORTED');
      }
      const cert = parseCertificate(t.certificate);
      need(
        equal(body.certificateID, cert.certificateID) &&
          equal(body.trustDomainID, trust.trustDomainID),
        'ORG_CERTIFICATE_STATUS_BINDING',
      );
      if (body.publishedAt > K) return;
      const admitAt = (at) => {
        admit(authorityResolver, member.issuerCertificate, 'STATUS_AUTHORITY', scope, at, K);
        const signer = parseCertificate(member.issuerCertificate),
          alg = ALG[signer.publicKey.asymmetricKeyType];
        need(signer.notBefore <= at && at < signer.notAfter, 'ORG_CERTIFICATE_TIME');
        for (const [map, id] of [
          [trust.keyDeadlines, keyID(signer.publicKey).toString('hex')],
          [trust.algorithmDeadlines, alg?.oid],
          [trust.algorithmDeadlines, signer.algorithm],
          [trust.hashDeadlines, signer.publicKey.asymmetricKeyType === 'ec' ? SHA256 : SHA512],
        ]) {
          need(integer(map?.[id]), 'ORG_PROTECTION_DEADLINE_MISSING', 'INDETERMINATE');
          need(at < map[id], 'ORG_PROTECTION_DEADLINE');
        }
      };
      // A known publication-time authority failure remains applicable even if
      // the separately supplied preservation material is unavailable.
      admitAt(body.publishedAt);
      const separatelyPreserved = !member.original && Object.hasOwn(member, 'evidenceRecord');
      admitAt(
        member.original
          ? P
          : separatelyPreserved
            ? verifyStatusPreservation(
                member,
                body.publishedAt,
                trust,
                K,
                preservation,
                'ORG_CERTIFICATE_STATUS',
              )
            : K,
      );
      const decision = evaluateStatus(body, {
        stateTime: statusTime,
        knowledgeTime: K,
        scope: 'CERTIFICATE',
      });
      if (onAdmission)
        need(
          decision.overall !== 'INVALID' || decision.reason === 'STATUS_REVOKED',
          decision.reason,
          decision.overall,
        );
      statements.push(body);
      if (!member.original) currentStatements.push(body);
      if (decision.overall !== 'INVALID' || decision.reason === 'STATUS_REVOKED')
        onAdmission?.({
          kind: 'certificate-status',
          material: {
            cms: Buffer.from(member.cms),
            issuerCertificate: Buffer.from(member.issuerCertificate),
            ...(separatelyPreserved ? { evidenceRecord: Buffer.from(member.evidenceRecord) } : {}),
          },
          body: snapshot(body),
          original: member.original,
        });
    });
  checks.add('certificate-status-closure', 'status', () => {
    for (const body of statements) {
      const decision = evaluateStatus(body, {
        stateTime: statusTime,
        knowledgeTime: K,
        scope: 'CERTIFICATE',
      });
      if (decision.overall === 'INVALID') throw new VerificationError(decision.reason, 'INVALID');
      for (const other of statements)
        need(
          body.publishedAt !== other.publishedAt || equal(dcbor(body), dcbor(other)),
          'ORG_CERTIFICATE_STATUS_CONFLICT',
        );
    }
    need(statements.length > 0, 'ORG_CERTIFICATE_STATUS_MISSING', 'INDETERMINATE');
    const current = statements.reduce((a, b) => (a.publishedAt >= b.publishedAt ? a : b));
    const decision = evaluateStatus(current, {
      stateTime: statusTime,
      knowledgeTime: K,
      scope: 'CERTIFICATE',
    });
    need(
      decision.overall === 'VALID',
      decision.reason ?? 'ORG_CERTIFICATE_STATUS_UNKNOWN',
      decision.overall,
    );
  });
  return { statements, currentStatements };
}

/** Offline historical verification; this API has no signing, recovery, or current-admission capability. */
export function createOrganizationHistoryVerifier(options) {
  if (Object.hasOwn(options, 'source')) {
    record(options, ['source']);
    return connectOrganizationHistorySource(options.source, createHistoryVerifier);
  }
  return createHistoryVerifier(options);
}

// The admission observer is supplied only by the opaque source implementation.
// It reports authenticated raw material; it cannot supply an authorization.
function createHistoryVerifier(options, onAdmission) {
  const { trust: inputTrust, authorityResolver, readKnowledge, preservationPolicy } = options;
  need(
    typeof authorityResolver === 'function' &&
      typeof readKnowledge === 'function' &&
      preservationPolicy &&
      typeof preservationPolicy.resolveTimestamp === 'function',
    'ORG_HISTORY_CONFIGURATION',
  );
  const trust = snapshot(inputTrust),
    resolve = resolver(authorityResolver);
  fields(trust, [
    'trustDomainID',
    'organizationID',
    'issuerID',
    'identityNamespace',
    'policy',
    'controlTrust',
    'credentialTrust',
    'algorithmDeadlines',
    'hashDeadlines',
    'keyDeadlines',
  ]);
  const { resolveTimestamp, ...preservationData } = preservationPolicy;
  const timestampResolver = (token) =>
    sync(() => resolveTimestamp(Buffer.from(token)), 'ORG_TIMESTAMP_TRUST_UNAVAILABLE');
  const preservation = snapshot(preservationData);
  fields(preservation, ['hashValidUntil'], ['dataValidUntil']);
  const statusPreservation = {
    hashValidUntil: preservation.hashValidUntil,
    resolveTimestamp: timestampResolver,
  };
  let lastKnowledge;
  const retainedKnowledge = new HistoricalKnowledge(Boolean(onAdmission));
  return Object.freeze({
    verify(input) {
      const checks = new Checks();
      let original, knowledge, protection, proof, initialProof;
      checks.add('input', 'integrity', () => {
        fields(input, ['originalBytes', 'evidenceRecord']);
        input = snapshot(input);
        original = inspectOriginal(input.originalBytes, trust, checks);
      });
      knowledge = checks.add('knowledge', 'status', () => {
        const selected = snapshot(sync(readKnowledge, 'ORG_HISTORY_KNOWLEDGE_UNAVAILABLE'));
        fields(selected, ['knowledgeTime', 'statusMaterial', 'certificateStatusMaterial']);
        need(integer(selected.knowledgeTime), 'ORG_KNOWLEDGE_TIME');
        need(
          lastKnowledge === undefined || lastKnowledge <= selected.knowledgeTime,
          'ORG_KNOWLEDGE_ROLLBACK',
        );
        for (const name of ['statusMaterial', 'certificateStatusMaterial'])
          need(
            Array.isArray(selected[name]) && selected[name].length <= 64,
            'ORG_CAPABILITY_LIMIT',
            'UNSUPPORTED',
          );
        lastKnowledge = selected.knowledgeTime;
        return selected;
      });
      if (original)
        protection = checks.add('original-protection', 'time', () =>
          originalDeadline(original, trust),
        );
      if (original && protection)
        initialProof = checks.add('original-proof', 'time', () => {
          const bound = preservation.dataValidUntil ?? protection.validUntil;
          need(integer(bound) && bound > 0, 'ORG_HISTORY_PROTECTION_POLICY');
          return verifyERSOriginalProof(input.evidenceRecord, input.originalBytes, {
            ...preservation,
            dataValidUntil: Math.min(bound, protection.validUntil),
            resolveTimestamp: timestampResolver,
          });
        });
      const archiveChecks = new Checks();
      if (original && knowledge && protection)
        proof = archiveChecks.add('preservation', 'time', () => {
          const bound = preservation.dataValidUntil ?? protection.validUntil;
          need(integer(bound) && bound > 0, 'ORG_HISTORY_PROTECTION_POLICY');
          return verifyERSPreservation(input.evidenceRecord, input.originalBytes, {
            ...preservation,
            dataValidUntil: Math.min(bound, protection.validUntil),
            resolveTimestamp: timestampResolver,
            at: knowledge.knowledgeTime,
          });
        });
      else
        archiveChecks.absorb('preservation', 'time', {
          overall: 'INDETERMINATE',
          reason: 'ORG_HISTORY_PROOF_UNAVAILABLE',
        });
      const preserved = archiveChecks.result('ORG_HISTORY_PRESERVED', proof ?? {});
      const P = initialProof?.proofOfExistenceUpperBound,
        A = original?.A,
        K = knowledge?.knowledgeTime;
      let independent, independentCertificates;
      if (onAdmission && original && knowledge && Number.isFinite(P) && P <= K) {
        const values = original.values,
          authorization = original.controls.OrganizationAuthorization;
        independent = authenticateOrganizationHistoryMaterial(
          {
            context: {
              ...trust,
              knowledgeTime: K,
              statusMaterial: knowledge.statusMaterial,
              authorityResolver: resolve,
            },
            ...(values.OrganizationDelegationPath
              ? { delegationPath: values.OrganizationDelegationPath }
              : {}),
            ...(values.OrganizationApprovalSet
              ? { approvalSet: values.OrganizationApprovalSet }
              : {}),
            ...(values.OrganizationDelegationStatus
              ? { statusCollection: values.OrganizationDelegationStatus }
              : {}),
            ...(authorization
              ? {
                  authorization: {
                    cms: authorization.cms,
                    issuerCertificate: authorization.issuerCertificate,
                  },
                }
              : {}),
          },
          P,
          onAdmission,
          statusPreservation,
        );
      }
      if (onAdmission && knowledge) {
        // External credential status binds directly to the selected certificate.
        // Its signer admission uses S/K, or S/P_status with independent ERS.
        // Neither path needs an original PoE; original status still requires P.
        const candidate = original && Number.isFinite(P) ? original : { values: {}, A: undefined };
        independentCertificates = credentialView(
          candidate,
          trust,
          knowledge,
          P,
          resolve,
          new Checks(),
          onAdmission,
          statusPreservation,
        );
        if (!Number.isFinite(P))
          for (const body of independentCertificates.statements)
            retainedKnowledge.keep(
              retainedKnowledge.certificates,
              H('CertificateStatus', body).toString('hex'),
              body,
            );
      }
      const view = (latest) => {
        const run = new Checks();
        let admissionChecks,
          organizationKnowledgeChecked = false;
        const includeIndependentFailures = () => {
          if (!organizationKnowledgeChecked)
            for (const check of admissionChecks?.checks ?? [])
              if (check.overall !== 'VALID') run.absorb(check.check, 'status', check);
        };
        if (latest && independent) {
          admissionChecks = new Checks();
          retainedKnowledge.organization(
            independent,
            P,
            admissionChecks,
            retainedKnowledge.matchingTargets(original),
          );
        }
        if (latest && independentCertificates && Number.isFinite(P) && !integer(A))
          retainedKnowledge.certificate(
            independentCertificates.statements,
            P,
            K,
            run,
            independentCertificates.currentStatements,
          );
        for (const row of checks.checks)
          if (row.overall !== 'VALID' && (latest || row.check !== 'knowledge'))
            run.absorb(row.check, undefined, row);
        const time = latest ? K : P;
        const scope = latest
          ? 'HISTORICAL_EVIDENCE_UNDER_CURRENT_KNOWLEDGE'
          : 'AS_KNOWN_AT_PROOF_TIME';
        if (!(Number.isFinite(P) && integer(A))) {
          includeIndependentFailures();
          run.absorb('time-binding', 'time', {
            overall: 'INDETERMINATE',
            reason: 'ORG_HISTORY_TIME_UNAVAILABLE',
          });
          return run.result('ORG_HISTORY_AUTHORIZED', {
            scope,
            stateTime: P ?? null,
            knowledgeTime: time ?? null,
          });
        }
        if (A > P || (Number.isFinite(K) && P > K))
          run.absorb('time-binding', 'time', {
            overall: 'INVALID',
            reason: 'ORG_HISTORY_TIME_BINDING',
          });
        if (latest && !knowledge) {
          includeIndependentFailures();
          run.absorb('knowledge', 'status', {
            overall: 'INDETERMINATE',
            reason: 'ORG_HISTORY_KNOWLEDGE_UNAVAILABLE',
          });
          return run.result('ORG_HISTORY_AUTHORIZED', { scope, stateTime: P, knowledgeTime: null });
        }
        const selected = latest
          ? knowledge
          : { knowledgeTime: P, statusMaterial: [], certificateStatusMaterial: [] };
        const values = original.values,
          control = original.controls;
        run.add('organization', 'authorization', () => {
          need(
            original.sim &&
              original.policy &&
              original.signed &&
              control.OrganizationAuthorization &&
              control.OperationPermit &&
              control.ExecutionReceipt &&
              original.binding &&
              values.OrganizationDelegationPath &&
              values.OrganizationApprovalSet &&
              values.OrganizationDelegationStatus,
            'ORG_HISTORY_ORIGINAL_MISSING',
            'INDETERMINATE',
          );
          const result = verifyOrganizationHistoricalEvidence(
            {
              context: {
                ...trust,
                knowledgeTime: time,
                statusMaterial: selected.statusMaterial,
                authorityResolver: resolve,
              },
              sim: original.sim,
              activation: control.OperationPermit?.body.activation,
              tbs: original.signed?.tbs,
              delegationPath: values.OrganizationDelegationPath,
              approvalSet: values.OrganizationApprovalSet,
              statusCollection: values.OrganizationDelegationStatus,
              authorization: control.OrganizationAuthorization && {
                cms: control.OrganizationAuthorization.cms,
                issuerCertificate: control.OrganizationAuthorization.issuerCertificate,
              },
              permit: control.OperationPermit && {
                cms: control.OperationPermit.cms,
                issuerCertificate: control.OperationPermit.issuerCertificate,
              },
              binding: original.binding && {
                cms: original.binding.cms,
                issuerCertificate: original.binding.issuerCertificate,
              },
              receiptCertificate: control.ExecutionReceipt?.issuerCertificate,
              counterBaselines: { kind: 'RETAINED_REGISTRATION' },
            },
            { stateTime: P, operationTime: A, statusPreservation },
          );
          run.absorb('organization-semantics', 'authorization', result);
          if (latest) {
            const admitted = onAdmission
              ? {
                  ...result,
                  targetObservations: independent?.targetObservations ?? [],
                  statusObservations: independent?.statusObservations ?? [],
                  currentStatusObservations: independent?.currentStatusObservations ?? [],
                }
              : result;
            retainedKnowledge.organization(
              admitted,
              P,
              run,
              retainedKnowledge.matchingTargets(original),
            );
            organizationKnowledgeChecked = true;
          }
        });
        includeIndependentFailures();
        const certificateStatements = run.add('credential-view', 'status', () =>
          credentialView(
            original,
            trust,
            selected,
            P,
            resolve,
            run,
            latest ? onAdmission : undefined,
            statusPreservation,
          ),
        );
        if (latest && certificateStatements)
          run.add('retained-certificate-knowledge', 'status', () =>
            retainedKnowledge.certificate(
              certificateStatements.statements,
              P,
              K,
              run,
              certificateStatements.currentStatements,
            ),
          );
        return run.result('ORG_HISTORY_AUTHORIZED', { scope, stateTime: P, knowledgeTime: time });
      };
      const historicalAuthorization = view(false),
        currentAdmissibility = view(true);
      checks.absorb('preservation', 'time', preserved);
      checks.absorb('historical-authorization', 'authorization', historicalAuthorization);
      checks.absorb('current-admissibility', 'authorization', currentAdmissibility);
      return checks.result('ORG_HISTORY_VALID', {
        purpose: 'RETAINED_EVIDENCE_VERIFICATION',
        operationTime: A ?? null,
        proofOfExistenceUpperBound: P ?? null,
        knowledgeTime: K ?? null,
        historicalAuthorization,
        currentAdmissibility,
        preservation: preserved,
        ...(protection
          ? {
              originalProtectionDeadline: protection.validUntil,
              protectionLedger: protection.ledger,
            }
          : {}),
        limitations: [
          'AUTHORITY_ATTESTED_WORKLOAD_PERMISSION',
          'SIGNED_REGISTRATION_COUNTER_BASELINE_ONLY',
          'NO_CURRENT_EXECUTION_PERMISSION',
        ],
      });
    },
  });
}

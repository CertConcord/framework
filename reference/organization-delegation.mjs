import { createPublicKey, KeyObject } from 'node:crypto';
import {
  ALG,
  D,
  H,
  ProtocolError,
  b64u,
  dcbor,
  decodeCBOR,
  der,
  equal,
  integer,
  intValue,
  keyID,
  oidText,
  parseDER,
  random,
  seq,
  sha512,
  verify,
} from './core.mjs';
import {
  OID,
  RRA,
  algID,
  parseCertificate,
  prepareCMS,
  signCMS,
  validateCertificate,
  verifyCMS,
} from './pki.mjs';
import { activationContext, readControl, evaluateStatus, validateActivation } from './state.mjs';
import * as execution from './execution-binding.mjs';
import { createSignaturePackage } from './evidence.mjs';
import { evidenceLeaf, verifyEvidencePackage } from './evidence-plan.mjs';
import { organizationEvidenceTypes, verifyRegistrationBinding } from './document-evidence.mjs';
import { snapshotIssuanceScope } from './enrollment-scope.mjs';
import {
  evaluateOrganizationRequest,
  verifyOrganizationApproval,
  verifyOrganizationApprovalSet,
  verifyOrganizationEvidence,
} from './organization-delegation-evidence.mjs';
import {
  ORGANIZATION_PROFILE,
  ORGANIZATION_PLAN,
  OPERATION_NAMESPACE,
  OrganizationContext,
  OrganizationState,
  addCheck,
  binary,
  bindJournal,
  canonical,
  decision,
  failure,
  insist,
  instant,
  operationID,
  orgError,
  record,
  rejected,
  requireChecks,
  snapshot,
} from './organization-delegation-state.mjs';

const PROFILE = ORGANIZATION_PROFILE;
const SEAL_PROFILE = 'CERTCONCORD-ORG-SEAL-v1';
const SHA512 = '2.16.840.1.101.3.4.2.3';
const COUNTER_NAMESPACE = 'organization-delegation-counter';
const ROLES = {
  ORGANIZATION_FINAL_AUTHORIZATION: 'ORGANIZATION_AUTHORITY',
  ORGANIZATION_DELEGATION_STATUS: 'STATUS_AUTHORITY',
  ORGANIZATION_DELEGATION_PERMIT: 'PERMIT_AUTHORITY',
  ORGANIZATION_DELEGATION_RECEIPT: 'RECEIPT_AUTHORITY',
  ORGANIZATION_DELEGATION_EXECUTION_BINDING: 'EXECUTION_BINDING_AUTHORITY',
};
const TYPES = [
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

function run(operation) {
  return {
    checks: [],
    knowledgeTime: null,
    operationID: operation ?? null,
    effectMayHaveOccurred: false,
  };
}
function finish(run, success = {}, negative = {}) {
  const bad = rejected(run.checks);
  return Object.freeze(
    snapshot({
      overall: bad?.overall ?? 'VALID',
      reason: bad?.reason ?? 'ORG_VALID',
      knowledgeTime: run.knowledgeTime,
      operationID: run.operationID,
      effectMayHaveOccurred: run.effectMayHaveOccurred,
      checks: run.checks,
      ...(bad ? negative : success),
    }),
  );
}
function putFailure(run, error, stage, fallback, overall) {
  run.checks.push({ check: stage, ...failure(error, fallback, overall) });
}
function absorb(run, result, name) {
  result = decision(result);
  if (Array.isArray(result.checks))
    for (const item of result.checks)
      run.checks.push({
        check: item.check ?? name,
        ...decision({ ...item, reason: item.reason ?? 'ORG_CHECK_' + item.overall }),
      });
  run.checks.push({ check: name, overall: result.overall, reason: result.reason });
  return result;
}
function selectControl(context, purpose, certificate, objectType) {
  if (purpose === 'ORGANIZATION_DELEGATION_STATUS')
    insist(typeof objectType === 'string', 'ORG_CONTROL_OBJECT_TYPE');
  const matches = context.controlTrust.filter(
    (entry) =>
      entry.purpose === purpose &&
      (!certificate || equal(entry.certificate, certificate)) &&
      (objectType === undefined || entry.objectTypes.includes(objectType)),
  );
  insist(
    matches.length > 0 &&
      matches.every((entry) => equal(entry.certificate, matches[0].certificate)),
    'ORG_CONTROL_TRUST_REQUIRED',
    'INDETERMINATE',
  );
  return { ...matches[0], objectTypes: objectType === undefined ? [] : [objectType] };
}
function scope(context, purpose) {
  return {
    trustDomainID: context.trustDomainID,
    profileID: PROFILE,
    issuerID: context.issuerID,
    representation: 'X509',
    purpose,
  };
}
function authority(
  run,
  context,
  certificate,
  role,
  authorityScope,
  stateTime = context.knowledgeTime,
) {
  let result = decision(
    context.authorityResolver({
      certificate,
      role,
      scope: authorityScope,
      stateTime,
      knowledgeTime: context.knowledgeTime,
    }),
  );
  if (result.overall === 'VALID' && Object.hasOwn(result, 'coverageUntil')) {
    if (!instant(result.coverageUntil))
      result = { overall: 'INDETERMINATE', reason: 'ORG_AUTHORITY_DECISION' };
    else if (context.knowledgeTime >= result.coverageUntil)
      result = { overall: 'INDETERMINATE', reason: 'ORG_AUTHORITY_COVERAGE' };
    else
      run.authorityCoverageUntil = Math.min(
        run.authorityCoverageUntil ?? result.coverageUntil,
        result.coverageUntil,
      );
  }
  run.checks.push({ check: role, overall: result.overall, reason: result.reason });
  return result;
}
function deadline(context, map, id) {
  insist(Object.hasOwn(context[map], id), 'ORG_PROTECTION_DEADLINE_MISSING', 'INDETERMINATE');
  const cutoff = context[map][id];
  insist(context.knowledgeTime < cutoff, 'ORG_PROTECTION_DEADLINE');
  return cutoff;
}
function certificateProtection(context, raw) {
  const cert = parseCertificate(raw);
  insist(
    context.knowledgeTime >= cert.notBefore && context.knowledgeTime < cert.notAfter,
    'ORG_CERTIFICATE_TIME',
  );
  return Math.min(
    cert.notAfter,
    deadline(context, 'keyDeadlines', keyID(cert.publicKey).toString('hex')),
    deadline(context, 'algorithmDeadlines', cert.algorithm),
    deadline(context, 'algorithmDeadlines', ALG[cert.publicKey.asymmetricKeyType]?.oid ?? ''),
    deadline(context, 'hashDeadlines', SHA512),
  );
}
function admitControl(run, context, raw, purpose, objectType) {
  const entry = addCheck(run.checks, 'control-trust', () =>
    selectControl(context, purpose, raw, objectType),
  );
  const until = addCheck(run.checks, 'control-protection', () =>
    certificateProtection(context, raw),
  );
  if (entry) authority(run, context, raw, ROLES[purpose], scope(context, purpose));
  return until === undefined ? undefined : Math.min(until, run.authorityCoverageUntil ?? Infinity);
}
function signatureContext(context) {
  return {
    schemaVersion: 1,
    trustDomainID: context.trustDomainID,
    profileID: SEAL_PROFILE,
    container: 'CMS',
    adapterID: 'certconcord-cms-v1',
  };
}
function preparedCMS(context, document, sim) {
  return prepareCMS({
    content: document,
    certificate: context.credentialTrust.certificate,
    detached: true,
    context: signatureContext(context),
    simHash: H('SIM', sim),
    policyHash: H('SignaturePolicy', context.policy),
  });
}
function sealBindings(context, document, sim) {
  organizationEvidenceTypes(context.policy, 'CMS');
  insist(
    context.policy.organizationDelegation.identityNamespace === context.identityNamespace,
    'ORG_IDENTITY_NAMESPACE',
  );
  insist(execution.executionRequirement(context.policy), 'ORG_EXECUTION_REQUIRED');
  record(sim, [
    'schemaVersion',
    'trustDomainID',
    'transactionID',
    'subjectID',
    'profileID',
    'keyID',
    'certificateID',
    'certificateRepresentationHash',
    'container',
    'adapterID',
    'documents',
    'purpose',
    'origin',
    'policyHash',
    'issuedAt',
    'expiresAt',
    'nonce',
    'displayText',
    'organizationID',
    'organizationAuthorizationID',
  ]);
  for (const name of [
    'trustDomainID',
    'transactionID',
    'subjectID',
    'nonce',
    'organizationID',
    'organizationAuthorizationID',
  ])
    binary(sim[name], 32);
  for (const name of ['keyID', 'certificateID', 'certificateRepresentationHash', 'policyHash'])
    binary(sim[name], 64);
  insist(
    sim.schemaVersion === 1 &&
      sim.profileID === SEAL_PROFILE &&
      sim.container === 'CMS' &&
      sim.adapterID === 'certconcord-cms-v1' &&
      sim.purpose === 'ORGANIZATION_SEAL',
    'ORG_SIGNATURE_PROFILE',
  );
  insist(
    equal(sim.trustDomainID, context.trustDomainID) &&
      equal(sim.subjectID, context.organizationID) &&
      equal(sim.organizationID, context.organizationID) &&
      equal(sim.policyHash, H('SignaturePolicy', context.policy)),
    'ORG_SIGNATURE_BINDING',
  );
  insist(
    context.policy.allowedOrigins.includes(sim.origin) &&
      context.policy.allowedProfiles.includes(sim.profileID),
    'ORG_SIGNATURE_PROFILE',
  );
  insist(Array.isArray(sim.documents) && sim.documents.length === 1, 'ORG_DOCUMENT_SCOPE');
  const doc = sim.documents[0];
  record(doc, ['documentID', 'mediaType', 'digestAlgorithm', 'digest', 'scope', 'displayName']);
  binary(doc.documentID, 32);
  insist(
    doc.scope === 'CMS_CONTENT' &&
      doc.digestAlgorithm === 'SHA-512' &&
      equal(doc.digest, sha512(document)),
    'ORG_DOCUMENT_BINDING',
  );
  const cert = parseCertificate(context.credentialTrust.certificate);
  insist(
    equal(sim.keyID, keyID(cert.publicKey)) &&
      equal(sim.certificateID, cert.certificateID) &&
      equal(sim.certificateRepresentationHash, cert.representationHash),
    'ORG_CERTIFICATE_BINDING',
  );
  insist(
    instant(sim.issuedAt) &&
      instant(sim.expiresAt) &&
      sim.issuedAt <= context.knowledgeTime &&
      sim.expiresAt > context.knowledgeTime,
    'ORG_CURRENT_OPERATION_EXPIRED',
  );
  return cert;
}
function credentialChecks(run, context, document, sim, retainedStatus) {
  const trust = context.credentialTrust,
    K = context.knowledgeTime;
  const certificate = addCheck(run.checks, 'document-binding', () =>
    document !== null && sim !== null
      ? sealBindings(context, document, sim)
      : parseCertificate(trust.certificate),
  );
  const issuer = addCheck(run.checks, 'credential-issuer', () =>
    parseCertificate(trust.issuerCertificate),
  );
  const issuance = addCheck(run.checks, 'issuance-scope', () => {
    const value = snapshotIssuanceScope(trust.issuanceScope);
    insist(
      equal(value.trustDomainID, context.trustDomainID) &&
        value.representation === 'X509' &&
        issuer &&
        equal(value.issuerKeyID, keyID(issuer.publicKey)),
      'ISSUANCE_SCOPE',
    );
    return value;
  });
  if (issuer)
    addCheck(run.checks, 'credential-signature', () =>
      validateCertificate(trust.certificate, issuer.publicKey, { at: K, profileID: SEAL_PROFILE }),
    );
  const registration = addCheck(run.checks, 'credential-registration', () =>
    verifyRegistrationBinding(trust.registrationAuthorization, trust.certificate, {
      raCertificate: trust.raCertificate,
      issuanceScope: trust.issuanceScope,
      subjectID: context.organizationID,
      profileID: SEAL_PROFILE,
      policyHash: H('SignaturePolicy', context.policy),
      at: K,
    }),
  );
  const cutoffs = [];
  for (const name of ['certificate', 'issuerCertificate', 'raCertificate', 'statusCertificate']) {
    const until = addCheck(run.checks, 'credential-protection', () =>
      certificateProtection(context, trust[name]),
    );
    if (until !== undefined) cutoffs.push(until);
  }
  if (issuance) {
    const credentialScope = {
      trustDomainID: context.trustDomainID,
      profileID: SEAL_PROFILE,
      issuerID: issuance.issuerID,
      representation: 'X509',
    };
    authority(run, context, trust.issuerCertificate, 'ISSUER', credentialScope);
    authority(run, context, trust.raCertificate, 'REGISTRATION_AUTHORITY', credentialScope);
    if (registration) {
      authority(
        run,
        context,
        trust.issuerCertificate,
        'ISSUER',
        credentialScope,
        registration.issuedAt,
      );
      authority(
        run,
        context,
        trust.raCertificate,
        'REGISTRATION_AUTHORITY',
        credentialScope,
        registration.issuedAt,
      );
    }
    const statuses = [];
    if (retainedStatus) statuses.push({ raw: retainedStatus, required: false });
    if (trust.currentCertificateStatus)
      statuses.push({ raw: trust.currentCertificateStatus, required: true });
    else
      run.checks.push({
        check: 'credential-current-status',
        overall: 'INDETERMINATE',
        reason: 'ORG_CERTIFICATE_STATUS_MISSING',
      });
    for (const { raw, required } of statuses) {
      const status = addCheck(run.checks, 'credential-status-math', () =>
        readControl(raw, 'CertificateStatus', trust.statusCertificate),
      );
      if (!status) continue;
      addCheck(run.checks, 'credential-status-binding', () =>
        insist(
          certificate &&
            equal(status.certificateID, certificate.certificateID) &&
            equal(status.trustDomainID, context.trustDomainID),
          'ORG_CERTIFICATE_STATUS_BINDING',
        ),
      );
      const evaluated = evaluateStatus(status, {
        stateTime: K,
        knowledgeTime: K,
        scope: 'CERTIFICATE',
      });
      if (required || evaluated.overall !== 'INDETERMINATE')
        run.checks.push({
          check: 'credential-status',
          ...decision({
            ...evaluated,
            reason: evaluated.reason ?? 'CERTIFICATE_STATUS_' + evaluated.status,
          }),
        });
      if (status.publishedAt <= K)
        authority(
          run,
          context,
          trust.statusCertificate,
          'STATUS_AUTHORITY',
          credentialScope,
          status.publishedAt,
        );
    }
    authority(run, context, trust.statusCertificate, 'STATUS_AUTHORITY', credentialScope);
  }
  authority(run, context, trust.certificate, 'DOCUMENT_SEAL', scope(context, 'ORGANIZATION_SEAL'));
  return {
    certificate,
    validUntil: cutoffs.length ? Math.min(...cutoffs, run.authorityCoverageUntil ?? Infinity) : K,
  };
}
function controlKey(input, context, purpose, type) {
  record(input, ['certificate', 'privateKey']);
  const certificate = binary(input.certificate, 1, 65536),
    key = input.privateKey;
  insist(
    key instanceof KeyObject &&
      key.type === 'private' &&
      equal(keyID(createPublicKey(key)), keyID(parseCertificate(certificate).publicKey)),
    'ORG_CONTROL_KEY_BINDING',
  );
  const trust = selectControl(context, purpose, certificate, type);
  if (type) insist(trust.objectTypes.includes(type), 'ORG_CONTROL_TRUST');
  return { certificate, privateKey: key };
}
function controlEnvelope(label, body, key) {
  return signCMS({ content: D(label, body), certificate: key.certificate }, key.privateKey);
}
function member(cms, issuerCertificate) {
  return { cms, issuerCertificate };
}
function approvalPayload(operation) {
  return dcbor({
    schemaVersion: 1,
    profile: PROFILE,
    request: operation.request,
    approvals: operation.request.roster.flatMap((person, index) => {
      const accepted = operation.approvals.find((entry) => equal(entry.personID, person.personID));
      if (!accepted) return [];
      return [
        {
          personID: person.personID,
          registrationCMS: operation.registrations[index].cms,
          registrationIssuerCertificate: operation.registrations[index].issuerCertificate,
          assertion: accepted.assertion,
        },
      ];
    }),
  });
}
function counterBaselines(operation) {
  return {
    kind: 'SERVICE_ACCEPTED',
    entries: operation.request.roster.flatMap((person) => {
      const accepted = operation.approvals.find((entry) => equal(entry.personID, person.personID));
      return accepted
        ? [
            {
              personID: person.personID,
              assertionHash: accepted.assertionHash,
              counterBefore: accepted.counterBefore,
            },
          ]
        : [];
    }),
  };
}
function statusPayload(context, prior, extra = []) {
  const members = [...context.statusMaterial, ...extra];
  if (prior) members.push(...canonical(prior, 8 * 1024 * 1024).statements);
  const unique = [
    ...new Map(members.map((item) => [b64u(sha512(item.cms)), snapshot(item)])).values(),
  ];
  insist(unique.length <= 64, 'ORG_CAPABILITY_LIMIT', 'UNSUPPORTED');
  const parsed = unique.map((item) => ({
    member: item,
    body: readControl(item.cms, 'OrganizationDelegationStatus', item.issuerCertificate),
  }));
  parsed.sort(
    (a, b) =>
      (a.body.objectType < b.body.objectType
        ? -1
        : a.body.objectType > b.body.objectType
          ? 1
          : 0) ||
      Buffer.compare(a.body.objectID, b.body.objectID) ||
      a.body.epoch - b.body.epoch ||
      Buffer.compare(
        H('OrganizationDelegationStatus', a.body),
        H('OrganizationDelegationStatus', b.body),
      ),
  );
  return dcbor({
    schemaVersion: 1,
    profile: PROFILE,
    statements: parsed.map((item) => item.member),
  });
}
function executionMath(operation, result, context, certificates) {
  const cert = parseCertificate(context.credentialTrust.certificate);
  insist(verify(operation.tbs, result.signature, cert.publicKey), 'CMS_SIGNATURE');
  const receipt = readControl(result.receipt, 'ExecutionReceipt', certificates.receiptCertificate);
  const facts = execution.verifyOrganizationExecutionEvidence(
    {
      policy: context.policy,
      sim: operation.sim,
      permit: operation.permit,
      tbs: operation.tbs,
      signature: result.signature,
      publicKey: cert.publicKey,
      receipt: result.receipt,
      evidence: result.executionEvidence,
    },
    {
      ...certificates,
      trustDomainID: context.trustDomainID,
      at: receipt.executedAt,
      knowledgeTime: context.knowledgeTime,
    },
  );
  return { receipt, facts };
}
function executionCrypto(operation, result, context, certificates) {
  const cert = parseCertificate(context.credentialTrust.certificate);
  insist(verify(operation.tbs, result.signature, cert.publicKey), 'CMS_SIGNATURE');
  const receipt = readControl(result.receipt, 'ExecutionReceipt', certificates.receiptCertificate);
  insist(
    equal(receipt.operationID, operation.operationID) &&
      equal(receipt.tbsHash, sha512(operation.tbs)) &&
      equal(receipt.signatureHash, sha512(result.signature)) &&
      equal(receipt.permitHash, sha512(operation.permit)) &&
      equal(receipt.keyID, operation.sim.keyID),
    'EXECUTION_RECEIPT_BINDING',
  );
}

/** A bounded current-state organization authorization and one-signature workflow. */
export class OrganizationDelegationApplication {
  #context;
  #journal;
  #state;
  #initial;
  #keys;
  #execution;
  #configuration;
  #gateway;
  #clock;
  constructor(options) {
    record(options, ['journal', 'readContext', 'authorization', 'permit', 'status', 'execution']);
    this.#context = new OrganizationContext(options.readContext);
    const context = (this.#initial = this.#context.initial);
    organizationEvidenceTypes(context.policy, 'CMS');
    this.#journal = bindJournal(options.journal);
    this.#state = new OrganizationState(this.#journal, context.trustDomainID);
    this.#keys = {
      authorization: controlKey(options.authorization, context, 'ORGANIZATION_FINAL_AUTHORIZATION'),
      permit: controlKey(options.permit, context, 'ORGANIZATION_DELEGATION_PERMIT'),
      status: controlKey(
        options.status,
        context,
        'ORGANIZATION_DELEGATION_STATUS',
        'FINAL_AUTHORIZATION',
      ),
    };
    record(options.execution, [
      'binding',
      'bindingCertificate',
      'receiptCertificate',
      'receiptKey',
      'backend',
      'keyRef',
    ]);
    const supplied = options.execution;
    const receipt = controlKey(
      { certificate: supplied.receiptCertificate, privateKey: supplied.receiptKey },
      context,
      'ORGANIZATION_DELEGATION_RECEIPT',
    );
    selectControl(
      context,
      'ORGANIZATION_DELEGATION_EXECUTION_BINDING',
      supplied.bindingCertificate,
    );
    insist(
      supplied.backend &&
        typeof supplied.backend.capabilities === 'function' &&
        typeof supplied.backend.sign === 'function' &&
        typeof supplied.keyRef === 'string' &&
        supplied.keyRef.length > 0 &&
        supplied.keyRef.length <= 256,
      'ORG_EXECUTION_CONFIGURATION',
    );
    this.#execution = {
      binding: binary(supplied.binding, 1, 65536),
      bindingCertificate: binary(supplied.bindingCertificate, 1, 65536),
      receiptCertificate: receipt.certificate,
      receiptKey: receipt.privateKey,
      keyRef: supplied.keyRef,
      backend: Object.freeze({
        capabilities: supplied.backend.capabilities.bind(supplied.backend),
        sign: supplied.backend.sign.bind(supplied.backend),
      }),
    };
    this.#configuration = H('OrganizationApplicationBinding', {
      contextHash: this.#context.configurationHash,
      trustDomainID: context.trustDomainID,
      organizationID: context.organizationID,
      identityNamespace: context.identityNamespace,
      policyHash: H('SignaturePolicy', context.policy),
      operator: { type: context.operator.type, id: context.operator.id },
      certificate: context.credentialTrust.certificate,
      registrationAuthorization: context.credentialTrust.registrationAuthorization,
      controls: Object.fromEntries(
        Object.entries(this.#keys).map(([key, value]) => [key, value.certificate]),
      ),
      execution: {
        binding: this.#execution.binding,
        bindingCertificate: this.#execution.bindingCertificate,
        receiptCertificate: this.#execution.receiptCertificate,
        keyRef: this.#execution.keyRef,
      },
    });
    this.#clock = context.knowledgeTime;
  }
  #read(run) {
    const context = this.#context.read();
    this.#clock = run.knowledgeTime = context.knowledgeTime;
    return context;
  }
  #load(id) {
    binary(id, 32);
    const row = this.#state.operation(this.#initial, id);
    insist(row, 'ORG_OPERATION_MISSING', 'INDETERMINATE');
    insist(
      equal(row.value.configurationHash, this.#configuration) && equal(row.value.operationID, id),
      'ORG_OPERATION_BINDING',
    );
    return row;
  }
  #operationGuard(id, row) {
    return {
      namespace: OPERATION_NAMESPACE,
      id: operationID(this.#initial, id),
      revision: row.revision,
    };
  }
  #evaluate(run, context, operation, evaluator, extra = {}) {
    const closure = {
      delegationPath: operation.path,
      approverRegistrations: operation.registrations,
      ...(operation.approvalSet ? { approvalSet: operation.approvalSet } : {}),
      ...(operation.authorization
        ? { authorization: member(operation.authorization, this.#keys.authorization.certificate) }
        : {}),
      ...(operation.statusCollection ? { statusCollection: operation.statusCollection } : {}),
      binding: member(this.#execution.binding, this.#execution.bindingCertificate),
    };
    const projection = this.#state.load(context, closure);
    const credential = credentialChecks(run, context, operation.document, operation.sim);
    const input = {
      context,
      state: projection.state,
      sim: operation.sim,
      activation: operation.activation,
      tbs: operation.tbs,
      delegationPath: operation.path,
      ...extra,
    };
    let evaluated;
    try {
      evaluated = evaluator(input);
    } catch (error) {
      evaluated = {
        ...failure(error),
        checks: [],
        targetObservations: [],
        statusObservations: [],
        executionObservations: [],
        counterFacts: [],
      };
    }
    const result = absorb(run, evaluated, 'organization-evidence');
    const currentGuard = this.#state.merge(context, projection, result);
    return { result, currentGuard, credential };
  }
  #full(run, context, operation) {
    insist(
      operation.authorization && operation.permit && operation.approvalSet,
      'ORG_AUTHORIZATION_MISSING',
      'INDETERMINATE',
    );
    return this.#evaluate(run, context, operation, verifyOrganizationEvidence, {
      approvalSet: operation.approvalSet,
      statusCollection: operation.statusCollection,
      authorization: member(operation.authorization, this.#keys.authorization.certificate),
      permit: member(operation.permit, this.#keys.permit.certificate),
      binding: member(this.#execution.binding, this.#execution.bindingCertificate),
      receiptCertificate: this.#execution.receiptCertificate,
      counterBaselines: counterBaselines(operation),
    });
  }
  prepare(input) {
    const current = run();
    try {
      record(input, ['operationID', 'document', 'sim', 'delegationPath', 'approverRegistrations']);
      const frozen = snapshot(input);
      binary(frozen.operationID, 32);
      binary(frozen.document, 0, 16 * 1024 * 1024);
      binary(frozen.delegationPath, 1, 2 * 1024 * 1024);
      insist(
        Array.isArray(frozen.approverRegistrations) &&
          frozen.approverRegistrations.length >= 2 &&
          frozen.approverRegistrations.length <= 16,
        'ORG_ROSTER_SIZE',
      );
      current.operationID = frozen.operationID;
      const context = this.#read(current),
        prior = this.#state.operation(context, frozen.operationID);
      const inputHash = H('OrganizationPreparation', {
        ...frozen,
        configurationHash: this.#configuration,
      });
      if (prior) {
        insist(
          equal(prior.value.configurationHash, this.#configuration) &&
            equal(prior.value.inputHash, inputHash),
          'IDEMPOTENCY_CONFLICT',
        );
        const operation = prior.value;
        const checked = this.#evaluate(current, context, operation, evaluateOrganizationRequest, {
          approverRegistrations: operation.registrations,
          rosterNonces: operation.rosterNonces,
        });
        requireChecks(current.checks);
        const { expiresAt: refreshedUntil, ...refreshedRequest } = checked.result.facts.request;
        const { expiresAt, ...savedRequest } = operation.request;
        insist(
          equal(dcbor(refreshedRequest), dcbor(savedRequest)) &&
            savedRequest.issuedAt <= context.knowledgeTime &&
            context.knowledgeTime < expiresAt,
          'ORG_REQUEST_BINDING_OR_EXPIRY',
        );
        return finish(current, this.#preparedResult(operation));
      }
      const certificate = sealBindings(context, frozen.document, frozen.sim);
      const prepared = preparedCMS(context, frozen.document, frozen.sim);
      const activation = activationContext({
        trustDomainID: context.trustDomainID,
        tbsKind: 'CMS_SIGNED_ATTRS_DER',
        simHash: H('SIM', frozen.sim),
        tbs: prepared.tbs,
        publicKey: certificate.publicKey,
        certificateID: certificate.certificateID,
        certificateRepresentationHash: certificate.representationHash,
        transactionID: frozen.sim.transactionID,
        operationID: frozen.operationID,
        policyHash: H('SignaturePolicy', context.policy),
        origin: frozen.sim.origin,
        rpID: context.policy.rpID,
        audience: context.policy.audience,
        issuedAt: context.knowledgeTime,
        expiresAt: Math.min(
          frozen.sim.expiresAt,
          context.knowledgeTime + context.policy.maxActivationLifetime,
        ),
        serverNonce: random(),
      });
      const operation = {
        configurationHash: this.#configuration,
        inputHash,
        operationID: frozen.operationID,
        document: frozen.document,
        sim: frozen.sim,
        path: frozen.delegationPath,
        registrations: frozen.approverRegistrations,
        tbs: prepared.tbs,
        activation,
        rosterNonces: frozen.approverRegistrations.map(() => random()),
        approvals: [],
        status: 'PREPARED',
        serverNonceConsumed: false,
      };
      const checked = this.#evaluate(current, context, operation, evaluateOrganizationRequest, {
        approverRegistrations: operation.registrations,
        rosterNonces: operation.rosterNonces,
      });
      requireChecks(current.checks);
      const facts = checked.result.facts;
      insist(
        facts && facts.request && Array.isArray(facts.registrations),
        'ORG_EVALUATOR_FACTS',
        'INDETERMINATE',
      );
      operation.request = facts.request;
      operation.registrationFacts = facts.registrations;
      this.#journal.transaction(() => {
        this.#state.guard(checked.currentGuard);
        insist(
          !this.#state.operation(context, operation.operationID),
          'ORG_STATE_CONFLICT',
          'INDETERMINATE',
        );
        this.#journal.put(
          OPERATION_NAMESPACE,
          operationID(context, operation.operationID),
          operation,
          -1,
        );
        this.#state.bump(context, checked.currentGuard);
      });
      return finish(current, this.#preparedResult(operation));
    } catch (error) {
      putFailure(current, error, 'prepare');
      return finish(current);
    }
  }
  #preparedResult(operation) {
    return {
      status: 'PREPARED',
      claim: 'PREPARATION_ONLY',
      request: operation.request,
      activation: operation.activation,
      challenges: operation.request.roster.map((person, index) => ({
        personID: person.personID,
        credentialID: operation.registrationFacts[index].credentialID,
        challenge: H('OrganizationApprovalChallenge', {
          schemaVersion: 1,
          profile: PROFILE,
          requestHash: H('OrganizationApprovalRequest', operation.request),
          personID: person.personID,
          credentialIDHash: person.credentialIDHash,
        }),
        rpID: operation.registrationFacts[index].rpID,
        origin: person.origin,
        expiresAt: operation.request.expiresAt,
      })),
    };
  }
  approve(input) {
    const current = run();
    try {
      record(input, [
        'operationID',
        'personID',
        'credentialID',
        'clientDataJSON',
        'authenticatorData',
        'signature',
      ]);
      const frozen = snapshot(input);
      current.operationID = binary(frozen.operationID, 32);
      binary(frozen.personID, 32);
      const context = this.#read(current),
        row = this.#load(frozen.operationID),
        operation = row.value;
      const index = operation.request.roster.findIndex((person) =>
        equal(person.personID, frozen.personID),
      );
      insist(index >= 0, 'ORG_PERSON_NOT_SELECTED');
      const registration = operation.registrationFacts[index],
        counterID = this.#state.counterID(context, registration),
        counter = this.#journal.get(COUNTER_NAMESPACE, counterID);
      const assertion = {
        credentialID: frozen.credentialID,
        clientDataJSON: frozen.clientDataJSON,
        authenticatorData: frozen.authenticatorData,
        signature: frozen.signature,
      };
      const accepted = operation.approvals.find((entry) => equal(entry.personID, frozen.personID));
      if (accepted)
        insist(equal(dcbor(accepted.assertion), dcbor(assertion)), 'IDEMPOTENCY_CONFLICT');
      const counterBefore =
        accepted?.counterBefore ?? Math.max(counter?.value.counter ?? 0, registration.counter);
      const checked = this.#evaluate(current, context, operation, verifyOrganizationApproval, {
        request: operation.request,
        approverRegistrations: operation.registrations,
        personID: frozen.personID,
        assertion,
        counterBefore,
      });
      requireChecks(current.checks);
      if (!accepted) {
        const fact = checked.result.counterFacts[0];
        insist(
          fact &&
            fact.counterBefore === counterBefore &&
            equal(fact.personID, frozen.personID) &&
            equal(fact.nonce, operation.request.roster[index].nonce),
          'ORG_COUNTER_FACTS',
          'INDETERMINATE',
        );
        this.#journal.transaction(() => {
          this.#state.guard(checked.currentGuard);
          this.#state.guard(this.#operationGuard(frozen.operationID, row));
          insist(
            (this.#journal.get(COUNTER_NAMESPACE, counterID)?.revision ?? -1) ===
              (counter?.revision ?? -1),
            'ORG_STATE_CONFLICT',
            'INDETERMINATE',
          );
          operation.approvals.push({
            personID: frozen.personID,
            assertion,
            assertionHash: fact.assertionHash,
            counterBefore,
            counterAfter: fact.counterAfter,
            nonce: fact.nonce,
          });
          this.#journal.put(
            COUNTER_NAMESPACE,
            counterID,
            { counter: fact.counterAfter },
            counter?.revision ?? -1,
          );
          this.#journal.put(
            OPERATION_NAMESPACE,
            operationID(context, frozen.operationID),
            operation,
            row.revision,
          );
          this.#state.bump(context, checked.currentGuard);
        });
      }
      return finish(current, {
        status: 'APPROVAL_RECORDED',
        claim: 'APPROVAL_RECORD_ONLY',
        acceptedCount: operation.approvals.length,
        requiredCount: operation.request.roster.length,
      });
    } catch (error) {
      putFailure(current, error, 'approve');
      return finish(current);
    }
  }
  authorize(input) {
    const current = run();
    try {
      record(input, ['operationID']);
      current.operationID = binary(input.operationID, 32);
      const context = this.#read(current),
        row = this.#load(current.operationID),
        operation = row.value;
      if (operation.authorization) {
        this.#full(current, context, operation);
        requireChecks(current.checks);
        return finish(current, this.#authorizationResult(operation));
      }
      operation.approvalSet = approvalPayload(operation);
      const checked = this.#evaluate(current, context, operation, verifyOrganizationApprovalSet, {
        approvalSet: operation.approvalSet,
        counterBaselines: counterBaselines(operation),
      });
      const bounds = [checked.credential.validUntil];
      for (const [name, purpose] of [
        ['authorization', 'ORGANIZATION_FINAL_AUTHORIZATION'],
        ['permit', 'ORGANIZATION_DELEGATION_PERMIT'],
        ['status', 'ORGANIZATION_DELEGATION_STATUS'],
      ]) {
        const bound = admitControl(
          current,
          context,
          this.#keys[name].certificate,
          purpose,
          name === 'status' ? 'FINAL_AUTHORIZATION' : undefined,
        );
        if (bound !== undefined) bounds.push(bound);
      }
      admitControl(
        current,
        context,
        this.#execution.receiptCertificate,
        'ORGANIZATION_DELEGATION_RECEIPT',
      );
      requireChecks(current.checks);
      const facts = checked.result.facts;
      insist(
        facts && equal(facts.terminalCertificate, this.#keys.authorization.certificate),
        'ORG_FINAL_AUTHORITY_BINDING',
      );
      const issuedAt = context.knowledgeTime,
        expiresAt = Math.min(
          issuedAt + 30,
          operation.request.expiresAt,
          operation.activation.expiresAt,
          facts.validUntil,
          ...bounds,
        );
      insist(instant(expiresAt) && expiresAt > issuedAt, 'ORG_CURRENT_OPERATION_EXPIRED');
      const authorization = {
        schemaVersion: 2,
        profile: PROFILE,
        authorizationID: operation.sim.organizationAuthorizationID,
        trustDomainID: context.trustDomainID,
        organizationID: context.organizationID,
        identityNamespace: context.identityNamespace,
        actorID: context.operator.id,
        actorType: 'WORKLOAD',
        keyID: operation.sim.keyID,
        certificateID: operation.sim.certificateID,
        certificateRepresentationHash: operation.sim.certificateRepresentationHash,
        purpose: 'ORGANIZATION_SEAL',
        activationHash: H('ActivationContext', operation.activation),
        policyHash: H('SignaturePolicy', context.policy),
        requestHash: facts.requestHash,
        approvalPolicyHash: facts.approvalPolicyHash,
        delegationPathLeafID: facts.pathLeafID,
        approvalSetLeafID: facts.approvalSetLeafID,
        issuedAt,
        expiresAt,
      };
      const before = statusPayload(context);
      this.#journal.transaction(() => {
        this.#state.guard(checked.currentGuard);
        this.#state.guard(this.#operationGuard(operation.operationID, row));
        insist(!operation.serverNonceConsumed, 'ORG_NONCE_REPLAY');
        this.#state.requireImmutableTarget({
          trustDomainID: context.trustDomainID,
          organizationID: context.organizationID,
          objectType: 'FINAL_AUTHORIZATION',
          objectID: authorization.authorizationID,
          semanticHash: H('OrganizationAuthorization', authorization),
        });
        operation.authorization = controlEnvelope(
          'OrganizationAuthorization',
          authorization,
          this.#keys.authorization,
        );
        const body = {
          schemaVersion: 1,
          profile: PROFILE,
          trustDomainID: context.trustDomainID,
          organizationID: context.organizationID,
          scope: 'ORGANIZATION_DELEGATION',
          objectType: 'FINAL_AUTHORIZATION',
          objectID: authorization.authorizationID,
          objectHash: sha512(operation.authorization),
          subjectKeyID: keyID(parseCertificate(this.#keys.authorization.certificate).publicKey),
          epoch: 1,
          status: 'GOOD',
          publishedAt: issuedAt,
          nextUpdate: expiresAt,
        };
        operation.authorizationStatus = controlEnvelope(
          'OrganizationDelegationStatus',
          body,
          this.#keys.status,
        );
        operation.statusCollection = statusPayload({ ...context, statusMaterial: [] }, before, [
          member(operation.authorizationStatus, this.#keys.status.certificate),
        ]);
        operation.permit = controlEnvelope(
          'OperationPermit',
          {
            schemaVersion: 1,
            activation: operation.activation,
            activationEvidenceHash: sha512(operation.authorization),
            proofMode: 'WORKLOAD',
            issuedAt,
            expiresAt,
          },
          this.#keys.permit,
        );
        operation.serverNonceConsumed = true;
        operation.status = 'AUTHORIZED';
        const target = {
          trustDomainID: context.trustDomainID,
          organizationID: context.organizationID,
          identityNamespace: context.identityNamespace,
          objectType: body.objectType,
          objectID: body.objectID,
          objectHash: body.objectHash,
          semanticHash: H('OrganizationAuthorization', authorization),
          subjectKeyID: body.subjectKeyID,
        };
        this.#state.merge(
          context,
          { revision: checked.currentGuard.revision },
          {
            targetObservations: [target],
            statusObservations: [
              {
                trustDomainID: body.trustDomainID,
                organizationID: body.organizationID,
                objectType: body.objectType,
                objectID: body.objectID,
                objectHash: body.objectHash,
                subjectKeyID: body.subjectKeyID,
                epoch: body.epoch,
                status: body.status,
                publishedAt: body.publishedAt,
                nextUpdate: body.nextUpdate,
                semanticHash: H('OrganizationDelegationStatus', body),
                rawHash: sha512(operation.authorizationStatus),
                effectiveTime: null,
                compromiseStart: null,
                issuerKeyID: keyID(parseCertificate(this.#keys.status.certificate).publicKey),
                observedAt: issuedAt,
              },
            ],
          },
        );
        this.#journal.put(
          OPERATION_NAMESPACE,
          operationID(context, operation.operationID),
          operation,
          row.revision,
        );
      });
      return finish(current, this.#authorizationResult(operation));
    } catch (error) {
      putFailure(current, error, 'authorize');
      return finish(current, {}, { status: 'PENDING' });
    }
  }
  #authorizationResult(operation) {
    return {
      status: 'AUTHORIZED',
      claim: 'CURRENT_OPERATION_AUTHORIZATION',
      authorization: operation.authorization,
      authorizationStatus: operation.authorizationStatus,
      permit: operation.permit,
      pathLeaf: evidenceLeaf('OrganizationDelegationPath', operation.path),
      approvalLeaf: evidenceLeaf('OrganizationApprovalSet', operation.approvalSet),
    };
  }
  #admission(view) {
    const current = run(view.operationID);
    try {
      const frozen = snapshot(view),
        context = this.#read(current),
        row = this.#load(frozen.operationID),
        operation = row.value;
      insist(
        equal(frozen.permitHash, sha512(operation.permit)) &&
          equal(frozen.bindingHash, sha512(this.#execution.binding)) &&
          equal(frozen.keyID, operation.sim.keyID) &&
          equal(dcbor(frozen.sim), dcbor(operation.sim)) &&
          equal(
            dcbor(frozen.permit),
            dcbor(readControl(operation.permit, 'OperationPermit', this.#keys.permit.certificate)),
          ) &&
          frozen.keyRef === this.#execution.keyRef,
        'ORG_EXECUTION_TUPLE',
      );
      const checked = this.#full(current, context, operation);
      requireChecks(current.checks);
      return {
        overall: 'VALID',
        reason: 'ORG_CURRENT_ADMISSION',
        binding: {
          stage: frozen.stage,
          operationID: frozen.operationID,
          requestHash: frozen.requestHash,
          bindingHash: frozen.bindingHash,
          permitHash: frozen.permitHash,
          keyID: frozen.keyID,
          signatureHash: frozen.signatureHash,
          knowledgeTime: context.knowledgeTime,
        },
        journalGuards: [this.#operationGuard(frozen.operationID, row), checked.currentGuard],
      };
    } catch (error) {
      putFailure(current, error, 'current-admission');
      const bad = rejected(current.checks);
      return { overall: bad.overall, reason: bad.reason, checks: current.checks };
    }
  }
  #gatewayFor(context) {
    if (!this.#gateway)
      this.#gateway = new execution.ExecutionBindingGateway({
        journal: this.#journal,
        ...this.#execution,
        permitCertificate: this.#keys.permit.certificate,
        policy: context.policy,
        trustDomainID: context.trustDomainID,
        authorityResolver: context.authorityResolver,
        clock: () => this.#clock,
        authorize: () => true,
        currentAdmission: (view) => this.#admission(view),
      });
    return this.#gateway;
  }
  async execute(input) {
    return this.#perform(input, false);
  }
  async reconcile(input) {
    return this.#perform(input, true);
  }
  async #perform(input, reconcile) {
    const current = run();
    let operation,
      completed = false;
    try {
      record(input, reconcile ? ['operationID', 'signature'] : ['operationID']);
      const frozen = snapshot(input);
      current.operationID = binary(frozen.operationID, 32);
      if (reconcile) binary(frozen.signature, 1, 65536);
      const row = this.#load(current.operationID);
      operation = row.value;
      if (reconcile)
        addCheck(current.checks, 'candidate-mathematics', () =>
          insist(
            verify(
              operation.tbs,
              frozen.signature,
              parseCertificate(this.#initial.credentialTrust.certificate).publicKey,
            ),
            'CMS_SIGNATURE',
          ),
        );
      const context = this.#read(current);
      this.#full(current, context, operation);
      requireChecks(current.checks);
      const gateway = this.#gatewayFor(context);
      const result = snapshot(
        await (reconcile
          ? gateway.reconcile({ operationID: current.operationID, signature: frozen.signature })
          : gateway.execute({ permit: operation.permit, tbs: operation.tbs, sim: operation.sim })),
      );
      current.effectMayHaveOccurred = true;
      const stored = this.#journal.result(b64u(current.operationID));
      insist(
        stored?.status === 'COMPLETED' && stored.result && equal(stored.result, dcbor(result)),
        'ORG_EXECUTION_RESULT_UNCOMMITTED',
        'INDETERMINATE',
      );
      completed = true;
      // Mathematical checks precede the final current-state decision after the await.
      let fresh;
      try {
        fresh = this.#read(current);
      } catch (error) {
        putFailure(current, error, 'final-context');
      }
      addCheck(current.checks, 'execution-mathematics', () =>
        fresh
          ? executionMath(operation, result, fresh, this.#certificates())
          : executionCrypto(operation, result, this.#initial, this.#certificates()),
      );
      requireChecks(current.checks);
      const finalRow = this.#load(current.operationID),
        checked = this.#full(current, fresh, finalRow.value);
      requireChecks(current.checks);
      const p = preparedCMS(fresh, operation.document, operation.sim);
      insist(equal(p.tbs, operation.tbs), 'ORG_PREPARATION_BINDING');
      const cms = p.finish(result.signature),
        statuses = statusPayload(fresh, operation.statusCollection);
      const bundle =
        finalRow.value.bundle ??
        dcbor(
          createSignaturePackage({
            document: operation.document,
            certificate: fresh.credentialTrust.certificate,
            registrationAuthorization: fresh.credentialTrust.registrationAuthorization,
            sim: operation.sim,
            policy: fresh.policy,
            permit: operation.permit,
            receipt: result.receipt,
            status: fresh.credentialTrust.currentCertificateStatus,
            cms,
            executionEvidence: result.executionEvidence,
            organizationEvidence: {
              OrganizationAuthorization: operation.authorization,
              OrganizationDelegationPath: operation.path,
              OrganizationApprovalSet: operation.approvalSet,
              OrganizationDelegationStatus: statuses,
            },
          }),
        );
      try {
        this.#journal.transaction(() => {
          this.#state.guard(checked.currentGuard);
          this.#state.guard(this.#operationGuard(current.operationID, finalRow));
          this.#journal.put(
            OPERATION_NAMESPACE,
            operationID(fresh, current.operationID),
            { ...finalRow.value, status: 'COMPLETED', bundle, result },
            finalRow.revision,
          );
          this.#state.bump(fresh, checked.currentGuard);
        });
      } catch (error) {
        putFailure(
          current,
          orgError('ORG_PACKAGE_PERSISTENCE_UNAVAILABLE', 'INDETERMINATE'),
          'package-commit',
        );
        return finish(current, {}, { status: 'OUTPUT_PENDING', executionStatus: 'COMPLETED' });
      }
      return finish(current, {
        status: 'COMPLETED',
        claim: 'CURRENT_EXECUTION',
        signature: result.signature,
        receipt: result.receipt,
        cms,
        bundle,
      });
    } catch (error) {
      putFailure(
        current,
        error,
        'execution',
        'ORG_EXECUTION_UNAVAILABLE',
        error instanceof ProtocolError ? 'INVALID' : 'INDETERMINATE',
      );
      let state;
      try {
        // Global gateway rows are not an operation lookup API across application scopes.
        if (operation) state = this.#journal.result(b64u(current.operationID));
      } catch (readError) {
        putFailure(current, readError, 'execution-result');
        current.effectMayHaveOccurred ||= !!operation;
      }
      completed ||= state?.status === 'COMPLETED';
      current.effectMayHaveOccurred ||= !!state;
      return finish(
        current,
        {},
        completed
          ? { status: 'OUTPUT_WITHHELD', executionStatus: 'COMPLETED' }
          : current.effectMayHaveOccurred
            ? { status: 'UNKNOWN_EXECUTION' }
            : {},
      );
    }
  }
  #certificates() {
    return {
      bindingCertificate: this.#execution.bindingCertificate,
      permitCertificate: this.#keys.permit.certificate,
      receiptCertificate: this.#execution.receiptCertificate,
    };
  }
  getOperationResult(input) {
    record(input, ['operationID']);
    const id = binary(input.operationID, 32);
    const row = this.#state.operation(this.#initial, id);
    if (!row) return null;
    insist(equal(row.value.configurationHash, this.#configuration), 'ORG_OPERATION_BINDING');
    const executed = this.#journal.result(b64u(id));
    return Object.freeze(
      snapshot({
        status: 'RETRIEVED',
        originalStatus: executed?.status ?? row.value.status,
        admission: 'NOT_REEVALUATED',
        operationID: id,
        record: {
          ...row.value,
          ...(executed
            ? {
                execution: {
                  status: executed.status,
                  ...(executed.result ? { result: decodeCBOR(executed.result) } : {}),
                },
              }
            : {}),
        },
      }),
    );
  }
}

function extractControl(raw, label, context, purpose) {
  const checked = verifyCMS(raw),
    cert = checked.certificate;
  selectControl(context, purpose, cert);
  return { cms: raw, issuerCertificate: cert, body: readControl(raw, label, cert) };
}

function retainedLeaves(current, bundle) {
  let checked;
  try {
    checked = verifyEvidencePackage(bundle);
  } catch (error) {
    if (error?.code === 'ECP_UNSUPPORTED_SCHEMA' && bundle.schemaVersion === 1)
      throw orgError(error.code, 'UNSUPPORTED');
    if (!['ECP_MISSING_OBJECT', 'ECP_UNSUPPORTED_SCHEMA'].includes(error?.code)) throw error;
    // These failures follow the bounded flat leaf shapes and commitment checks.
    if (error.code === 'ECP_MISSING_OBJECT')
      putFailure(current, orgError('ECP_MISSING_OBJECT', 'INDETERMINATE'), 'evidence-closure');
    checked = {
      plan: bundle.plan ?? null,
      values: Object.fromEntries(bundle.objects.map((leaf) => [leaf.type, leaf.payload])),
    };
  }
  if (bundle.schemaVersion !== 2 || (checked.plan && checked.plan.schemaVersion !== 2))
    putFailure(current, orgError('ECP_UNSUPPORTED_SCHEMA', 'UNSUPPORTED'), 'evidence-schema');
  if (checked.plan && checked.plan.profile !== ORGANIZATION_PLAN)
    putFailure(current, orgError('ORG_PLAN_DOWNGRADE'), 'evidence-plan');
  if (Object.keys(checked.values).some((type) => !TYPES.includes(type)))
    putFailure(current, orgError('ECP_PLAN'), 'evidence-plan');
  for (const type of TYPES)
    if (!Object.hasOwn(checked.values, type))
      putFailure(current, orgError('ECP_MISSING_OBJECT', 'INDETERMINATE'), 'missing:' + type);
  return checked;
}

// Check only available signature mathematics when the detached document is absent.
// This mirrors verifyCMS's selected structure and suites; it returns no content or trust facts.
function checkRetainedCMSMath(raw, expectedCertificate) {
  const root = parseDER(raw);
  insist(
    root.tag === 0x30 &&
      root.children?.length === 2 &&
      oidText(root.children[0]) === OID.signed &&
      root.children[1].tag === 0xa0 &&
      root.children[1].children?.length === 1 &&
      root.children[1].children[0].tag === 0x30,
    'CMS_CONTENT_TYPE',
  );
  const sd = root.children[1].children[0].children;
  insist(
    sd?.length === 5 &&
      intValue(sd[0]) === 1n &&
      sd[1].tag === 0x31 &&
      sd[1].children?.length === 1 &&
      sd[2].tag === 0x30 &&
      [1, 2].includes(sd[2].children?.length) &&
      oidText(sd[2].children[0]) === OID.data &&
      sd[3].tag === 0xa0 &&
      sd[3].children?.length === 1 &&
      sd[3].children[0].tag === 0x30 &&
      sd[4].tag === 0x31 &&
      sd[4].children?.length === 1 &&
      sd[4].children[0].tag === 0x30,
    'CMS_SIGNER_STRUCTURE',
  );
  if (sd[2].children[1])
    insist(
      sd[2].children[1].tag === 0xa0 &&
        sd[2].children[1].children?.length === 1 &&
        sd[2].children[1].children[0].tag === 4,
      'CMS_ENCAP_STRUCTURE',
    );
  insist(equal(sd[3].children[0].raw, expectedCertificate), 'CERTIFICATE_REPRESENTATION');
  const cert = parseCertificate(expectedCertificate),
    algorithm = cert.publicKey.asymmetricKeyType;
  if (algorithm === 'ec')
    insist(
      cert.publicKey.asymmetricKeyDetails.namedCurve === 'prime256v1' &&
        cert.extensions.get(RRA['id-pe-certconcordPasskeyBinding'])?.critical,
      'CMS_ALGORITHM',
    );
  else insist(['ml-dsa-65', 'ml-dsa-87'].includes(algorithm), 'CMS_ALGORITHM');
  const digest = algID(algorithm === 'ec' ? OID.sha256 : OID.sha512),
    si = sd[4].children[0].children;
  insist(
    equal(sd[1].children[0].raw, digest) &&
      si &&
      [6, 7].includes(si.length) &&
      intValue(si[0]) === 1n &&
      equal(si[1].raw, seq(cert.issuer, integer(cert.serial))) &&
      equal(si[2].raw, digest) &&
      si[3].tag === 0xa0 &&
      equal(si[4].raw, algID(algorithm)) &&
      si[5].tag === 4 &&
      (!si[6] || si[6].tag === 0xa1),
    'CMS_SIGNER_ID_OR_ALGORITHM',
  );
  const tbs = der(0x31, si[3].value);
  parseDER(tbs);
  insist(verify(tbs, si[5].value, cert.publicKey), 'CMS_SIGNATURE');
}

/** Independently validate retained raw evidence against constructor-bound current trust. */
export class OrganizationDelegationVerifier {
  #context;
  #journal;
  #state;
  #initial;
  constructor(options) {
    record(options, ['journal', 'readContext']);
    this.#context = new OrganizationContext(options.readContext);
    this.#initial = this.#context.initial;
    organizationEvidenceTypes(this.#initial.policy, 'CMS');
    this.#journal = bindJournal(options.journal);
    this.#state = new OrganizationState(this.#journal, this.#initial.trustDomainID);
  }
  verify(input) {
    const current = run();
    try {
      record(input, ['bundle']);
      const raw = binary(input.bundle, 1, 64 * 1024 * 1024),
        bundle = canonical(raw, 64 * 1024 * 1024);
      const { values } = retainedLeaves(current, bundle);
      const sim = values.SIM
          ? addCheck(current.checks, 'signing-intent', () => decodeCBOR(values.SIM))
          : null,
        policy = values.SignaturePolicy
          ? addCheck(current.checks, 'signature-policy', () => decodeCBOR(values.SignaturePolicy))
          : null;
      let context;
      try {
        context = this.#context.read();
        current.knowledgeTime = context.knowledgeTime;
      } catch (error) {
        putFailure(current, error, 'current-context');
      }
      const pins = context ?? this.#initial;
      if (policy)
        addCheck(current.checks, 'retained-policy', () =>
          insist(equal(dcbor(policy), dcbor(pins.policy)), 'ORG_POLICY_BINDING'),
        );
      addCheck(current.checks, 'retained-credential', () =>
        insist(
          (!values.Certificate || equal(values.Certificate, pins.credentialTrust.certificate)) &&
            (!values.RegistrationAuthorization ||
              equal(
                values.RegistrationAuthorization,
                pins.credentialTrust.registrationAuthorization,
              )),
          'ORG_CERTIFICATE_BINDING',
        ),
      );
      if (values.CMS && !values.Document)
        addCheck(current.checks, 'available-document-mathematics', () =>
          checkRetainedCMSMath(values.CMS, pins.credentialTrust.certificate),
        );
      const signed =
        values.CMS &&
        values.Document &&
        addCheck(current.checks, 'document-mathematics', () =>
          verifyCMS(values.CMS, {
            content: values.Document,
            expectedCertificate: pins.credentialTrust.certificate,
            context: signatureContext(pins),
            ...(sim ? { simHash: H('SIM', sim) } : {}),
            ...(policy ? { policyHash: H('SignaturePolicy', policy) } : {}),
          }),
        );
      const authorization =
        values.OrganizationAuthorization &&
        addCheck(current.checks, 'authorization-mathematics', () =>
          extractControl(
            values.OrganizationAuthorization,
            'OrganizationAuthorization',
            pins,
            'ORGANIZATION_FINAL_AUTHORIZATION',
          ),
        );
      const permit =
        values.OperationPermit &&
        addCheck(current.checks, 'permit-mathematics', () =>
          extractControl(
            values.OperationPermit,
            'OperationPermit',
            pins,
            'ORGANIZATION_DELEGATION_PERMIT',
          ),
        );
      const receipt =
        values.ExecutionReceipt &&
        addCheck(current.checks, 'receipt-mathematics', () =>
          extractControl(
            values.ExecutionReceipt,
            'ExecutionReceipt',
            pins,
            'ORGANIZATION_DELEGATION_RECEIPT',
          ),
        );
      const executionEvidence =
        values.ExecutionBindingEvidence &&
        addCheck(current.checks, 'execution-evidence', () =>
          decodeCBOR(values.ExecutionBindingEvidence),
        );
      const binding =
        executionEvidence &&
        addCheck(current.checks, 'binding-mathematics', () =>
          extractControl(
            executionEvidence.binding,
            'ExecutionBinding',
            pins,
            'ORGANIZATION_DELEGATION_EXECUTION_BINDING',
          ),
        );
      if (permit) current.operationID = permit.body.activation?.operationID ?? null;
      let mathematical;
      if (context && policy && sim && signed && permit && receipt && binding)
        mathematical = addCheck(current.checks, 'execution-mathematics', () =>
          execution.verifyOrganizationExecutionEvidence(
            {
              policy,
              sim,
              permit: values.OperationPermit,
              tbs: signed.tbs,
              signature: signed.signature,
              publicKey: signed.cert.publicKey,
              receipt: values.ExecutionReceipt,
              evidence: executionEvidence,
            },
            {
              bindingCertificate: binding.issuerCertificate,
              permitCertificate: permit.issuerCertificate,
              receiptCertificate: receipt.issuerCertificate,
              trustDomainID: pins.trustDomainID,
              at: receipt.body.executedAt,
              knowledgeTime: context.knowledgeTime,
            },
          ),
        );
      if (context)
        credentialChecks(
          current,
          context,
          values.Document ?? null,
          sim ?? null,
          values.CertificateStatus,
        );
      const closure = {
        delegationPath: values.OrganizationDelegationPath ?? null,
        approvalSet: values.OrganizationApprovalSet ?? null,
        statusCollection: values.OrganizationDelegationStatus ?? null,
        authorization: authorization
          ? member(authorization.cms, authorization.issuerCertificate)
          : null,
        binding: binding ? member(binding.cms, binding.issuerCertificate) : null,
      };
      const projection = context ? this.#state.load(context, closure) : null;
      const evaluated = absorb(
        current,
        verifyOrganizationEvidence({
          context: context ?? { ...pins, knowledgeTime: null },
          state: projection?.state ?? {
            knowledgeTime: null,
            targets: [],
            heads: [],
            terminalObservations: [],
            keyIncidents: [],
            executions: [],
          },
          sim: sim ?? null,
          activation: permit?.body.activation ?? null,
          tbs: signed?.tbs ?? null,
          ...closure,
          permit: permit ? member(permit.cms, permit.issuerCertificate) : null,
          receiptCertificate: receipt?.issuerCertificate ?? null,
          counterBaselines: { kind: 'RETAINED_REGISTRATION' },
        }),
        'organization-evidence',
      );
      if (context) this.#state.merge(context, projection, evaluated);
      requireChecks(current.checks);
      return finish(current, {
        mode: 'CURRENT_STATE_ONLY',
        organizationID: context.organizationID,
        operator: { type: context.operator.type, id: context.operator.id },
        admittedPersonIDs: evaluated.facts.admittedPersonIDs,
        pathLength: canonical(values.OrganizationDelegationPath, 2 * 1024 * 1024).grants.length,
        authorizationHash: evaluated.facts.authorizationHash,
        pathLeafID: evaluated.facts.pathLeafID,
        approvalSetLeafID: evaluated.facts.approvalSetLeafID,
        execution: mathematical,
        limitations: [
          'CURRENT_STATE_ONLY',
          'NO_INDEPENDENT_HISTORICAL_PERMISSION_POE',
          'SIGNED_REGISTRATION_COUNTER_BASELINE_ONLY',
        ],
      });
    } catch (error) {
      putFailure(current, error, 'retained-verification');
      return finish(current, {}, { mode: 'CURRENT_STATE_ONLY' });
    }
  }
}

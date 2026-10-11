import { types } from 'node:util';
import {
  ALG,
  H,
  dcbor,
  decodeCBOR,
  sha256,
  sha512,
  equal,
  fields,
  keyID,
  publicFromDER,
  spki,
  b64u,
  ProtocolError,
  verify,
} from './core.mjs';
import { parseCertificate, verifyCMS } from './pki.mjs';
import { readControl, validateActivation, evaluateStatus } from './state.mjs';
import { verifyAssertion } from './webauthn.mjs';
import { executionRequirement, EXECUTION_BINDING_PROFILE } from './execution-binding.mjs';

const PROFILE = 'certconcord-organization-delegation-v1';
const SEAL_PROFILE = 'CERTCONCORD-ORG-SEAL-v1';
const SHA256 = '2.16.840.1.101.3.4.2.1';
const SHA512 = '2.16.840.1.101.3.4.2.3';
const DAY30 = 30 * 86400;
const MiB = 1024 * 1024;
const TYPES = ['GRANT', 'APPROVER_REGISTRATION', 'FINAL_AUTHORIZATION'];
const PURPOSES = {
  ROOT: ['ORGANIZATION_AUTHORITY', 'ORGANIZATION_DELEGATION_ROOT'],
  ISSUE: ['ORGANIZATION_AUTHORITY', 'ORGANIZATION_DELEGATION_ISSUE'],
  FINAL: ['ORGANIZATION_AUTHORITY', 'ORGANIZATION_FINAL_AUTHORIZATION'],
  REGISTRATION: ['REGISTRATION_AUTHORITY', 'ORGANIZATION_APPROVER_REGISTRATION'],
  STATUS: ['STATUS_AUTHORITY', 'ORGANIZATION_DELEGATION_STATUS'],
  PERMIT: ['PERMIT_AUTHORITY', 'ORGANIZATION_DELEGATION_PERMIT'],
  RECEIPT: ['RECEIPT_AUTHORITY', 'ORGANIZATION_DELEGATION_RECEIPT'],
  BINDING: ['EXECUTION_BINDING_AUTHORITY', 'ORGANIZATION_DELEGATION_EXECUTION_BINDING'],
};
const LABELS = {
  GRANT: 'OrganizationDelegationGrant',
  APPROVER_REGISTRATION: 'OrganizationApproverRegistration',
  FINAL_AUTHORIZATION: 'OrganizationAuthorization',
};
const own = (v, k) => Object.hasOwn(v, k);
const integer = (v) => Number.isSafeInteger(v) && v >= 0;
const same = (a, b) => equal(dcbor(a), dcbor(b));
const hex = (v) => v.toString('hex');

function fail(reason, overall = 'INVALID') {
  const error = new ProtocolError(reason);
  error.overall = overall;
  throw error;
}
function need(condition, reason, overall = 'INVALID') {
  if (!condition) fail(reason, overall);
}
function sized(value, max, reason, size) {
  need(Buffer.isBuffer(value) && value.length > 0, reason);
  need(value.length <= max, reason + '_LIMIT', 'UNSUPPORTED');
  if (size !== undefined) need(value.length === size, reason);
  return value;
}
const id = (v) => sized(v, 32, 'ORG_ID', 32);
const hash = (v) => sized(v, 64, 'ORG_HASH', 64);
function text(v, max = 256) {
  need(typeof v === 'string' && v.length > 0 && v === v.normalize('NFC'), 'ORG_TEXT');
  need(Buffer.byteLength(v) <= max, 'ORG_TEXT_LIMIT', 'UNSUPPORTED');
}
function list(v, max, min = 0) {
  need(Array.isArray(v) && v.length >= min, 'ORG_ARRAY');
  need(v.length <= max, 'ORG_ARRAY_LIMIT', 'UNSUPPORTED');
  return v;
}
function times(body, names) {
  for (const name of names) need(integer(body[name]), 'ORG_TIME');
}
function set(values, validate, max = 32) {
  list(values, max, 1);
  let previous;
  for (const value of values) {
    validate(value);
    const encoded = dcbor(value);
    need(!previous || Buffer.compare(previous, encoded) < 0, 'ORG_SET_ORDER_OR_DUPLICATE');
    previous = encoded;
  }
  return values;
}
function tuple(v) {
  fields(v, ['keyID', 'certificateID', 'certificateRepresentationHash']);
  Object.values(v).forEach(hash);
}
function certificateTuple(cert) {
  return {
    keyID: keyID(cert.publicKey),
    certificateID: cert.certificateID,
    certificateRepresentationHash: cert.representationHash,
  };
}

// Detach every message and trusted data record before calling external admission.
// Functions are admitted only at the one explicitly captured resolver slot.
function snapshot(value, budget = { nodes: 0, bytes: 0 }, depth = 0) {
  need(depth <= 32 && ++budget.nodes <= 200000, 'ORG_SNAPSHOT_LIMIT', 'UNSUPPORTED');
  if (Buffer.isBuffer(value)) {
    budget.bytes += value.length;
    need(budget.bytes <= 64 * MiB, 'ORG_SNAPSHOT_LIMIT', 'UNSUPPORTED');
    return Buffer.from(value);
  }
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    budget.bytes += Buffer.byteLength(value);
    need(budget.bytes <= 64 * MiB, 'ORG_SNAPSHOT_LIMIT', 'UNSUPPORTED');
    return value;
  }
  if (typeof value === 'number') {
    need(Number.isSafeInteger(value), 'ORG_NUMBER');
    return value;
  }
  need(
    value &&
      typeof value === 'object' &&
      [Object.prototype, null, Array.prototype].includes(Object.getPrototypeOf(value)),
    'ORG_DATA_SHAPE',
  );
  const descriptors = Object.getOwnPropertyDescriptors(value);
  need(
    Reflect.ownKeys(descriptors).every(
      (k) => typeof k === 'string' && own(descriptors[k], 'value'),
    ),
    'ORG_DATA_ACCESSOR',
  );
  if (Array.isArray(value)) {
    need(Object.keys(descriptors).length === value.length + 1, 'ORG_ARRAY_SHAPE');
    return Array.from({ length: value.length }, (_, i) => {
      need(own(descriptors, String(i)), 'ORG_ARRAY_HOLE');
      return snapshot(descriptors[i].value, budget, depth + 1);
    });
  }
  const out = Object.create(null);
  for (const [k, descriptor] of Object.entries(descriptors)) {
    need(descriptor.enumerable && /^[\x20-\x7e]+$/.test(k), 'ORG_DATA_PROPERTY');
    out[k] = snapshot(descriptor.value, budget, depth + 1);
  }
  return out;
}
function resolverResult(value) {
  if (types.isPromise(value)) {
    Promise.prototype.then.call(value, undefined, () => {});
    fail('ORG_AUTHORITY_ASYNC', 'INDETERMINATE');
  }
  let result;
  try {
    result = snapshot(value);
  } catch {
    fail('ORG_AUTHORITY_DECISION', 'INDETERMINATE');
  }
  need(
    !own(result, 'then') &&
      ['VALID', 'INVALID', 'UNSUPPORTED', 'INDETERMINATE'].includes(result.overall),
    'ORG_AUTHORITY_DECISION',
    'INDETERMINATE',
  );
  if (result.overall !== 'VALID')
    fail(
      typeof result.reason === 'string' && result.reason ? result.reason : 'ORG_AUTHORITY_DENIED',
      result.overall,
    );
  need(
    typeof result.reason === 'string' && result.reason.length > 0,
    'ORG_AUTHORITY_DECISION',
    'INDETERMINATE',
  );
  if (own(result, 'coverageUntil'))
    need(integer(result.coverageUntil), 'ORG_AUTHORITY_DECISION', 'INDETERMINATE');
  return result;
}
function detach(input) {
  need(input && typeof input === 'object', 'ORG_INPUT');
  const descriptors = Object.getOwnPropertyDescriptors(input);
  need(
    Reflect.ownKeys(descriptors).every(
      (k) => typeof k === 'string' && own(descriptors[k], 'value'),
    ),
    'ORG_INPUT',
  );
  const context = descriptors.context?.value;
  need(context && typeof context === 'object', 'ORG_CONTEXT_REQUIRED', 'INDETERMINATE');
  const contextDescriptors = Object.getOwnPropertyDescriptors(context);
  need(
    Reflect.ownKeys(contextDescriptors).every(
      (k) => typeof k === 'string' && own(contextDescriptors[k], 'value'),
    ),
    'ORG_CONTEXT_DATA',
  );
  const resolver = contextDescriptors.authorityResolver?.value;
  const plain = Object.fromEntries(
    Object.entries(contextDescriptors)
      .filter(([k]) => k !== 'authorityResolver')
      .map(([k, d]) => [k, d.value]),
  );
  const data = Object.fromEntries(
    Object.entries(descriptors).map(([k, d]) => [k, k === 'context' ? plain : d.value]),
  );
  return { data: snapshot(data), resolver };
}

class Evaluation {
  constructor() {
    this.checks = [];
    this.statusObservations = [];
    this.targetObservations = [];
    this.executionObservations = [];
    this.counterFacts = [];
    this.controls = new Map();
    this.certificates = new Map();
    this.admissions = new Map();
    this.targets = [];
    this.usedKeys = new Set();
    this.validUntil = Number.MAX_SAFE_INTEGER;
  }
  attempt(check, action) {
    try {
      const value = action();
      this.checks.push({ check, overall: 'VALID' });
      return value;
    } catch (error) {
      this.checks.push({
        check,
        overall: ['INVALID', 'UNSUPPORTED', 'INDETERMINATE'].includes(error.overall)
          ? error.overall
          : error instanceof ProtocolError
            ? 'INVALID'
            : 'INDETERMINATE',
        reason: error.code ?? 'ORG_DEPENDENCY_UNAVAILABLE',
      });
      return undefined;
    }
  }
  complete(facts) {
    const bad = ['INVALID', 'UNSUPPORTED', 'INDETERMINATE']
      .map((o) => this.checks.find((c) => c.overall === o))
      .find(Boolean);
    const overall = bad?.overall ?? (facts ? 'VALID' : 'INDETERMINATE');
    return snapshot({
      overall,
      reason: bad?.reason ?? (facts ? 'ORG_EVIDENCE_VALID' : 'ORG_EVIDENCE_INCOMPLETE'),
      checks: this.checks,
      knowledgeTime: integer(this.K) ? this.K : null,
      statusObservations: this.statusObservations,
      targetObservations: this.targetObservations,
      executionObservations: this.executionObservations,
      counterFacts: overall === 'VALID' ? this.counterFacts : [],
      ...(overall === 'VALID' ? { facts } : {}),
    });
  }
  cert(raw) {
    sized(raw, 65536, 'ORG_CERTIFICATE');
    const k = hex(sha512(raw));
    if (!this.certificates.has(k)) this.certificates.set(k, parseCertificate(raw));
    return this.certificates.get(k);
  }
  control(member, label, max = 128 * 1024) {
    need(member !== null && member !== undefined, 'ORG_CONTROL_MISSING', 'INDETERMINATE');
    fields(
      member,
      label === LABELS.GRANT
        ? ['cms', 'issuerCertificate', 'delegateCertificate']
        : ['cms', 'issuerCertificate'],
    );
    sized(member.cms, max, 'ORG_CONTROL');
    this.cert(member.issuerCertificate);
    const k = label + ':' + hex(sha512(member.cms)) + ':' + hex(sha512(member.issuerCertificate));
    if (!this.controls.has(k)) {
      try {
        const body = readControl(member.cms, label, member.issuerCertificate);
        this.controls.set(k, { body });
      } catch (error) {
        this.controls.set(k, { error });
      }
    }
    const cached = this.controls.get(k);
    if (cached.error) throw cached.error;
    return cached.body;
  }
  deadline(record, name, reason) {
    need(own(record, name), reason + '_MISSING', 'INDETERMINATE');
    need(this.K < record[name], reason + '_EXPIRED');
    this.validUntil = Math.min(this.validUntil, record[name]);
  }
  key(publicKey) {
    const k = keyID(publicKey),
      key = hex(k);
    this.usedKeys.add(key);
    this.deadline(this.context.keyDeadlines, key, 'ORG_KEY');
    const algorithm = ALG[publicKey.asymmetricKeyType];
    need(algorithm, 'ORG_KEY_ALGORITHM', 'UNSUPPORTED');
    this.deadline(this.context.algorithmDeadlines, algorithm.oid, 'ORG_ALGORITHM');
    this.deadline(
      this.context.hashDeadlines,
      publicKey.asymmetricKeyType === 'ec' ? SHA256 : SHA512,
      'ORG_HASH',
    );
    for (const incident of this.state.keyIncidents)
      if (
        equal(incident.trustDomainID, this.context.trustDomainID) &&
        equal(incident.keyID, k) &&
        incident.compromiseStart <= this.K
      )
        fail('ORG_KEY_COMPROMISED');
    return k;
  }
  protection(raw) {
    const cert = this.cert(raw);
    this.key(cert.publicKey);
    this.deadline(this.context.algorithmDeadlines, cert.algorithm, 'ORG_CERTIFICATE_ALGORITHM');
    need(cert.notBefore <= this.K && this.K < cert.notAfter, 'ORG_CERTIFICATE_TIME');
    this.validUntil = Math.min(this.validUntil, cert.notAfter);
    return cert;
  }
  authority(raw, usage, at = this.K, objectType) {
    const [role, purpose] = PURPOSES[usage];
    const entry = this.context.controlTrust.find(
      (e) =>
        e.purpose === purpose &&
        equal(e.certificate, raw) &&
        (usage !== 'STATUS' || e.objectTypes.includes(objectType)),
    );
    need(entry, 'ORG_AUTHORITY_MAPPING', 'INDETERMINATE');
    this.protection(raw);
    return this.authorityQuery(
      raw,
      role,
      {
        trustDomainID: this.context.trustDomainID,
        profileID: PROFILE,
        issuerID: entry.issuerID,
        representation: 'X509',
        purpose,
      },
      at,
    );
  }
  authorityQuery(certificate, role, scope, stateTime = this.K) {
    const query = { certificate, role, scope, stateTime, knowledgeTime: this.K };
    const k = hex(H('OrganizationAuthorityQuery', query));
    if (this.admissions.has(k)) {
      const result = this.admissions.get(k);
      if (result.error) throw result.error;
      return result.value;
    }
    try {
      need(typeof this.resolver === 'function', 'AUTHORITY_RESOLVER_REQUIRED', 'INDETERMINATE');
      let value;
      try {
        value = this.resolver(snapshot(query));
      } catch (error) {
        if (['INVALID', 'UNSUPPORTED', 'INDETERMINATE'].includes(error?.overall)) throw error;
        fail('ORG_AUTHORITY_UNAVAILABLE', 'INDETERMINATE');
      }
      const result = resolverResult(value);
      if (result.coverageUntil !== undefined)
        this.validUntil = Math.min(this.validUntil, result.coverageUntil);
      this.admissions.set(k, { value: result });
      return result;
    } catch (error) {
      this.admissions.set(k, { error });
      throw error;
    }
  }
  scope(body) {
    need(body.schemaVersion === 1 && body.profile === PROFILE, 'ORG_PROFILE');
    id(body.trustDomainID);
    id(body.organizationID);
    need(
      equal(body.trustDomainID, this.context.trustDomainID) &&
        equal(body.organizationID, this.context.organizationID),
      'ORG_SCOPE',
    );
    if (own(body, 'identityNamespace'))
      need(body.identityNamespace === this.context.identityNamespace, 'ORG_IDENTITY_NAMESPACE');
  }
  lifetime(body) {
    times(body, ['issuedAt', 'knownAt', 'validFrom', 'validUntil']);
    need(
      body.issuedAt <= body.knownAt &&
        body.knownAt <= this.K &&
        body.issuedAt <= body.validFrom &&
        body.validFrom <= this.K &&
        this.K < body.validUntil,
      'ORG_OBJECT_TIME',
    );
    need(body.validUntil - body.validFrom <= DAY30, 'ORG_OBJECT_LIFETIME', 'UNSUPPORTED');
    this.validUntil = Math.min(this.validUntil, body.validUntil);
  }
  target(type, member, body, subjectKeyID) {
    const objectID = body.grantID ?? body.registrationID ?? body.authorizationID;
    const result = {
      trustDomainID: this.context.trustDomainID,
      organizationID: this.context.organizationID,
      identityNamespace: this.context.identityNamespace,
      objectType: type,
      objectID,
      objectHash: sha512(member.cms),
      semanticHash: H(LABELS[type], body),
      subjectKeyID,
    };
    const conflict = [...this.state.targets, ...this.targetObservations].some(
      (previous) =>
        sameTarget(previous, result) && !equal(previous.semanticHash, result.semanticHash),
    );
    if (!this.targetObservations.some((v) => same(v, result))) this.targetObservations.push(result);
    if (!this.targets.some((v) => same(v, result))) this.targets.push(result);
    need(!conflict, 'ORG_TARGET_CONFLICT');
    return result;
  }
}

function sameTarget(a, b) {
  return (
    equal(a.trustDomainID, b.trustDomainID) &&
    equal(a.organizationID, b.organizationID) &&
    a.objectType === b.objectType &&
    equal(a.objectID, b.objectID)
  );
}
function stateShape(state) {
  fields(state, [
    'knowledgeTime',
    'targets',
    'heads',
    'terminalObservations',
    'keyIncidents',
    'executions',
  ]);
  need(state.knowledgeTime === null || integer(state.knowledgeTime), 'ORG_STATE_TIME');
  for (const name of ['targets', 'heads', 'terminalObservations', 'keyIncidents', 'executions'])
    list(state[name], 4096);
  for (const target of state.targets) {
    fields(target, [
      'trustDomainID',
      'organizationID',
      'identityNamespace',
      'objectType',
      'objectID',
      'objectHash',
      'semanticHash',
      'subjectKeyID',
    ]);
    id(target.trustDomainID);
    id(target.organizationID);
    id(target.objectID);
    for (const k of ['objectHash', 'semanticHash', 'subjectKeyID']) hash(target[k]);
    text(target.identityNamespace, 128);
    need(TYPES.includes(target.objectType), 'ORG_STATE_TARGET');
  }
  for (const row of [...state.heads, ...state.terminalObservations]) statusObservationShape(row);
  for (const row of state.keyIncidents) {
    fields(row, [
      'trustDomainID',
      'keyID',
      'compromiseStart',
      'observedAt',
      'sourceStatusHash',
      'sourceObjectHash',
    ]);
    id(row.trustDomainID);
    ['keyID', 'sourceStatusHash', 'sourceObjectHash'].forEach((k) => hash(row[k]));
    times(row, ['compromiseStart', 'observedAt']);
  }
  state.executions.forEach(executionObservationShape);
}
function contextShape(e) {
  const c = e.context;
  fields(c, [
    'knowledgeTime',
    'trustDomainID',
    'organizationID',
    'issuerID',
    'identityNamespace',
    'operator',
    'policy',
    'controlTrust',
    'credentialTrust',
    'statusMaterial',
    'algorithmDeadlines',
    'hashDeadlines',
    'keyDeadlines',
    'executionCurrent',
  ]);
  need(integer(c.knowledgeTime), 'ORG_KNOWLEDGE_TIME');
  e.K = c.knowledgeTime;
  id(c.trustDomainID);
  id(c.organizationID);
  text(c.issuerID);
  text(c.identityNamespace, 128);
  need(/^[\x21-\x7e]+$/.test(c.identityNamespace), 'ORG_IDENTITY_NAMESPACE');
  fields(c.operator, ['type', 'id', 'active', 'knownAt', 'validFrom', 'validUntil']);
  id(c.operator.id);
  times(c.operator, ['knownAt', 'validFrom', 'validUntil']);
  need(
    typeof c.operator.active === 'boolean' && c.operator.validFrom < c.operator.validUntil,
    'ORG_OPERATOR_SCHEMA',
  );
  need(c.operator.type === 'WORKLOAD', 'ORG_OPERATOR_TYPE', 'UNSUPPORTED');
  const p = c.policy;
  need(p && typeof p === 'object', 'ORG_POLICY');
  need(!own(p, 'documentEvidence'), 'ORG_PLAN_DOWNGRADE');
  fields(p.organizationDelegation, ['profile', 'mode', 'identityNamespace', 'minimumApprovers']);
  const s = p.organizationDelegation;
  need(
    s.profile === PROFILE && s.mode === 'CURRENT_STATE_ONLY',
    'ORG_POLICY_PROFILE',
    'UNSUPPORTED',
  );
  need(
    s.identityNamespace === c.identityNamespace &&
      integer(s.minimumApprovers) &&
      s.minimumApprovers >= 2 &&
      s.minimumApprovers <= 16,
    'ORG_POLICY_APPROVALS',
  );
  need(
    p.activationMode === 'WORKLOAD' &&
      p.requireTrustedTime === false &&
      integer(p.maxActivationLifetime) &&
      p.maxActivationLifetime > 0 &&
      p.maxActivationLifetime <= 120,
    'ORG_POLICY',
  );
  list(p.allowedProfiles, 32, 1);
  need(p.allowedProfiles.includes(SEAL_PROFILE), 'ORG_POLICY_SEAL');
  set(p.allowedOrigins, (v) => text(v));
  text(p.audience);
  text(p.rpID);
  need(executionRequirement(p), 'ORG_EXECUTION_REQUIRED');
  const seen = new Set();
  for (const entry of list(c.controlTrust, 64)) {
    fields(entry, [
      'certificate',
      'organizationID',
      'identityNamespace',
      'issuerID',
      'purpose',
      'objectTypes',
    ]);
    sized(entry.certificate, 65536, 'ORG_CERTIFICATE');
    id(entry.organizationID);
    need(
      equal(entry.organizationID, c.organizationID) &&
        entry.identityNamespace === c.identityNamespace &&
        entry.issuerID === c.issuerID,
      'ORG_CONTROL_TRUST_SCOPE',
    );
    need(
      Object.values(PURPOSES).some(([, purpose]) => purpose === entry.purpose),
      'ORG_CONTROL_PURPOSE',
      'UNSUPPORTED',
    );
    list(entry.objectTypes, 3);
    need(
      new Set(entry.objectTypes).size === entry.objectTypes.length &&
        entry.objectTypes.every((v) => TYPES.includes(v)) &&
        (entry.purpose === PURPOSES.STATUS[1]
          ? entry.objectTypes.length > 0
          : entry.objectTypes.length === 0),
      'ORG_CONTROL_OBJECT_TYPES',
    );
    const k =
      hex(sha512(entry.certificate)) +
      ':' +
      entry.purpose +
      ':' +
      [...entry.objectTypes].sort().join(',');
    need(!seen.has(k), 'ORG_CONTROL_TRUST_DUPLICATE');
    seen.add(k);
  }
  const t = c.credentialTrust;
  fields(t, [
    'certificate',
    'registrationAuthorization',
    'issuerCertificate',
    'raCertificate',
    'statusCertificate',
    'issuanceScope',
    'currentCertificateStatus',
  ]);
  for (const k of ['certificate', 'issuerCertificate', 'raCertificate', 'statusCertificate'])
    sized(t[k], 65536, 'ORG_CERTIFICATE');
  sized(t.registrationAuthorization, 128 * 1024, 'ORG_REGISTRATION_AUTHORIZATION');
  if (t.currentCertificateStatus !== null)
    sized(t.currentCertificateStatus, 128 * 1024, 'ORG_CERTIFICATE_STATUS');
  fields(t.issuanceScope, ['trustDomainID', 'issuerID', 'issuerKeyID', 'representation']);
  id(t.issuanceScope.trustDomainID);
  hash(t.issuanceScope.issuerKeyID);
  text(t.issuanceScope.issuerID);
  need(
    equal(t.issuanceScope.trustDomainID, c.trustDomainID) &&
      t.issuanceScope.representation === 'X509',
    'ORG_CREDENTIAL_SCOPE',
  );
  list(c.statusMaterial, 64);
  for (const name of ['algorithmDeadlines', 'hashDeadlines', 'keyDeadlines']) {
    const record = c[name];
    need(record && !Array.isArray(record) && typeof record === 'object', 'ORG_DEADLINES');
    need(Object.keys(record).length <= 4096, 'ORG_DEADLINES_LIMIT', 'UNSUPPORTED');
    for (const [k, value] of Object.entries(record))
      need(
        integer(value) &&
          (name === 'keyDeadlines'
            ? /^[a-f0-9]{128}$/.test(k)
            : /^(0|1|2)(\.(0|[1-9][0-9]*)){1,}$/.test(k)),
        'ORG_DEADLINES',
      );
  }
  stateShape(e.state);
  need(e.state.knowledgeTime === null || e.state.knowledgeTime <= e.K, 'ORG_KNOWLEDGE_ROLLBACK');
  for (const name of ['heads', 'terminalObservations', 'keyIncidents', 'executions'])
    need(
      e.state[name].every((row) => row.observedAt <= e.K),
      'ORG_KNOWLEDGE_ROLLBACK',
    );
  return c;
}

function collection(raw, kind, max, count) {
  need(raw !== null && raw !== undefined, 'ORG_COLLECTION_MISSING', 'INDETERMINATE');
  sized(raw, max, 'ORG_COLLECTION');
  const value = decodeCBOR(raw, { maxBytes: max });
  fields(value, ['schemaVersion', 'profile', kind], kind === 'approvals' ? ['request'] : []);
  need(value.schemaVersion === 1 && value.profile === PROFILE, 'ORG_COLLECTION_PROFILE');
  list(value[kind], count);
  if (kind === 'approvals') need(own(value, 'request'), 'ORG_REQUEST_MISSING', 'INDETERMINATE');
  return value;
}
function entitlement(v) {
  fields(v, [
    'purpose',
    'container',
    'adapterID',
    'operatorType',
    'allowedOperatorIDs',
    'sealKeys',
    'policyHashes',
    'audiences',
    'origins',
    'rpIDs',
    'eligiblePersonIDs',
    'minimumApprovers',
  ]);
  need(
    v.purpose === 'ORGANIZATION_SEAL' &&
      v.container === 'CMS' &&
      v.adapterID === 'certconcord-cms-v1' &&
      v.operatorType === 'WORKLOAD',
    'ORG_ENTITLEMENT_PROFILE',
    'UNSUPPORTED',
  );
  set(v.allowedOperatorIDs, id);
  set(v.sealKeys, tuple);
  set(v.policyHashes, hash);
  ['audiences', 'origins', 'rpIDs'].forEach((k) => set(v[k], (s) => text(s)));
  set(v.eligiblePersonIDs, id);
  need(
    integer(v.minimumApprovers) &&
      v.minimumApprovers >= 2 &&
      v.minimumApprovers <= 16 &&
      v.minimumApprovers <= v.eligiblePersonIDs.length,
    'ORG_ENTITLEMENT_THRESHOLD',
  );
}
function included(values, value) {
  return values.some((v) => same(v, value));
}
function path(e, parsed) {
  need(parsed.grants.length > 0, 'ORG_PATH_MISSING', 'INDETERMINATE');
  const records = [],
    usedKeys = new Set(),
    ids = new Set(),
    envelopes = new Set();
  for (const [i, member] of parsed.grants.entries()) {
    const record = e.attempt('grant:' + i, () => {
      const body = e.control(member, LABELS.GRANT);
      fields(body, [
        'schemaVersion',
        'profile',
        'trustDomainID',
        'organizationID',
        'identityNamespace',
        'grantID',
        'parentGrantHash',
        'issuerKeyID',
        'delegateAuthority',
        'entitlement',
        'remainingDelegations',
        'issuedAt',
        'knownAt',
        'validFrom',
        'validUntil',
      ]);
      e.scope(body);
      id(body.grantID);
      hash(body.issuerKeyID);
      tuple(body.delegateAuthority);
      entitlement(body.entitlement);
      need(
        integer(body.remainingDelegations) && body.remainingDelegations <= 7,
        'ORG_DELEGATION_DEPTH',
      );
      const issuer = e.cert(member.issuerCertificate),
        delegate = e.cert(member.delegateCertificate);
      need(
        equal(body.issuerKeyID, keyID(issuer.publicKey)) &&
          same(body.delegateAuthority, certificateTuple(delegate)),
        'ORG_GRANT_KEY_BINDING',
      );
      e.authority(member.issuerCertificate, i === 0 ? 'ROOT' : 'ISSUE');
      e.target('GRANT', member, body, body.delegateAuthority.keyID);
      e.authority(member.delegateCertificate, i === parsed.grants.length - 1 ? 'FINAL' : 'ISSUE');
      e.lifetime(body);
      const key = hex(body.delegateAuthority.keyID),
        envelope = hex(sha512(member.cms)),
        grantID = hex(body.grantID);
      if (i === 0) {
        need(body.parentGrantHash === null, 'ORG_ROOT_PARENT');
        usedKeys.add(hex(body.issuerKeyID));
      } else {
        hash(body.parentGrantHash);
        const previous = records[i - 1];
        need(previous, 'ORG_PATH_PARENT_UNAVAILABLE', 'INDETERMINATE');
        need(
          equal(body.parentGrantHash, sha512(previous.member.cms)) &&
            equal(member.issuerCertificate, previous.member.delegateCertificate),
          'ORG_PATH_PARENT',
        );
        const parent = previous.body;
        need(
          body.validFrom >= parent.validFrom &&
            body.validUntil <= parent.validUntil &&
            parent.remainingDelegations > 0 &&
            body.remainingDelegations <= parent.remainingDelegations - 1 &&
            body.entitlement.minimumApprovers >= parent.entitlement.minimumApprovers,
          'ORG_ATTENUATION',
        );
        for (const name of [
          'allowedOperatorIDs',
          'sealKeys',
          'policyHashes',
          'audiences',
          'origins',
          'rpIDs',
          'eligiblePersonIDs',
        ])
          need(
            body.entitlement[name].every((v) => included(parent.entitlement[name], v)),
            'ORG_ATTENUATION',
          );
      }
      need(
        !ids.has(grantID) && !envelopes.has(envelope) && !usedKeys.has(key),
        'ORG_PATH_CYCLE_OR_DUPLICATE',
      );
      ids.add(grantID);
      envelopes.add(envelope);
      usedKeys.add(key);
      return { body, member };
    });
    records.push(record);
  }
  if (records.some((r) => !r)) return undefined;
  const terminal = records.at(-1),
    ent = terminal.body.entitlement;
  const minimum = Math.max(
    e.context.policy.organizationDelegation.minimumApprovers,
    ...records.map((r) => r.body.entitlement.minimumApprovers),
  );
  need(minimum <= 16 && minimum <= ent.eligiblePersonIDs.length, 'ORG_QUORUM_UNSATISFIABLE');
  return { records, terminal, ent, minimum };
}

function registration(e, member, index) {
  const body = e.control(member, LABELS.APPROVER_REGISTRATION, 65536);
  fields(body, [
    'schemaVersion',
    'profile',
    'trustDomainID',
    'organizationID',
    'identityNamespace',
    'registrationID',
    'personID',
    'credentialID',
    'publicKeyDER',
    'keyID',
    'purpose',
    'rpID',
    'origins',
    'backupEligible',
    'counter',
    'issuedAt',
    'knownAt',
    'validFrom',
    'validUntil',
  ]);
  e.scope(body);
  id(body.registrationID);
  id(body.personID);
  hash(body.keyID);
  sized(body.credentialID, 1024, 'ORG_CREDENTIAL_ID');
  sized(body.publicKeyDER, 2048, 'ORG_PUBLIC_KEY');
  text(body.rpID);
  set(body.origins, (v) => text(v), 8);
  need(body.purpose === 'ORGANIZATION_OPERATION_APPROVAL', 'ORG_REGISTRATION_PURPOSE');
  need(
    typeof body.backupEligible === 'boolean' && integer(body.counter) && body.counter <= 0xffffffff,
    'ORG_REGISTRATION_SCHEMA',
  );
  const publicKey = publicFromDER(body.publicKeyDER);
  need(equal(spki(publicKey), body.publicKeyDER), 'ORG_KEY_ENCODING');
  need(
    publicKey.asymmetricKeyType === 'ec' &&
      publicKey.asymmetricKeyDetails?.namedCurve === 'prime256v1',
    'ORG_APPROVER_ALGORITHM',
    'UNSUPPORTED',
  );
  need(equal(keyID(publicKey), body.keyID), 'ORG_REGISTRATION_KEY');
  e.authority(member.issuerCertificate, 'REGISTRATION');
  e.target('APPROVER_REGISTRATION', member, body, body.keyID);
  e.lifetime(body);
  e.key(publicKey);
  return {
    body,
    member,
    publicKey,
    index,
    fact: {
      personID: body.personID,
      registrationHash: sha512(member.cms),
      credentialID: body.credentialID,
      credentialIDHash: sha512(body.credentialID),
      credentialKeyID: body.keyID,
      publicKeyDER: body.publicKeyDER,
      counter: body.counter,
      backupEligible: body.backupEligible,
      rpID: body.rpID,
      origins: body.origins,
      validUntil: body.validUntil,
    },
  };
}
function registrations(e, members, pathInfo) {
  list(members, 16);
  const records = members.map((m, i) =>
    e.attempt('registration:' + i, () => registration(e, m, i)),
  );
  const persons = new Set(),
    keys = new Set(),
    credentials = new Set();
  for (let i = 0; i < records.length; i++)
    if (records[i])
      e.attempt('roster:' + i, () => {
        const { body } = records[i];
        for (const [set, value] of [
          [persons, body.personID],
          [keys, body.keyID],
          [credentials, body.credentialID],
        ]) {
          need(!set.has(hex(value)), 'ORG_ROSTER_DUPLICATE');
          set.add(hex(value));
        }
        if (i && records[i - 1])
          need(Buffer.compare(records[i - 1].body.personID, body.personID) < 0, 'ORG_ROSTER_ORDER');
        need(
          body.rpID === e.context.policy.rpID && body.origins.includes(e.input.sim.origin),
          'ORG_REGISTRATION_ORIGIN',
        );
        if (pathInfo)
          need(included(pathInfo.ent.eligiblePersonIDs, body.personID), 'ORG_PERSON_NOT_ELIGIBLE');
      });
  if (pathInfo)
    e.attempt('roster-quorum', () =>
      need(
        members.length === pathInfo.minimum,
        members.length < pathInfo.minimum ? 'ORG_APPROVALS_MISSING' : 'ORG_APPROVALS_EXTRA',
        members.length < pathInfo.minimum ? 'INDETERMINATE' : 'INVALID',
      ),
    );
  return records.every(Boolean) ? records : undefined;
}

function statusObservationShape(row) {
  fields(row, [
    'trustDomainID',
    'organizationID',
    'objectType',
    'objectID',
    'objectHash',
    'subjectKeyID',
    'epoch',
    'semanticHash',
    'rawHash',
    'status',
    'publishedAt',
    'nextUpdate',
    'effectiveTime',
    'compromiseStart',
    'issuerKeyID',
    'observedAt',
  ]);
  ['trustDomainID', 'organizationID', 'objectID'].forEach((k) => id(row[k]));
  ['objectHash', 'subjectKeyID', 'semanticHash', 'rawHash', 'issuerKeyID'].forEach((k) =>
    hash(row[k]),
  );
  times(row, ['epoch', 'publishedAt', 'nextUpdate', 'observedAt']);
  need(
    row.epoch > 0 &&
      row.nextUpdate > row.publishedAt &&
      TYPES.includes(row.objectType) &&
      ['GOOD', 'REVOKED', 'UNKNOWN'].includes(row.status),
    'ORG_STATE_STATUS',
  );
  for (const k of ['effectiveTime', 'compromiseStart'])
    need(row[k] === null || integer(row[k]), 'ORG_STATE_STATUS');
  need(row.status !== 'REVOKED' || row.effectiveTime !== null, 'ORG_STATE_STATUS');
}
function executionObservationShape(row) {
  fields(row, [
    'trustDomainID',
    'providerID',
    'keyID',
    'epoch',
    'status',
    'semanticHash',
    'rawHash',
    'issuedAt',
    'expiresAt',
    'observedAt',
  ]);
  id(row.trustDomainID);
  ['keyID', 'semanticHash', 'rawHash'].forEach((k) => hash(row[k]));
  text(row.providerID, 128);
  times(row, ['epoch', 'issuedAt', 'expiresAt', 'observedAt']);
  need(
    row.epoch > 0 &&
      row.expiresAt > row.issuedAt &&
      ['ACTIVE', 'SUSPENDED', 'REVOKED'].includes(row.status),
    'ORG_STATE_EXECUTION',
  );
}
function statusBody(e, member) {
  const body = e.control(member, 'OrganizationDelegationStatus');
  fields(
    body,
    [
      'schemaVersion',
      'profile',
      'trustDomainID',
      'organizationID',
      'scope',
      'objectType',
      'objectID',
      'objectHash',
      'subjectKeyID',
      'epoch',
      'status',
      'publishedAt',
      'nextUpdate',
    ],
    ['effectiveTime', 'compromiseStart', 'critical'],
  );
  e.scope(body);
  id(body.objectID);
  hash(body.objectHash);
  hash(body.subjectKeyID);
  times(body, ['epoch', 'publishedAt', 'nextUpdate']);
  need(
    body.scope === 'ORGANIZATION_DELEGATION' &&
      TYPES.includes(body.objectType) &&
      body.epoch > 0 &&
      ['GOOD', 'REVOKED', 'UNKNOWN'].includes(body.status) &&
      body.nextUpdate > body.publishedAt,
    'ORG_STATUS_SCHEMA',
  );
  need(body.nextUpdate - body.publishedAt <= 300, 'ORG_STATUS_LIFETIME', 'UNSUPPORTED');
  for (const k of ['effectiveTime', 'compromiseStart'])
    if (own(body, k)) need(integer(body[k]), 'ORG_STATUS_TIME');
  need(body.status !== 'REVOKED' || own(body, 'effectiveTime'), 'ORG_STATUS_REVOCATION_TIME');
  if (own(body, 'critical')) {
    list(body.critical, 32);
    body.critical.forEach((v) => text(v));
  }
  return body;
}
function statusOrder(a, b) {
  return (
    (a.objectType < b.objectType ? -1 : a.objectType > b.objectType ? 1 : 0) ||
    Buffer.compare(a.objectID, b.objectID) ||
    a.epoch - b.epoch ||
    Buffer.compare(H('OrganizationDelegationStatus', a), H('OrganizationDelegationStatus', b))
  );
}
function statuses(e, retained) {
  if (retained) {
    let prior;
    for (const [i, member] of retained.statements.entries())
      e.attempt('status-order:' + i, () => {
        const body = statusBody(e, member);
        need(!prior || statusOrder(prior, body) < 0, 'ORG_STATUS_ORDER_OR_DUPLICATE');
        prior = body;
      });
  }
  const incoming = [...e.context.statusMaterial, ...(retained?.statements ?? [])],
    authenticated = [];
  const seen = new Set();
  for (const [i, member] of incoming.entries())
    e.attempt('status:' + i, () => {
      const body = statusBody(e, member),
        rawHash = sha512(member.cms),
        k = hex(rawHash);
      if (seen.has(k)) return;
      seen.add(k);
      // A future statement cannot establish a current epoch, conflict or key incident.
      if (body.publishedAt > e.K) return;
      const target = [...e.targets, ...e.state.targets].find(
        (t) =>
          sameTarget(t, body) &&
          equal(t.objectHash, body.objectHash) &&
          equal(t.subjectKeyID, body.subjectKeyID),
      );
      need(target, 'ORG_STATUS_TARGET_UNAVAILABLE', 'INDETERMINATE');
      e.authority(member.issuerCertificate, 'STATUS', body.publishedAt, body.objectType);
      e.authority(member.issuerCertificate, 'STATUS', e.K, body.objectType);
      const observation = {
        trustDomainID: body.trustDomainID,
        organizationID: body.organizationID,
        objectType: body.objectType,
        objectID: body.objectID,
        objectHash: body.objectHash,
        subjectKeyID: body.subjectKeyID,
        epoch: body.epoch,
        semanticHash: H('OrganizationDelegationStatus', body),
        rawHash,
        status: body.status,
        publishedAt: body.publishedAt,
        nextUpdate: body.nextUpdate,
        effectiveTime: body.effectiveTime ?? null,
        compromiseStart: body.compromiseStart ?? null,
        issuerKeyID: keyID(e.cert(member.issuerCertificate).publicKey),
        observedAt: e.K,
      };
      e.statusObservations.push(observation);
      authenticated.push({ observation, body });
    });
  const known = [...e.state.heads, ...e.state.terminalObservations, ...e.statusObservations];
  for (const target of e.targets)
    e.attempt('status-closure:' + target.objectType + ':' + hex(target.objectID), () => {
      const rows = known.filter(
        (s) => sameTarget(s, target) && s.publishedAt <= e.K && s.observedAt <= e.K,
      );
      // Compare every authenticated same-epoch semantic statement, even if a later head exists.
      for (let i = 0; i < rows.length; i++)
        for (let j = 0; j < i; j++)
          need(
            rows[i].epoch !== rows[j].epoch || equal(rows[i].semanticHash, rows[j].semanticHash),
            'ORG_STATUS_CONFLICT',
          );
      for (const row of rows)
        if (
          row.status === 'REVOKED' &&
          Math.min(row.effectiveTime ?? Infinity, row.compromiseStart ?? Infinity) <= e.K
        )
          fail('ORG_STATUS_REVOKED');
      const presented = authenticated.filter(({ observation: s }) => sameTarget(s, target));
      const prior = e.state.heads.filter((s) => sameTarget(s, target) && s.observedAt <= e.K);
      if (presented.length && prior.length)
        need(
          Math.max(...presented.map(({ observation: s }) => s.epoch)) >=
            Math.max(...prior.map((s) => s.epoch)),
          'ORG_STATUS_ROLLBACK',
        );
      need(rows.length, 'ORG_STATUS_MISSING', 'INDETERMINATE');
      const maximum = Math.max(...rows.map((r) => r.epoch));
      const current = rows.find(
        (r) =>
          r.epoch === maximum &&
          equal(r.objectHash, target.objectHash) &&
          equal(r.subjectKeyID, target.subjectKeyID),
      );
      need(current, 'ORG_STATUS_TARGET_MISMATCH');
      const original = authenticated.find(({ observation }) =>
        equal(observation.rawHash, current.rawHash),
      );
      // The projection deliberately omits extension bytes. It is anti-rollback knowledge,
      // not a substitute for the current original statement's positive semantics.
      need(original, 'ORG_STATUS_CURRENT_MATERIAL_MISSING', 'INDETERMINATE');
      const body = original.body;
      const decision = evaluateStatus(body, {
        stateTime: e.K,
        knowledgeTime: e.K,
        scope: 'ORGANIZATION_DELEGATION',
      });
      if (decision.overall !== 'VALID')
        fail(decision.reason ?? 'ORG_STATUS_UNAVAILABLE', decision.overall);
      e.validUntil = Math.min(e.validUntil, current.nextUpdate);
    });
  // Incidents are key-wide. An old registration's known compromise also constrains a new one.
  for (const row of known)
    if (
      equal(row.trustDomainID, e.context.trustDomainID) &&
      row.observedAt <= e.K &&
      row.publishedAt <= e.K &&
      row.status === 'REVOKED' &&
      row.compromiseStart !== null &&
      row.compromiseStart <= e.K &&
      e.usedKeys.has(hex(row.subjectKeyID))
    )
      e.attempt('key-incident:' + hex(row.subjectKeyID), () => fail('ORG_KEY_COMPROMISED'));
  // Off-path authenticated semantic conflicts must remain visible to the durable merge.
  const epochs = new Map();
  for (const row of known) {
    const k = [
      hex(row.trustDomainID),
      hex(row.organizationID),
      row.objectType,
      hex(row.objectID),
      row.epoch,
    ].join(':');
    if (epochs.has(k) && !equal(epochs.get(k), row.semanticHash))
      e.attempt('status-conflict', () => fail('ORG_STATUS_CONFLICT'));
    else epochs.set(k, row.semanticHash);
  }
}

const bindingFields = [
  'schemaVersion',
  'profile',
  'trustDomainID',
  'providerID',
  'epoch',
  'status',
  'keyID',
  'permitKeyID',
  'receiptKeyID',
  'policyHash',
  'audience',
  'enforcement',
  'issuedAt',
  'expiresAt',
];
function bindingBody(e, member) {
  const body = e.control(member, 'ExecutionBinding');
  fields(body, bindingFields);
  id(body.trustDomainID);
  ['keyID', 'permitKeyID', 'receiptKeyID', 'policyHash'].forEach((k) => hash(body[k]));
  times(body, ['epoch', 'issuedAt', 'expiresAt']);
  need(
    body.schemaVersion === 1 &&
      body.profile === EXECUTION_BINDING_PROFILE &&
      body.enforcement === 'BROKER_ENFORCED' &&
      ['ACTIVE', 'SUSPENDED', 'REVOKED'].includes(body.status) &&
      body.epoch > 0 &&
      body.expiresAt > body.issuedAt,
    'ORG_EXECUTION_SCHEMA',
  );
  need(
    typeof body.providerID === 'string' &&
      /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(body.providerID),
    'ORG_EXECUTION_PROVIDER',
  );
  text(body.audience);
  const requirement = executionRequirement(e.context.policy);
  need(
    equal(body.trustDomainID, e.context.trustDomainID) &&
      equal(body.keyID, e.input.sim.keyID) &&
      equal(body.policyHash, H('SignaturePolicy', e.context.policy)) &&
      body.audience === e.context.policy.audience &&
      body.providerID === requirement.providerID &&
      body.expiresAt - body.issuedAt <= requirement.maxLeaseSeconds,
    'ORG_EXECUTION_BINDING',
  );
  for (const [usage, name] of [
    ['PERMIT', 'permitKeyID'],
    ['RECEIPT', 'receiptKeyID'],
  ]) {
    const entry = e.context.controlTrust.find(
      (v) =>
        v.purpose === PURPOSES[usage][1] &&
        equal(keyID(e.cert(v.certificate).publicKey), body[name]),
    );
    need(entry, 'ORG_EXECUTION_AUTHORITY_BINDING', 'INDETERMINATE');
    e.authority(entry.certificate, usage);
  }
  e.authority(member.issuerCertificate, 'BINDING');
  return body;
}
function currentExecution(e) {
  const current = e.context.executionCurrent;
  need(current, 'ORG_EXECUTION_CURRENT_MISSING', 'INDETERMINATE');
  fields(current, ['binding', 'observedAt']);
  need(current.observedAt === e.K, 'ORG_EXECUTION_OBSERVATION_TIME', 'INDETERMINATE');
  sized(current.binding, 65536, 'ORG_EXECUTION_BINDING');
  const verified = verifyCMS(current.binding);
  const member = { cms: current.binding, issuerCertificate: verified.certificate };
  const body = bindingBody(e, member);
  // Authentic future material is not a current head and cannot advance durable epochs.
  need(body.issuedAt <= e.K, 'ORG_EXECUTION_NOT_YET_KNOWN', 'INDETERMINATE');
  const observation = {
    trustDomainID: body.trustDomainID,
    providerID: body.providerID,
    keyID: body.keyID,
    epoch: body.epoch,
    status: body.status,
    semanticHash: H('ExecutionBinding', body),
    rawHash: sha512(current.binding),
    issuedAt: body.issuedAt,
    expiresAt: body.expiresAt,
    observedAt: e.K,
  };
  e.executionObservations.push(observation);
  const prior = e.state.executions.filter(
    (v) =>
      equal(v.trustDomainID, body.trustDomainID) &&
      v.providerID === body.providerID &&
      equal(v.keyID, body.keyID) &&
      v.observedAt <= e.K &&
      v.issuedAt <= e.K,
  );
  need(
    prior.every((v) => v.epoch <= body.epoch),
    'ORG_EXECUTION_ROLLBACK',
  );
  const epochs = new Map();
  for (const row of prior) {
    need(
      !epochs.has(row.epoch) || equal(epochs.get(row.epoch), row.semanticHash),
      'ORG_EXECUTION_CONFLICT',
    );
    epochs.set(row.epoch, row.semanticHash);
  }
  need(
    prior.every((v) => v.epoch !== body.epoch || equal(v.semanticHash, observation.semanticHash)),
    'ORG_EXECUTION_CONFLICT',
  );
  need(
    body.status !== 'REVOKED' && !prior.some((v) => v.status === 'REVOKED'),
    'ORG_EXECUTION_REVOKED',
  );
  need(body.status === 'ACTIVE', 'ORG_EXECUTION_SUSPENDED');
  need(body.expiresAt > e.K, 'ORG_EXECUTION_EXPIRED');
  e.validUntil = Math.min(e.validUntil, body.expiresAt);
  return { body, member };
}

function operation(e) {
  const { sim, activation, tbs } = e.input,
    { context: c } = e;
  need(sim && activation, 'ORG_OPERATION_MISSING', 'INDETERMINATE');
  sized(tbs, 16 * MiB, 'ORG_TBS');
  fields(activation, [
    'schemaVersion',
    'trustDomainID',
    'transactionID',
    'operationID',
    'tbsKind',
    'tbsHash',
    'simHash',
    'keyID',
    'certificateID',
    'certificateRepresentationHash',
    'policyHash',
    'origin',
    'rpID',
    'audience',
    'issuedAt',
    'expiresAt',
    'serverNonce',
  ]);
  need(activation.tbsKind === 'CMS_SIGNED_ATTRS_DER', 'ORG_TBS_KIND', 'UNSUPPORTED');
  need(
    sim.schemaVersion === 1 &&
      sim.profileID === SEAL_PROFILE &&
      sim.container === 'CMS' &&
      sim.adapterID === 'certconcord-cms-v1' &&
      sim.purpose === 'ORGANIZATION_SEAL',
    'ORG_SIM_PROFILE',
  );
  id(sim.organizationAuthorizationID);
  id(sim.organizationID);
  id(sim.subjectID);
  need(
    equal(sim.organizationID, c.organizationID) && equal(sim.subjectID, c.organizationID),
    'ORG_SIM_ORGANIZATION',
  );
  const seal = e.protection(c.credentialTrust.certificate);
  const actualTuple = certificateTuple(seal);
  for (const k of Object.keys(actualTuple)) need(equal(sim[k], actualTuple[k]), 'ORG_SEAL_TUPLE');
  validateActivation(activation, {
    tbs,
    publicKey: seal.publicKey,
    audience: c.policy.audience,
    at: e.K,
    maxLifetime: c.policy.maxActivationLifetime,
  });
  for (const name of [
    'trustDomainID',
    'transactionID',
    'keyID',
    'certificateID',
    'certificateRepresentationHash',
    'policyHash',
  ])
    need(equal(sim[name], activation[name]), 'ORG_ACTIVATION_SIM');
  need(
    equal(H('SIM', sim), activation.simHash) &&
      equal(sim.trustDomainID, c.trustDomainID) &&
      equal(sim.policyHash, H('SignaturePolicy', c.policy)) &&
      sim.origin === activation.origin &&
      activation.rpID === c.policy.rpID &&
      c.policy.allowedOrigins.includes(sim.origin),
    'ORG_OPERATION_SCOPE',
  );
  times(sim, ['issuedAt', 'expiresAt']);
  need(
    sim.issuedAt <= activation.issuedAt &&
      activation.expiresAt <= sim.expiresAt &&
      sim.issuedAt <= e.K &&
      e.K < sim.expiresAt,
    'ORG_SIM_TIME',
  );
  need(
    c.operator.active &&
      c.operator.knownAt <= e.K &&
      c.operator.validFrom <= e.K &&
      e.K < c.operator.validUntil,
    'ORG_WORKLOAD_INACTIVE',
  );
  e.validUntil = Math.min(e.validUntil, sim.expiresAt, activation.expiresAt, c.operator.validUntil);
  e.authorityQuery(c.credentialTrust.certificate, 'DOCUMENT_SEAL', {
    trustDomainID: c.trustDomainID,
    profileID: PROFILE,
    issuerID: c.issuerID,
    representation: 'X509',
    purpose: 'ORGANIZATION_SEAL',
  });
  // Credential issuance retains its original scope; it is not replaced by an organization-purpose wildcard.
  const credentialScope = {
    trustDomainID: c.trustDomainID,
    profileID: SEAL_PROFILE,
    issuerID: c.credentialTrust.issuanceScope.issuerID,
    representation: 'X509',
  };
  for (const [field, role] of [
    ['issuerCertificate', 'ISSUER'],
    ['raCertificate', 'REGISTRATION_AUTHORITY'],
    ['statusCertificate', 'STATUS_AUTHORITY'],
  ]) {
    e.protection(c.credentialTrust[field]);
    e.authorityQuery(c.credentialTrust[field], role, credentialScope);
  }
  need(
    equal(
      c.credentialTrust.issuanceScope.issuerKeyID,
      keyID(e.cert(c.credentialTrust.issuerCertificate).publicKey),
    ),
    'ORG_CREDENTIAL_ISSUER',
  );
  e.deadline(c.hashDeadlines, SHA512, 'ORG_HASH');
  return { seal, tuple: actualTuple };
}
function pathOperation(e, info, operationInfo) {
  const { ent } = info,
    { context: c } = e;
  need(
    included(ent.allowedOperatorIDs, c.operator.id) &&
      included(ent.sealKeys, operationInfo.tuple) &&
      included(ent.policyHashes, H('SignaturePolicy', c.policy)) &&
      ent.audiences.includes(c.policy.audience) &&
      ent.origins.includes(e.input.sim.origin) &&
      ent.rpIDs.includes(c.policy.rpID),
    'ORG_OPERATION_NOT_ENTITLED',
  );
}
function policyHash(e, info) {
  return H('OrganizationApprovalPolicy', {
    schemaVersion: 1,
    profile: PROFILE,
    identityNamespace: e.context.identityNamespace,
    minimumApprovers: info.minimum,
    eligiblePersonIDs: info.ent.eligiblePersonIDs,
    rpID: e.context.policy.rpID,
    allowedOrigins: e.context.policy.allowedOrigins,
  });
}
function requestExpected(e, info) {
  return {
    schemaVersion: 1,
    profile: PROFILE,
    trustDomainID: e.context.trustDomainID,
    organizationID: e.context.organizationID,
    identityNamespace: e.context.identityNamespace,
    operationID: e.input.activation.operationID,
    authorizationID: e.input.sim.organizationAuthorizationID,
    activationHash: H('ActivationContext', e.input.activation),
    simHash: H('SIM', e.input.sim),
    policyHash: H('SignaturePolicy', e.context.policy),
    pathLeafID: H('EvidenceLeaf', {
      type: 'OrganizationDelegationPath',
      payload: e.input.delegationPath,
    }),
    approvalPolicyHash: policyHash(e, info),
    operator: { type: 'WORKLOAD', id: e.context.operator.id },
  };
}
function checkRequest(e, request, info, regs) {
  const expected = requestExpected(e, info);
  fields(request, [...Object.keys(expected), 'roster', 'issuedAt', 'expiresAt']);
  for (const [k, v] of Object.entries(expected)) need(same(request[k], v), 'ORG_REQUEST_BINDING');
  times(request, ['issuedAt', 'expiresAt']);
  need(
    request.issuedAt === e.input.activation.issuedAt &&
      request.issuedAt <= e.K &&
      e.K < request.expiresAt &&
      request.expiresAt > request.issuedAt &&
      request.expiresAt <= e.input.activation.expiresAt &&
      request.expiresAt - request.issuedAt <= 120,
    'ORG_REQUEST_TIME',
  );
  // A later fresh context may narrow current permission without rewriting the frozen request window.
  need(
    request.expiresAt <=
      Math.min(
        ...info.records.map((r) => r.body.validUntil),
        ...regs.map((r) => r.body.validUntil),
      ),
    'ORG_REQUEST_LIFETIME',
  );
  list(request.roster, 16);
  need(
    request.roster.length === regs.length && request.roster.length === info.minimum,
    'ORG_REQUEST_ROSTER',
  );
  const nonces = new Set();
  for (const [i, row] of request.roster.entries()) {
    fields(row, [
      'personID',
      'registrationHash',
      'credentialIDHash',
      'credentialKeyID',
      'nonce',
      'origin',
    ]);
    id(row.personID);
    id(row.nonce);
    ['registrationHash', 'credentialIDHash', 'credentialKeyID'].forEach((k) => hash(row[k]));
    const fact = regs[i].fact;
    need(
      ['personID', 'registrationHash', 'credentialIDHash', 'credentialKeyID'].every((k) =>
        equal(row[k], fact[k]),
      ) && row.origin === e.input.sim.origin,
      'ORG_REQUEST_REGISTRATION',
    );
    need(!nonces.has(hex(row.nonce)), 'ORG_REQUEST_NONCE_DUPLICATE');
    nonces.add(hex(row.nonce));
  }
  e.validUntil = Math.min(e.validUntil, request.expiresAt);
  return request;
}
function makeRequest(e, info, regs) {
  const nonces = list(e.input.rosterNonces, 16);
  need(nonces.length === regs.length, 'ORG_NONCE_COUNT');
  const request = {
    ...requestExpected(e, info),
    roster: regs.map(({ fact }, i) => ({
      personID: fact.personID,
      registrationHash: fact.registrationHash,
      credentialIDHash: fact.credentialIDHash,
      credentialKeyID: fact.credentialKeyID,
      nonce: id(nonces[i]),
      origin: e.input.sim.origin,
    })),
    issuedAt: e.input.activation.issuedAt,
    expiresAt: Math.min(
      e.validUntil,
      e.input.activation.expiresAt,
      e.input.activation.issuedAt + 120,
    ),
  };
  need(request.issuedAt === e.K, 'ORG_PREPARATION_TIME');
  return checkRequest(e, request, info, regs);
}
function approval(e, request, reg, assertion, counterBefore) {
  fields(assertion, ['credentialID', 'clientDataJSON', 'authenticatorData', 'signature']);
  sized(assertion.credentialID, 1024, 'ORG_ASSERTION_CREDENTIAL');
  sized(assertion.clientDataJSON, 8192, 'ORG_CLIENT_DATA');
  sized(assertion.authenticatorData, 65536, 'ORG_AUTHENTICATOR_DATA');
  sized(assertion.signature, 128, 'ORG_ASSERTION_SIGNATURE');
  need(
    integer(counterBefore) && counterBefore <= 0xffffffff && counterBefore >= reg.body.counter,
    'ORG_COUNTER_BASELINE',
  );
  need(equal(assertion.credentialID, reg.body.credentialID), 'ORG_ASSERTION_CREDENTIAL');
  const row = request.roster[reg.index];
  const challenge = H('OrganizationApprovalChallenge', {
    schemaVersion: 1,
    profile: PROFILE,
    requestHash: H('OrganizationApprovalRequest', request),
    personID: reg.body.personID,
    credentialIDHash: reg.fact.credentialIDHash,
  });
  const verified = verifyAssertion(
    {
      type: 'public-key',
      id: b64u(assertion.credentialID),
      rawId: b64u(assertion.credentialID),
      response: {
        clientDataJSON: b64u(assertion.clientDataJSON),
        authenticatorData: b64u(assertion.authenticatorData),
        signature: b64u(assertion.signature),
      },
    },
    {
      credentialID: reg.body.credentialID,
      publicKey: reg.publicKey,
      counter: counterBefore,
      backupEligible: reg.body.backupEligible,
      rpID: reg.body.rpID,
      origin: row.origin,
    },
    { challenge, origin: row.origin, rpID: reg.body.rpID, uv: true },
  );
  return {
    personID: reg.body.personID,
    identityNamespace: e.context.identityNamespace,
    rpID: reg.body.rpID,
    credentialIDHash: reg.fact.credentialIDHash,
    credentialKeyID: reg.fact.credentialKeyID,
    assertionHash: verified.assertionHash,
    counterBefore,
    counterAfter: verified.counter,
    nonce: row.nonce,
  };
}

function approvalSet(e, parsed, info, regs) {
  const request = checkRequest(e, parsed.request, info, regs);
  const approvals = parsed.approvals,
    baseline = e.input.counterBaselines;
  need(
    approvals.length === request.roster.length,
    approvals.length < request.roster.length ? 'ORG_APPROVALS_MISSING' : 'ORG_APPROVALS_EXTRA',
    approvals.length < request.roster.length ? 'INDETERMINATE' : 'INVALID',
  );
  need(baseline && typeof baseline === 'object', 'ORG_COUNTER_BASELINES_REQUIRED', 'INDETERMINATE');
  if (baseline.kind === 'RETAINED_REGISTRATION') fields(baseline, ['kind']);
  else {
    fields(baseline, ['kind', 'entries']);
    need(baseline.kind === 'SERVICE_ACCEPTED', 'ORG_COUNTER_BASELINE_KIND', 'UNSUPPORTED');
    list(baseline.entries, 16);
    need(baseline.entries.length === request.roster.length, 'ORG_COUNTER_BASELINE_COUNT');
  }
  const facts = [];
  for (const [i, member] of approvals.entries()) {
    const fact = e.attempt('approval:' + i, () => {
      fields(member, ['personID', 'registrationCMS', 'registrationIssuerCertificate', 'assertion']);
      id(member.personID);
      need(
        equal(member.personID, request.roster[i].personID) &&
          equal(member.personID, regs[i].body.personID) &&
          equal(member.registrationCMS, regs[i].member.cms) &&
          equal(member.registrationIssuerCertificate, regs[i].member.issuerCertificate),
        'ORG_APPROVAL_ROSTER',
      );
      let before = regs[i].body.counter;
      if (baseline.kind === 'SERVICE_ACCEPTED') {
        const row = baseline.entries[i];
        fields(row, ['personID', 'assertionHash', 'counterBefore']);
        id(row.personID);
        hash(row.assertionHash);
        need(
          equal(row.personID, member.personID) &&
            equal(row.assertionHash, H('WebAuthnAssertion', member.assertion)),
          'ORG_ACCEPTED_ASSERTION_BINDING',
        );
        before = row.counterBefore;
      }
      return approval(e, request, regs[i], member.assertion, before);
    });
    if (fact) facts.push(fact);
  }
  e.counterFacts.push(...facts);
  return {
    request,
    counterScope:
      baseline.kind === 'RETAINED_REGISTRATION' ? 'SIGNED_REGISTRATION_ONLY' : 'SERVICE_ACCEPTED',
    approvalSetLeafID: H('EvidenceLeaf', {
      type: 'OrganizationApprovalSet',
      payload: e.input.approvalSet,
    }),
  };
}
function finalAuthorization(e, info, setInfo, operationInfo) {
  const { authorization: member } = e.input;
  const body = e.control(member, 'OrganizationAuthorization');
  fields(body, [
    'schemaVersion',
    'profile',
    'authorizationID',
    'trustDomainID',
    'organizationID',
    'identityNamespace',
    'actorID',
    'actorType',
    'keyID',
    'certificateID',
    'certificateRepresentationHash',
    'purpose',
    'activationHash',
    'policyHash',
    'requestHash',
    'approvalPolicyHash',
    'delegationPathLeafID',
    'approvalSetLeafID',
    'issuedAt',
    'expiresAt',
  ]);
  need(body.schemaVersion === 2, 'ORG_AUTHORIZATION_VERSION');
  e.scope({ ...body, schemaVersion: 1 });
  id(body.authorizationID);
  id(body.actorID);
  [
    'keyID',
    'certificateID',
    'certificateRepresentationHash',
    'activationHash',
    'policyHash',
    'requestHash',
    'approvalPolicyHash',
    'delegationPathLeafID',
    'approvalSetLeafID',
  ].forEach((k) => hash(body[k]));
  need(
    equal(member.issuerCertificate, info.terminal.member.delegateCertificate),
    'ORG_FINAL_SIGNER',
  );
  e.authority(member.issuerCertificate, 'FINAL');
  e.target('FINAL_AUTHORIZATION', member, body, keyID(e.cert(member.issuerCertificate).publicKey));
  need(
    body.actorType === 'WORKLOAD' &&
      equal(body.actorID, e.context.operator.id) &&
      body.purpose === 'ORGANIZATION_SEAL' &&
      equal(body.authorizationID, e.input.sim.organizationAuthorizationID),
    'ORG_AUTHORIZATION_SCOPE',
  );
  for (const [k, v] of Object.entries(operationInfo.tuple))
    need(equal(body[k], v), 'ORG_AUTHORIZATION_SEAL');
  const r = setInfo.request;
  need(
    equal(body.activationHash, H('ActivationContext', e.input.activation)) &&
      equal(body.policyHash, r.policyHash) &&
      equal(body.requestHash, H('OrganizationApprovalRequest', r)) &&
      equal(body.approvalPolicyHash, r.approvalPolicyHash) &&
      equal(body.delegationPathLeafID, r.pathLeafID) &&
      equal(body.approvalSetLeafID, setInfo.approvalSetLeafID),
    'ORG_AUTHORIZATION_BINDING',
  );
  times(body, ['issuedAt', 'expiresAt']);
  need(
    body.issuedAt >= r.issuedAt &&
      body.issuedAt <= e.K &&
      e.K < body.expiresAt &&
      body.expiresAt <= r.expiresAt &&
      body.expiresAt > body.issuedAt &&
      body.expiresAt - body.issuedAt <= 30,
    'ORG_AUTHORIZATION_TIME',
  );
  e.validUntil = Math.min(e.validUntil, body.expiresAt);
  return body;
}
function finalExecution(e, oa, current) {
  const { permit, binding, receiptCertificate } = e.input;
  const p = e.control(permit, 'OperationPermit');
  fields(p, [
    'schemaVersion',
    'activation',
    'activationEvidenceHash',
    'proofMode',
    'issuedAt',
    'expiresAt',
  ]);
  hash(p.activationEvidenceHash);
  times(p, ['issuedAt', 'expiresAt']);
  e.authority(permit.issuerCertificate, 'PERMIT');
  e.authority(receiptCertificate, 'RECEIPT');
  const b = bindingBody(e, binding);
  need(
    p.schemaVersion === 1 &&
      p.proofMode === 'WORKLOAD' &&
      same(p.activation, e.input.activation) &&
      equal(p.activationEvidenceHash, sha512(e.input.authorization.cms)),
    'ORG_PERMIT_BINDING',
  );
  need(
    p.issuedAt === oa.issuedAt &&
      p.issuedAt <= e.K &&
      e.K < p.expiresAt &&
      p.expiresAt > p.issuedAt &&
      p.expiresAt <= oa.expiresAt &&
      p.expiresAt - p.issuedAt <= 30,
    'ORG_PERMIT_TIME',
  );
  need(
    equal(b.permitKeyID, keyID(e.cert(permit.issuerCertificate).publicKey)) &&
      equal(b.receiptKeyID, keyID(e.cert(receiptCertificate).publicKey)),
    'ORG_EXECUTION_AUTHORITY_BINDING',
  );
  need(current, 'ORG_EXECUTION_CURRENT_MISSING', 'INDETERMINATE');
  need(
    equal(sha512(binding.cms), sha512(current.member.cms)) && b.epoch === current.body.epoch,
    'ORG_EXECUTION_LEASE_CHANGED',
  );
  need(b.issuedAt <= e.K && e.K < b.expiresAt && b.status === 'ACTIVE', 'ORG_EXECUTION_INACTIVE');
  e.validUntil = Math.min(e.validUntil, p.expiresAt, b.expiresAt);
  return {
    authorizationHash: sha512(e.input.authorization.cms),
    permitHash: sha512(permit.cms),
    bindingHash: sha512(binding.cms),
    operationID: e.input.activation.operationID,
    keyID: e.input.activation.keyID,
  };
}

function preflightAssertion(e, regMember, assertion, label) {
  e.attempt(label, () => {
    const body = e.control(regMember, LABELS.APPROVER_REGISTRATION, 65536);
    sized(body.publicKeyDER, 2048, 'ORG_PUBLIC_KEY');
    const publicKey = publicFromDER(body.publicKeyDER);
    need(
      publicKey.asymmetricKeyType === 'ec' &&
        publicKey.asymmetricKeyDetails?.namedCurve === 'prime256v1',
      'ORG_APPROVER_ALGORITHM',
      'UNSUPPORTED',
    );
    fields(assertion, ['credentialID', 'clientDataJSON', 'authenticatorData', 'signature']);
    sized(assertion.clientDataJSON, 8192, 'ORG_CLIENT_DATA');
    sized(assertion.authenticatorData, 65536, 'ORG_AUTHENTICATOR_DATA');
    sized(assertion.signature, 128, 'ORG_ASSERTION_SIGNATURE');
    need(
      verify(
        Buffer.concat([assertion.authenticatorData, sha256(assertion.clientDataJSON)]),
        assertion.signature,
        publicKey,
      ),
      'ASSERTION_SIGNATURE',
    );
  });
}
function preflight(e, mode) {
  e.path = e.attempt('path-collection', () =>
    collection(e.input.delegationPath, 'grants', 2 * MiB, 8),
  );
  if (mode === 'set' || mode === 'evidence')
    e.approvalCollection = e.attempt('approval-collection', () =>
      collection(e.input.approvalSet, 'approvals', 4 * MiB, 16),
    );
  if (mode === 'evidence')
    e.statusCollection = e.attempt('status-collection', () =>
      collection(e.input.statusCollection, 'statements', 8 * MiB, 64),
    );
  e.regMembers =
    e.approvalCollection?.approvals.map((m) => ({
      cms: m.registrationCMS,
      issuerCertificate: m.registrationIssuerCertificate,
    })) ?? e.input.approverRegistrations;
  for (const [i, m] of (e.path?.grants ?? []).entries())
    e.attempt('grant-math:' + i, () => e.control(m, LABELS.GRANT));
  if (Array.isArray(e.regMembers) && e.regMembers.length <= 16)
    for (const [i, m] of e.regMembers.entries())
      e.attempt('registration-math:' + i, () => e.control(m, LABELS.APPROVER_REGISTRATION, 65536));
  for (const [label, members] of [
    ['source', e.context.statusMaterial],
    ['retained', e.statusCollection?.statements],
  ])
    if (Array.isArray(members) && members.length <= 64)
      for (const [i, m] of members.entries())
        e.attempt('status-math:' + label + ':' + i, () =>
          e.control(m, 'OrganizationDelegationStatus'),
        );
  if (mode === 'approval' && Array.isArray(e.regMembers)) {
    const index = e.regMembers.findIndex((m) => {
      try {
        return equal(e.control(m, LABELS.APPROVER_REGISTRATION, 65536).personID, e.input.personID);
      } catch {
        return false;
      }
    });
    if (index >= 0) preflightAssertion(e, e.regMembers[index], e.input.assertion, 'assertion-math');
  }
  for (const [i, member] of (e.approvalCollection?.approvals ?? []).entries())
    preflightAssertion(
      e,
      { cms: member.registrationCMS, issuerCertificate: member.registrationIssuerCertificate },
      member.assertion,
      'assertion-math:' + i,
    );
  if (mode === 'evidence')
    for (const [name, label] of [
      ['authorization', 'OrganizationAuthorization'],
      ['permit', 'OperationPermit'],
      ['binding', 'ExecutionBinding'],
    ])
      e.attempt(name + '-math', () => e.control(e.input[name], label));
  if (e.context.executionCurrent?.binding)
    e.attempt('current-binding-math', () => {
      sized(e.context.executionCurrent.binding, 65536, 'ORG_EXECUTION_BINDING');
      return verifyCMS(e.context.executionCurrent.binding);
    });
}
function start(input, mode) {
  const e = new Evaluation();
  const detached = e.attempt('input-snapshot', () => detach(input));
  if (!detached) return e;
  e.input = detached.data;
  e.context = e.input.context;
  e.state = e.input.state;
  e.resolver = detached.resolver;
  e.K = e.context.knowledgeTime;
  const extra = {
    prepare: ['approverRegistrations', 'rosterNonces'],
    approval: ['approverRegistrations', 'request', 'personID', 'assertion', 'counterBefore'],
    set: ['approvalSet', 'counterBaselines'],
    evidence: [
      'approvalSet',
      'statusCollection',
      'authorization',
      'permit',
      'binding',
      'receiptCertificate',
      'counterBaselines',
    ],
  };
  e.attempt('input-fields', () =>
    fields(e.input, [
      'context',
      'state',
      'sim',
      'activation',
      'tbs',
      'delegationPath',
      ...extra[mode],
    ]),
  );
  e.attempt('material-limit', () => {
    let bytes = 0;
    const count = (v) => {
      if (Buffer.isBuffer(v)) bytes += v.length;
      else if (Array.isArray(v)) v.forEach(count);
      else if (v && typeof v === 'object') Object.values(v).forEach(count);
    };
    for (const k of [
      'delegationPath',
      'approverRegistrations',
      'approvalSet',
      'statusCollection',
      'authorization',
      'permit',
      'binding',
    ])
      count(e.input[k]);
    need(bytes <= 12 * MiB, 'ORG_MATERIAL_LIMIT', 'UNSUPPORTED');
  });
  // Bounded independent signature checks precede external authority and freshness dependencies.
  e.attempt('preflight', () => preflight(e, mode));
  if (!e.attempt('context', () => contextShape(e))) return e;
  e.operation = e.attempt('operation', () => operation(e));
  e.pathInfo = e.path && e.attempt('path', () => path(e, e.path));
  if (e.operation && e.pathInfo)
    e.attempt('entitlement', () => pathOperation(e, e.pathInfo, e.operation));
  if (e.regMembers)
    e.regs = e.attempt('registrations', () => registrations(e, e.regMembers, e.pathInfo));
  e.current = e.attempt('current-execution', () => currentExecution(e));
  e.ready = true;
  return e;
}
function basicFacts(e, request) {
  return {
    request,
    requestHash: H('OrganizationApprovalRequest', request),
    pathLeafID: request.pathLeafID,
    approvalPolicyHash: request.approvalPolicyHash,
    terminalCertificate: e.pathInfo.terminal.member.delegateCertificate,
    terminalGrantHash: sha512(e.pathInfo.terminal.member.cms),
    effectiveMinimum: e.pathInfo.minimum,
    admittedPersonIDs: e.regs.map((r) => r.body.personID),
    validUntil: e.validUntil,
  };
}

/** Validate current preparatory scope and build a request; this is not final permission. */
export function evaluateOrganizationRequest(input) {
  const e = start(input, 'prepare');
  let facts;
  if (e.ready) {
    e.attempt('status-closure', () => statuses(e));
    if (e.pathInfo && e.regs && e.operation)
      facts = e.attempt('request', () => {
        const request = makeRequest(e, e.pathInfo, e.regs);
        return { ...basicFacts(e, request), registrations: e.regs.map((r) => r.fact) };
      });
  }
  return e.complete(facts);
}

/** Verify one original assertion against an explicit counter baseline without consuming it. */
export function verifyOrganizationApproval(input) {
  const e = start(input, 'approval');
  let facts;
  if (e.ready) {
    e.attempt('status-closure', () => statuses(e));
    if (e.pathInfo && e.regs && e.operation)
      facts = e.attempt('approval', () => {
        id(e.input.personID);
        const request = checkRequest(e, e.input.request, e.pathInfo, e.regs);
        const reg = e.regs.find((r) => equal(r.body.personID, e.input.personID));
        need(reg, 'ORG_APPROVER_NOT_IN_ROSTER');
        const fact = approval(e, request, reg, e.input.assertion, e.input.counterBefore);
        e.counterFacts.push(fact);
        return {
          requestHash: H('OrganizationApprovalRequest', request),
          pathLeafID: request.pathLeafID,
          approvalPolicyHash: request.approvalPolicyHash,
          personID: reg.body.personID,
          registrationHash: reg.fact.registrationHash,
          credentialIDHash: fact.credentialIDHash,
          credentialKeyID: fact.credentialKeyID,
          assertionHash: fact.assertionHash,
          nonce: fact.nonce,
        };
      });
  }
  return e.complete(facts);
}

/** Require the complete roster; there is deliberately no incomplete-set success option. */
export function verifyOrganizationApprovalSet(input) {
  const e = start(input, 'set');
  let facts;
  if (e.ready) {
    e.attempt('status-closure', () => statuses(e));
    if (e.pathInfo && e.regs && e.operation && e.approvalCollection)
      facts = e.attempt('approval-set', () => {
        const setInfo = approvalSet(e, e.approvalCollection, e.pathInfo, e.regs);
        return {
          ...basicFacts(e, setInfo.request),
          approvalSetLeafID: setInfo.approvalSetLeafID,
          counterScope: setInfo.counterScope,
        };
      });
  }
  return e.complete(facts);
}

/** Verify organization closure only; document, credential/RAR and receipt checks compose separately. */
export function verifyOrganizationEvidence(input) {
  const e = start(input, 'evidence');
  let facts, setInfo, oa, execution;
  if (e.ready) {
    if (e.pathInfo && e.regs && e.operation && e.approvalCollection) {
      setInfo = e.attempt('approval-set', () =>
        approvalSet(e, e.approvalCollection, e.pathInfo, e.regs),
      );
      if (setInfo)
        oa = e.attempt('authorization', () =>
          finalAuthorization(e, e.pathInfo, setInfo, e.operation),
        );
      if (oa) execution = e.attempt('execution', () => finalExecution(e, oa, e.current));
    }
    e.attempt('status-closure', () => statuses(e, e.statusCollection));
    if (setInfo && oa && execution && e.statusCollection)
      facts = {
        request: setInfo.request,
        requestHash: H('OrganizationApprovalRequest', setInfo.request),
        pathLeafID: setInfo.request.pathLeafID,
        approvalSetLeafID: setInfo.approvalSetLeafID,
        approvalPolicyHash: setInfo.request.approvalPolicyHash,
        ...execution,
        terminalCertificate: e.pathInfo.terminal.member.delegateCertificate,
        admittedPersonIDs: e.regs.map((r) => r.body.personID),
        validUntil: e.validUntil,
        counterScope: setInfo.counterScope,
      };
  }
  return e.complete(facts);
}

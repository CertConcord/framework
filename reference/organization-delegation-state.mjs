import { types } from 'node:util';
import { H, b64u, dcbor, decodeCBOR, equal, keyID, sha512 } from './core.mjs';
import { parseCertificate, verifyCMS } from './pki.mjs';
import { readControl } from './state.mjs';

export const ORGANIZATION_PROFILE = 'certconcord-organization-delegation-v1';
export const ORGANIZATION_PLAN = 'certconcord-ecp-cms-organization-delegation-v1';
export const OPERATION_NAMESPACE = 'organization-delegation-operation';
const CURRENT_NAMESPACE = 'organization-delegation-current';
const PREFIX = 'organization-delegation-';
const OUTCOMES = ['INVALID', 'UNSUPPORTED', 'INDETERMINATE', 'VALID'];
export const instant = (value) => Number.isSafeInteger(value) && value >= 0;

export function orgError(code, overall = 'INVALID') {
  return Object.assign(new Error(code), { code, reason: code, overall });
}
export function insist(condition, code, overall = 'INVALID') {
  if (!condition) throw orgError(code, overall);
}
export function observePromise(value) {
  if (types.isPromise(value)) Promise.prototype.then.call(value, undefined, () => {});
}
export function record(value, required, optional = []) {
  insist(
    value &&
      !types.isProxy(value) &&
      (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null),
    'ORG_OBJECT_SCHEMA',
  );
  const descriptors = Object.getOwnPropertyDescriptors(value);
  insist(
    Reflect.ownKeys(value).every((key) => typeof key === 'string'),
    'ORG_OBJECT_SCHEMA',
  );
  insist(
    Object.values(descriptors).every((entry) => Object.hasOwn(entry, 'value')),
    'ORG_OBJECT_SCHEMA',
  );
  insist(
    required.every((key) => Object.hasOwn(descriptors, key)),
    'ORG_MISSING_FIELD',
  );
  insist(
    Object.keys(descriptors).every((key) => required.includes(key) || optional.includes(key)),
    'ORG_UNKNOWN_FIELD',
  );
}
export function snapshot(value, budget = { bytes: 0, items: 0 }, depth = 0, seen = new Set()) {
  insist(++budget.items <= 100000 && depth <= 32, 'ORG_CAPABILITY_LIMIT', 'UNSUPPORTED');
  insist(!types.isProxy(value), 'ORG_OBJECT_SCHEMA');
  if (Buffer.isBuffer(value)) {
    budget.bytes += value.length;
    insist(budget.bytes <= 80 * 1024 * 1024, 'ORG_CAPABILITY_LIMIT', 'UNSUPPORTED');
    return Buffer.from(value);
  }
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    insist(Number.isSafeInteger(value), 'ORG_NUMBER');
    return value;
  }
  if (typeof value === 'string') {
    budget.bytes += Buffer.byteLength(value);
    insist(budget.bytes <= 80 * 1024 * 1024, 'ORG_CAPABILITY_LIMIT', 'UNSUPPORTED');
    return value;
  }
  insist(value && typeof value === 'object' && !seen.has(value), 'ORG_OBJECT_SCHEMA');
  observePromise(value);
  insist(!types.isPromise(value), 'ORG_ASYNC_DEPENDENCY', 'INDETERMINATE');
  const descriptors = Object.getOwnPropertyDescriptors(value);
  insist(
    Reflect.ownKeys(value).every((key) => typeof key === 'string'),
    'ORG_OBJECT_SCHEMA',
  );
  insist(
    Object.values(descriptors).every((entry) => Object.hasOwn(entry, 'value')),
    'ORG_OBJECT_SCHEMA',
  );
  seen.add(value);
  let copied;
  if (Array.isArray(value)) {
    insist(Object.keys(value).length === value.length, 'ORG_ARRAY_SCHEMA');
    copied = Array.from({ length: value.length }, (_, index) => {
      insist(Object.hasOwn(descriptors, index), 'ORG_ARRAY_SCHEMA');
      return snapshot(descriptors[index].value, budget, depth + 1, seen);
    });
  } else {
    insist(
      Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null,
      'ORG_OBJECT_SCHEMA',
    );
    copied = Object.fromEntries(
      Object.entries(descriptors).map(([key, entry]) => [
        key,
        snapshot(entry.value, budget, depth + 1, seen),
      ]),
    );
  }
  seen.delete(value);
  return copied;
}
export function binary(value, length, maximum = length) {
  insist(Buffer.isBuffer(value), 'ORG_BINARY');
  insist(value.length >= length, 'ORG_BINARY');
  insist(value.length <= maximum, 'ORG_CAPABILITY_LIMIT', 'UNSUPPORTED');
  return Buffer.from(value);
}
export function canonical(raw, maximum) {
  binary(raw, 1, maximum);
  const decoded = decodeCBOR(raw, { maxBytes: maximum });
  insist(equal(dcbor(decoded), raw), 'ORG_CANONICAL_CBOR');
  return decoded;
}
export function failure(error, fallback = 'ORG_VALIDATION_FAILED', overall = 'INVALID') {
  return {
    overall: OUTCOMES.slice(0, 3).includes(error?.overall) ? error.overall : overall,
    reason:
      typeof error?.code === 'string'
        ? error.code
        : typeof error?.reason === 'string'
          ? error.reason
          : fallback,
  };
}
export function decision(value) {
  observePromise(value);
  if (types.isPromise(value)) return { overall: 'INDETERMINATE', reason: 'ORG_ASYNC_DEPENDENCY' };
  try {
    const copied = snapshot(value);
    insist(OUTCOMES.includes(copied.overall), 'ORG_DECISION_SCHEMA', 'INDETERMINATE');
    if (typeof copied.reason !== 'string' || !copied.reason.length)
      return {
        ...copied,
        overall: copied.overall === 'VALID' ? 'INDETERMINATE' : copied.overall,
        reason: 'ORG_DECISION_INCOMPLETE',
      };
    return copied;
  } catch (error) {
    return failure(error, 'ORG_DECISION_UNAVAILABLE', 'INDETERMINATE');
  }
}
export function rejected(checks) {
  for (const overall of OUTCOMES.slice(0, 3)) {
    const result = checks.find((entry) => entry.overall === overall);
    if (result) return result;
  }
  return null;
}
export function addCheck(checks, name, callback) {
  try {
    return callback();
  } catch (error) {
    checks.push({ check: name, ...failure(error) });
    return undefined;
  }
}
export function requireChecks(checks) {
  const bad = rejected(checks);
  if (bad) throw orgError(bad.reason, bad.overall);
}
export function operationID(context, operation) {
  return b64u(
    H('OrganizationOperation', {
      profile: ORGANIZATION_PROFILE,
      trustDomainID: context.trustDomainID,
      organizationID: context.organizationID,
      operationID: operation,
    }),
  );
}
const currentID = (domain) => b64u(H('OrganizationCurrentState', { trustDomainID: domain }));
const index = (label, value) => b64u(H(label, value));
const objectIdentity = (entry) => ({
  trustDomainID: entry.trustDomainID,
  organizationID: entry.organizationID,
  objectType: entry.objectType,
  objectID: entry.objectID,
});
const objectIndex = (entry) => index('OrganizationStateObject', objectIdentity(entry));
const targetIndex = (domain, hash) =>
  index('OrganizationStateTarget', { trustDomainID: domain, objectHash: hash });
const keyIndex = (domain, key) =>
  index('OrganizationStateKey', { trustDomainID: domain, keyID: key });
const executionIndex = (entry) =>
  index('OrganizationExecutionState', {
    trustDomainID: entry.trustDomainID,
    providerID: entry.providerID,
    keyID: entry.keyID,
  });

function deadlineMap(value, keys) {
  record(value, [], Object.keys(value));
  insist(Object.keys(value).length <= 1024, 'ORG_CAPABILITY_LIMIT', 'UNSUPPORTED');
  for (const [key, cutoff] of Object.entries(value))
    insist(keys.test(key) && instant(cutoff), 'ORG_PROTECTION_POLICY');
  return snapshot(value);
}

/** Fixed source identities with fresh detached current data. */
export class OrganizationContext {
  #read;
  #resolver;
  #pin;
  #initial;
  constructor(readContext) {
    insist(typeof readContext === 'function', 'ORG_CONTEXT_REQUIRED', 'INDETERMINATE');
    this.#read = readContext;
    this.#initial = this.read();
  }
  get initial() {
    return this.#copy(this.#initial);
  }
  get configurationHash() {
    return Buffer.from(this.#pin);
  }
  #copy(context) {
    const { authorityResolver, ...data } = context;
    return { ...snapshot(data), authorityResolver };
  }
  read() {
    let raw;
    try {
      raw = this.#read();
    } catch {
      throw orgError('ORG_CONTEXT_UNAVAILABLE', 'INDETERMINATE');
    }
    observePromise(raw);
    insist(!types.isPromise(raw), 'ORG_ASYNC_DEPENDENCY', 'INDETERMINATE');
    record(raw, [
      'knowledgeTime',
      'trustDomainID',
      'organizationID',
      'issuerID',
      'identityNamespace',
      'operator',
      'policy',
      'authorityResolver',
      'controlTrust',
      'credentialTrust',
      'statusMaterial',
      'algorithmDeadlines',
      'hashDeadlines',
      'keyDeadlines',
      'executionCurrent',
    ]);
    const resolver = raw.authorityResolver;
    insist(typeof resolver === 'function', 'ORG_AUTHORITY_RESOLVER_REQUIRED', 'INDETERMINATE');
    insist(!this.#resolver || this.#resolver === resolver, 'ORG_CONTEXT_CHANGED');
    const { authorityResolver: ignored, ...data } = raw;
    const context = snapshot(data);
    binary(context.trustDomainID, 32);
    binary(context.organizationID, 32);
    insist(instant(context.knowledgeTime), 'ORG_KNOWLEDGE_TIME', 'INDETERMINATE');
    insist(
      typeof context.issuerID === 'string' &&
        context.issuerID.length > 0 &&
        context.issuerID.length <= 128,
      'ORG_ISSUER_ID',
    );
    insist(
      typeof context.identityNamespace === 'string' &&
        /^[\x21-\x7e]{1,128}$/.test(context.identityNamespace),
      'ORG_IDENTITY_NAMESPACE',
    );
    record(context.operator, ['type', 'id', 'active', 'knownAt', 'validFrom', 'validUntil']);
    binary(context.operator.id, 32);
    insist(context.operator.type === 'WORKLOAD', 'ORG_OPERATOR_UNSUPPORTED', 'UNSUPPORTED');
    insist(
      typeof context.operator.active === 'boolean' &&
        ['knownAt', 'validFrom', 'validUntil'].every((key) => instant(context.operator[key])) &&
        context.operator.validFrom < context.operator.validUntil,
      'ORG_OPERATOR_SCHEMA',
    );
    insist(
      Array.isArray(context.controlTrust) && Array.isArray(context.statusMaterial),
      'ORG_TRUST_SCHEMA',
    );
    insist(
      context.controlTrust.length <= 64 && context.statusMaterial.length <= 64,
      'ORG_CAPABILITY_LIMIT',
      'UNSUPPORTED',
    );
    const controlIDs = new Set();
    const purposes = [
      'ORGANIZATION_DELEGATION_ROOT',
      'ORGANIZATION_DELEGATION_ISSUE',
      'ORGANIZATION_FINAL_AUTHORIZATION',
      'ORGANIZATION_APPROVER_REGISTRATION',
      'ORGANIZATION_DELEGATION_STATUS',
      'ORGANIZATION_DELEGATION_PERMIT',
      'ORGANIZATION_DELEGATION_RECEIPT',
      'ORGANIZATION_DELEGATION_EXECUTION_BINDING',
    ];
    for (const trust of context.controlTrust) {
      record(trust, [
        'certificate',
        'organizationID',
        'identityNamespace',
        'issuerID',
        'purpose',
        'objectTypes',
      ]);
      binary(trust.certificate, 1, 65536);
      insist(
        equal(trust.organizationID, context.organizationID) &&
          trust.identityNamespace === context.identityNamespace &&
          trust.issuerID === context.issuerID &&
          purposes.includes(trust.purpose),
        'ORG_CONTROL_TRUST',
      );
      insist(
        Array.isArray(trust.objectTypes) &&
          new Set(trust.objectTypes).size === trust.objectTypes.length &&
          trust.objectTypes.every((type) =>
            ['GRANT', 'APPROVER_REGISTRATION', 'FINAL_AUTHORIZATION'].includes(type),
          ) &&
          (trust.purpose === 'ORGANIZATION_DELEGATION_STATUS'
            ? trust.objectTypes.length > 0
            : trust.objectTypes.length === 0),
        'ORG_CONTROL_TRUST',
      );
      const id = b64u(H('OrganizationControlTrust', trust));
      insist(!controlIDs.has(id), 'ORG_CONTROL_TRUST_DUPLICATE');
      controlIDs.add(id);
    }
    record(context.credentialTrust, [
      'certificate',
      'registrationAuthorization',
      'issuerCertificate',
      'raCertificate',
      'statusCertificate',
      'issuanceScope',
      'currentCertificateStatus',
    ]);
    for (const key of ['certificate', 'issuerCertificate', 'raCertificate', 'statusCertificate'])
      binary(context.credentialTrust[key], 1, 65536);
    binary(context.credentialTrust.registrationAuthorization, 1, 131072);
    if (context.credentialTrust.currentCertificateStatus !== null)
      binary(context.credentialTrust.currentCertificateStatus, 1, 131072);
    for (const member of context.statusMaterial) {
      record(member, ['cms', 'issuerCertificate']);
      binary(member.cms, 1, 131072);
      binary(member.issuerCertificate, 1, 65536);
    }
    context.algorithmDeadlines = deadlineMap(
      context.algorithmDeadlines,
      /^(?:0|1|2)(?:\.(?:0|[1-9][0-9]*))+$/,
    );
    context.hashDeadlines = deadlineMap(
      context.hashDeadlines,
      /^(?:0|1|2)(?:\.(?:0|[1-9][0-9]*))+$/,
    );
    context.keyDeadlines = deadlineMap(context.keyDeadlines, /^[0-9a-f]{128}$/);
    if (context.executionCurrent !== null) {
      record(context.executionCurrent, ['binding', 'observedAt']);
      binary(context.executionCurrent.binding, 1, 65536);
      insist(instant(context.executionCurrent.observedAt), 'ORG_EXECUTION_CURRENT');
    }
    const { currentCertificateStatus, ...credentialIdentity } = context.credentialTrust;
    const pin = H('OrganizationConfiguration', {
      trustDomainID: context.trustDomainID,
      organizationID: context.organizationID,
      issuerID: context.issuerID,
      identityNamespace: context.identityNamespace,
      operator: { type: context.operator.type, id: context.operator.id },
      policy: context.policy,
      controlTrust: context.controlTrust,
      credentialTrust: credentialIdentity,
    });
    insist(!this.#pin || equal(pin, this.#pin), 'ORG_CONTEXT_CHANGED');
    this.#pin ??= pin;
    this.#resolver ??= resolver;
    context.authorityResolver = (query) => {
      try {
        return decision(this.#resolver(snapshot(query)));
      } catch (error) {
        return failure(error, 'ORG_AUTHORITY_UNAVAILABLE', 'INDETERMINATE');
      }
    };
    return context;
  }
}

export function bindJournal(journal) {
  insist(
    journal && typeof journal === 'object' && journal.db && !journal.depth,
    'ORG_JOURNAL_REQUIRED',
  );
  const names = ['get', 'put', 'transaction', 'result', 'reserve', 'reconcile', 'uncertain'];
  const methods = Object.fromEntries(
    names.map((name) => {
      insist(typeof journal[name] === 'function', 'ORG_JOURNAL_REQUIRED');
      return [name, journal[name]];
    }),
  );
  const receiver = Object.create(null);
  for (const [name, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(journal)))
    if (Object.hasOwn(descriptor, 'value')) receiver[name] = descriptor.value;
  for (const name of names)
    Object.defineProperty(receiver, name, {
      enumerable: true,
      value: (...args) => {
        try {
          return methods[name].apply(receiver, args);
        } catch (error) {
          if (error?.overall) throw error;
          if (error?.code === 'CAS_CONFLICT') throw orgError('ORG_STATE_CONFLICT', 'INDETERMINATE');
          if (error?.code && !error.code.startsWith('ERR_'))
            throw orgError(
              error.code,
              error.code === 'UNKNOWN_EXECUTION' ? 'INDETERMINATE' : 'INVALID',
            );
          throw orgError('ORG_PERSISTENCE_UNAVAILABLE', 'INDETERMINATE');
        }
      },
    });
  return receiver;
}

/** Indexed projections and CAS persistence of already authenticated observations. */
export class OrganizationState {
  constructor(journal, domain) {
    this.journal = journal;
    this.domain = Buffer.from(domain);
    this.currentID = currentID(domain);
  }
  operation(context, operation) {
    return this.journal.get(OPERATION_NAMESPACE, operationID(context, operation));
  }
  requireImmutableTarget(target) {
    const prior = this.journal.get(PREFIX + 'target-id', objectIndex(target))?.value?.targets ?? [];
    insist(
      prior.every((entry) => equal(entry.semanticHash, target.semanticHash)),
      'ORG_IMMUTABLE_OBJECT_CONFLICT',
    );
  }
  counterID(context, member) {
    return index('OrganizationApprovalCounter', {
      trustDomainID: this.domain,
      identityNamespace: context.identityNamespace,
      rpID: member.rpID,
      credentialIDHash: member.credentialIDHash,
      credentialKeyID: member.credentialKeyID,
    });
  }
  load(
    context,
    {
      delegationPath,
      approverRegistrations = [],
      approvalSet,
      authorization,
      statusCollection,
      binding,
    } = {},
  ) {
    const current = this.journal.get(CURRENT_NAMESPACE, this.currentID);
    insist(
      !current || context.knowledgeTime >= current.value.knowledgeTime,
      'ORG_CLOCK_ROLLBACK',
      'INDETERMINATE',
    );
    const state = {
      knowledgeTime: current?.value.knowledgeTime ?? null,
      targets: [],
      heads: [],
      terminalObservations: [],
      keyIncidents: [],
      executions: [],
    };
    const objects = new Map(),
      hashes = new Map(),
      keys = new Map(),
      executions = new Map();
    const addKey = (key) => {
      if (Buffer.isBuffer(key) && key.length === 64) keys.set(b64u(key), key);
    };
    const addObject = (body, type, cms) => {
      const id = body.grantID ?? body.registrationID ?? body.authorizationID;
      if (Buffer.isBuffer(id) && id.length === 32 && equal(body.trustDomainID, this.domain)) {
        const item = {
          trustDomainID: this.domain,
          organizationID: body.organizationID,
          objectType: type,
          objectID: id,
        };
        objects.set(objectIndex(item), item);
        hashes.set(b64u(sha512(cms)), sha512(cms));
      }
      addKey(body.delegateAuthority?.keyID ?? body.keyID);
    };
    const inspect = (member, label, type) => {
      try {
        addObject(readControl(member.cms, label, member.issuerCertificate), type, member.cms);
      } catch {
        /* Only lookup hints; the evaluator checks the original evidence. */
      }
    };
    try {
      for (const grant of canonical(delegationPath, 2 * 1024 * 1024).grants)
        inspect(grant, 'OrganizationDelegationGrant', 'GRANT');
    } catch {}
    let registrations = approverRegistrations;
    try {
      if (approvalSet)
        registrations = canonical(approvalSet, 4 * 1024 * 1024).approvals.map((item) => ({
          cms: item.registrationCMS,
          issuerCertificate: item.registrationIssuerCertificate,
        }));
    } catch {}
    for (const member of registrations)
      inspect(member, 'OrganizationApproverRegistration', 'APPROVER_REGISTRATION');
    if (authorization) inspect(authorization, 'OrganizationAuthorization', 'FINAL_AUTHORIZATION');
    let statuses = [...context.statusMaterial];
    try {
      if (statusCollection)
        statuses.push(...canonical(statusCollection, 8 * 1024 * 1024).statements);
    } catch {}
    insist(statuses.length <= 128, 'ORG_CAPABILITY_LIMIT', 'UNSUPPORTED');
    for (const member of statuses) {
      try {
        const body = readControl(
          member.cms,
          'OrganizationDelegationStatus',
          member.issuerCertificate,
        );
        if (
          equal(body.trustDomainID, this.domain) &&
          Buffer.isBuffer(body.objectHash) &&
          body.objectHash.length === 64
        ) {
          hashes.set(b64u(body.objectHash), body.objectHash);
          objects.set(objectIndex(body), objectIdentity(body));
        }
      } catch {}
    }
    for (const hash of hashes.values()) {
      const value = this.journal.get(PREFIX + 'target', targetIndex(this.domain, hash))?.value;
      if (value) {
        state.targets.push(value);
        addKey(value.subjectKeyID);
      }
    }
    for (const [id] of objects) {
      const known = this.journal.get(PREFIX + 'target-id', id)?.value?.targets ?? [];
      for (const target of known) {
        if (!state.targets.some((item) => equal(item.objectHash, target.objectHash)))
          state.targets.push(target);
        addKey(target.subjectKeyID);
      }
      const row = this.journal.get(PREFIX + 'status', id)?.value;
      if (row) {
        state.heads.push(...row.heads);
        state.terminalObservations.push(...row.terminals);
      }
    }
    for (const cert of [
      ...context.controlTrust.map((item) => item.certificate),
      ...['certificate', 'issuerCertificate', 'raCertificate', 'statusCertificate'].map(
        (name) => context.credentialTrust[name],
      ),
    ]) {
      try {
        addKey(keyID(parseCertificate(cert).publicKey));
      } catch {}
    }
    for (const raw of [context.executionCurrent?.binding, binding?.cms]) {
      try {
        if (!raw) continue;
        const body = readControl(raw, 'ExecutionBinding', verifyCMS(raw).certificate);
        if (equal(body.trustDomainID, this.domain)) executions.set(executionIndex(body), body);
      } catch {}
    }
    for (const [id] of executions) {
      const row = this.journal.get(PREFIX + 'execution', id)?.value;
      if (row) state.executions.push(...row.observations);
    }
    for (const key of keys.values()) {
      const incident = this.journal.get(PREFIX + 'key-incident', keyIndex(this.domain, key))?.value;
      if (incident) state.keyIncidents.push(incident);
    }
    return { state: snapshot(state), revision: current?.revision ?? -1 };
  }
  #put(namespace, id, value) {
    const old = this.journal.get(namespace, id);
    this.journal.put(namespace, id, value, old?.revision ?? -1);
  }
  #mergeHeads(existing, observation) {
    const values = [...existing];
    if (
      values.some(
        (entry) =>
          entry.epoch === observation.epoch && equal(entry.semanticHash, observation.semanticHash),
      )
    )
      return values;
    values.push(observation);
    const max = Math.max(...values.map((entry) => entry.epoch));
    const conflicts = values.filter((entry) =>
      values.some(
        (other) => other.epoch === entry.epoch && !equal(other.semanticHash, entry.semanticHash),
      ),
    );
    return [
      ...new Map(
        [...values.filter((entry) => entry.epoch === max), ...conflicts.slice(0, 2)].map(
          (entry) => [b64u(entry.semanticHash), entry],
        ),
      ).values(),
    ];
  }
  merge(context, projection, result) {
    const observations = snapshot({
      targets: result.targetObservations ?? [],
      statuses: result.statusObservations ?? [],
      executions: result.executionObservations ?? [],
    });
    return this.journal.transaction(() => {
      const current = this.journal.get(CURRENT_NAMESPACE, this.currentID);
      insist(
        (current?.revision ?? -1) === projection.revision,
        'ORG_STATE_CONFLICT',
        'INDETERMINATE',
      );
      insist(
        !current || context.knowledgeTime >= current.value.knowledgeTime,
        'ORG_CLOCK_ROLLBACK',
        'INDETERMINATE',
      );
      for (const target of observations.targets) {
        insist(equal(target.trustDomainID, this.domain), 'ORG_STATE_DOMAIN');
        const old =
          this.journal.get(PREFIX + 'target-id', objectIndex(target))?.value?.targets ?? [];
        this.#put(PREFIX + 'target', targetIndex(this.domain, target.objectHash), target);
        // Two authenticated meanings are sufficient to retain an immutable-ID fork.
        if (!old.some((entry) => equal(entry.semanticHash, target.semanticHash)))
          this.#put(PREFIX + 'target-id', objectIndex(target), {
            targets: [...old, target].slice(0, 2),
          });
      }
      for (const status of observations.statuses) {
        insist(
          equal(status.trustDomainID, this.domain) &&
            status.publishedAt <= context.knowledgeTime &&
            status.observedAt === context.knowledgeTime,
          'ORG_STATE_OBSERVATION',
        );
        const id = objectIndex(status),
          row = this.journal.get(PREFIX + 'status', id)?.value ?? { heads: [], terminals: [] };
        row.heads = this.#mergeHeads(row.heads, status);
        if (
          status.status === 'REVOKED' &&
          !row.terminals.some((entry) => equal(entry.semanticHash, status.semanticHash))
        ) {
          row.terminals.push(status);
          row.terminals.sort(
            (a, b) =>
              Math.min(a.compromiseStart ?? Infinity, a.effectiveTime ?? a.publishedAt) -
              Math.min(b.compromiseStart ?? Infinity, b.effectiveTime ?? b.publishedAt),
          );
          row.terminals = row.terminals.slice(0, 2);
        }
        this.#put(PREFIX + 'status', id, row);
        if (
          status.status === 'REVOKED' &&
          status.compromiseStart !== null &&
          status.compromiseStart !== undefined
        ) {
          const incidentID = keyIndex(this.domain, status.subjectKeyID),
            prior = this.journal.get(PREFIX + 'key-incident', incidentID)?.value;
          if (!prior || status.compromiseStart < prior.compromiseStart)
            this.#put(PREFIX + 'key-incident', incidentID, {
              trustDomainID: this.domain,
              keyID: status.subjectKeyID,
              compromiseStart: status.compromiseStart,
              observedAt: context.knowledgeTime,
              sourceStatusHash: status.rawHash,
              sourceObjectHash: status.objectHash,
            });
        }
      }
      for (const observation of observations.executions) {
        insist(
          equal(observation.trustDomainID, this.domain) &&
            observation.issuedAt <= context.knowledgeTime &&
            observation.observedAt === context.knowledgeTime,
          'ORG_STATE_OBSERVATION',
        );
        const id = executionIndex(observation),
          previous = this.journal.get(PREFIX + 'execution', id)?.value?.observations ?? [];
        const merged = this.#mergeHeads(previous, observation),
          revoked = [...previous, observation].find((entry) => entry.status === 'REVOKED');
        if (revoked && !merged.some((entry) => equal(entry.semanticHash, revoked.semanticHash)))
          merged.push(revoked);
        this.#put(PREFIX + 'execution', id, { observations: merged });
      }
      const revision = this.journal.put(
        CURRENT_NAMESPACE,
        this.currentID,
        { knowledgeTime: context.knowledgeTime },
        projection.revision,
      );
      return { namespace: CURRENT_NAMESPACE, id: this.currentID, revision };
    });
  }
  guard(expected) {
    const row = this.journal.get(expected.namespace, expected.id);
    insist(row && row.revision === expected.revision, 'ORG_STATE_CONFLICT', 'INDETERMINATE');
  }
  bump(context, guard) {
    this.guard(guard);
    return {
      ...guard,
      revision: this.journal.put(
        CURRENT_NAMESPACE,
        this.currentID,
        { knowledgeTime: context.knowledgeTime },
        guard.revision,
      ),
    };
  }
}

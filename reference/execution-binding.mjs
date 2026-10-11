import { requireAuthority } from './authority-history.mjs';
import { types } from 'node:util';
import {
  requireOperationAuthorities,
  operationAuthorityQueries,
  requireAuthorities,
} from './control-authority.mjs';
import {
  D,
  H,
  dcbor,
  decodeCBOR,
  sha512,
  equal,
  requireThat,
  fields,
  keyID,
  b64u,
  now,
  verify,
  ProtocolError,
  spki,
  publicFromDER,
} from './core.mjs';
import { parseCertificate, signCMS } from './pki.mjs';
import { readControl, validateActivation } from './state.mjs';

export const EXECUTION_BINDING_PROFILE = 'certconcord-execution-binding-draft-03';
const copy = (value) => decodeCBOR(dcbor(value));
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

export function executionRequirement(policy) {
  if (!Object.hasOwn(policy, 'executionBinding')) return null;
  const requirement = policy.executionBinding;
  fields(requirement, ['profile', 'providerID', 'maxLeaseSeconds']);
  requireThat(
    requirement.profile === EXECUTION_BINDING_PROFILE &&
      typeof requirement.providerID === 'string' &&
      /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(requirement.providerID) &&
      Number.isSafeInteger(requirement.maxLeaseSeconds) &&
      requirement.maxLeaseSeconds > 0 &&
      requirement.maxLeaseSeconds <= 86400,
    'EXECUTION_PROFILE',
  );
  return requirement;
}

function shapeBinding(binding) {
  fields(binding, bindingFields);
  requireThat(
    binding.schemaVersion === 1 &&
      binding.profile === EXECUTION_BINDING_PROFILE &&
      binding.enforcement === 'BROKER_ENFORCED' &&
      ['ACTIVE', 'SUSPENDED', 'REVOKED'].includes(binding.status) &&
      Number.isSafeInteger(binding.epoch) &&
      binding.epoch >= 1 &&
      Number.isSafeInteger(binding.issuedAt) &&
      binding.issuedAt >= 0 &&
      Number.isSafeInteger(binding.expiresAt) &&
      binding.expiresAt > binding.issuedAt &&
      binding.expiresAt - binding.issuedAt <= 86400 &&
      typeof binding.providerID === 'string' &&
      /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(binding.providerID) &&
      typeof binding.audience === 'string' &&
      binding.audience.length > 0 &&
      binding.audience.length <= 256,
    'EXECUTION_BINDING_SCHEMA',
  );
  for (const name of ['keyID', 'permitKeyID', 'receiptKeyID', 'policyHash'])
    requireThat(
      Buffer.isBuffer(binding[name]) && binding[name].length === 64,
      'EXECUTION_BINDING_HASH',
    );
  requireThat(
    Buffer.isBuffer(binding.trustDomainID) && binding.trustDomainID.length === 32,
    'EXECUTION_DOMAIN',
  );
  return binding;
}

export function issueExecutionBinding(binding, { certificate, privateKey }) {
  shapeBinding(binding);
  return signCMS({ content: D('ExecutionBinding', binding), certificate }, privateKey);
}

function readBinding(envelope, trust, { active = true, at = now(), checkAuthority = true } = {}) {
  requireThat(Number.isSafeInteger(at) && at >= 0, 'EXECUTION_TIME');
  requireThat(Buffer.isBuffer(envelope) && envelope.length <= 65536, 'EXECUTION_BINDING_LIMIT');
  const binding = shapeBinding(readControl(envelope, 'ExecutionBinding', trust.bindingCertificate));
  const requirement = executionRequirement(trust.policy);
  requireThat(requirement && requirement.providerID === binding.providerID, 'EXECUTION_PROVIDER');
  requireThat(
    equal(binding.trustDomainID, trust.trustDomainID) &&
      equal(binding.policyHash, H('SignaturePolicy', trust.policy)) &&
      binding.audience === trust.policy.audience &&
      equal(binding.permitKeyID, keyID(parseCertificate(trust.permitCertificate).publicKey)) &&
      equal(binding.receiptKeyID, keyID(parseCertificate(trust.receiptCertificate).publicKey)),
    'EXECUTION_AUTHORITY_BINDING',
  );
  requireThat(
    binding.issuedAt <= at &&
      binding.expiresAt > at &&
      binding.expiresAt - binding.issuedAt <= requirement.maxLeaseSeconds &&
      (!active || binding.status === 'ACTIVE'),
    'EXECUTION_BINDING_INACTIVE',
  );
  if (checkAuthority)
    requireAuthority(trust.authorityResolver, {
      certificate: trust.bindingCertificate,
      role: 'EXECUTION_BINDING_AUTHORITY',
      scope: { trustDomainID: trust.trustDomainID },
      stateTime: at,
      knowledgeTime: trust.knowledgeTime ?? at,
    });
  return binding;
}

function requestBinding(
  { permit, tbs, sim },
  binding,
  trust,
  publicKey,
  at,
  checkAuthority = true,
) {
  requireThat(
    Buffer.isBuffer(tbs) && tbs.length > 0 && tbs.length <= 16 * 1024 * 1024,
    'EXECUTION_INPUT_LIMIT',
  );
  requireThat(Buffer.isBuffer(permit) && permit.length <= 1024 * 1024, 'EXECUTION_PERMIT_LIMIT');
  const p = readControl(permit, 'OperationPermit', trust.permitCertificate);
  fields(p, [
    'schemaVersion',
    'activation',
    'activationEvidenceHash',
    'proofMode',
    'issuedAt',
    'expiresAt',
  ]);
  const activation = p.activation;
  const activationHash = validateActivation(activation, {
    tbs,
    publicKey,
    audience: binding.audience,
    at,
    maxLifetime: Math.min(120, trust.policy.maxActivationLifetime),
  });
  requireThat(
    p.schemaVersion === 1 &&
      Number.isSafeInteger(p.issuedAt) &&
      Number.isSafeInteger(p.expiresAt) &&
      p.issuedAt >= activation.issuedAt &&
      p.issuedAt <= at &&
      p.expiresAt > at &&
      p.expiresAt <= activation.expiresAt &&
      p.expiresAt - p.issuedAt <= 30 &&
      p.expiresAt > p.issuedAt &&
      Buffer.isBuffer(p.activationEvidenceHash) &&
      p.activationEvidenceHash.length === 64 &&
      p.proofMode === trust.policy.activationMode,
    'EXECUTION_PERMIT',
  );
  for (const name of [
    'trustDomainID',
    'transactionID',
    'keyID',
    'certificateID',
    'certificateRepresentationHash',
    'policyHash',
  ])
    requireThat(equal(sim[name], activation[name]), 'EXECUTION_SIM_BINDING');
  requireThat(
    equal(binding.keyID, keyID(publicKey)) &&
      equal(binding.policyHash, activation.policyHash) &&
      equal(binding.trustDomainID, activation.trustDomainID) &&
      equal(H('SIM', sim), activation.simHash) &&
      sim.origin === activation.origin &&
      trust.policy.allowedOrigins.includes(sim.origin) &&
      trust.policy.allowedProfiles.includes(sim.profileID) &&
      sim.profileID !== 'CERTCONCORD-PERSON-PASSKEY-SIGN-v1' &&
      Number.isSafeInteger(sim.issuedAt) &&
      Number.isSafeInteger(sim.expiresAt) &&
      sim.issuedAt >= 0 &&
      sim.issuedAt <= activation.issuedAt &&
      sim.expiresAt >= activation.expiresAt &&
      sim.issuedAt <= at &&
      sim.expiresAt > at,
    'EXECUTION_SCOPE',
  );
  const requestHash = H('IntentExecutionRequest', {
    schemaVersion: 1,
    profile: EXECUTION_BINDING_PROFILE,
    bindingHash: sha512(trust.binding),
    permitHash: sha512(permit),
    activationHash,
    simHash: H('SIM', sim),
    tbsHash: sha512(tbs),
    keyID: binding.keyID,
  });
  if (checkAuthority)
    requireOperationAuthorities(
      trust,
      { trustDomainID: activation.trustDomainID, profileID: sim.profileID },
      at,
      trust.knowledgeTime ?? at,
    );
  return { permit: p, activation, activationHash, requestHash };
}

// This boundary requires exclusive backend credentials and rollback-resistant durable state.
// Its signed admission describes a governed broker; it is not hardware attestation.
export class ExecutionBindingGateway {
  #organization;
  constructor({
    journal,
    binding,
    bindingCertificate,
    permitCertificate,
    receiptCertificate,
    receiptKey,
    backend,
    keyRef,
    policy,
    trustDomainID,
    authorize,
    authorityResolver,
    clock = now,
    currentAdmission,
  }) {
    if (Object.hasOwn(policy, 'organizationDelegation')) {
      this.#organization = new OrganizationGateway({
        journal,
        binding,
        bindingCertificate,
        permitCertificate,
        receiptCertificate,
        receiptKey,
        policy,
        trustDomainID,
        backend,
        keyRef,
        authorize,
        clock,
        currentAdmission,
      });
      return;
    }
    requireThat(
      typeof authorize === 'function' &&
        typeof clock === 'function' &&
        typeof keyRef === 'string' &&
        keyRef.length > 0,
      'EXECUTION_CONFIGURATION',
    );
    Object.assign(this, { journal, receiptKey, backend, keyRef, authorize, clock });
    this.trust = {
      binding: Buffer.from(binding),
      bindingCertificate: Buffer.from(bindingCertificate),
      permitCertificate: Buffer.from(permitCertificate),
      receiptCertificate: Buffer.from(receiptCertificate),
      policy: copy(policy),
      trustDomainID: Buffer.from(trustDomainID),
      authorityResolver,
    };
    this.installBinding(binding);
  }
  installBinding(envelope) {
    if (this.#organization) return this.#organization.installBinding(envelope);
    envelope = Buffer.from(envelope);
    const b = readBinding(envelope, this.trust, { active: false, at: this.clock() });
    const id = b64u(H('ExecutionProviderKey', { providerID: b.providerID, keyID: b.keyID }));
    const digest = sha512(envelope);
    this.journal.transaction(() => {
      const old = this.journal.get('execution-binding', id);
      requireThat(!old || old.value.epoch <= b.epoch, 'EXECUTION_EPOCH_ROLLBACK');
      if (old?.value.epoch === b.epoch)
        requireThat(equal(old.value.digest, digest), 'EXECUTION_EPOCH_FORK');
      requireThat(
        !old || old.value.status !== 'REVOKED' || b.status === 'REVOKED',
        'EXECUTION_REVOCATION_TERMINAL',
      );
      if (!old || old.value.epoch < b.epoch)
        this.journal.put(
          'execution-binding',
          id,
          { epoch: b.epoch, digest, status: b.status },
          old?.revision ?? -1,
        );
    });
    this.bindingID = id;
    this.trust.binding = envelope;
  }
  current(binding, envelope) {
    const row = this.journal.get('execution-binding', this.bindingID)?.value;
    requireThat(
      row?.status === 'ACTIVE' &&
        row.epoch === binding.epoch &&
        equal(row.digest, sha512(envelope)),
      'EXECUTION_BINDING_CHANGED',
    );
  }
  async execute(input) {
    if (this.#organization) return this.#organization.execute(input);
    fields(input, ['permit', 'tbs', 'sim']);
    requireThat(
      Buffer.isBuffer(input.permit) &&
        input.permit.length <= 1024 * 1024 &&
        Buffer.isBuffer(input.tbs) &&
        input.tbs.length <= 16 * 1024 * 1024,
      'EXECUTION_INPUT_LIMIT',
    );
    input = copy(input);
    const trust = { ...this.trust, binding: Buffer.from(this.trust.binding) };
    const b = readBinding(trust.binding, trust, { at: this.clock() });
    const capabilities = await this.backend.capabilities(this.keyRef);
    requireThat(capabilities.input === 'MESSAGE', 'EXECUTION_MESSAGE_PROVIDER_REQUIRED');
    let checked = requestBinding(input, b, trust, capabilities.publicKey, this.clock());
    requireThat(
      (await this.authorize(
        copy({
          keyRef: this.keyRef,
          binding: b,
          permit: checked.permit,
          sim: input.sim,
          requestHash: checked.requestHash,
        }),
      )) === true,
      'EXECUTION_DENIED',
    );
    const id = b64u(checked.activation.operationID),
      lockID = b64u(b.keyID);
    const prior = this.journal.transaction(() => {
      readBinding(trust.binding, trust, { at: this.clock() });
      checked = requestBinding(input, b, trust, capabilities.publicKey, this.clock());
      this.current(b, trust.binding);
      const previous = this.journal.reserve(id, checked.requestHash);
      if (previous) {
        requireThat(previous.status === 'COMPLETED', 'UNKNOWN_EXECUTION');
        return decodeCBOR(previous.result);
      }
      const lock = this.journal.get('execution-key-lock', lockID);
      requireThat(!lock || lock.value.operationID === null, 'EXECUTION_KEY_PENDING');
      this.journal.put('execution-key-lock', lockID, { operationID: id }, lock?.revision ?? -1);
      this.journal.put('execution-dispatch', id, {
        input,
        binding: trust.binding,
        dispatchedAt: this.clock(),
      });
      return null;
    });
    if (prior) return prior;
    try {
      const signature = Buffer.from(
        await this.backend.sign({
          keyRef: this.keyRef,
          tbs: Buffer.from(input.tbs),
          operationID: id,
          permit: Buffer.from(input.permit),
        }),
      );
      return await this.finish(id, signature, capabilities.publicKey);
    } catch (error) {
      this.journal.uncertain(id);
      throw error;
    }
  }
  async finish(id, signature, publicKey) {
    if (this.#organization) return this.#organization.finish(id, signature, publicKey);
    signature = Buffer.from(signature);
    const dispatch = this.journal.get('execution-dispatch', id)?.value;
    requireThat(dispatch, 'EXECUTION_DISPATCH_REQUIRED');
    const trust = { ...this.trust, binding: dispatch.binding };
    const b = readBinding(dispatch.binding, trust, { at: this.clock() });
    const checked = requestBinding(dispatch.input, b, trust, publicKey, this.clock());
    requireThat(verify(dispatch.input.tbs, signature, publicKey), 'EXECUTION_SIGNATURE');
    requireThat(
      (await this.authorize(
        copy({
          keyRef: this.keyRef,
          binding: b,
          permit: checked.permit,
          sim: dispatch.input.sim,
          requestHash: checked.requestHash,
        }),
      )) === true,
      'EXECUTION_DENIED',
    );
    return this.journal.transaction(() => {
      const previous = this.journal.result(id);
      if (previous?.status === 'COMPLETED') {
        const result = decodeCBOR(previous.result);
        requireThat(equal(result.signature, signature), 'IDEMPOTENCY_CONFLICT');
        return result;
      }
      const at = this.clock();
      requireThat(at >= dispatch.dispatchedAt, 'EXECUTION_CLOCK_ROLLBACK');
      readBinding(dispatch.binding, trust, { at });
      requestBinding(dispatch.input, b, trust, publicKey, at);
      this.current(b, dispatch.binding);
      const lockID = b64u(b.keyID),
        lock = this.journal.get('execution-key-lock', lockID);
      requireThat(lock?.value.operationID === id, 'EXECUTION_KEY_LOCK');
      const receipt = {
        schemaVersion: 1,
        operationID: checked.activation.operationID,
        activationHash: checked.activationHash,
        permitHash: sha512(dispatch.input.permit),
        keyID: b.keyID,
        tbsHash: sha512(dispatch.input.tbs),
        signatureHash: sha512(signature),
        executedAt: at,
        dispatchedAt: dispatch.dispatchedAt,
        provider: b.providerID,
        executionProfile: EXECUTION_BINDING_PROFILE,
        enforcement: b.enforcement,
        executionBindingHash: sha512(dispatch.binding),
        executionRequestHash: checked.requestHash,
      };
      const result = {
        signature,
        receipt: signCMS(
          { content: D('ExecutionReceipt', receipt), certificate: this.trust.receiptCertificate },
          this.receiptKey,
        ),
        executionEvidence: { binding: dispatch.binding },
      };
      this.journal.reconcile(id, dcbor(result));
      this.journal.put('execution-key-lock', lockID, { operationID: null }, lock.revision);
      return result;
    });
  }
  async reconcile({ operationID, signature }) {
    if (this.#organization) return this.#organization.reconcile({ operationID, signature });
    requireThat(
      Buffer.isBuffer(operationID) && operationID.length === 32,
      'EXECUTION_OPERATION_ID',
    );
    const id = b64u(operationID),
      frozenSignature = Buffer.from(signature);
    const capabilities = await this.backend.capabilities(this.keyRef);
    try {
      return await this.finish(id, frozenSignature, capabilities.publicKey);
    } catch (error) {
      this.journal.uncertain(id);
      throw error;
    }
  }
  getOperationResult(operationID) {
    if (this.#organization) return this.#organization.getOperationResult(operationID);
    requireThat(
      Buffer.isBuffer(operationID) && operationID.length === 32,
      'EXECUTION_OPERATION_ID',
    );
    const result = this.journal.result(b64u(operationID));
    return (
      result && {
        status: result.status,
        ...(result.result ? { result: decodeCBOR(result.result) } : {}),
      }
    );
  }
}

function executionEvidenceMath(
  { policy, sim, permit, tbs, signature, publicKey, receipt, evidence },
  {
    bindingCertificate,
    permitCertificate,
    receiptCertificate,
    trustDomainID,
    at,
    knowledgeTime = at,
  },
) {
  fields(evidence, ['binding']);
  requireThat(Number.isSafeInteger(knowledgeTime) && knowledgeTime >= 0, 'EXECUTION_TIME');
  requireThat(Buffer.isBuffer(bindingCertificate), 'EXECUTION_TRUST_REQUIRED');
  const trust = {
    binding: evidence.binding,
    bindingCertificate,
    permitCertificate,
    receiptCertificate,
    policy,
    trustDomainID,
    knowledgeTime,
  };
  const binding = readBinding(evidence.binding, trust, { at, checkAuthority: false });
  const checked = requestBinding({ permit, tbs, sim }, binding, trust, publicKey, at, false);
  const r = readControl(receipt, 'ExecutionReceipt', receiptCertificate);
  fields(r, [
    'schemaVersion',
    'operationID',
    'activationHash',
    'permitHash',
    'keyID',
    'tbsHash',
    'signatureHash',
    'executedAt',
    'dispatchedAt',
    'provider',
    'executionProfile',
    'enforcement',
    'executionBindingHash',
    'executionRequestHash',
  ]);
  requireThat(
    r.schemaVersion === 1 &&
      r.executionProfile === EXECUTION_BINDING_PROFILE &&
      r.enforcement === 'BROKER_ENFORCED' &&
      r.provider === binding.providerID &&
      equal(r.executionBindingHash, sha512(evidence.binding)) &&
      equal(r.executionRequestHash, checked.requestHash) &&
      equal(r.operationID, checked.activation.operationID) &&
      equal(r.activationHash, checked.activationHash) &&
      equal(r.permitHash, sha512(permit)) &&
      equal(r.keyID, binding.keyID) &&
      equal(r.tbsHash, sha512(tbs)) &&
      equal(r.signatureHash, sha512(signature)) &&
      r.executedAt === at &&
      Number.isSafeInteger(r.dispatchedAt) &&
      r.dispatchedAt >= checked.permit.issuedAt &&
      r.dispatchedAt >= binding.issuedAt &&
      r.dispatchedAt <= at &&
      at <= knowledgeTime &&
      verify(tbs, signature, publicKey),
    'EXECUTION_RECEIPT_BINDING',
  );
  return { binding, checked, trust };
}

export function verifyExecutionEvidence(input, options) {
  requireThat(typeof options.status === 'function', 'EXECUTION_TRUST_REQUIRED');
  const { binding, trust } = executionEvidenceMath(input, options);
  const {
    at,
    knowledgeTime = at,
    authorityResolver,
    status,
    bindingCertificate,
    trustDomainID,
  } = options;
  const { sim } = input;
  requireThat(status(copy(binding), { at, knowledgeTime }) === true, 'EXECUTION_STATUS');
  const scope = { trustDomainID, profileID: sim.profileID };
  requireAuthorities(authorityResolver, [
    {
      certificate: bindingCertificate,
      role: 'EXECUTION_BINDING_AUTHORITY',
      scope,
      stateTime: at,
      knowledgeTime,
    },
    ...operationAuthorityQueries(trust, scope, at, knowledgeTime),
  ]);
  return {
    profile: EXECUTION_BINDING_PROFILE,
    enforcement: 'BROKER_ENFORCED',
    epoch: binding.epoch,
  };
}

/** This selected-profile result supplies mathematics and bindings, never current permission. */
export function verifyOrganizationExecutionEvidence(input, options) {
  organizationSelection(input.policy);
  const { binding, checked } = executionEvidenceMath(input, options);
  return {
    scope: 'MATHEMATICS_AND_BINDINGS_ONLY',
    profile: EXECUTION_BINDING_PROFILE,
    enforcement: binding.enforcement,
    epoch: binding.epoch,
    bindingHash: sha512(input.evidence.binding),
    permitHash: sha512(input.permit),
    executionRequestHash: checked.requestHash,
    keyID: Buffer.from(binding.keyID),
    operationID: Buffer.from(checked.activation.operationID),
  };
}

const ORGANIZATION_PROFILE = 'certconcord-organization-delegation-v1';
const outcomes = ['VALID', 'INVALID', 'UNSUPPORTED', 'INDETERMINATE'];
function admissionError(code, overall = 'INDETERMINATE', checks) {
  const error = new ProtocolError(code);
  error.overall = overall;
  if (checks) error.checks = checks;
  return error;
}
function organizationSelection(policy) {
  const selection = policy?.organizationDelegation;
  fields(selection, ['profile', 'mode', 'identityNamespace', 'minimumApprovers']);
  if (selection.profile !== ORGANIZATION_PROFILE || selection.mode !== 'CURRENT_STATE_ONLY')
    throw admissionError('ORG_PROFILE_UNSUPPORTED', 'UNSUPPORTED');
  requireThat(
    typeof selection.identityNamespace === 'string' &&
      /^[\x21-\x7e]{1,128}$/.test(selection.identityNamespace) &&
      Number.isSafeInteger(selection.minimumApprovers) &&
      selection.minimumApprovers >= 2 &&
      selection.minimumApprovers <= 16 &&
      policy.activationMode === 'WORKLOAD' &&
      policy.requireTrustedTime === false,
    'ORG_POLICY',
  );
  requireThat(!Object.hasOwn(policy, 'documentEvidence'), 'ORG_PLAN_DOWNGRADE');
}

// Snapshot data without invoking user-defined accessors, array iterators or toJSON methods.
function organizationCopy(value, budget = { bytes: 0, nodes: 0 }, depth = 0) {
  requireThat(depth <= 32 && ++budget.nodes <= 100000, 'ORG_INPUT_LIMIT');
  if (Buffer.isBuffer(value)) {
    budget.bytes += value.length;
    requireThat(budget.bytes <= 20 * 1024 * 1024, 'ORG_INPUT_LIMIT');
    return Buffer.from(value);
  }
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    requireThat(Number.isSafeInteger(value), 'ORG_INPUT_SCHEMA');
    return value;
  }
  if (typeof value === 'string') {
    budget.bytes += Buffer.byteLength(value);
    requireThat(budget.bytes <= 20 * 1024 * 1024, 'ORG_INPUT_LIMIT');
    return value;
  }
  requireThat(value && typeof value === 'object', 'ORG_INPUT_SCHEMA');
  const array = Array.isArray(value);
  requireThat(
    array || [Object.prototype, null].includes(Object.getPrototypeOf(value)),
    'ORG_INPUT_SCHEMA',
  );
  const result = array ? [] : Object.create(null);
  if (array) requireThat(value.length <= 100000, 'ORG_INPUT_LIMIT');
  const descriptors = Object.getOwnPropertyDescriptors(value);
  requireThat(Object.getOwnPropertySymbols(value).length === 0, 'ORG_INPUT_SCHEMA');
  if (array)
    for (let i = 0; i < value.length; ++i)
      requireThat(Object.hasOwn(descriptors, i), 'ORG_INPUT_SCHEMA');
  for (const [name, descriptor] of Object.entries(descriptors)) {
    if (array && name === 'length') continue;
    requireThat(Object.hasOwn(descriptor, 'value') && descriptor.enumerable, 'ORG_INPUT_SCHEMA');
    if (array)
      requireThat(
        /^(0|[1-9][0-9]*)$/.test(name) && Number(name) < value.length,
        'ORG_INPUT_SCHEMA',
      );
    Object.defineProperty(result, name, {
      value: organizationCopy(descriptor.value, budget, depth + 1),
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  return result;
}
function synchronousDecision(value) {
  if (types.isPromise(value)) {
    Promise.prototype.then.call(value, undefined, () => {});
    throw admissionError('ORG_CURRENT_ADMISSION_ASYNC');
  }
  try {
    return organizationCopy(value);
  } catch {
    throw admissionError('ORG_CURRENT_ADMISSION_SCHEMA');
  }
}

// Keep Journal's nested get/transaction calls on the same captured implementation as its
// outer calls. The private receiver shares the configured database, not replaceable methods.
function fixedJournal(source) {
  requireThat(source && source.db && !source.depth, 'ORG_JOURNAL_CONFIGURATION');
  const receiver = Object.create(null);
  for (const [name, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(source)))
    if (Object.hasOwn(descriptor, 'value')) receiver[name] = descriptor.value;
  for (const name of ['transaction', 'get', 'put', 'reserve', 'reconcile', 'result', 'uncertain']) {
    requireThat(typeof source[name] === 'function', 'ORG_JOURNAL_CONFIGURATION');
    receiver[name] = source[name].bind(receiver);
  }
  return receiver;
}

class OrganizationGateway {
  #journal;
  #trust;
  #receiptKey;
  #keyRef;
  #authorize;
  #clock;
  #admission;
  #capabilities;
  #sign;
  #bindingID;
  constructor(options) {
    organizationSelection(options.policy);
    requireThat(
      typeof options.authorize === 'function' &&
        typeof options.clock === 'function' &&
        typeof options.keyRef === 'string' &&
        options.keyRef.length > 0,
      'EXECUTION_CONFIGURATION',
    );
    if (typeof options.currentAdmission !== 'function')
      throw admissionError('ORG_CURRENT_ADMISSION_REQUIRED');
    requireThat(
      typeof options.backend?.capabilities === 'function' &&
        typeof options.backend?.sign === 'function',
      'EXECUTION_CONFIGURATION',
    );
    this.#journal = fixedJournal(options.journal);
    this.#trust = organizationCopy({
      binding: options.binding,
      bindingCertificate: options.bindingCertificate,
      permitCertificate: options.permitCertificate,
      receiptCertificate: options.receiptCertificate,
      policy: options.policy,
      trustDomainID: options.trustDomainID,
    });
    this.#receiptKey = options.receiptKey;
    this.#keyRef = options.keyRef;
    this.#authorize = options.authorize;
    this.#clock = options.clock;
    this.#admission = options.currentAdmission;
    this.#capabilities = options.backend.capabilities.bind(options.backend);
    this.#sign = options.backend.sign.bind(options.backend);
    this.installBinding(this.#trust.binding);
  }
  #time() {
    const value = this.#clock();
    if (types.isPromise(value)) {
      Promise.prototype.then.call(value, undefined, () => {});
      throw admissionError('EXECUTION_TIME');
    }
    requireThat(Number.isSafeInteger(value) && value >= 0, 'EXECUTION_TIME');
    return value;
  }
  installBinding(envelope) {
    requireThat(Buffer.isBuffer(envelope), 'EXECUTION_BINDING_LIMIT');
    envelope = Buffer.from(envelope);
    const binding = readBinding(envelope, this.#trust, {
      active: false,
      at: this.#time(),
      checkAuthority: false,
    });
    const id = b64u(
      H('ExecutionProviderKey', { providerID: binding.providerID, keyID: binding.keyID }),
    );
    const digest = sha512(envelope);
    this.#journal.transaction(() => {
      const old = this.#journal.get('execution-binding', id);
      requireThat(!old || old.value.epoch <= binding.epoch, 'EXECUTION_EPOCH_ROLLBACK');
      if (old?.value.epoch === binding.epoch)
        requireThat(equal(old.value.digest, digest), 'EXECUTION_EPOCH_FORK');
      requireThat(
        !old || old.value.status !== 'REVOKED' || binding.status === 'REVOKED',
        'EXECUTION_REVOCATION_TERMINAL',
      );
      if (!old || old.value.epoch < binding.epoch)
        this.#journal.put(
          'execution-binding',
          id,
          { epoch: binding.epoch, digest, status: binding.status },
          old?.revision ?? -1,
        );
    });
    this.#bindingID = id;
    this.#trust.binding = envelope;
  }
  #current(binding, envelope) {
    const row = this.#journal.get('execution-binding', this.#bindingID)?.value;
    requireThat(
      row?.status === 'ACTIVE' &&
        row.epoch === binding.epoch &&
        equal(row.digest, sha512(envelope)),
      'EXECUTION_BINDING_CHANGED',
    );
  }
  #view(stage, input, trust, binding, checked, signature = null) {
    requireThat(
      input.sim.profileID === 'CERTCONCORD-ORG-SEAL-v1' &&
        Buffer.isBuffer(input.sim.organizationID) &&
        input.sim.organizationID.length === 32 &&
        equal(input.sim.organizationID, input.sim.subjectID),
      'ORG_SIM_BINDING',
    );
    return organizationCopy({
      stage,
      keyRef: this.#keyRef,
      binding,
      permit: checked.permit,
      sim: input.sim,
      requestHash: checked.requestHash,
      bindingHash: sha512(trust.binding),
      permitHash: sha512(input.permit),
      keyID: binding.keyID,
      operationID: checked.activation.operationID,
      signatureHash: signature === null ? null : sha512(signature),
    });
  }
  #gate(view) {
    let decision;
    try {
      decision = synchronousDecision(this.#admission(organizationCopy(view)));
    } catch (error) {
      if (outcomes.includes(error?.overall)) throw error;
      throw admissionError('ORG_CURRENT_ADMISSION_UNAVAILABLE');
    }
    if (!decision || !outcomes.includes(decision.overall))
      throw admissionError('ORG_CURRENT_ADMISSION_SCHEMA');
    if (decision.overall !== 'VALID')
      throw admissionError(
        typeof decision.reason === 'string' && decision.reason
          ? decision.reason
          : 'ORG_CURRENT_ADMISSION_DENIED',
        decision.overall,
        decision.checks,
      );
    try {
      fields(decision, ['overall', 'binding', 'journalGuards'], ['reason', 'checks']);
      const binding = decision.binding;
      fields(binding, [
        'stage',
        'operationID',
        'requestHash',
        'bindingHash',
        'permitHash',
        'keyID',
        'signatureHash',
        'knowledgeTime',
      ]);
      requireThat(
        Number.isSafeInteger(binding.knowledgeTime) && binding.knowledgeTime >= 0,
        'ORG_CURRENT_ADMISSION_SCHEMA',
      );
      requireThat(
        Array.isArray(decision.journalGuards) && decision.journalGuards.length === 2,
        'ORG_CURRENT_ADMISSION_SCHEMA',
      );
      for (const guard of decision.journalGuards) {
        fields(guard, ['namespace', 'id', 'revision']);
        requireThat(
          typeof guard.namespace === 'string' &&
            typeof guard.id === 'string' &&
            Number.isSafeInteger(guard.revision) &&
            guard.revision >= 0,
          'ORG_CURRENT_ADMISSION_SCHEMA',
        );
      }
      if (decision.checks) {
        requireThat(
          Array.isArray(decision.checks) && decision.checks.length <= 256,
          'ORG_CURRENT_ADMISSION_SCHEMA',
        );
        for (const check of decision.checks)
          requireThat(check?.overall === 'VALID', 'ORG_CURRENT_ADMISSION_SCHEMA');
      }
    } catch {
      throw admissionError('ORG_CURRENT_ADMISSION_SCHEMA');
    }
    const ticket = decision.binding;
    requireThat(
      ticket.stage === view.stage &&
        ['operationID', 'requestHash', 'bindingHash', 'permitHash', 'keyID'].every((name) =>
          equal(ticket[name], view[name]),
        ) &&
        (view.signatureHash === null
          ? ticket.signatureHash === null
          : equal(ticket.signatureHash, view.signatureHash)),
      'ORG_CURRENT_ADMISSION_BINDING',
    );
    const expected = [
      {
        namespace: 'organization-delegation-operation',
        id: b64u(
          H('OrganizationOperation', {
            profile: ORGANIZATION_PROFILE,
            trustDomainID: this.#trust.trustDomainID,
            organizationID: view.sim.organizationID,
            operationID: view.operationID,
          }),
        ),
      },
      {
        namespace: 'organization-delegation-current',
        id: b64u(H('OrganizationCurrentState', { trustDomainID: this.#trust.trustDomainID })),
      },
    ];
    requireThat(
      expected.every(
        (guard, i) =>
          guard.namespace === decision.journalGuards[i].namespace &&
          guard.id === decision.journalGuards[i].id,
      ),
      'ORG_CURRENT_ADMISSION_GUARD',
    );
    return decision;
  }
  #guards(decision) {
    for (const guard of decision.journalGuards) {
      const row = this.#journal.get(guard.namespace, guard.id);
      if (!row || row.revision !== guard.revision)
        throw admissionError('ORG_CURRENT_ADMISSION_CHANGED');
    }
  }
  async #capability() {
    const capability = await this.#capabilities(this.#keyRef);
    requireThat(capability?.input === 'MESSAGE', 'EXECUTION_MESSAGE_PROVIDER_REQUIRED');
    return publicFromDER(spki(capability.publicKey));
  }
  async execute(input) {
    input = organizationCopy(input);
    fields(input, ['permit', 'tbs', 'sim']);
    const trust = organizationCopy(this.#trust);
    const binding = readBinding(trust.binding, trust, { at: this.#time(), checkAuthority: false });
    const publicKey = await this.#capability();
    const checked = requestBinding(input, binding, trust, publicKey, this.#time(), false);
    const view = this.#view('DISPATCH', input, trust, binding, checked);
    requireThat(
      (await this.#authorize(
        organizationCopy({
          keyRef: this.#keyRef,
          binding,
          permit: checked.permit,
          sim: input.sim,
          requestHash: checked.requestHash,
        }),
      )) === true,
      'EXECUTION_DENIED',
    );
    const decision = this.#gate(view),
      at = decision.binding.knowledgeTime;
    const id = b64u(checked.activation.operationID),
      lockID = b64u(binding.keyID);
    const prior = this.#journal.transaction(() => {
      readBinding(trust.binding, trust, { at, checkAuthority: false });
      requestBinding(input, binding, trust, publicKey, at, false);
      this.#guards(decision);
      this.#current(binding, trust.binding);
      const previous = this.#journal.reserve(id, checked.requestHash);
      if (previous) {
        requireThat(previous.status === 'COMPLETED', 'UNKNOWN_EXECUTION');
        return decodeCBOR(previous.result);
      }
      const lock = this.#journal.get('execution-key-lock', lockID);
      requireThat(!lock || lock.value.operationID === null, 'EXECUTION_KEY_PENDING');
      this.#journal.put('execution-key-lock', lockID, { operationID: id }, lock?.revision ?? -1);
      this.#journal.put('execution-dispatch', id, {
        input,
        binding: trust.binding,
        dispatchedAt: at,
      });
      return null;
    });
    if (prior) return prior;
    try {
      const result = await this.#sign({
        keyRef: this.#keyRef,
        tbs: Buffer.from(input.tbs),
        operationID: id,
        permit: Buffer.from(input.permit),
      });
      requireThat(Buffer.isBuffer(result), 'EXECUTION_SIGNATURE');
      return await this.finish(id, Buffer.from(result), publicKey);
    } catch (error) {
      try {
        this.#journal.uncertain(id);
      } catch {
        /* The reservation remains authoritative. */
      }
      throw error;
    }
  }
  async finish(id, signature, publicKey) {
    requireThat(Buffer.isBuffer(signature) && signature.length <= 65536, 'EXECUTION_SIGNATURE');
    signature = Buffer.from(signature);
    publicKey = publicFromDER(spki(publicKey));
    const dispatch = this.#journal.get('execution-dispatch', id)?.value;
    requireThat(dispatch, 'EXECUTION_DISPATCH_REQUIRED');
    const trust = { ...organizationCopy(this.#trust), binding: Buffer.from(dispatch.binding) };
    const binding = readBinding(dispatch.binding, trust, {
      at: this.#time(),
      checkAuthority: false,
    });
    const checked = requestBinding(dispatch.input, binding, trust, publicKey, this.#time(), false);
    requireThat(verify(dispatch.input.tbs, signature, publicKey), 'EXECUTION_SIGNATURE');
    const view = this.#view('COMPLETE', dispatch.input, trust, binding, checked, signature);
    requireThat(
      (await this.#authorize(
        organizationCopy({
          keyRef: this.#keyRef,
          binding,
          permit: checked.permit,
          sim: dispatch.input.sim,
          requestHash: checked.requestHash,
        }),
      )) === true,
      'EXECUTION_DENIED',
    );
    const decision = this.#gate(view),
      at = decision.binding.knowledgeTime;
    return this.#journal.transaction(() => {
      requireThat(at >= dispatch.dispatchedAt, 'EXECUTION_CLOCK_ROLLBACK');
      readBinding(dispatch.binding, trust, { at, checkAuthority: false });
      requestBinding(dispatch.input, binding, trust, publicKey, at, false);
      this.#guards(decision);
      this.#current(binding, dispatch.binding);
      const previous = this.#journal.result(id);
      if (previous?.status === 'COMPLETED') {
        const result = decodeCBOR(previous.result);
        requireThat(equal(result.signature, signature), 'IDEMPOTENCY_CONFLICT');
        return result;
      }
      const lockID = b64u(binding.keyID),
        lock = this.#journal.get('execution-key-lock', lockID);
      requireThat(lock?.value.operationID === id, 'EXECUTION_KEY_LOCK');
      const receipt = {
        schemaVersion: 1,
        operationID: checked.activation.operationID,
        activationHash: checked.activationHash,
        permitHash: sha512(dispatch.input.permit),
        keyID: binding.keyID,
        tbsHash: sha512(dispatch.input.tbs),
        signatureHash: sha512(signature),
        executedAt: at,
        dispatchedAt: dispatch.dispatchedAt,
        provider: binding.providerID,
        executionProfile: EXECUTION_BINDING_PROFILE,
        enforcement: binding.enforcement,
        executionBindingHash: sha512(dispatch.binding),
        executionRequestHash: checked.requestHash,
      };
      const result = {
        signature,
        receipt: signCMS(
          { content: D('ExecutionReceipt', receipt), certificate: trust.receiptCertificate },
          this.#receiptKey,
        ),
        executionEvidence: { binding: dispatch.binding },
      };
      this.#journal.reconcile(id, dcbor(result));
      this.#journal.put('execution-key-lock', lockID, { operationID: null }, lock.revision);
      return result;
    });
  }
  async reconcile({ operationID, signature }) {
    requireThat(
      Buffer.isBuffer(operationID) && operationID.length === 32 && Buffer.isBuffer(signature),
      'EXECUTION_OPERATION_ID',
    );
    const id = b64u(operationID),
      candidate = Buffer.from(signature);
    try {
      return await this.finish(id, candidate, await this.#capability());
    } catch (error) {
      try {
        this.#journal.uncertain(id);
      } catch {
        /* Never repeat the private operation. */
      }
      throw error;
    }
  }
  getOperationResult(operationID) {
    requireThat(
      Buffer.isBuffer(operationID) && operationID.length === 32,
      'EXECUTION_OPERATION_ID',
    );
    const result = this.#journal.result(b64u(operationID));
    return (
      result && {
        status: result.status,
        ...(result.result ? { result: decodeCBOR(result.result) } : {}),
      }
    );
  }
}

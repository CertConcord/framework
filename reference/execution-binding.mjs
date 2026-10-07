import { requireAuthority } from './authority-history.mjs';
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
} from './core.mjs';
import { parseCertificate, signCMS } from './pki.mjs';
import { readControl, validateActivation } from './state.mjs';

export const EXECUTION_BINDING_PROFILE = 'certconcord-execution-binding-draft-02';
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
  }) {
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

export function verifyExecutionEvidence(
  { policy, sim, permit, tbs, signature, publicKey, receipt, evidence },
  {
    bindingCertificate,
    permitCertificate,
    receiptCertificate,
    trustDomainID,
    at,
    knowledgeTime = at,
    authorityResolver,
    status,
  },
) {
  fields(evidence, ['binding']);
  requireThat(Number.isSafeInteger(knowledgeTime) && knowledgeTime >= 0, 'EXECUTION_TIME');
  requireThat(
    typeof status === 'function' && Buffer.isBuffer(bindingCertificate),
    'EXECUTION_TRUST_REQUIRED',
  );
  const trust = {
    binding: evidence.binding,
    bindingCertificate,
    permitCertificate,
    receiptCertificate,
    policy,
    trustDomainID,
    authorityResolver,
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

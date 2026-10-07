import { requireOperationAuthorities } from './control-authority.mjs';
import {
  D,
  H,
  b64u,
  random,
  now,
  equal,
  requireThat,
  sha512,
  spki,
  keyID,
  publicFromDER,
  octet,
  parseDER,
  dcbor,
  decodeCBOR,
} from './core.mjs';
import { prepareCSR, completeCSR, verifyCSR } from './enrollment.mjs';
import { RRA, extension, parseCertificate, signCMS } from './pki.mjs';
import { readControl, validateActivation } from './state.mjs';
import {
  PASSKEY_SIGN_PROFILE,
  rawExtension,
  verifySigningKeyGeneration,
  verifyRawSigningAssertion,
  storeParentCounter,
} from './raw-signing.mjs';
import { deriveARKG, ARKG_OPERATION } from './arkg.mjs';
import { issueCRL } from './revocation.mjs';

const savedParent = (r) => ({
  credentialID: r.credentialID,
  publicKeyDER: spki(r.publicKey),
  counter: r.counter,
  backupEligible: r.backupEligible,
  backedUp: r.backedUp ?? false,
  attestationVerified: r.attestationVerified === true,
  rpID: r.rpID,
  origin: r.origin,
  ...(r.aaguid ? { aaguid: r.aaguid } : {}),
});
const restoredParent = (r) => ({ ...r, publicKey: publicFromDER(r.publicKeyDER) });
const idText = (id) => (typeof id === 'string' ? id : b64u(id));
const possessionContext = (context, generation, csrInfo, publicKey, additionalArgs) => ({
  schemaVersion: 1,
  enrollmentHash: H('PasskeyKeyEnrollment', context),
  documentKeyID: keyID(publicKey),
  csrInfoHash: sha512(csrInfo),
  parentCredentialIDHash: sha512(generation.registration.credentialID),
  keyHandleHash: sha512(generation.keyHandle),
  version: generation.version,
  algorithm: generation.algorithm,
  additionalArgsHash: sha512(additionalArgs ?? Buffer.alloc(0)),
});

export class PasskeySigningRegistry {
  constructor({
    journal,
    trustDomainID,
    policyHash,
    rpID,
    origin,
    attestationPolicy,
    registrationAuthorityCertificate,
    certificateVerifier,
    mdocVerifier,
    maxValidity = 90 * 86400,
  }) {
    requireThat(
      (typeof certificateVerifier === 'function' || typeof mdocVerifier === 'function') &&
        maxValidity > 0 &&
        maxValidity <= 90 * 86400,
      'PASSKEY_REGISTRY_POLICY',
    );
    Object.assign(this, {
      journal,
      trustDomainID,
      policyHash,
      rpID,
      origin,
      attestationPolicy,
      registrationAuthorityCertificate,
      certificateVerifier,
      mdocVerifier,
      maxValidity,
    });
  }
  begin({
    subjectID,
    subject,
    identityEvidenceHash,
    version = 'previewSign5-2026-09-09',
    algorithms = [-9],
  }) {
    rawExtension(version);
    requireThat(
      Buffer.isBuffer(subjectID) &&
        subjectID.length === 32 &&
        (identityEvidenceHash === undefined ||
          (Buffer.isBuffer(identityEvidenceHash) && identityEvidenceHash.length === 64)) &&
        Buffer.isBuffer(subject) &&
        subject.length <= 4096 &&
        Array.isArray(algorithms) &&
        algorithms.length > 0 &&
        algorithms.length <= 3 &&
        new Set(algorithms).size === algorithms.length &&
        algorithms.every((a) => [-9, -300, ARKG_OPERATION].includes(a)),
      'PASSKEY_ENROLLMENT_FIELDS',
    );
    requireThat(parseDER(subject).tag === 48, 'PASSKEY_SUBJECT');
    const context = {
      schemaVersion: 1,
      requestID: random(),
      trustDomainID: this.trustDomainID,
      policyHash: this.policyHash,
      subjectID,
      subject,
      ...(identityEvidenceHash ? { identityEvidenceHash } : {}),
      profileID: PASSKEY_SIGN_PROFILE,
      rpID: this.rpID,
      origin: this.origin,
      version,
      algorithms,
      issuedAt: now(),
      expiresAt: now() + 120,
    };
    this.journal.put('passkey-enrollment', b64u(context.requestID), { state: 'PENDING', context });
    return { context, challenge: H('PasskeyKeyEnrollment', context) };
  }
  generation(evidence, context) {
    return verifySigningKeyGeneration(
      { ...evidence, registration: evidence.registration && restoredParent(evidence.registration) },
      {
        challenge: H('PasskeyKeyEnrollment', context),
        origin: this.origin,
        rpID: this.rpID,
        version: context.version,
        algorithms: context.algorithms,
        attestationPolicy: this.attestationPolicy,
      },
    );
  }
  stage({ requestID, ceremony, generatedKey, registration, derivationIKM }) {
    const id = idText(requestID),
      row = this.journal.get('passkey-enrollment', id);
    requireThat(
      row?.value.state === 'PENDING' && row.value.context.expiresAt > now(),
      'PASSKEY_ENROLLMENT_STATE',
    );
    let knownParent;
    if (!ceremony.response.attestationObject) {
      knownParent = this.journal.get('passkey-parent-registration', ceremony.rawId)?.value;
      requireThat(
        knownParent &&
          (!registration || equal(spki(registration.publicKey), knownParent.publicKeyDER)),
        'RAW_PARENT_REGISTRATION',
      );
    }
    const context = row.value.context,
      evidence = { ceremony, generatedKey, ...(knownParent ? { registration: knownParent } : {}) };
    const g = this.generation(evidence, context);
    let publicKey = g.publicKey,
      additionalArgs,
      derivation;
    if (g.algorithm === ARKG_OPERATION) {
      const ctx = H('PasskeyARKGContext', {
        enrollmentHash: H('PasskeyKeyEnrollment', context),
        parentCredentialIDHash: sha512(g.registration.credentialID),
        seedHash: sha512(g.publicKeyBytes),
      });
      const result = deriveARKG({
        seedPublicKey: g.publicKeyBytes,
        ikm: derivationIKM,
        context: ctx,
      });
      publicKey = result.publicKey;
      additionalArgs = result.additionalArgs;
      derivation = { ikm: derivationIKM, context: ctx, ticket: result.ticket };
    } else requireThat(derivationIKM === undefined, 'PASSKEY_UNEXPECTED_DERIVATION');
    requireThat(
      !equal(keyID(publicKey), keyID(g.registration.publicKey)),
      'RAW_KEY_ROLE_COLLISION',
    );
    const csr = prepareCSR({ subject: context.subject, publicKey });
    const possession = possessionContext(context, g, csr.info, publicKey, additionalArgs);
    this.journal.transaction(() => {
      const parentStatus = this.journal.get(
        'passkey-parent-status',
        b64u(g.registration.credentialID),
      );
      requireThat(
        !parentStatus || parentStatus.value.status === 'ACTIVE',
        'PASSKEY_PARENT_INACTIVE',
      );
      if (!ceremony.response.attestationObject)
        storeParentCounter(this.journal, g.registration, { counter: g.parentCounter });
      else {
        const parentID = b64u(g.registration.credentialID);
        requireThat(
          !this.journal.get('passkey-parent-registration', parentID),
          'RAW_PARENT_REGISTRATION_EXISTS',
        );
        this.journal.put('passkey-parent-registration', parentID, savedParent(g.registration));
      }
      this.journal.put(
        'passkey-enrollment',
        id,
        {
          state: 'POSSESSION_REQUIRED',
          context,
          evidence,
          parent: savedParent({ ...g.registration, counter: g.parentCounter }),
          documentSPKI: spki(publicKey),
          csrInfo: csr.info,
          possession,
          ...(derivation ? { derivation, additionalArgs } : {}),
        },
        row.revision,
      );
    });
    return {
      bindingID: context.requestID,
      tbs: csr.info,
      challenge: H('PasskeyKeyPossession', possession),
      credentialID: g.registration.credentialID,
      keyHandle: g.keyHandle,
      algorithm: g.algorithm,
      version: g.version,
      rpID: this.rpID,
      ...(additionalArgs ? { additionalArgs } : {}),
    };
  }
  finish({ bindingID, assertion, signature }) {
    const id = idText(bindingID),
      row = this.journal.get('passkey-enrollment', id),
      r = row?.value;
    requireThat(
      r?.state === 'POSSESSION_REQUIRED' && r.context.expiresAt > now(),
      'PASSKEY_ENROLLMENT_STATE',
    );
    const g = this.generation(r.evidence, r.context),
      publicKey = publicFromDER(r.documentSPKI);
    const proof = verifyRawSigningAssertion({ assertion, signature }, restoredParent(r.parent), {
      challenge: H('PasskeyKeyPossession', r.possession),
      version: g.version,
      algorithm: g.algorithm,
      publicKey,
      tbs: r.csrInfo,
    });
    const csr = completeCSR(prepareCSR({ subject: r.context.subject, publicKey }), signature);
    const binding = {
      schemaVersion: 1,
      bindingID: r.context.requestID,
      trustDomainID: this.trustDomainID,
      subjectID: r.context.subjectID,
      policyHash: this.policyHash,
      profileID: PASSKEY_SIGN_PROFILE,
      ...(r.context.identityEvidenceHash
        ? { identityEvidenceHash: r.context.identityEvidenceHash }
        : {}),
      csrHash: sha512(csr),
      documentKeyID: keyID(publicKey),
      documentSPKI: r.documentSPKI,
      parentCredentialIDHash: sha512(g.registration.credentialID),
      parentSPKIHash: sha512(spki(g.registration.publicKey)),
      rpID: this.rpID,
      origin: this.origin,
      version: g.version,
      algorithm: g.algorithm,
      keyHandleHash: sha512(g.keyHandle),
      additionalArgsHash: sha512(r.additionalArgs ?? Buffer.alloc(0)),
      attestationHash: g.attestationHash,
      generationProofHash: g.generationProofHash,
      possessionProofHash: proof.evidenceHash,
      modelPolicyHash: g.modelPolicyHash,
      keyAssurance: { level: g.level, custody: g.custody, fixedFlags: 5 },
      issuedAt: now(),
      expiresAt: Math.min(now() + this.maxValidity, g.expiresAt),
      ...(r.derivation ? { derivation: r.derivation, seedHash: sha512(g.publicKeyBytes) } : {}),
    };
    this.journal.transaction(() => {
      storeParentCounter(this.journal, restoredParent(r.parent), proof);
      this.journal.put(
        'passkey-enrollment',
        id,
        {
          ...r,
          state: 'ADMITTED',
          csr,
          binding,
          possessionProof: { assertion, signature },
          parent: { ...r.parent, counter: proof.counter },
        },
        row.revision,
      );
    });
    return { csr, binding, bindingHash: H('PasskeySigningBinding', binding) };
  }
  admitted(bindingID) {
    const row = this.journal.get('passkey-enrollment', idText(bindingID)),
      r = row?.value;
    requireThat(
      r && ['ADMITTED', 'ACTIVE'].includes(r.state) && r.binding.expiresAt > now(),
      'PASSKEY_BINDING_INACTIVE',
    );
    const status = this.journal.get('passkey-parent-status', b64u(r.parent.credentialID));
    requireThat(!status || status.value.status === 'ACTIVE', 'PASSKEY_PARENT_INACTIVE');
    const g = this.generation(r.evidence, r.context);
    requireThat(
      equal(g.attestationHash, r.binding.attestationHash) &&
        equal(g.modelPolicyHash, r.binding.modelPolicyHash),
      'PASSKEY_ATTESTATION_POLICY_CHANGED',
    );
    return r;
  }
  forIssuance(
    bindingID,
    { csr, subjectID, policyHash, profileID, identityEvidenceHash, requestID },
  ) {
    const r = this.admitted(bindingID),
      binding = r.binding;
    if (r.state === 'ACTIVE') {
      const original = readControl(
        r.rar,
        'RegistrationAuthorization',
        this.registrationAuthorityCertificate,
      );
      requireThat(
        requestID && equal(requestID, original.requestID),
        'PASSKEY_ISSUANCE_ALREADY_ACTIVE',
      );
    }
    requireThat(
      equal(sha512(csr), binding.csrHash) &&
        equal(subjectID, binding.subjectID) &&
        equal(policyHash, binding.policyHash) &&
        profileID === binding.profileID &&
        Buffer.isBuffer(identityEvidenceHash) &&
        identityEvidenceHash.length === 64 &&
        (!binding.identityEvidenceHash ||
          equal(identityEvidenceHash, binding.identityEvidenceHash)),
      'PASSKEY_ISSUANCE_BINDING',
    );
    verifyCSR(csr, { expectedSPKI: binding.documentSPKI });
    return { binding, hash: H('PasskeySigningBinding', binding), assurance: binding.keyAssurance };
  }
  activate(bindingID, { certificate, rar }) {
    const r = this.admitted(bindingID);
    requireThat(!r.credential, 'PASSKEY_CERTIFICATE_CONFLICT');
    const a = readControl(rar, 'RegistrationAuthorization', this.registrationAuthorityCertificate);
    const admission = this.forIssuance(bindingID, { ...a, csr: r.csr });
    requireThat(equal(a.keyBindingHash, admission.hash), 'PASSKEY_RA_BINDING');
    requireThat(
      this.certificateVerifier(certificate, { profileID: PASSKEY_SIGN_PROFILE }) === true,
      'PASSKEY_CERTIFICATE_TRUST',
    );
    const cert = parseCertificate(certificate);
    checkPasskeyCertificate(cert, admission.binding);
    requireThat(
      equal(
        parseDER(cert.extensions.get(RRA['id-pe-certconcordAuthorizationID']).value).value,
        H('RegistrationAuthorization', a),
      ),
      'PASSKEY_CERTIFICATE_RA',
    );
    const row = this.journal.get('passkey-enrollment', idText(bindingID));
    requireThat(
      !row.value.credential &&
        (!row.value.certificate || equal(row.value.certificate, certificate)),
      'PASSKEY_CERTIFICATE_CONFLICT',
    );
    if (row.value.state === 'ACTIVE') return admission.binding;
    this.journal.put(
      'passkey-enrollment',
      idText(bindingID),
      { ...row.value, state: 'ACTIVE', certificate, rar },
      row.revision,
    );
    return admission.binding;
  }
  active(bindingID) {
    const r = this.admitted(bindingID);
    requireThat(r.state === 'ACTIVE', 'PASSKEY_CERTIFICATE_INACTIVE');
    this.credentialInfo(r);
    return r;
  }
  activateMdoc(bindingID, { credential, seal, rar }) {
    const r = this.admitted(bindingID);
    requireThat(!r.certificate, 'PASSKEY_CERTIFICATE_CONFLICT');
    const a = readControl(rar, 'RegistrationAuthorization', this.registrationAuthorityCertificate);
    const admission = this.forIssuance(bindingID, { ...a, csr: r.csr });
    requireThat(equal(a.keyBindingHash, admission.hash), 'PASSKEY_RA_BINDING');
    const info = this.credentialInfo({ ...r, credential, seal });
    requireThat(equal(info.claims.ra_authorization_hash, sha512(rar)), 'PASSKEY_CERTIFICATE_RA');
    const row = this.journal.get('passkey-enrollment', idText(bindingID));
    requireThat(
      !row.value.certificate &&
        (!row.value.credential ||
          (equal(row.value.credential, credential) && equal(row.value.seal, seal))),
      'PASSKEY_CERTIFICATE_CONFLICT',
    );
    if (row.value.state !== 'ACTIVE')
      this.journal.put(
        'passkey-enrollment',
        idText(bindingID),
        {
          ...row.value,
          state: 'ACTIVE',
          credential,
          seal,
          rar,
        },
        row.revision,
      );
    return admission.binding;
  }
  credentialInfo(r) {
    if (r.credential) {
      requireThat(typeof this.mdocVerifier === 'function', 'PASSKEY_MDOC_TRUST');
      const v = this.mdocVerifier(r.credential, { seal: r.seal });
      checkPasskeyMdoc(v, r.binding);
      return { ...v, certificateID: v.credentialID, representationHash: v.representationHash };
    }
    requireThat(
      typeof this.certificateVerifier === 'function' &&
        this.certificateVerifier(r.certificate, { profileID: PASSKEY_SIGN_PROFILE }) === true,
      'PASSKEY_CERTIFICATE_INACTIVE',
    );
    return parseCertificate(r.certificate);
  }
  registration(bindingID) {
    const r = this.active(bindingID),
      counter = this.journal.get('credential-counter', b64u(r.parent.credentialID));
    return {
      ...restoredParent(r.parent),
      counter: counter?.value.counter ?? r.parent.counter,
      active: true,
      keyID: r.binding.documentKeyID,
      subjectID: r.binding.subjectID,
    };
  }
  change({ authorization }) {
    const c = readControl(
      authorization,
      'PasskeyBindingChange',
      this.registrationAuthorityCertificate,
    );
    requireThat(
      c.schemaVersion === 1 &&
        equal(c.trustDomainID, this.trustDomainID) &&
        equal(c.policyHash, this.policyHash) &&
        c.issuedAt <= now() &&
        c.expiresAt > now() &&
        c.expiresAt - c.issuedAt <= 120 &&
        ['SUSPENDED', 'REVOKED'].includes(c.status) &&
        typeof c.reason === 'string' &&
        c.reason.length > 0 &&
        c.reason.length <= 128,
      'PASSKEY_LIFECYCLE_AUTHORITY',
    );
    return this.journal.transaction(() => {
      const id = idText(c.bindingID),
        row = this.journal.get('passkey-enrollment', id);
      requireThat(
        row?.value.binding && row.revision === c.revision && row.value.state !== 'REVOKED',
        'PASSKEY_LIFECYCLE_STATE',
      );
      this.journal.put('passkey-lifecycle-command', b64u(sha512(authorization)), {
        receivedAt: now(),
      });
      const event = {
        bindingID: row.value.binding.bindingID,
        status: c.status,
        reason: c.reason,
        effectiveAt: now(),
        commandHash: sha512(authorization),
        ...(row.value.certificate ? { certificate: row.value.certificate } : {}),
      };
      this.journal.put('passkey-status-outbox', b64u(sha512(authorization)), event);
      this.journal.put(
        'passkey-enrollment',
        id,
        { ...row.value, state: c.status, lifecycleEvent: event },
        row.revision,
      );
      if (c.cascadeParent === true) {
        const parentID = b64u(row.value.parent.credentialID),
          prior = this.journal.get('passkey-parent-status', parentID);
        requireThat(
          prior?.value.status !== 'REVOKED' || c.status === 'REVOKED',
          'PASSKEY_PARENT_REVOCATION_TERMINAL',
        );
        this.journal.put(
          'passkey-parent-status',
          parentID,
          {
            status: c.status,
            effectiveAt: prior?.value.effectiveAt ?? event.effectiveAt,
            commandHash: sha512(authorization),
          },
          prior?.revision ?? -1,
        );
        // An issuer consumes the durable event and publishes every affected credential's status.
        this.journal.put('passkey-parent-status-outbox', b64u(sha512(authorization)), {
          ...event,
          parentCredentialIDHash: row.value.binding.parentCredentialIDHash,
        });
      }
      return event;
    });
  }
}

export function passkeyCertificateExtensions(admission) {
  return [extension(RRA['id-pe-certconcordPasskeyBinding'], octet(admission.hash), true)];
}
export function checkPasskeyCertificate(cert, binding) {
  const e = cert.extensions.get(RRA['id-pe-certconcordPasskeyBinding']);
  requireThat(
    e?.critical &&
      equal(parseDER(e.value).value, H('PasskeySigningBinding', binding)) &&
      equal(cert.spki, binding.documentSPKI) &&
      binding.profileID === PASSKEY_SIGN_PROFILE,
    'PASSKEY_CERTIFICATE_BINDING',
  );
}
export function checkPasskeyMdoc(v, binding) {
  requireThat(
    v?.documentKeyMode === 'PASSKEY_KEY' &&
      equal(v.claims.passkey_binding_hash, H('PasskeySigningBinding', binding)) &&
      equal(v.claims.subject_id, binding.subjectID) &&
      equal(v.claims.policy_hash, binding.policyHash) &&
      equal(v.claims.trust_domain_id, binding.trustDomainID) &&
      equal(spki(v.publicKey), binding.documentSPKI),
    'PASSKEY_MDOC_BINDING',
  );
}
export const rawOperationChallenge = (permit, binding) =>
  H('PasskeyRawOperation', {
    schemaVersion: 1,
    permitHash: sha512(permit),
    bindingHash: H('PasskeySigningBinding', binding),
  });

export class PasskeySigningService {
  constructor({
    journal,
    registry,
    permitCertificate,
    receiptCertificate,
    receiptKey,
    audience,
    authorize,
    authorityResolver,
  }) {
    requireThat(
      journal === registry.journal && typeof authorize === 'function',
      'PASSKEY_SERVICE_POLICY',
    );
    Object.assign(this, {
      journal,
      registry,
      permitCertificate,
      receiptCertificate,
      receiptKey,
      audience,
      authorize,
      authorityResolver,
    });
  }
  async check({ bindingID, permit, tbs }) {
    const r = this.registry.active(bindingID),
      p = readControl(permit, 'OperationPermit', this.permitCertificate);
    requireOperationAuthorities(this, { trustDomainID: p.activation.trustDomainID, profileID: PASSKEY_SIGN_PROFILE }, now());
    requireThat(
      p.proofMode === 'HUMAN_WEBAUTHN' &&
        p.issuedAt <= now() &&
        p.expiresAt > now() &&
        p.expiresAt <= p.activation.expiresAt &&
        p.expiresAt - p.issuedAt <= 30,
      'PASSKEY_PREAUTHORIZATION',
    );
    const cert = this.registry.credentialInfo(r),
      a = p.activation;
    const activationHash = validateActivation(a, {
      tbs,
      publicKey: cert.publicKey,
      audience: this.audience,
    });
    requireThat(
      equal(a.trustDomainID, r.binding.trustDomainID) &&
        equal(a.policyHash, r.binding.policyHash) &&
        equal(a.certificateID, cert.certificateID) &&
        equal(a.certificateRepresentationHash, cert.representationHash) &&
        a.origin === r.binding.origin &&
        a.rpID === r.binding.rpID,
      'PASSKEY_OPERATION_BINDING',
    );
    requireThat(
      (await this.authorize({
        binding: r.binding,
        ...(r.credential ? { credential: r.credential } : { certificate: r.certificate }),
        permit: p,
        tbs,
        activationHash,
      })) === true,
      'PASSKEY_OPERATION_DENIED',
    );
    requireThat(p.expiresAt > now() && a.expiresAt > now(), 'PASSKEY_PREAUTHORIZATION');
    this.registry.active(bindingID);
    return { r, p, activationHash };
  }
  async begin(input) {
    input = decodeCBOR(dcbor(input));
    const { r, p } = await this.check(input),
      id = b64u(p.activation.operationID);
    const digest = H('PasskeyDispatch', {
      bindingID: r.binding.bindingID,
      permitHash: sha512(input.permit),
      tbsHash: sha512(input.tbs),
    });
    return this.journal.transaction(() => {
      requireThat(p.expiresAt > now(), 'PASSKEY_PREAUTHORIZATION');
      const prior = this.journal.reserve(id, digest);
      requireThat(
        !prior,
        prior?.status === 'COMPLETED' ? 'PASSKEY_RESULT_ALREADY_AVAILABLE' : 'UNKNOWN_EXECUTION',
      );
      const keyLock = this.journal.get('passkey-operation-lock', b64u(r.binding.bindingID));
      requireThat(!keyLock || keyLock.value.operationID === null, 'PASSKEY_KEY_OPERATION_PENDING');
      const challenge = rawOperationChallenge(input.permit, r.binding),
        request = {
          operationID: p.activation.operationID,
          credentialID: r.parent.credentialID,
          keyHandle: r.evidence.generatedKey.keyHandle,
          version: r.binding.version,
          algorithm: r.binding.algorithm,
          rpID: r.binding.rpID,
          challenge,
          tbs: input.tbs,
          ...(r.additionalArgs ? { additionalArgs: r.additionalArgs } : {}),
        };
      this.journal.put('passkey-dispatch', id, {
        ...input,
        bindingID: r.binding.bindingID,
        registration: savedParent(this.registry.registration(input.bindingID)),
        request,
        dispatchedAt: now(),
      });
      this.journal.put(
        'passkey-operation-lock',
        b64u(r.binding.bindingID),
        { operationID: id },
        keyLock?.revision ?? -1,
      );
      return request;
    });
  }
  async complete({ operationID, assertion, signature }) {
    ({ operationID, assertion, signature } = decodeCBOR(
      dcbor({ operationID, assertion, signature }),
    ));
    const id = idText(operationID),
      responseHash = H('PasskeyRawResponse', { assertion, signature });
    const completed = this.journal.get('passkey-result', id);
    if (completed) {
      requireThat(equal(completed.value.responseHash, responseHash), 'IDEMPOTENCY_CONFLICT');
      return completed.value.result;
    }
    const dispatch = this.journal.get('passkey-dispatch', id)?.value;
    requireThat(dispatch, 'PASSKEY_DISPATCH_REQUIRED');
    try {
      const { r, p, activationHash } = await this.check(dispatch);
      const proof = verifyRawSigningAssertion(
        { assertion, signature },
        restoredParent(dispatch.registration),
        {
          challenge: dispatch.request.challenge,
          version: r.binding.version,
          algorithm: r.binding.algorithm,
          publicKey: publicFromDER(r.binding.documentSPKI),
          tbs: dispatch.tbs,
        },
      );
      return this.journal.transaction(() => {
        const again = this.journal.get('passkey-result', id);
        if (again) {
          requireThat(equal(again.value.responseHash, responseHash), 'IDEMPOTENCY_CONFLICT');
          return again.value.result;
        }
        this.registry.active(dispatch.bindingID);
        requireThat(p.expiresAt > now(), 'PASSKEY_PREAUTHORIZATION');
        storeParentCounter(this.journal, restoredParent(dispatch.registration), proof);
        const receipt = {
          schemaVersion: 1,
          operationID: p.activation.operationID,
          activationHash,
          permitHash: sha512(dispatch.permit),
          keyID: r.binding.documentKeyID,
          tbsHash: sha512(dispatch.tbs),
          signatureHash: sha512(signature),
          executedAt: now(),
          provider: 'certconcord-passkey-signing-v1',
          enforcement: 'PREAUTHORIZED_EVIDENCE',
          bindingHash: H('PasskeySigningBinding', r.binding),
          rawProofHash: proof.evidenceHash,
          dispatchedAt: dispatch.dispatchedAt,
        };
        const result = {
          signature,
          assertion,
          receipt: signCMS(
            { content: D('ExecutionReceipt', receipt), certificate: this.receiptCertificate },
            this.receiptKey,
          ),
        };
        // A verified late response reconciles UNKNOWN_EXECUTION without another signing invocation.
        this.journal.reconcile(id, dcbor(result));
        this.journal.put('passkey-result', id, { responseHash, result });
        const lock = this.journal.get('passkey-operation-lock', b64u(r.binding.bindingID));
        requireThat(lock?.value.operationID === id, 'PASSKEY_OPERATION_LOCK');
        this.journal.put(
          'passkey-operation-lock',
          b64u(r.binding.bindingID),
          { operationID: null },
          lock.revision,
        );
        return result;
      });
    } catch (e) {
      this.journal.uncertain(id);
      throw e;
    }
  }
  getOperationResult(operationID) {
    const result = this.journal.result(idText(operationID));
    return (
      result && {
        status: result.status,
        ...(result.result ? { result: decodeCBOR(result.result) } : {}),
      }
    );
  }
}

export function verifyPasskeyOperation(
  {
    permit,
    tbs,
    signature,
    assertion,
    receipt,
    binding,
    registration,
    certificate,
    credential,
    seal,
  },
  {
    permitCertificate,
    receiptCertificate,
    certificateVerifier,
    mdocVerifier,
    audience,
    at = now(),
    knowledgeTime = at,
    authorityResolver,
    status,
  },
) {
  requireThat(
    typeof status === 'function' && status({ binding, certificate, credential, at }) === true,
    'PASSKEY_EVIDENCE_TRUST',
  );
  let cert;
  if (credential) {
    requireThat(!certificate && typeof mdocVerifier === 'function', 'PASSKEY_EVIDENCE_TRUST');
    const v = mdocVerifier(credential, { seal, at });
    checkPasskeyMdoc(v, binding);
    cert = { ...v, certificateID: v.credentialID };
  } else {
    requireThat(
      typeof certificateVerifier === 'function' &&
        certificateVerifier(certificate, { at, profileID: PASSKEY_SIGN_PROFILE }) === true,
      'PASSKEY_EVIDENCE_TRUST',
    );
    cert = parseCertificate(certificate);
    checkPasskeyCertificate(cert, binding);
  }
  const p = readControl(permit, 'OperationPermit', permitCertificate);
  const activationHash = validateActivation(p.activation, {
    tbs,
    publicKey: cert.publicKey,
    audience,
    at,
  });
  requireThat(
    p.proofMode === 'HUMAN_WEBAUTHN' &&
      p.issuedAt <= at &&
      p.expiresAt > at &&
      p.expiresAt <= p.activation.expiresAt &&
      p.expiresAt - p.issuedAt <= 30 &&
      binding.issuedAt <= at &&
      binding.expiresAt > at &&
      equal(p.activation.trustDomainID, binding.trustDomainID) &&
      equal(p.activation.policyHash, binding.policyHash) &&
      equal(p.activation.certificateID, cert.certificateID) &&
      equal(p.activation.certificateRepresentationHash, cert.representationHash) &&
      p.activation.origin === binding.origin &&
      p.activation.rpID === binding.rpID &&
      equal(sha512(registration.credentialID), binding.parentCredentialIDHash) &&
      equal(sha512(spki(registration.publicKey)), binding.parentSPKIHash),
    'PASSKEY_EVIDENCE_BINDING',
  );
  const proof = verifyRawSigningAssertion({ assertion, signature }, registration, {
    challenge: rawOperationChallenge(permit, binding),
    version: binding.version,
    algorithm: binding.algorithm,
    origin: binding.origin,
    rpID: binding.rpID,
    publicKey: cert.publicKey,
    tbs,
  });
  const r = readControl(receipt, 'ExecutionReceipt', receiptCertificate);
  requireThat(
    r.provider === 'certconcord-passkey-signing-v1' &&
      r.enforcement === 'PREAUTHORIZED_EVIDENCE' &&
      equal(r.operationID, p.activation.operationID) &&
      equal(r.keyID, binding.documentKeyID) &&
      equal(r.activationHash, activationHash) &&
      equal(r.permitHash, sha512(permit)) &&
      equal(r.signatureHash, sha512(signature)) &&
      equal(r.tbsHash, sha512(tbs)) &&
      equal(r.bindingHash, H('PasskeySigningBinding', binding)) &&
      equal(r.rawProofHash, proof.evidenceHash) &&
      r.dispatchedAt >= p.issuedAt &&
      r.dispatchedAt <= r.executedAt &&
      r.executedAt <= at &&
      r.executedAt < p.expiresAt,
    'PASSKEY_EXECUTION_RECEIPT',
  );
  requireOperationAuthorities({ permitCertificate, receiptCertificate, authorityResolver },
    { trustDomainID: binding.trustDomainID, profileID: PASSKEY_SIGN_PROFILE }, at, knowledgeTime);
  return {
    cryptographicValidity: 'VALID',
    authorization: 'PREAUTHORIZED_EVIDENCE',
    keyAssurance: binding.keyAssurance,
    quantumResistance: 'CLASSICAL',
    proof,
    receipt: r,
  };
}

export function publishPasskeyCRL({
  registry,
  issuer,
  privateKey,
  existingEntries,
  nextUpdate = now() + 300,
}) {
  requireThat(Array.isArray(existingEntries), 'PASSKEY_COMPLETE_CRL_INVENTORY_REQUIRED');
  const journal = registry.journal;
  return journal.transaction(() => {
    const id = b64u(H('PasskeyCRLIssuer', issuer)),
      previous = journal.get('passkey-crl', id);
    const inventory = new Map();
    const merge = (entry) => {
      const serial = String(entry.serial),
        old = inventory.get(serial);
      inventory.set(serial, {
        ...old,
        ...entry,
        serial,
        reason: old && old.reason !== 6 ? old.reason : entry.reason,
        revokedAt: old ? Math.min(old.revokedAt, entry.revokedAt) : entry.revokedAt,
        ...(old?.invalidityDate !== undefined || entry.invalidityDate !== undefined
          ? {
              invalidityDate: Math.min(
                old?.invalidityDate ?? Infinity,
                entry.invalidityDate ?? Infinity,
              ),
            }
          : {}),
      });
    };
    for (const entry of [...(previous?.value.entries ?? []), ...existingEntries]) merge(entry);
    for (const row of journal.list('passkey-enrollment')) {
      const r = journal.get('passkey-enrollment', row.id).value;
      if (!r.certificate) continue;
      const cert = parseCertificate(r.certificate);
      if (!equal(cert.issuer, issuer)) continue;
      const parent = journal.get('passkey-parent-status', b64u(r.parent.credentialID));
      if (
        ['SUSPENDED', 'REVOKED'].includes(r.state) ||
        ['SUSPENDED', 'REVOKED'].includes(parent?.value.status)
      ) {
        merge({
          serial: cert.serial,
          reason: r.state === 'REVOKED' || parent?.value.status === 'REVOKED' ? 1 : 6,
          revokedAt: Math.min(
            r.lifecycleEvent?.effectiveAt ?? Infinity,
            parent?.value.effectiveAt ?? Infinity,
          ),
        });
      }
    }
    const entries = [...inventory.values()];
    const number = (previous?.value.number ?? 0) + 1;
    const crl = issueCRL({ issuer, privateKey, number, entries, nextUpdate });
    journal.put('passkey-crl', id, { number, crl, entries }, previous?.revision ?? -1);
    return crl;
  });
}

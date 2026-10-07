import { createPublicKey } from 'node:crypto';
import { requireAuthorities } from './control-authority.mjs';
import {
  D,
  H,
  dcbor,
  decodeCBOR,
  sha256,
  sha512,
  equal,
  requireThat,
  now,
  b64u,
  keyID,
  spki,
  publicFromDER,
  random,
  fields,
} from './core.mjs';
import { signCMS, parseCertificate } from './pki.mjs';
import {
  readControl,
  issuePermit,
  validateActivation,
  assertRecoverySeparation,
} from './state.mjs';
import { verifyAssertion } from './webauthn.mjs';
import { encryptCMS } from './protection.mjs';

export function makeBatch(contexts) {
  requireThat(
    Array.isArray(contexts) && contexts.length >= 1 && contexts.length <= 100,
    'BATCH_SIZE',
  );
  const first = contexts[0];
  for (const context of contexts) {
    requireThat(!Object.hasOwn(context, 'batchHash'), 'BATCH_RECURSIVE_HASH');
    for (const field of ['trustDomainID', 'transactionID', 'policyHash'])
      requireThat(equal(context[field], first[field]), 'BATCH_CONTEXT');
    for (const field of ['origin', 'rpID', 'audience', 'issuedAt', 'expiresAt'])
      requireThat(context[field] === first[field], 'BATCH_CONTEXT');
  }
  requireThat(
    new Set(contexts.map((c) => b64u(c.operationID))).size === contexts.length &&
      new Set(contexts.map((c) => b64u(c.serverNonce))).size === contexts.length,
    'BATCH_DUPLICATE',
  );
  const manifest = { schemaVersion: 1, contexts },
    hash = H('ActivationBatch', manifest);
  return { manifest, hash, contexts: contexts.map((c) => ({ ...c, batchHash: hash })) };
}
export function authorizeWebAuthnBatch({
  manifest,
  items,
  assertion,
  registration,
  policy,
  journal,
  permitCertificate,
  permitKey,
  authorizeItem,
}) {
  requireThat(
    policy.batchEnabled === true &&
      policy.activationMode === 'HUMAN_WEBAUTHN' &&
      typeof authorizeItem === 'function',
    'BATCH_POLICY',
  );
  const batch = makeBatch(manifest.contexts);
  requireThat(
    items.length === batch.contexts.length && items.length <= policy.maxBatchSize,
    'BATCH_SIZE',
  );
  for (let i = 0; i < items.length; i++) {
    const { activation, tbs, publicKey, sim } = items[i];
    requireThat(equal(dcbor(activation), dcbor(batch.contexts[i])), 'BATCH_MEMBERSHIP');
    validateActivation(activation, {
      tbs,
      publicKey,
      audience: policy.audience,
      maxLifetime: policy.maxActivationLifetime,
    });
    requireThat(
      equal(activation.simHash, H('SIM', sim)) &&
        equal(activation.policyHash, H('SignaturePolicy', policy)) &&
        equal(registration.keyID, activation.keyID) &&
        equal(registration.subjectID, sim.subjectID) &&
        registration.active,
      'BATCH_AUTHORITY',
    );
    requireThat(
      sim.expiresAt >= activation.expiresAt &&
        sim.issuedAt <= now() &&
        sim.origin === activation.origin &&
        policy.allowedProfiles.includes(sim.profileID) &&
        policy.allowedOrigins.includes(activation.origin) &&
        activation.rpID === policy.rpID,
      'BATCH_SIM',
    );
    for (const f of [
      'trustDomainID',
      'transactionID',
      'keyID',
      'certificateID',
      'certificateRepresentationHash',
      'policyHash',
    ])
      requireThat(equal(sim[f], activation[f]), 'BATCH_SIM');
    requireThat(authorizeItem(items[i]) === true, 'BATCH_ITEM_DENIED');
  }
  const proof = verifyAssertion(assertion, registration, {
    challenge: batch.hash,
    origin: batch.contexts[0].origin,
    rpID: policy.rpID,
    uv: true,
  });
  return journal.transaction(() => {
    for (const c of batch.contexts) journal.consumeNonce('activation', b64u(c.serverNonce));
    const id = b64u(registration.credentialID),
      old = journal.get('credential-counter', id);
    requireThat(
      !old || (proof.counter === 0 && old.value.counter === 0) || proof.counter > old.value.counter,
      'SIGN_COUNT_CONCURRENT_REPLAY',
    );
    journal.put('credential-counter', id, { counter: proof.counter }, old?.revision ?? -1);
    return batch.contexts.map((a) =>
      issuePermit(a, {
        certificate: permitCertificate,
        privateKey: permitKey,
        proofMode: 'HUMAN_WEBAUTHN',
        activationEvidenceHash: H('BatchActivationEvidence', {
          batchHash: batch.hash,
          assertionHash: proof.assertionHash,
        }),
      }),
    );
  });
}

export class CapabilityRegistry {
  constructor({ journal, certificate, trustDomainID }) {
    Object.assign(this, { journal, certificate, trustDomainID });
  }
  challenge({ registration, publicKey, expiresAt }) {
    requireThat(
      registration.active && expiresAt > now() && expiresAt <= now() + 30 * 86400,
      'CAPABILITY_ENROLLMENT',
    );
    return {
      schemaVersion: 1,
      trustDomainID: this.trustDomainID,
      subjectID: registration.subjectID,
      credentialIDHash: sha256(registration.credentialID),
      documentKeyID: registration.keyID,
      publicKey: spki(publicKey),
      purpose: 'REMOTE_SIGNING_ACTIVATION',
      nonce: this.journal.issueNonce('capability-enrollment'),
      issuedAt: now(),
      expiresAt,
    };
  }
  enroll(context, assertion, registration) {
    requireThat(
      registration.active &&
        equal(context.trustDomainID, this.trustDomainID) &&
        equal(context.subjectID, registration.subjectID) &&
        equal(context.credentialIDHash, sha256(registration.credentialID)) &&
        equal(context.documentKeyID, registration.keyID) &&
        context.purpose === 'REMOTE_SIGNING_ACTIVATION' &&
        context.issuedAt <= now() &&
        context.expiresAt > now() &&
        context.expiresAt - context.issuedAt <= 30 * 86400,
      'CAPABILITY_ENROLLMENT_BINDING',
    );
    const proof = verifyAssertion(assertion, registration, {
      challenge: H('CapabilityEnrollment', context),
      uv: true,
    });
    return this.journal.transaction(() => {
      this.journal.consumeNonce('capability-enrollment', context.nonce);
      const id = b64u(registration.credentialID),
        old = this.journal.get('capability', id),
        record = {
          ...context,
          epoch: (old?.value.epoch ?? -1) + 1,
          status: 'ACTIVE',
          assertionHash: proof.assertionHash,
        };
      this.journal.put('capability', id, record, old?.revision ?? -1);
      return record;
    });
  }
  active(registration) {
    const r = this.journal.get('capability', b64u(registration.credentialID))?.value;
    requireThat(
      registration.active &&
        r?.status === 'ACTIVE' &&
        r.expiresAt > now() &&
        equal(r.documentKeyID, registration.keyID) &&
        equal(r.subjectID, registration.subjectID) &&
        equal(r.trustDomainID, this.trustDomainID),
      'CAPABILITY_INACTIVE',
    );
    return { ...r, publicKey: publicFromDER(r.publicKey) };
  }
  revoke(registration, { authorization }) {
    const r = this.journal.get('capability', b64u(registration.credentialID)),
      a = readControl(authorization, 'CapabilityRevocation', this.certificate);
    requireThat(
      r &&
        equal(a.credentialIDHash, r.value.credentialIDHash) &&
        a.epoch === r.value.epoch &&
        a.expiresAt > now(),
      'CAPABILITY_REVOCATION_AUTHORITY',
    );
    this.journal.put(
      'capability',
      b64u(registration.credentialID),
      { ...r.value, status: 'REVOKED', revokedAt: now() },
      r.revision,
    );
  }
}

export class EncryptionRecoveryService {
  constructor({
    journal,
    approvers,
    threshold,
    graph,
    attackerRoots,
    signingTargets,
    loadEncryptionRoot,
    certificate,
    privateKey,
    trustDomainID,
    authorityResolver,
  }) {
    requireThat(
      Buffer.isBuffer(trustDomainID) &&
        trustDomainID.length === 32 &&
        typeof loadEncryptionRoot === 'function',
      'RECOVERY_CONFIGURATION',
    );
    requireThat(
      Number.isSafeInteger(threshold) &&
        threshold >= 2 &&
        Array.isArray(approvers) &&
        approvers.every((a) => typeof a.operatorID === 'string' && a.operatorID.length > 0) &&
        threshold <= approvers.length &&
        new Set(approvers.map((a) => b64u(keyID(parseCertificate(a.certificate).publicKey))))
          .size === approvers.length &&
        new Set(approvers.map((a) => a.operatorID)).size >= threshold,
      'RECOVERY_THRESHOLD',
    );
    assertRecoverySeparation(graph, attackerRoots, signingTargets);
    Object.assign(this, {
      journal,
      approvers: approvers.map((a) => ({
        certificate: Buffer.from(a.certificate),
        operatorID: a.operatorID,
      })),
      threshold,
      graph: decodeCBOR(dcbor(graph)),
      attackerRoots: [...attackerRoots],
      signingTargets: [...signingTargets],
      loadEncryptionRoot,
      certificate: Buffer.from(certificate),
      privateKey,
      trustDomainID: Buffer.from(trustDomainID),
      authorityResolver,
    });
  }
  async recover(request, approvals, recipientPublicKey) {
    request = decodeCBOR(dcbor(request));
    fields(request, [
      'schemaVersion',
      'trustDomainID',
      'requestID',
      'targetRootID',
      'subjectID',
      'recipientKeyID',
      'purpose',
      'issuedAt',
      'expiresAt',
    ]);
    requireThat(
      Array.isArray(approvals) &&
        approvals.length <= 128 &&
        approvals.every((approval) => Buffer.isBuffer(approval)),
      'RECOVERY_APPROVAL',
    );
    approvals = approvals.map((approval) => Buffer.from(approval));
    requireThat(
      request.schemaVersion === 1 &&
        request.purpose === 'ENCRYPTION_VAULT_WRAP' &&
        equal(request.trustDomainID, this.trustDomainID) &&
        [request.requestID, request.targetRootID, request.subjectID].every(
          (value) => Buffer.isBuffer(value) && value.length === 32,
        ) &&
        Number.isSafeInteger(request.issuedAt) &&
        request.issuedAt >= 0 &&
        Number.isSafeInteger(request.expiresAt) &&
        request.issuedAt <= now() &&
        request.expiresAt > now() &&
        request.expiresAt - request.issuedAt <= 300 &&
        equal(request.recipientKeyID, keyID(recipientPublicKey)) &&
        recipientPublicKey.asymmetricKeyType.startsWith('ml-kem-'),
      'RECOVERY_REQUEST',
    );
    assertRecoverySeparation(this.graph, this.attackerRoots, this.signingTargets);
    const hash = H('EncryptionRecoveryRequest', request),
      operators = new Set(),
      approvalAuthorities = new Map();
    for (const approval of approvals) {
      for (const authority of this.approvers) {
        try {
          const a = readControl(approval, 'EncryptionRecoveryApproval', authority.certificate);
          fields(a, ['requestHash', 'approved', 'expiresAt']);
          requireThat(
            equal(a.requestHash, hash) &&
              a.approved === true &&
              Number.isSafeInteger(a.expiresAt) &&
              a.expiresAt >= request.expiresAt,
            'RECOVERY_APPROVAL',
          );
          operators.add(authority.operatorID);
          approvalAuthorities.set(
            b64u(keyID(parseCertificate(authority.certificate).publicKey)),
            authority.certificate,
          );
          break;
        } catch {}
      }
    }
    requireThat(operators.size >= this.threshold, 'RECOVERY_APPROVAL_THRESHOLD');
    const checkAuthority = () => {
      const at = now(),
        scope = { trustDomainID: this.trustDomainID, purpose: request.purpose };
      requireThat(
        equal(
          keyID(parseCertificate(this.certificate).publicKey),
          keyID(createPublicKey(this.privateKey)),
        ),
        'RECOVERY_RESULT_KEY_BINDING',
      );
      requireAuthorities(
        this.authorityResolver,
        [...approvalAuthorities.values(), this.certificate].map((certificate) => ({
          certificate,
          role: 'RECOVERY_AUTHORITY',
          scope,
          stateTime: at,
          knowledgeTime: at,
        })),
      );
    };
    checkAuthority();
    const id = b64u(request.requestID),
      operationID = 'recovery:' + b64u(this.trustDomainID) + ':' + id,
      previous = this.journal.reserve(operationID, hash);
    if (previous) {
      requireThat(previous.status === 'COMPLETED', 'UNKNOWN_EXECUTION');
      return Buffer.from(previous.result);
    }
    let root;
    try {
      root = await this.loadEncryptionRoot({
        trustDomainID: Buffer.from(request.trustDomainID),
        rootID: Buffer.from(request.targetRootID),
        subjectID: Buffer.from(request.subjectID),
        purpose: request.purpose,
      });
      requireThat(Buffer.isBuffer(root) && root.length === 32, 'RECOVERY_ROOT');
      requireThat(request.expiresAt > now(), 'RECOVERY_EXPIRED');
      checkAuthority();
      assertRecoverySeparation(this.graph, this.attackerRoots, this.signingTargets);
      const encrypted = encryptCMS(
          dcbor({
            schemaVersion: 1,
            trustDomainID: request.trustDomainID,
            requestHash: hash,
            root,
          }),
          [{ publicKey: recipientPublicKey, subjectKeyIdentifier: request.recipientKeyID }],
        ),
        receipt = signCMS(
          {
            content: D('EncryptionRecoveryResult', {
              trustDomainID: request.trustDomainID,
              requestHash: hash,
              ciphertextHash: sha512(encrypted),
              operatorIDs: [...operators].sort(),
              issuedAt: now(),
            }),
            certificate: this.certificate,
          },
          this.privateKey,
        ),
        result = dcbor({ encrypted, receipt });
      this.journal.complete(operationID, result);
      return result;
    } catch (e) {
      this.journal.uncertain(operationID);
      throw e;
    } finally {
      root?.fill(0);
    }
  }
  result(requestID) {
    requireThat(Buffer.isBuffer(requestID) && requestID.length === 32, 'RECOVERY_REQUEST_ID');
    return this.journal.result('recovery:' + b64u(this.trustDomainID) + ':' + b64u(requestID));
  }
}

import test from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { Journal, activationContext, readControl } from './state.mjs';
import { Mirror, verifyMTC } from './mtc.mjs';
import { createCSR, RegistrationAuthority } from './enrollment.mjs';
import { MTCIssuer } from './issuance.mjs';
import { LandmarkPublisher, LandmarkStore, parseLandmarks } from './landmark.mjs';
import {
  makeBatch,
  authorizeWebAuthnBatch,
  CapabilityRegistry,
  EncryptionRecoveryService,
} from './lifecycle.mjs';
import { decryptCMS } from './protection.mjs';

const control = () => {
  const key = c.generate('ml-dsa-87'),
    name = p.name('Synthetic Authority'),
    certificate = p.issueCertificate(
      {
        publicKey: key.publicKey,
        subject: name,
        issuer: name,
        serial: 1,
        profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1',
      },
      key.privateKey,
    );
  return { ...key, certificate };
};
function assertion(key, registration, challenge, counter = 1) {
  const cd = Buffer.from(
      JSON.stringify({
        type: 'webauthn.get',
        challenge: c.b64u(challenge),
        origin: registration.origin,
        crossOrigin: false,
      }),
    ),
    n = Buffer.alloc(4);
  n.writeUInt32BE(counter);
  const ad = Buffer.concat([c.sha256(Buffer.from(registration.rpID)), Buffer.from([5]), n]),
    id = c.b64u(registration.credentialID);
  return {
    id,
    rawId: id,
    type: 'public-key',
    response: {
      clientDataJSON: c.b64u(cd),
      authenticatorData: c.b64u(ad),
      signature: c.b64u(c.sign(Buffer.concat([ad, c.sha256(cd)]), key.privateKey)),
    },
  };
}

test('RA-authorized MTC issuance requires independent durable mirrors; landmark representation preserves TBS', async () => {
  const journal = new Journal(),
    ra = control(),
    ca = control(),
    key = c.generate(),
    policyHash = c.random(64),
    rtmHash = c.random(64),
    subjectID = c.random(),
    profileID = 'CERTCONCORD-PERSON-SIGN-v1',
    caID = '32473.7',
    logNumber = 1,
    members = [
      { id: '32473.8', operatorID: 'a', ...c.generate('ml-dsa-87') },
      { id: '32473.9', operatorID: 'b', ...c.generate('ml-dsa-87') },
    ],
    mirrors = members.map((m) => new Mirror({ journal, id: m.id, privateKey: m.privateKey })),
    raService = new RegistrationAuthority({
      journal,
      ...ra,
      approve: async () => ({ approved: true }),
    }),
    csr = createCSR({
      subject: p.name('Synthetic Subject'),
      publicKey: key.publicKey,
      privateKey: key.privateKey,
    }),
    rar = await raService.authorize({
      csr,
      subjectID,
      profileID,
      policyHash,
      identityEvidenceHash: c.random(64),
    }),
    options = {
      journal,
      caID,
      logNumber,
      policyHash,
      rtmHash,
      membershipEpoch: 1,
      members,
      threshold: 2,
      caPublicKey: ca.publicKey,
    };
  try {
    const issuer = new MTCIssuer({
        ...options,
        raCertificate: ra.certificate,
        privateKey: ca.privateKey,
        mirrors,
        allowedProfiles: [profileID],
      }),
      cert = await issuer.issue({ csr, rar });
    assert(c.equal(cert, await issuer.issue({ csr, rar })));
    assert.equal(verifyMTC(cert, { ...options, profileID }).mode, 'STANDALONE');
    const entries = issuer.log.entries(0, issuer.log.head().size),
      publisher = new LandmarkPublisher({
        ...options,
        caKey: ca.privateKey,
        certificate: ca.certificate,
        mirrors,
      });
    publisher.allocate(entries, {
      expiresAt: c.now() + 2 * 86400,
      certificateExpiries: [p.parseCertificate(cert).notAfter],
    });
    const distribution = await publisher.publish(entries),
      store = new LandmarkStore({ ...options, certificate: ca.certificate }),
      trustedSubtrees = store.accept(distribution),
      relative = publisher.relative(p.parseCertificate(cert).tbs, { entries, index: 0 });
    assert(c.equal(p.parseCertificate(relative).tbs, p.parseCertificate(cert).tbs));
    assert.equal(verifyMTC(relative, { ...options, trustedSubtrees }).mode, 'LANDMARK');
    assert.throws(
      () =>
        verifyMTC(relative, {
          ...options,
          trustedSubtrees,
          revokedRanges: [{ logNumber: 1, start: 0, end: 1 }],
        }),
      /REVOKED/,
    );
    assert.throws(() => parseLandmarks('1\n1 9999999999\n0 0\n', { draft06Strict: true }), /COUNT/);
  } finally {
    journal.close();
  }
});

test('batch consent authenticates exact complete ordered contexts and consumes every nonce', () => {
  const journal = new Journal(),
    auth = control(),
    key = c.generate('ec'),
    docKey = c.generate(),
    origin = 'https://example.org',
    registration = {
      active: true,
      credentialID: c.random(),
      publicKey: key.publicKey,
      subjectID: c.random(),
      keyID: c.keyID(docKey.publicKey),
      rpID: 'example.org',
      origin,
      counter: 0,
      backupEligible: false,
    },
    policy = {
      activationMode: 'HUMAN_WEBAUTHN',
      allowedProfiles: ['CERTCONCORD-PERSON-SIGN-v1'],
      allowedOrigins: [origin],
      rpID: 'example.org',
      audience: 'gateway',
      maxActivationLifetime: 120,
      batchEnabled: true,
      maxBatchSize: 3,
    },
    trustDomainID = c.random(),
    transactionID = c.random(),
    at = c.now(),
    items = [1, 2].map((i) => {
      const tbs = Buffer.from('message' + i),
        sim = {
          schemaVersion: 1,
          trustDomainID,
          transactionID,
          subjectID: registration.subjectID,
          profileID: 'CERTCONCORD-PERSON-SIGN-v1',
          keyID: registration.keyID,
          certificateID: c.random(64),
          certificateRepresentationHash: c.random(64),
          policyHash: c.H('SignaturePolicy', policy),
          origin,
          issuedAt: at,
          expiresAt: at + 120,
        },
        activation = activationContext({
          ...sim,
          tbs,
          publicKey: docKey.publicKey,
          simHash: c.H('SIM', sim),
          rpID: policy.rpID,
          audience: policy.audience,
          serverNonce: c.unb64u(journal.issueNonce('activation')),
          issuedAt: at,
          expiresAt: at + 120,
        });
      return { tbs, sim, activation, publicKey: docKey.publicKey };
    }),
    batch = makeBatch(items.map((i) => i.activation));
  items.forEach((x, i) => (x.activation = batch.contexts[i]));
  const options = {
    manifest: batch.manifest,
    items,
    assertion: assertion(key, registration, batch.hash),
    registration,
    policy,
    journal,
    permitCertificate: auth.certificate,
    permitKey: auth.privateKey,
    authorizeItem: () => true,
  };
  try {
    assert.throws(
      () => authorizeWebAuthnBatch({ ...options, items: [...items].reverse() }),
      /MEMBERSHIP/,
    );
    assert.equal(authorizeWebAuthnBatch(options).length, 2);
    assert.throws(() => authorizeWebAuthnBatch(options), /REPLAY/);
    assert.throws(
      () => makeBatch([batch.manifest.contexts[0], batch.manifest.contexts[0]]),
      /DUPLICATE/,
    );
  } finally {
    journal.close();
  }
});

test('PRF capability public enrollment binds credential and document key, revocation is effective', () => {
  const journal = new Journal(),
    authority = control(),
    credential = c.generate('ec'),
    cap = c.generate(),
    registration = {
      active: true,
      credentialID: c.random(),
      publicKey: credential.publicKey,
      subjectID: c.random(),
      keyID: c.random(64),
      rpID: 'example.org',
      origin: 'https://example.org',
      counter: 0,
      backupEligible: false,
    },
    registry = new CapabilityRegistry({
      journal,
      certificate: authority.certificate,
      trustDomainID: c.random(),
    });
  try {
    const context = registry.challenge({
        registration,
        publicKey: cap.publicKey,
        expiresAt: c.now() + 3600,
      }),
      proof = assertion(credential, registration, c.H('CapabilityEnrollment', context)),
      record = registry.enroll(context, proof, registration);
    assert(c.equal(c.keyID(registry.active(registration).publicKey), c.keyID(cap.publicKey)));
    assert.throws(() => registry.enroll(context, proof, registration), /REPLAY/);
    record.publicKey.fill(0);
    record.status = 'REVOKED';
    assert(c.equal(c.keyID(registry.active(registration).publicKey), c.keyID(cap.publicKey)));
    const authorization = p.signCMS(
      {
        content: c.D('CapabilityRevocation', {
          credentialIDHash: record.credentialIDHash,
          epoch: record.epoch,
          expiresAt: c.now() + 60,
        }),
        certificate: authority.certificate,
      },
      authority.privateKey,
    );
    registry.revoke(registration, { authorization });
    assert.throws(() => registry.active(registration), /INACTIVE/);
  } finally {
    journal.close();
  }
});

test('encryption recovery needs distinct approvals, encrypts only to bound recipient, excludes signing paths', async () => {
  const journal = new Journal(),
    authorities = [control(), control()],
    receipt = control(),
    kem = c.generate('ml-kem-768'),
    root = c.random(),
    graph = {
      nodes: ['admin', 'kra', 'encryption', 'signing'],
      edges: [{ from: ['admin', 'kra'], threshold: 2, to: 'encryption' }],
    },
    service = new EncryptionRecoveryService({
      journal,
      approvers: authorities.map((a, i) => ({
        certificate: a.certificate,
        operatorID: 'operator' + i,
      })),
      threshold: 2,
      graph,
      attackerRoots: ['admin', 'kra'],
      signingTargets: ['signing'],
      loadEncryptionRoot: async () => Buffer.from(root),
      ...receipt,
    }),
    request = {
      schemaVersion: 1,
      requestID: c.random(),
      targetRootID: c.random(),
      subjectID: c.random(),
      recipientKeyID: c.keyID(kem.publicKey),
      purpose: 'ENCRYPTION_VAULT_WRAP',
      issuedAt: c.now(),
      expiresAt: c.now() + 120,
    },
    approvals = authorities.map((a) =>
      p.signCMS(
        {
          content: c.D('EncryptionRecoveryApproval', {
            requestHash: c.H('EncryptionRecoveryRequest', request),
            approved: true,
            expiresAt: request.expiresAt,
          }),
          certificate: a.certificate,
        },
        a.privateKey,
      ),
    );
  try {
    await assert.rejects(
      service.recover(request, [approvals[0], approvals[0]], kem.publicKey),
      /THRESHOLD/,
    );
    const raw = await service.recover(request, approvals, kem.publicKey),
      result = c.decodeCBOR(raw),
      plain = c.decodeCBOR(
        decryptCMS(result.encrypted, {
          privateKey: kem.privateKey,
          subjectKeyIdentifier: request.recipientKeyID,
        }),
      );
    assert(c.equal(plain.root, root));
    assert(c.equal(raw, await service.recover(request, approvals, kem.publicKey)));
    await assert.rejects(
      service.recover({ ...request, purpose: 'SIGNING_VAULT_WRAP' }, approvals, kem.publicKey),
      /REQUEST/,
    );
  } finally {
    journal.close();
  }
});

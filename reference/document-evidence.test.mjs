import test from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { evaluateStatus, readControl } from './state.mjs';
import { evidenceLeaf, createEvidencePackage } from './evidence-plan.mjs';
import { runDemo } from './demo.mjs';
import { runFoundationDemo } from './foundation-demo.mjs';
import { runDocumentDemo } from './document-demo.mjs';
import { createVerifier } from './sdk/index.mjs';
import { documentPlans } from './document-evidence.mjs';
import {
  admitDocumentRecipient,
  encryptDocument,
  decryptDocument,
} from './document-encryption.mjs';
import { parseTSTInfo } from './archive.mjs';
import { verifyMTC } from './mtc.mjs';
import { encryptCMS, decryptCMS } from './protection.mjs';
import { createAuthorityResolver } from './authority-history.mjs';

function replace(bundle, type, payload, planChanges = {}) {
  const objects = bundle.objects.map((o) => (o.type === type ? evidenceLeaf(type, payload) : o));
  const replaced = createEvidencePackage(bundle.plan.profile, objects);
  return { ...replaced, plan: { ...replaced.plan, ...planChanges } };
}

test('offline document verification retains standalone MTC trust, time and status requirements', async (t) => {
  const r = await runDemo({ trustedTime: true, activationMode: 'HUMAN_WEBAUTHN' }),
    trust = { ...r.trust, mtc: { ...r.trust.mtc, trustedSubtrees: [] } },
    certificate = r.bundle.objects.find((o) => o.type === 'Certificate').payload,
    network = t.mock.method(globalThis, 'fetch', () => {
      throw new Error('Offline verification attempted a network request');
    }),
    verify = (bundle, policy = trust) =>
      createVerifier({ format: 'CMS', trust: policy }).verify(c.dcbor(bundle));
  assert.equal(verifyMTC(certificate, trust.mtc).mode, 'STANDALONE');
  assert.equal(verify(r.bundle).overall, 'VALID');
  for (const type of ['CertificateStatus', 'RegistrationAuthorization', 'DocumentTimestamp']) {
    const missing = { ...r.bundle, objects: r.bundle.objects.filter((o) => o.type !== type) };
    assert.deepEqual(
      { overall: verify(missing).overall, reason: verify(missing).reason },
      { overall: 'INDETERMINATE', reason: 'ECP_MISSING_OBJECT' },
    );
  }
  const later = verify(r.bundle, { ...trust, knowledgeTime: c.now() + 600 });
  assert.equal(later.overall, 'INDETERMINATE');
  assert.equal(later.reason, 'ECP_STATUS_STALE');
  const substitutedTrust = verify(r.bundle, {
    ...trust,
    mtc: { ...trust.mtc, caPublicKey: c.generate('ml-dsa-87').publicKey },
  });
  assert.equal(substitutedTrust.overall, 'INVALID');
  assert.equal(network.mock.callCount(), 0);
});

test('document evidence binds trusted time and subject admission for CMS and native mdoc', async () => {
  for (const format of ['CMS', 'MDOC']) {
    const r = await (format === 'CMS' ? runDemo : runFoundationDemo)({
      trustedTime: true,
      activationMode: 'HUMAN_WEBAUTHN',
    });
    const verifier = createVerifier({ format, trust: r.trust });
    const verified = verifier.verify(c.dcbor(r.bundle));
    assert.equal(verified.overall, 'VALID');
    assert.equal(verified.time, 'TRUSTED_PROOF_OF_EXISTENCE');
    assert.equal(
      verified.subjectBinding,
      format === 'CMS' ? 'REGISTRATION_AUTHORIZATION' : 'NATIVE_MDOC',
    );
    const missing = {
      ...r.bundle,
      objects: r.bundle.objects.filter((o) => o.type !== 'DocumentTimestamp'),
    };
    assert.equal(verifier.verify(c.dcbor(missing)).overall, 'INDETERMINATE');
    const plan = r.bundle.plan;
    const downgrade = replace(r.bundle, null, null, { profile: documentPlans[plan.profile] });
    assert.equal(verifier.verify(c.dcbor(downgrade)).overall, 'INVALID');
    const denied = createVerifier({
      format,
      trust: { ...r.trust, timestamp: { ...r.trust.timestamp, status: () => false } },
    });
    assert.equal(denied.verify(c.dcbor(r.bundle)).overall, 'INVALID');
    const other = await (format === 'CMS' ? runDemo : runFoundationDemo)({ trustedTime: true });
    const swapped = replace(
      r.bundle,
      'DocumentTimestamp',
      other.bundle.objects.find((o) => o.type === 'DocumentTimestamp').payload,
    );
    assert.equal(verifier.verify(c.dcbor(swapped)).overall, 'INVALID');
  }
});

test('organization evidence rejects authority substitution, wrong grants and revocation at the proof bound', async () => {
  await runDocumentDemo({
    timestampOptions: { accuracySeconds: 2 },
    onComplete: async (r) => {
      const verifier = createVerifier({ format: 'CMS', trust: r.trust });
      const verify = (bundle, trust = r.trust) =>
        createVerifier({ format: 'CMS', trust }).verify(c.dcbor(bundle));
      const original = verify(r.bundle),
        upper = original.proofOfExistenceUpperBound;
      assert.equal(original.overall, 'VALID');
      assert.equal(original.actorType, 'WORKLOAD');
      assert.equal(
        verify(r.bundle, { ...r.trust, organizationAuthorities: [] }).overall,
        'INVALID',
      );
      const wrong = r.signControl(
        'OrganizationAuthorization',
        { ...r.authorizationBody, organizationID: c.random() },
        r.organizationAuthority,
      );
      assert.equal(
        verify(replace(r.bundle, 'OrganizationAuthorization', wrong)).reason,
        'DOCUMENT_ORGANIZATION_BINDING',
      );
      assert.equal(
        verify(replace(r.bundle, 'RegistrationAuthorization', r.recipient.evidence.rar)).reason,
        'DOCUMENT_REGISTRATION_BINDING',
      );
      const certificate = r.bundle.objects.find((o) => o.type === 'Certificate').payload;
      const fresh = replace(
        r.bundle,
        'CertificateStatus',
        r.statusFor(certificate, { nextUpdate: c.now() + 600 }),
      );
      assert.equal(verify(fresh).overall, 'VALID');
      const revoked = replace(
        r.bundle,
        'CertificateStatus',
        r.statusFor(certificate, {
          status: 'REVOKED',
          effectiveTime: upper,
          publishedAt: upper,
          nextUpdate: upper + 300,
        }),
      );
      assert.equal(verify(revoked).reason, 'ECP_STATUS_REVOKED');
      const compromise = replace(
        r.bundle,
        'CertificateStatus',
        r.statusFor(certificate, {
          status: 'REVOKED',
          effectiveTime: upper + 1,
          compromiseStart: upper - 1,
          publishedAt: upper,
          nextUpdate: upper + 300,
        }),
      );
      assert.equal(verify(compromise).overall, 'INVALID');
      const revokedGrant = replace(
        r.bundle,
        'OrganizationAuthorizationStatus',
        r.organizationStatus({
          status: 'REVOKED',
          effectiveTime: upper,
          publishedAt: upper,
          nextUpdate: upper + 300,
        }),
      );
      assert.equal(verify(revokedGrant).reason, 'DOCUMENT_ORGANIZATION_STATUS_REVOKED');
      const afterProof = replace(
        r.bundle,
        'CertificateStatus',
        r.statusFor(certificate, {
          status: 'REVOKED',
          effectiveTime: upper + 10,
          publishedAt: upper + 10,
          nextUpdate: upper + 300,
        }),
      );
      assert.equal(verify(afterProof, { ...r.trust, knowledgeTime: upper + 10 }).overall, 'VALID');
      const missing = {
        ...r.bundle,
        objects: r.bundle.objects.filter((o) => o.type !== 'OrganizationAuthorization'),
      };
      assert.equal(verifier.verify(c.dcbor(missing)).overall, 'INDETERMINATE');
    },
  });
});

test('certified encryption closes admission, delivery and recovery with purpose and replay controls', async () => {
  await runDocumentDemo({
    onComplete: async (r) => {
      const { recipient, replacement, trust, delivery, decryption } = r;
      const bytes = decryptDocument(delivery, decryption);
      assert.equal(createVerifier({ format: 'CMS', trust }).verify(bytes).overall, 'VALID');
      assert.throws(
        () =>
          admitDocumentRecipient(recipient.evidence, {
            ...recipient.trust,
            issuerCertificate: recipient.trust.raCertificate,
          }),
        { code: 'ISSUER_KEY_BINDING' },
      );
      assert.throws(
        () => decryptDocument(delivery, { ...decryption, privateKey: replacement.key.privateKey }),
        /DECRYPTION_KEY/,
      );
      const tampered = c.decodeCBOR(c.dcbor(delivery));
      tampered.ciphertext[tampered.ciphertext.length - 1] ^= 1;
      assert.throws(() => decryptDocument(tampered, decryption));
      const changedID = c.random();
      assert.throws(
        () =>
          decryptDocument(
            { ...delivery, deliveryID: changedID },
            {
              ...decryption,
              expectedDeliveryID: changedID,
            },
          ),
        /PLAINTEXT_BINDING/,
      );
      assert.throws(
        () => decryptDocument(delivery, { ...decryption, subjectID: c.random() }),
        /PLAINTEXT_BINDING/,
      );
      assert.throws(
        () =>
          encryptDocument(bytes, [recipient, recipient], { trustDomainID: trust.trustDomainID }),
        /DUPLICATE_RECIPIENT/,
      );
      assert.throws(
        () =>
          admitDocumentRecipient(recipient.evidence, { ...recipient.trust, subjectID: c.random() }),
        /REGISTRATION_BINDING/,
      );
      assert.throws(
        () =>
          admitDocumentRecipient(
            {
              ...recipient.evidence,
              status: r.statusFor(recipient.evidence.certificate, {
                status: 'REVOKED',
                effectiveTime: c.now(),
              }),
            },
            recipient.trust,
          ),
        /RECIPIENT_STATUS/,
      );
      assert.throws(
        () => admitDocumentRecipient(recipient.evidence, recipient.trust, c.now() + 3600),
        /RECIPIENT_STATUS/,
      );
      const cert = r.bundle.objects.find((o) => o.type === 'Certificate').payload;
      assert.throws(
        () => admitDocumentRecipient({ ...recipient.evidence, certificate: cert }, recipient.trust),
        /PROFILE|PURPOSE|EKU/,
      );
      const request = {
        csr: recipient.request,
        subjectID: recipient.trust.subjectID,
        profileID: 'CERTCONCORD-DOC-ENC-v1',
        policyHash: r.policyHash,
        validatePossessionCertificate: r.validatePossessionCertificate,
        identityEvidenceHash: c.random(64),
        kemProof: recipient.kemProof,
        issuanceScope: trust.issuanceScope,
      };
      await assert.rejects(r.ra.authorize(request), /KEM_POP_INVALID_OR_REPLAY/);
      await assert.rejects(
        r.ra.authorize({ ...request, kemProof: undefined }),
        /RA_KEM_POSSESSION_REQUIRED/,
      );
      await assert.rejects(
        r.recovery.recover(r.request, [r.approvals[0], r.approvals[0]], replacement.key.publicKey),
        /RECOVERY_APPROVAL_THRESHOLD/,
      );
      await assert.rejects(
        r.recovery.recover(
          { ...r.request, purpose: 'SIGNING_VAULT_WRAP' },
          r.approvals,
          replacement.key.publicKey,
        ),
        /RECOVERY_REQUEST/,
      );
      assert.deepEqual(decryptDocument(delivery, decryption), bytes);
    },
  });
});

test('timestamp accuracy and historical status cannot manufacture an earlier proof bound', () => {
  const info = (...optional) =>
    c.seq(
      c.integer(1),
      c.oid('1.2.3'),
      c.seq(p.algID(p.OID.sha512), c.octet(c.random(64))),
      c.integer(1),
      p.generalizedTime(c.now()),
      ...optional,
    );
  const absent = parseTSTInfo(info());
  assert.equal(absent.accuracy, undefined);
  assert.equal(absent.poeUpperBound, undefined);
  assert.throws(
    () => parseTSTInfo(info(c.seq(c.der(2, Buffer.from([255]))))),
    /ACCURACY|EXPECTED_UINT/,
  );
  assert.throws(() => parseTSTInfo(info(c.seq(c.integer(1), c.integer(2)))), /ACCURACY/);
  assert.throws(() => parseTSTInfo(info(c.seq(c.integer(1)), c.seq(c.integer(1)))), /DUPLICATE/);
  const interval = parseTSTInfo(info(c.seq(c.integer(1), c.der(0x80, Buffer.from([1])))));
  assert.equal(interval.accuracy, 1.001);
  const revoked = {
    scope: 'CERTIFICATE',
    status: 'REVOKED',
    effectiveTime: 5,
    publishedAt: 6,
    nextUpdate: 7,
  };
  assert.equal(
    evaluateStatus(revoked, { stateTime: 5, knowledgeTime: 10, scope: 'CERTIFICATE' }).status,
    'REVOKED',
  );
  assert.equal(
    evaluateStatus(revoked, { stateTime: 4, knowledgeTime: 10, scope: 'CERTIFICATE' }).status,
    'STALE',
  );
  assert.equal(
    evaluateStatus(
      { ...revoked, effectiveTime: undefined },
      { stateTime: 5, knowledgeTime: 10, scope: 'CERTIFICATE' },
    ).overall,
    'INVALID',
  );
});

test('CMS KEM rejects tag substitution without releasing plaintext', () => {
  const recipient = c.generate('ml-kem-768'),
    subjectKeyIdentifier = c.random();
  const plaintext = Buffer.from('Authenticated document bytes');
  const raw = encryptCMS(plaintext, [{ publicKey: recipient.publicKey, subjectKeyIdentifier }]);
  const options = { privateKey: recipient.privateKey, subjectKeyIdentifier };
  assert.deepEqual(decryptCMS(raw, options), plaintext);
  const top = c.parseDER(raw),
    envelope = top.children[1].children[0].children;
  for (const [index, tag] of [
    [1, 48],
    [2, 49],
    [3, 0x80],
  ]) {
    const modified = envelope.map((node, i) => (i === index ? c.der(tag, node.value) : node.raw));
    const changed = c.seq(top.children[0].raw, c.der(0xa0, c.seq(...modified)));
    assert.throws(() => decryptCMS(changed, options), /CMS_ENVELOPE_STRUCTURE/);
  }
  const wrapped = c.seq(top.children[0].raw, c.der(0xa1, top.children[1].value));
  assert.throws(() => decryptCMS(wrapped, options), /CMS_ENVELOPE_TYPE/);
});

test('recipient status preserves knowledge time and known authority failures', async (t) => {
  await runDocumentDemo({
    onComplete: async (r) => {
      const { evidence, trust } = r.recipient;
      const at = c.now(),
        issuedAt = readControl(
          evidence.rar,
          'RegistrationAuthorization',
          trust.raCertificate,
        ).issuedAt;
      const stale = {
        ...evidence,
        status: r.statusFor(evidence.certificate, { publishedAt: at - 60, nextUpdate: at - 1 }),
      };
      await t.test('stale recipient status alone remains indeterminate', () => {
        assert.throws(() => admitDocumentRecipient(stale, trust, at), { overall: 'INDETERMINATE' });
      });
      for (const role of ['COSIGNER', 'ISSUER'])
        await t.test(`staleness cannot hide a known compromised ${role}`, () => {
          const keys =
            role === 'COSIGNER'
              ? trust.mtc.members.map((member) => member.publicKey)
              : [trust.mtc.caPublicKey];
          const resolve = createAuthorityResolver({
            trustDomainID: trust.trustDomainID,
            authorities: keys.map((publicKey) => ({
              mode: 'RAW_KEY',
              publicKeyDER: c.spki(publicKey),
              roles: [role],
              scopes: [{ trustDomainID: trust.trustDomainID }],
              knownAt: issuedAt - 60,
              validFrom: issuedAt - 60,
              validUntil: at + 3600,
              status: {
                scope: 'AUTHORITY',
                authorityID: c.keyID(publicKey),
                trustDomainID: trust.trustDomainID,
                status: 'REVOKED',
                publishedAt: at,
                nextUpdate: at + 3600,
                effectiveTime: at,
                compromiseStart: issuedAt - 1,
              },
            })),
          });
          assert.throws(
            () =>
              admitDocumentRecipient(
                stale,
                {
                  ...trust,
                  authorityResolver: (query) =>
                    query.role === role ? resolve(query) : trust.authorityResolver(query),
                },
                at,
              ),
            { overall: 'INVALID' },
          );
        });
      const future = {
        ...evidence,
        status: r.statusFor(evidence.certificate, { publishedAt: at + 10, nextUpdate: at + 300 }),
      };
      await t.test('future publication is unavailable without querying a future authority', () => {
        const queries = [];
        assert.throws(
          () =>
            admitDocumentRecipient(
              future,
              {
                ...trust,
                knowledgeTime: at,
                authorityResolver: (query) => {
                  queries.push(query);
                  return trust.authorityResolver(query);
                },
              },
              at,
            ),
          { overall: 'INDETERMINATE' },
        );
        assert(queries.every((query) => query.stateTime <= query.knowledgeTime));
      });
      await t.test(
        'a statement learned after the operation can establish historical good status',
        () => {
          const admitted = admitDocumentRecipient(future, { ...trust, knowledgeTime: at + 20 }, at);
          assert.deepEqual(admitted.binding.keyID, c.keyID(r.recipient.key.publicKey));
        },
      );
    },
  });
});

test('unsupported organization status cannot hide known document authority revocation', async (t) => {
  await runDocumentDemo({
    onComplete: async (r) => {
      const knowledgeTime = r.trust.knowledgeTime;
      const changed = replace(
        r.bundle,
        'OrganizationAuthorizationStatus',
        r.organizationStatus({
          critical: ['unknown-critical'],
          publishedAt: knowledgeTime,
          nextUpdate: knowledgeTime + 300,
        }),
      );
      assert.equal(
        createVerifier({ format: 'CMS', trust: r.trust }).verify(c.dcbor(changed)).overall,
        'UNSUPPORTED',
      );
      for (const [role, certificate] of [
        ['REGISTRATION_AUTHORITY', r.trust.raCertificate],
        ['ORGANIZATION_AUTHORITY', r.organizationAuthority.certificate],
        ['TIMESTAMP_AUTHORITY', r.trust.timestamp.certificate],
      ])
        await t.test(role, () => {
          const cert = p.parseCertificate(certificate);
          const resolve = createAuthorityResolver({
            trustDomainID: r.trust.trustDomainID,
            authorities: [
              {
                mode: 'CERTIFICATE',
                certificate,
                roles: [role],
                scopes: [{ trustDomainID: r.trust.trustDomainID }],
                knownAt: cert.notBefore,
                validFrom: cert.notBefore,
                validUntil: cert.notAfter,
                status: {
                  scope: 'AUTHORITY',
                  authorityID: c.keyID(cert.publicKey),
                  trustDomainID: r.trust.trustDomainID,
                  status: 'REVOKED',
                  publishedAt: knowledgeTime,
                  nextUpdate: knowledgeTime + 3600,
                  effectiveTime: knowledgeTime,
                  compromiseStart: 0,
                },
              },
            ],
          });
          const verifier = createVerifier({
            format: 'CMS',
            trust: {
              ...r.trust,
              authorityResolver: (query) =>
                query.role === role ? resolve(query) : r.trust.authorityResolver(query),
            },
          });
          assert.equal(verifier.verify(c.dcbor(r.bundle)).reason, 'AUTHORITY_REVOKED');
          const combined = verifier.verify(c.dcbor(changed));
          assert.equal(combined.overall, 'INVALID', combined.reason);
          assert.equal(combined.reason, 'AUTHORITY_REVOKED');
        });
    },
  });
});

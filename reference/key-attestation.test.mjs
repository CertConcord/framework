import test from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import {
  assessKeyAttestation,
  readAttestationDER,
  fetchAndroidRevocationStatus,
} from './key-attestation.mjs';
import { androidFixture, appleFixture, tpmFixture } from './attestation-fixtures.mjs';
import { DeviceBindingRegistry } from './bridge.mjs';
import { Journal } from './state.mjs';
const holder = c.generate('ec'),
  challenge = c.b64u(c.random());
const assess = (fixture, options = {}) =>
  assessKeyAttestation(fixture.evidence, {
    holderPublicKey: holder.publicKey,
    challenge,
    policy: fixture.policy,
    ...options,
  });
test('Android attestation verifies exact key, challenge, hardware, app, boot, patch and UV constraints', () => {
  const fixture = androidFixture(holder.publicKey, challenge),
    good = assess(fixture);
  assert.equal(good.assurance, 'HARDWARE_KEY_VERIFIED');
  assert.equal(good.boundary, 'ANDROID_STRONGBOX');
  assert.equal(good.localUVPolicy, 'PER_USE_AUTH_REQUIRED');
  for (const [changes, error] of [
    [{ challenge: 'changed' }, /CHALLENGE/],
    [{ level: 0 }, /SECURITY_LEVEL/],
    [{ level: 1 }, /SECURITY_LEVEL/],
    [{ packageName: 'org.attacker.wallet' }, /APPLICATION/],
    [{ locked: false }, /VERIFIED_BOOT/],
    [{ bootState: 1 }, /VERIFIED_BOOT/],
    [{ patch: 202001 }, /PATCH/],
    [{ noAuth: true }, /USER_AUTH/],
    [{ timeout: 60 }, /USER_AUTH/],
    [{ origin: 2 }, /KEY_PROPERTIES/],
  ])
    assert.throws(() => assess(androidFixture(holder.publicKey, challenge, changes)), error);
  assert.throws(
    () => assess(fixture, { holderPublicKey: c.generate('ec').publicKey }),
    /SUBJECT_KEY/,
  );
  const policy = fixture.policy.formats['android-key'];
  const revoked = {
    ...fixture,
    policy: {
      ...fixture.policy,
      formats: { 'android-key': { ...policy, status: () => ({ status: 'REVOKED' }) } },
    },
  };
  assert.throws(() => assess(revoked), /STATUS/);
  assert.throws(
    () => assess(fixture, { policy: androidFixture(holder.publicKey, challenge).policy }),
    /ROOT/,
  );
  const signatureTampered = {
    ...fixture.evidence,
    x5c: [Buffer.from(fixture.evidence.x5c[0]), fixture.evidence.x5c[1]],
  };
  signatureTampered.x5c[0][signatureTampered.x5c[0].length - 1] ^= 1;
  assert.throws(() => assess({ ...fixture, evidence: signatureTampered }), /CHAIN_SIGNATURE/);
});
test('Apple ACME attestation requires the exact attested holder key and challenge', () => {
  const fixture = appleFixture(holder.publicKey, challenge);
  assert.equal(assess(fixture).boundary, 'APPLE_SECURE_ENCLAVE');
  assert.equal(assess(fixture).localUVPolicy, 'UNASSESSED');
  assert.throws(
    () => assess(fixture, { holderPublicKey: c.generate('ec').publicKey }),
    /SUBJECT_KEY/,
  );
  assert.throws(
    () => assess(appleFixture(holder.publicKey, challenge, { challenge: 'other' })),
    /CHALLENGE/,
  );
  const policy = fixture.policy.formats['apple-managed-acme'];
  assert.throws(
    () =>
      assess(fixture, {
        policy: {
          ...fixture.policy,
          formats: { 'apple-managed-acme': { ...policy, flow: 'DeviceInformation' } },
        },
      }),
    /APPLE_POLICY/,
  );
  assert.throws(
    () =>
      assessKeyAttestation(
        { format: 'apple-appattest' },
        {
          holderPublicKey: holder.publicKey,
          challenge,
          policy: { id: 'test', formats: { 'apple-appattest': {} } },
        },
      ),
    /UNSUPPORTED_FORMAT/,
  );
});
test('TPM Certify verifies trusted AK enrollment, object Name, nonexport attributes and nonce', () => {
  const fixture = tpmFixture(holder.publicKey, challenge);
  assert.equal(assess(fixture).boundary, 'TPM2');
  assert.throws(
    () => assess(tpmFixture(holder.publicKey, challenge, { attributes: 0x40040 })),
    /ATTRIBUTES/,
  );
  assert.throws(
    () => assess(tpmFixture(holder.publicKey, challenge, { attributes: 0x50072 })),
    /ATTRIBUTES/,
  );
  assert.throws(
    () => assess(tpmFixture(holder.publicKey, challenge, { challenge: 'old' })),
    /CHALLENGE/,
  );
  assert.throws(
    () => assess(fixture, { holderPublicKey: c.generate('ec').publicKey }),
    /SUBJECT_KEY/,
  );
  assert.throws(
    () => assess(fixture, { policy: tpmFixture(holder.publicKey, challenge).policy }),
    /SIGNER|SIGNATURE/,
  );
  const area = Buffer.from(fixture.evidence.pubArea);
  area[4] ^= 8;
  assert.throws(
    () => assess({ ...fixture, evidence: { ...fixture.evidence, pubArea: area } }),
    /TPM_NAME/,
  );
  const ak = fixture.policy.formats['tpm2-certify'].authorizedAKs.get('synthetic-AK');
  ak.enrollmentMethod = 'SELF_SIGNED';
  assert.throws(() => assess(fixture), /ENROLLMENT/);
});
test('attestation DER rejects truncation, non-minimal high tags and trailing data', () => {
  for (const hex of ['bf800100', 'bf0100', '30800000', '300000', '02020001', '3005020101'])
    assert.throws(() => readAttestationDER(Buffer.from(hex, 'hex')), /DER/);
});
test('hardware admission cannot be replaced by an RA hardware string, a different session or stale status', () => {
  const journal = new Journal(),
    ra = c.generate('ml-dsa-87'),
    certificate = p.issueCertificate(
      { publicKey: ra.publicKey, issuer: p.name('RA'), subject: p.name('RA'), serial: 1 },
      ra.privateKey,
    ),
    registry = new DeviceBindingRegistry({
      journal,
      registrationAuthorityCertificate: certificate,
      trustDomainID: c.random(),
      policyHash: c.random(64),
    }),
    subjectID = c.random(),
    profileID = 'CERTCONCORD-PERSON-DEVICE-SIGN-v1',
    sessionID = c.b64u(c.random());
  try {
    assert.throws(() => registry.challenge(), /CONTEXT/);
    const nonce = registry.challenge({ subjectID, profileID, sessionID }),
      fixture = androidFixture(holder.publicKey, nonce);
    registry.attestationPolicy = fixture.policy;
    const evaluation = registry.assess({
      holderPublicKey: holder.publicKey,
      nonce,
      evidence: fixture.evidence,
      sessionID,
    });
    const authorization = p.signCMS(
        {
          certificate,
          content: c.D('DeviceRegistrationAuthorization', {
            schemaVersion: 1,
            trustDomainID: registry.trustDomainID,
            subjectID,
            profileID,
            holderKeyID: c.keyID(holder.publicKey),
            documentKeyID: c.keyID(holder.publicKey),
            policyHash: registry.policyHash,
            attestationEvidenceHash: evaluation.evidenceHash,
            keyAssurance: evaluation.keyAssurance,
            localUVPolicy: evaluation.localUVPolicy,
            audience: registry.audience,
            issuedAt: c.now(),
            expiresAt: c.now() + 120,
            bindingExpiresAt: c.now() + 3600,
          }),
        },
        ra.privateKey,
      ),
      proof = c.sign(
        c.D('DeviceRegistrationProof', {
          schemaVersion: 1,
          authorizationHash: c.sha512(authorization),
          nonce,
          audience: registry.audience,
        }),
        holder.privateKey,
      ),
      request = {
        authorization,
        proof,
        holderPublicKey: holder.publicKey,
        nonce,
        attestation: fixture.evidence,
        sessionID,
      };
    assert.throws(() => registry.enroll({ ...request, attestation: undefined }), /REQUIRED/);
    assert.throws(() => registry.enroll({ ...request, sessionID: c.b64u(c.random()) }), /SESSION/);
    const binding = registry.enroll(request);
    assert.equal(binding.keyAdmission.assurance, 'HARDWARE_KEY_VERIFIED');
    assert.equal(registry.active(binding.bindingID).profileID, profileID);
    assert.throws(() => registry.enroll(request), /NONCE|REPLAY|UNIQUE/);
    fixture.policy.formats['android-key'].status = () => ({ status: 'REVOKED' });
    assert.throws(() => registry.active(binding.bindingID), /STATUS/);
  } finally {
    journal.close();
  }
});
test('Android status input is fetched from the fixed authority with bounded freshness', async () => {
  const at = c.now(),
    status = await fetchAndroidRevocationStatus({
      at,
      fetchImpl: async (url, options) => {
        assert.equal(url, 'https://android.googleapis.com/attestation/status');
        assert.equal(options.redirect, 'error');
        return new Response(JSON.stringify({ entries: { '00aB': { status: 'REVOKED' } } }));
      },
    });
  assert.equal(status({ serialNumber: 'ab' }).status, 'REVOKED');
  assert.equal(status({ serialNumber: 'ac' }).status, 'GOOD');
  await assert.rejects(
    fetchAndroidRevocationStatus({ fetchImpl: async () => new Response('{}') }),
    /FORMAT/,
  );
});

test('issuer-authenticated key assessments cannot inflate assurance or outlive admission', async () => {
  const { validateAdmissionAssessment } = await import('./key-attestation.mjs');
  const a = assess(androidFixture(holder.publicKey, challenge));
  assert.equal(validateAdmissionAssessment(a, holder.publicKey).assurance, 'HARDWARE_KEY_VERIFIED');
  for (const change of [
    { keyAssurance: 'KAL3' },
    { boundary: 'APPLE_SECURE_ENCLAVE' },
    { format: 'none' },
    { policyID: '' },
    { expiresAt: c.now() - 1 },
    { verifiedAt: c.now() + 60 },
    { holderKeyID: c.random(64) },
    { statusEvidenceHash: Buffer.alloc(0) },
  ])
    assert.throws(
      () => validateAdmissionAssessment({ ...a, ...change }, holder.publicKey),
      /ASSESSMENT/,
    );
  const fixture = tpmFixture(holder.publicKey, challenge);
  fixture.policy.formats['tpm2-certify'].authorizedAKs.get('synthetic-AK').restrictedSigning =
    false;
  assert.throws(() => assess(fixture), /AK_ENROLLMENT/);
});

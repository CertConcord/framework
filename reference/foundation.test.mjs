import test from 'node:test';
import assert from 'node:assert/strict';
import { runFoundationDemo } from './foundation-demo.mjs';
import { verifyMdocSignaturePackage } from './signer-mdoc.mjs';
import { random } from './core.mjs';
for (const identityTransport of ['openid4vp', 'annex-c'])
  test(
    identityTransport +
      ': government mDL -> RA -> CA personal mdoc -> ML-DSA document, no personal X.509 certificate',
    async () => {
      const { bundle, trust, verification } = await runFoundationDemo({
        identityTransport,
        identityType: 'mdl',
      });
      assert.equal(verification.overall, 'VALID_UNDER_POLICY');
      assert.equal(verification.signerCredential, 'MDOC');
      assert.equal(
        bundle.objects.some((o) => o.type === 'Certificate'),
        false,
      );
      assert.throws(
        () => verifyMdocSignaturePackage(bundle, { ...trust, trustDomainID: random() }),
        /PURPOSE/,
      );
      assert.throws(
        () =>
          verifyMdocSignaturePackage(bundle, {
            ...trust,
            knowledgeTime: Math.floor(Date.now() / 1000) + 3600,
          }),
        /STALE|EXPIRED|TIME/,
      );
      const objects = bundle.objects.map((o) =>
        o.type === 'Document' ? { ...o, payload: Buffer.from('changed document') } : o,
      );
      assert.throws(() => verifyMdocSignaturePackage({ ...bundle, objects }, trust), /HASH/);
    },
  );
test('a governed government issuer directly issues a combined mDL and signer mdoc', async () => {
  const { bundle, trust, verification } = await runFoundationDemo({
    issuerModel: 'direct',
    identityType: 'mdl',
  });
  assert.equal(verification.overall, 'VALID_UNDER_POLICY');
  assert.equal(trust.docType, 'org.iso.18013.5.1.mDL');
  assert.throws(
    () => verifyMdocSignaturePackage(bundle, { ...trust, docType: 'org.certconcord.signer.1' }),
    { code: 'MDOC_DOCTYPE' },
  );
});

test('DeviceKey and independent ML-DSA profiles preserve distinct key and algorithm semantics', async () => {
  const { documentKeyMode, DEVICE_SIGN_PROFILE } = await import('./signer-mdoc.mjs');
  const { generate } = await import('./core.mjs');
  const key = generate('ec'),
    other = generate('ec'),
    pq = generate();
  assert.equal(documentKeyMode(DEVICE_SIGN_PROFILE, key.publicKey, key.publicKey), 'DEVICE_KEY');
  assert.throws(
    () => documentKeyMode(DEVICE_SIGN_PROFILE, other.publicKey, key.publicKey),
    /DEVICE_KEY_BINDING/,
  );
  assert.throws(
    () => documentKeyMode('CERTCONCORD-PERSON-SIGN-v1', key.publicKey, key.publicKey),
    /INDEPENDENT_PQ/,
  );
  assert.throws(
    () => documentKeyMode(DEVICE_SIGN_PROFILE, pq.publicKey, key.publicKey),
    /DEVICE_KEY_BINDING/,
  );
  assert.throws(
    () => documentKeyMode('ordinary-mDL', key.publicKey, key.publicKey),
    /INDEPENDENT_PQ/,
  );
});
for (const issuerModel of ['delegated', 'direct'])
  test(
    issuerModel +
      ': an explicitly issued DeviceKey signing mdoc creates a distinct ES256 document signature',
    async () => {
      const { verification, summary } = await runFoundationDemo({
        issuerModel,
        documentKeyMode: 'DEVICE_KEY',
        identityTransport: 'annex-c',
      });
      assert.equal(verification.overall, 'VALID_UNDER_POLICY');
      assert.equal(verification.documentAlgorithm, 'ES256');
      assert.equal(verification.documentAlgorithmAssurance, 'CLASSICAL');
      assert.equal(verification.holderKeyAssurance, 'UNATTESTED');
      assert.equal(summary.custody, 'SYNTHETIC_SOFTWARE');
    },
  );
test('strict hardware admission remains bound through RA, CA, VCI, document signature and evidence verification', async () => {
  const { androidFixture } = await import('./attestation-fixtures.mjs');
  for (const documentKeyMode of ['DEVICE_KEY', 'INDEPENDENT_PQ']) {
    const { verification, summary, bundle, trust } = await runFoundationDemo({
      documentKeyMode,
      attestationFactory: androidFixture,
    });
    assert.equal(verification.overall, 'VALID_UNDER_POLICY');
    assert.equal(verification.holderKeyAssurance, 'HARDWARE_KEY_VERIFIED');
    assert.equal(
      verification.documentKeyAssurance,
      documentKeyMode === 'DEVICE_KEY' ? 'KAL2' : 'KAL1',
    );
    assert.equal(summary.custody, 'SYNTHETIC_ATTESTATION_FIXTURE');
    assert.throws(
      () =>
        verifyMdocSignaturePackage(bundle, {
          ...trust,
          expectedPolicy: {
            ...trust.expectedPolicy,
            requirePostQuantumDocument: true,
            changedPolicy: true,
          },
        }),
      /POLICY/,
    );
  }
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { runDemo } from './demo.mjs';
import { createSignaturePackage, verifySignaturePackage } from './evidence.mjs';
import { decodeCBOR, random } from './core.mjs';
test('PAR/PKCE VCI HTTP -> Annex C holder proof -> MTC document signature -> semantic ECP', async () => {
  const { verification } = await runDemo({
    presentationTransport: 'annex-c',
    grantType: 'authorization-code',
  });
  assert.equal(verification.overall, 'VALID_UNDER_POLICY');
});
test('RA -> native-holder contract -> VCI HTTP -> VP -> document permit -> CMS -> semantic ECP', async () => {
  const { bundle, trust, verification } = await runDemo();
  assert.equal(verification.overall, 'VALID_UNDER_POLICY');
  assert.equal(verification.activation, 'ATTESTED_VALID');
  const data = Object.fromEntries(bundle.objects.map((o) => [o.type, o.payload])),
    sim = decodeCBOR(data.SIM);
  sim.documents[0].digest = random(64);
  const forged = createSignaturePackage({
    document: data.Document,
    certificate: data.Certificate,
    sim,
    policy: decodeCBOR(data.SignaturePolicy),
    activation: decodeCBOR(data.ActivationContext),
    permit: data.OperationPermit,
    receipt: data.ExecutionReceipt,
    status: data.CertificateStatus,
    cms: data.CMS,
  });
  assert.throws(() => verifySignaturePackage(forged, trust), /SIGNED_BINDING/);
  assert.throws(
    () => verifySignaturePackage(bundle, { ...trust, trustDomainID: random() }),
    /POLICY_AUTHORITY/,
  );
  assert.throws(
    () =>
      verifySignaturePackage(bundle, {
        ...trust,
        knowledgeTime: Math.floor(Date.now() / 1000) + 3600,
      }),
    /STALE/,
  );
  assert.throws(
    () => verifySignaturePackage({ ...bundle, objects: bundle.objects.slice(1) }, trust),
    /MISSING/,
  );
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dcbor, decodeCBOR, now } from './core.mjs';
import { evidenceObject, readControl } from './state.mjs';
import { runDemo } from './demo.mjs';
import { runFoundationDemo } from './foundation-demo.mjs';
import { createVerifier } from './sdk/index.mjs';

function replacePlan(bundle, changes) {
  const old = bundle.objects.find((o) => o.type === 'VerificationPlan');
  const next = evidenceObject(
    'VerificationPlan',
    dcbor({ ...decodeCBOR(old.payload), ...changes }),
    old.dependencies,
  );
  return {
    ...bundle,
    root: next.id,
    objects: bundle.objects.map((o) => (o === old ? next : o)),
  };
}

test('SDK distinguishes invalid, incomplete and unsupported evidence for CMS and mdoc', async () => {
  for (const format of ['CMS', 'MDOC']) {
    const r = format === 'CMS' ? await runDemo() : await runFoundationDemo();
    const verifier = createVerifier({ format, trust: r.trust });
    assert.equal(verifier.verify(dcbor(r.bundle)).overall, 'VALID');
    for (const type of ['Document', 'VerificationPlan']) {
      const missing = { ...r.bundle, objects: r.bundle.objects.filter((o) => o.type !== type) };
      assert.equal(verifier.verify(dcbor(missing)).overall, 'INDETERMINATE');
    }
    const altered = decodeCBOR(dcbor(r.bundle));
    altered.objects.find((o) => o.type === 'Document').payload[0] ^= 1;
    assert.equal(verifier.verify(dcbor(altered)).overall, 'INVALID');
    const duplicate = { ...r.bundle, objects: [...r.bundle.objects, r.bundle.objects[0]] };
    assert.equal(verifier.verify(dcbor(duplicate)).reason, 'ECP_DUPLICATE');
    const unused = evidenceObject('ExecutionReceipt', Buffer.from('untrusted extra receipt'));
    assert.equal(
      verifier.verify(dcbor({ ...r.bundle, objects: [...r.bundle.objects, unused] })).reason,
      'ECP_UNREACHABLE_OBJECT',
    );
    const cyclic = decodeCBOR(dcbor(r.bundle));
    const root = cyclic.objects.find((o) => o.type === 'VerificationPlan');
    root.dependencies.push(root.id);
    assert.equal(verifier.verify(dcbor(cyclic)).reason, 'ECP_HASH');
    const disconnected = decodeCBOR(dcbor(r.bundle));
    const oldRoot = disconnected.objects.find((o) => o.type === 'VerificationPlan');
    const newRoot = evidenceObject('VerificationPlan', oldRoot.payload, []);
    disconnected.root = newRoot.id;
    disconnected.objects = disconnected.objects.map((o) => (o === oldRoot ? newRoot : o));
    assert.equal(verifier.verify(dcbor(disconnected)).reason, 'ECP_UNREACHABLE_OBJECT');
    const unknown = replacePlan(r.bundle, { profile: 'urn:example:unsupported-plan' });
    assert.equal(verifier.verify(dcbor(unknown)).overall, 'UNSUPPORTED');
    const badUnknown = decodeCBOR(dcbor(unknown));
    badUnknown.objects.find((o) => o.type === 'Document').payload[0] ^= 1;
    assert.equal(verifier.verify(dcbor(badUnknown)).overall, 'INVALID');
    assert.equal(verifier.verify(dcbor({ ...r.bundle, schemaVersion: 2 })).overall, 'UNSUPPORTED');
    assert.equal(verifier.verify(dcbor(replacePlan(r.bundle, { profile: 12 }))).overall, 'INVALID');
    assert.equal(
      createVerifier({ format, trust: { ...r.trust, trustDomainID: Buffer.alloc(32) } }).verify(
        dcbor(r.bundle),
      ).overall,
      'INVALID',
    );
  }
});

test('execution plans are declared in CDDL and SDK enforces the selected policy', async () => {
  const cddl = readFileSync('schemas.cddl', 'utf8');
  const declaration = cddl.match(/verification-plan = \{([\s\S]*?)\n\}/)[1];
  for (const format of ['CMS', 'MDOC']) {
    const r =
      format === 'CMS'
        ? await runDemo({ executionBinding: true })
        : await runFoundationDemo({ executionBinding: true });
    const verifier = createVerifier({ format, trust: r.trust });
    const plan = decodeCBOR(r.bundle.objects.find((o) => o.type === 'VerificationPlan').payload);
    assert(declaration.includes('"' + plan.profile + '"'));
    assert.equal(verifier.verify(dcbor(r.bundle)).overall, 'VALID');
    const downgraded = replacePlan(r.bundle, {
      profile: format === 'CMS' ? 'certconcord-ecp-cms-attested-v1' : 'certconcord-ecp-mdoc-attested-v1',
    });
    assert.equal(verifier.verify(dcbor(downgraded)).overall, 'INVALID');
  }
});

test('ordinary WebAuthn completes CMS and mdoc document verification without raw signing or execution proposals', async () => {
  for (const format of ['CMS', 'MDOC']) {
    const options = { activationMode: 'HUMAN_WEBAUTHN', trustedTime: true };
    const r = format === 'CMS' ? await runDemo(options) : await runFoundationDemo(options);
    assert.equal(r.trust.passkeyStatus, undefined);
    assert.equal(r.trust.executionStatus, undefined);
    assert.equal(r.trust.expectedPolicy.executionBinding, undefined);
    assert.equal(
      r.bundle.objects.some((o) =>
        ['PasskeySigningBinding', 'PasskeyRawEvidence', 'ExecutionBindingEvidence'].includes(
          o.type,
        ),
      ),
      false,
    );
    const permit = r.bundle.objects.find((o) => o.type === 'OperationPermit');
    assert.equal(
      readControl(permit.payload, 'OperationPermit', r.trust.permitCertificate).proofMode,
      'HUMAN_WEBAUTHN',
    );
    const result = createVerifier({ format, trust: r.trust }).verify(dcbor(r.bundle));
    assert.equal(result.overall, 'VALID');
    assert.equal(result.time, 'TRUSTED_PROOF_OF_EXISTENCE');
  }
});

for (const format of ['CMS', 'MDOC'])
  test(
    format + ' reports stale retained status as indeterminate at a later knowledge time',
    async () => {
      const options = { activationMode: 'HUMAN_WEBAUTHN', trustedTime: true },
        r = format === 'CMS' ? await runDemo(options) : await runFoundationDemo(options),
        bytes = dcbor(r.bundle);
      assert.equal(createVerifier({ format, trust: r.trust }).verify(bytes).overall, 'VALID');
      const result = createVerifier({
        format,
        trust: { ...r.trust, knowledgeTime: now() + 86400 },
      }).verify(bytes);
      assert.equal(result.overall, 'INDETERMINATE');
      assert.equal(result.reason, format === 'CMS' ? 'ECP_STATUS_STALE' : 'STATUS_LIST_STALE');
    },
  );

test('invalid document signatures take precedence over stale status in both representations', async () => {
  for (const format of ['CMS', 'MDOC']) {
    const options = { activationMode: 'HUMAN_WEBAUTHN', trustedTime: true };
    const r = format === 'CMS' ? await runDemo(options) : await runFoundationDemo(options);
    const type = format === 'CMS' ? 'CMS' : 'COSE';
    const oldPlan = r.bundle.objects.find((object) => object.type === 'VerificationPlan');
    const objects = r.bundle.objects.filter((object) => object !== oldPlan).map((object) => {
      if (object.type !== type) return object;
      const corrupted = Buffer.from(object.payload);
      corrupted[corrupted.length - 1] ^= 1;
      return evidenceObject(type, corrupted);
    });
    const plan = evidenceObject('VerificationPlan', dcbor({ ...decodeCBOR(oldPlan.payload),
      objects: Object.fromEntries(objects.map((object) => [object.type, object.id])) }),
    objects.map((object) => object.id));
    const bytes = dcbor({ ...r.bundle, root: plan.id, objects: [...objects, plan] });
    for (const knowledgeTime of [now(), now() + 86400]) {
      const result = createVerifier({ format, trust: { ...r.trust, knowledgeTime } }).verify(bytes);
      assert.equal(result.overall, 'INVALID', format + ': ' + result.reason);
      assert.match(result.reason, /SIGNATURE/);
    }
  }
});

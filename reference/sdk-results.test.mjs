import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dcbor, decodeCBOR, now } from './core.mjs';
import { readControl } from './state.mjs';
import { evidenceLeaf, createEvidencePackage } from './evidence-plan.mjs';
import { runDemo } from './demo.mjs';
import { runFoundationDemo } from './foundation-demo.mjs';
import { createVerifier } from './sdk/index.mjs';
import { decodeJWS, signJWS } from './jose.mjs';

function replacePlan(bundle, changes) {
  return { ...bundle, plan: { ...bundle.plan, ...changes } };
}

test('SDK distinguishes invalid, incomplete and unsupported evidence for CMS and mdoc', async () => {
  for (const format of ['CMS', 'MDOC']) {
    const r = format === 'CMS' ? await runDemo() : await runFoundationDemo();
    const verifier = createVerifier({ format, trust: r.trust });
    assert.equal(verifier.verify(dcbor(r.bundle)).overall, 'VALID');
    const missingPlan = { ...r.bundle };
    delete missingPlan.plan;
    for (const missing of [
      { ...r.bundle, objects: r.bundle.objects.filter((o) => o.type !== 'Document') },
      {
        ...r.bundle,
        objects: r.bundle.objects.filter((o) => o.type !== 'RegistrationAuthorization'),
      },
      missingPlan,
    ]) {
      assert.equal(verifier.verify(dcbor(missing)).overall, 'INDETERMINATE');
    }
    const altered = decodeCBOR(dcbor(r.bundle));
    altered.objects.find((o) => o.type === 'Document').payload[0] ^= 1;
    assert.equal(verifier.verify(dcbor(altered)).overall, 'INVALID');
    const duplicate = { ...r.bundle, objects: [...r.bundle.objects, r.bundle.objects[0]] };
    assert.equal(verifier.verify(dcbor(duplicate)).reason, 'ECP_DUPLICATE');
    const unused = evidenceLeaf('UnusedReceipt', Buffer.from('untrusted extra receipt'));
    assert.equal(
      verifier.verify(dcbor({ ...r.bundle, objects: [...r.bundle.objects, unused] })).reason,
      'ECP_UNREACHABLE_OBJECT',
    );
    const cyclic = decodeCBOR(dcbor(r.bundle));
    cyclic.objects[0].dependencies = [cyclic.objects[0].id];
    assert.equal(verifier.verify(dcbor(cyclic)).reason, 'UNKNOWN_FIELD');
    const disconnected = decodeCBOR(dcbor(r.bundle));
    delete disconnected.plan.objects.Document;
    assert.equal(verifier.verify(dcbor(disconnected)).reason, 'ECP_UNREACHABLE_OBJECT');
    const unknown = replacePlan(r.bundle, { profile: 'urn:example:unsupported-plan' });
    assert.equal(verifier.verify(dcbor(unknown)).overall, 'UNSUPPORTED');
    const badUnknown = decodeCBOR(dcbor(unknown));
    badUnknown.objects.find((o) => o.type === 'Document').payload[0] ^= 1;
    assert.equal(verifier.verify(dcbor(badUnknown)).overall, 'INVALID');
    for (const schemaVersion of [1, 3])
      assert.equal(verifier.verify(dcbor({ ...r.bundle, schemaVersion })).overall, 'UNSUPPORTED');
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
    const plan = r.bundle.plan;
    assert(declaration.includes('"' + plan.profile + '"'));
    assert.equal(verifier.verify(dcbor(r.bundle)).overall, 'VALID');
    assert.equal(
      verifier.verify(
        dcbor({
          ...r.bundle,
          objects: r.bundle.objects.filter((o) => o.type !== 'RegistrationAuthorization'),
        }),
      ).overall,
      'INDETERMINATE',
    );
    const downgraded = replacePlan(r.bundle, {
      profile:
        format === 'CMS' ? 'certconcord-ecp-cms-attested-draft-03' : 'certconcord-ecp-mdoc-attested-draft-03',
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
        [
          'PasskeySigningBinding',
          'PasskeyRawEvidence',
          'ExecutionBindingEvidence',
          'ActivationContext',
          'VerificationPlan',
        ].includes(o.type),
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

for (const format of ['CMS', 'MDOC'])
  test(
    format + ' treats signed status published after the knowledge bound as unavailable',
    async () => {
      const run = format === 'CMS' ? runDemo : runFoundationDemo;
      await run({
        activationMode: 'HUMAN_WEBAUTHN',
        trustedTime: true,
        onComplete: async (r) => {
          const knowledgeTime = now(),
            type = format === 'CMS' ? 'CertificateStatus' : 'CredentialStatusList',
            original = r.bundle.objects.find((object) => object.type === type).payload;
          let changed;
          if (format === 'CMS') {
            const statement = readControl(original, 'CertificateStatus', r.trust.statusCertificate);
            changed = r.signStatus({
              ...statement,
              publishedAt: knowledgeTime + 60,
              nextUpdate: knowledgeTime + 180,
            });
          } else {
            const token = decodeJWS(original.toString('utf8'));
            changed = Buffer.from(
              signJWS(
                {
                  ...JSON.parse(token.payload.toString('utf8')),
                  iat: knowledgeTime + 60,
                  exp: knowledgeTime + 180,
                  ttl: 120,
                },
                r.issuer.privateKey,
                token.header,
              ),
            );
          }
          const objects = r.bundle.objects.map((object) =>
              object.type === type ? evidenceLeaf(type, changed) : object,
            ),
            bundle = createEvidencePackage(r.bundle.plan.profile, objects),
            result = createVerifier({ format, trust: { ...r.trust, knowledgeTime } }).verify(
              dcbor(bundle),
            );
          assert.equal(result.overall, 'INDETERMINATE', result.reason);
        },
      });
    },
  );

test('invalid document signatures take precedence over stale status in both representations', async () => {
  for (const format of ['CMS', 'MDOC']) {
    const options = { activationMode: 'HUMAN_WEBAUTHN', trustedTime: true };
    const r = format === 'CMS' ? await runDemo(options) : await runFoundationDemo(options);
    const type = format === 'CMS' ? 'CMS' : 'COSE';
    const objects = r.bundle.objects.map((object) => {
      if (object.type !== type) return object;
      const corrupted = Buffer.from(object.payload);
      corrupted[corrupted.length - 1] ^= 1;
      return evidenceLeaf(type, corrupted);
    });
    const bytes = dcbor(createEvidencePackage(r.bundle.plan.profile, objects));
    for (const knowledgeTime of [now(), now() + 86400]) {
      const result = createVerifier({ format, trust: { ...r.trust, knowledgeTime } }).verify(bytes);
      assert.equal(result.overall, 'INVALID', format + ': ' + result.reason);
      assert.match(result.reason, /SIGNATURE/);
    }
  }
});

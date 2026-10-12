import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { encode, decode } from './cose.mjs';
import { deriveARKG, p256PublicKey } from './arkg.mjs';
import { examplePasskey } from './example-passkey.mjs';
import {
  createRawSigningKey,
  generateRawSigningKey,
  rawSign,
  getRemoteSigningKey,
  remoteCryptoSign,
} from './browser.mjs';
import {
  verifySigningKeyGeneration,
  verifyRawSigningAssertion,
  PASSKEY_SIGN_PROFILE,
} from './raw-signing.mjs';
import {
  PasskeySigningRegistry,
  verifyPasskeyOperation,
  publishPasskeyCRL,
} from './passkey-credentials.mjs';
import { Journal, issuePermit } from './state.mjs';
import { verifyCRL } from './revocation.mjs';
import { runPasskeyDemo } from './passkey-demo.mjs';
import { runFoundationDemo } from './foundation-demo.mjs';
import { verifyMdocSignaturePackage } from './signer-mdoc.mjs';
import { verifyPersonalMdoc } from './signer-mdoc.mjs';
import { createSignaturePackage, verifySignaturePackage } from './evidence.mjs';

const version5 = 'previewSign5-2026-09-09',
  origin = 'https://website.example',
  rpID = 'website.example';
const binaryKey = (key) =>
  Object.fromEntries(
    Object.entries(key).map(([k, v]) => [k, k === 'algorithm' ? v : Buffer.from(v)]),
  );
async function generation(fixture, challenge = c.random(), version = version5, algorithm = -9) {
  const result = await createRawSigningKey(
    {
      challenge,
      rp: { id: rpID, name: 'Example' },
      user: { id: c.random(), name: 'synthetic', displayName: 'Synthetic' },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      attestation: 'direct',
    },
    { version, algorithms: [algorithm], credentials: fixture.credentials },
  );
  return {
    input: { ceremony: result.registration, generatedKey: binaryKey(result.key) },
    options: {
      challenge,
      origin,
      rpID,
      version,
      algorithms: [algorithm],
      attestationPolicy: fixture.attestationPolicy,
    },
  };
}

const vectors = JSON.parse(readFileSync(new URL('./test-vectors/arkg-p256.json', import.meta.url)));
for (const [i, v] of vectors.vectors.entries())
  test('ARKG public derivation matches upstream P-256 vector ' + (i + 1), () => {
    const cose = (hex) => {
      const b = Buffer.from(hex, 'hex');
      return new Map([
        [1, 2],
        [-1, 1],
        [-2, b.subarray(1, 33)],
        [-3, b.subarray(33)],
      ]);
    };
    const seed = encode(
      new Map([
        [1, -65537],
        [3, -65700],
        [-1, cose(v.blindingPublicKey)],
        [-2, cose(v.kemPublicKey)],
      ]),
    );
    const result = deriveARKG({
      seedPublicKey: seed,
      ikm: Buffer.from(v.ikm, 'hex'),
      context: Buffer.from(v.context),
    });
    assert.deepEqual(
      c.spki(result.publicKey),
      c.spki(p256PublicKey(Buffer.from(v.derivedPublicKey, 'hex'))),
    );
    assert.equal(result.ticket.toString('hex'), v.ticket);
    assert.equal(decode(result.additionalArgs).get(3), -65539);
    assert.throws(
      () => deriveARKG({ seedPublicKey: seed, ikm: c.random(31), context: Buffer.from(v.context) }),
      /ARKG_INPUT/,
    );
    assert.throws(
      () => deriveARKG({ seedPublicKey: seed, ikm: c.random(), context: c.random(65) }),
      /ARKG_INPUT/,
    );
  });

test('Passkey example authorization stays inside consent when the clock crosses seconds', async (t) => {
  let clock = Date.now();
  const issueNonce = Journal.prototype.issueNonce;
  t.mock.method(Date, 'now', () => clock);
  t.mock.method(Journal.prototype, 'issueNonce', function (purpose, ...args) {
    if (purpose === 'activation') clock += 1000;
    return Reflect.apply(issueNonce, this, [purpose, ...args]);
  });
  const result = await runPasskeyDemo({ version: version5, algorithm: -65539 });
  assert.equal(result.packageVerification.overall, 'VALID_UNDER_POLICY');
  const sim = c.decodeCBOR(result.bundle.objects.find((o) => o.type === 'SIM').payload),
    activation = c.decodeCBOR(
      result.bundle.objects.find((o) => o.type === 'ActivationContext').payload,
    );
  assert(activation.issuedAt > sim.issuedAt);
  assert(activation.expiresAt <= sim.expiresAt);
});

for (const version of ['previewSign-4', version5])
  for (const algorithm of [-9, -300, -65539])
    test(
      version +
        ' / ' +
        algorithm +
        ': independently certified key, preauthorization and dual-proof CMS',
      async () => {
        const result = await runPasskeyDemo({ version, algorithm, mtc: algorithm === -300 });
        assert.equal(result.verification.authorization, 'PREAUTHORIZED_EVIDENCE');
        assert.equal(result.verification.quantumResistance, 'CLASSICAL');
        assert.equal(result.packageVerification.overall, 'VALID_UNDER_POLICY');
        assert.equal(result.packageVerification.profile, 'certconcord-ecp-cms-passkey-v1');
        assert.throws(
          () =>
            verifySignaturePackage(result.bundle, {
              ...result.packageTrust,
              passkeyStatus: () => false,
            }),
          /EVIDENCE_TRUST/,
        );
        assert.throws(
          () =>
            verifySignaturePackage(
              {
                ...result.bundle,
                objects: result.bundle.objects.filter((o) => o.type !== 'PasskeyRawEvidence'),
              },
              result.packageTrust,
            ),
          /MISSING/,
        );
        const value = (type) => result.bundle.objects.find((o) => o.type === type).payload;
        const downgraded = createSignaturePackage({
          document: result.document,
          certificate: result.evidence.certificate,
          sim: result.sim,
          policy: result.policy,
          activation: c.decodeCBOR(value('ActivationContext')),
          permit: result.evidence.permit,
          receipt: result.evidence.receipt,
          status: value('CertificateStatus'),
          cms: result.cms,
        });
        assert.throws(
          () => verifySignaturePackage(downgraded, result.packageTrust),
          /ECP_PASSKEY_PROFILE/,
        );
        assert.throws(
          () =>
            verifyPasskeyOperation(
              { ...result.evidence, tbs: Buffer.from('substituted') },
              result.trust,
            ),
          /ACTIVATION_BINDING/,
        );
        assert.throws(
          () => verifyPasskeyOperation(result.evidence, { ...result.trust, status: () => false }),
          /EVIDENCE_TRUST/,
        );
        assert.throws(
          () =>
            verifyPasskeyOperation(
              { ...result.evidence, binding: { ...result.evidence.binding, algorithm: -7 } },
              result.trust,
            ),
          /CERTIFICATE_BINDING/,
        );
      },
    );

for (const version of ['previewSign-4', version5])
  test(
    version + ': signed child attestation and parent generation output are both required',
    async () => {
      const f = examplePasskey({ version }),
        { input, options } = await generation(f, c.random(), version);
      const result = verifySigningKeyGeneration(input, options);
      assert.equal(result.fixedFlags, 5);
      assert.notDeepEqual(c.spki(result.publicKey), c.spki(result.registration.publicKey));
      for (const key of ['publicKey', 'keyHandle', 'attestationObject']) {
        const bytes = Buffer.from(input.generatedKey[key]);
        bytes[bytes.length - 1] ^= 1;
        assert.throws(() =>
          verifySigningKeyGeneration(
            { ...input, generatedKey: { ...input.generatedKey, [key]: bytes } },
            options,
          ),
        );
      }
      assert.throws(
        () =>
          verifySigningKeyGeneration(input, {
            ...options,
            version: version === version5 ? 'previewSign-4' : version5,
          }),
        /VERSION_CONFUSION|EXTENSION/,
      );
      assert.throws(
        () => verifySigningKeyGeneration(input, { ...options, challenge: c.random() }),
        /CLIENT_DATA/,
      );
      assert.throws(
        () => verifySigningKeyGeneration(input, { ...options, algorithms: [-300] }),
        /ALGORITHM_BINDING/,
      );
      assert.throws(
        () =>
          verifySigningKeyGeneration(input, {
            ...options,
            attestationPolicy: { ...f.attestationPolicy, models: [] },
          }),
        /MODEL_POLICY/,
      );
      assert.throws(
        () =>
          verifySigningKeyGeneration(input, {
            ...options,
            attestationPolicy: { ...f.attestationPolicy, status: () => ({ status: 'REVOKED' }) },
          }),
        /STATUS/,
      );
      f.setFixedFlags(1);
      const weak = await generation(f, c.random(), version);
      assert.throws(() => verifySigningKeyGeneration(weak.input, weak.options), /FIXED_UV/);
    },
  );

test('v5 generation during assertion verifies existing parent; empty child handle is valid', async () => {
  const f = examplePasskey({ handle: Buffer.alloc(0) }),
    initial = await generation(f);
  const initialResult = verifySigningKeyGeneration(initial.input, initial.options),
    challenge = c.random();
  const next = await generateRawSigningKey(
    { challenge, rpId: rpID, allowCredentials: [{ type: 'public-key', id: f.credentialID }] },
    { credentials: f.credentials },
  );
  const result = verifySigningKeyGeneration(
    {
      ceremony: next.assertion,
      generatedKey: binaryKey(next.key),
      registration: initialResult.registration,
    },
    { ...initial.options, challenge },
  );
  assert.equal(result.keyHandle.length, 0);
  await assert.rejects(
    () => generateRawSigningKey({ allowCredentials: [] }, { credentials: f.credentials }),
    /CEREMONY/,
  );
  await assert.rejects(
    () =>
      generateRawSigningKey(
        { allowCredentials: [{ id: f.credentialID }] },
        { version: 'previewSign-4', credentials: f.credentials },
      ),
    /CEREMONY/,
  );
});

test('raw proof rejects an ordinary assertion, substituted raw output, and double-hashed input', async () => {
  const f = examplePasskey(),
    gen = await generation(f),
    admitted = verifySigningKeyGeneration(gen.input, gen.options);
  const tbs = c.random(100),
    challenge = c.random();
  const proof = await rawSign({
    credentialID: f.credentialID,
    keyHandle: f.keyHandle,
    rpID,
    challenge,
    tbs,
    credentials: f.credentials,
  });
  const options = {
    challenge,
    version: version5,
    algorithm: -9,
    publicKey: admitted.publicKey,
    tbs,
  };
  const raw = { ...proof, signature: Buffer.from(proof.signature) };
  assert.equal(
    verifyRawSigningAssertion(raw, admitted.registration, options).signatureHash.length,
    64,
  );
  assert.throws(
    () =>
      verifyRawSigningAssertion(
        { ...raw, signature: c.sign(tbs, f.document.privateKey) },
        admitted.registration,
        options,
      ),
    /DUAL_BINDING/,
  );
  assert.throws(
    () => verifyRawSigningAssertion(raw, admitted.registration, { ...options, tbs: c.sha256(tbs) }),
    /DOCUMENT_SIGNATURE/,
  );
  const output = decode(c.unb64u(proof.assertion.response.authenticatorData).subarray(37));
  assert.deepEqual(output.get('previewSign5').get(6), raw.signature);
});

test('registry consumes enrollment once and rejects issuance with a different subject or identity', async () => {
  const f = examplePasskey(),
    journal = new Journal();
  try {
    const subjectID = c.random(),
      identityEvidenceHash = c.random(64),
      policyHash = c.random(64);
    const registry = new PasskeySigningRegistry({
      journal,
      trustDomainID: c.random(),
      policyHash,
      origin,
      rpID,
      attestationPolicy: f.attestationPolicy,
      certificateVerifier: () => false,
    });
    const e = registry.begin({ subjectID, identityEvidenceHash, subject: p.name('Synthetic') });
    const g = await generation(f, e.challenge);
    const stage = registry.stage({ requestID: e.context.requestID, ...g.input });
    assert.throws(
      () => registry.stage({ requestID: e.context.requestID, ...g.input }),
      /ENROLLMENT_STATE/,
    );
    const proof = await rawSign({ ...stage, credentials: f.credentials });
    const args = {
      bindingID: stage.bindingID,
      assertion: proof.assertion,
      signature: Buffer.from(proof.signature),
    };
    const admitted = registry.finish(args);
    assert.throws(() => registry.finish(args), /ENROLLMENT_STATE/);
    const valid = {
      csr: admitted.csr,
      subjectID,
      policyHash,
      profileID: PASSKEY_SIGN_PROFILE,
      identityEvidenceHash,
    };
    assert.equal(registry.forIssuance(stage.bindingID, valid).assurance.level, 'KAL2');
    assert.throws(
      () => registry.forIssuance(stage.bindingID, { ...valid, subjectID: c.random() }),
      /ISSUANCE_BINDING/,
    );
    assert.throws(
      () => registry.forIssuance(stage.bindingID, { ...valid, identityEvidenceHash: c.random(64) }),
      /ISSUANCE_BINDING/,
    );
    const second = registry.begin({
      subjectID,
      subject: p.name('Synthetic'),
      identityEvidenceHash,
    });
    const generated = await generateRawSigningKey(
      {
        challenge: second.challenge,
        rpId: rpID,
        allowCredentials: [{ type: 'public-key', id: f.credentialID }],
      },
      { credentials: f.credentials },
    );
    const secondInput = {
      requestID: second.context.requestID,
      ceremony: generated.assertion,
      generatedKey: binaryKey(generated.key),
    };
    assert.throws(
      () =>
        registry.stage({ ...secondInput, registration: { publicKey: c.generate('ec').publicKey } }),
      /PARENT_REGISTRATION/,
    );
    const secondStage = registry.stage(secondInput);
    const secondProof = await rawSign({ ...secondStage, credentials: f.credentials });
    assert.equal(
      registry.finish({
        bindingID: secondStage.bindingID,
        assertion: secondProof.assertion,
        signature: Buffer.from(secondProof.signature),
      }).binding.profileID,
      PASSKEY_SIGN_PROFILE,
    );
  } finally {
    journal.close();
  }
});

test('durable execution rejects duplicate dispatch, reconciles a response once, and propagates signed revocation to CRL', async () => {
  await runPasskeyDemo({
    onComplete: async (x) => {
      const {
        service,
        registry,
        bindingID,
        evidence,
        operation,
        result,
        journal,
        raControl,
        ca,
        issuer,
      } = x;
      assert.deepEqual(
        c.dcbor(
          await service.complete({
            operationID: operation.operationID,
            assertion: result.assertion,
            signature: result.signature,
          }),
        ),
        c.dcbor(result),
      );
      await assert.rejects(
        () =>
          service.complete({
            operationID: operation.operationID,
            assertion: result.assertion,
            signature: c.random(70),
          }),
        /IDEMPOTENCY_CONFLICT/,
      );
      await assert.rejects(
        () => service.begin({ bindingID, permit: evidence.permit, tbs: evidence.tbs }),
        /ALREADY_AVAILABLE/,
      );
      assert.throws(() => registry.activateMdoc(bindingID, {}), /CERTIFICATE_CONFLICT/);
      registry.activate(bindingID, { certificate: evidence.certificate, rar: x.rar });
      await assert.rejects(
        () =>
          x.ra.authorize({
            csr: x.admitted.csr,
            subjectID: evidence.binding.subjectID,
            profileID: PASSKEY_SIGN_PROFILE,
            policyHash: registry.policyHash,
            identityEvidenceHash: evidence.binding.identityEvidenceHash,
            keyBindingID: bindingID,
            issuanceScope: x.issuingCA.issuanceScope,
          }),
        /ISSUANCE_ALREADY_ACTIVE/,
      );
      const second = registry.begin({
        subjectID: evidence.binding.subjectID,
        subject: p.name('Synthetic'),
      });
      const g = await generateRawSigningKey(
        {
          challenge: second.challenge,
          rpId: registry.rpID,
          allowCredentials: [{ type: 'public-key', id: x.authenticator.credentialID }],
        },
        { credentials: x.authenticator.credentials },
      );
      const staged = registry.stage({
        requestID: second.context.requestID,
        ceremony: g.assertion,
        generatedKey: binaryKey(g.key),
      });
      const proof = await rawSign({ ...staged, credentials: x.authenticator.credentials });
      registry.finish({
        bindingID: staged.bindingID,
        assertion: proof.assertion,
        signature: Buffer.from(proof.signature),
      });
      const old = journal.get('passkey-enrollment', c.b64u(bindingID));
      const command = {
        schemaVersion: 1,
        bindingID,
        revision: old.revision,
        trustDomainID: registry.trustDomainID,
        policyHash: registry.policyHash,
        status: 'REVOKED',
        cascadeParent: true,
        reason: 'KEY_COMPROMISE',
        issuedAt: c.now(),
        expiresAt: c.now() + 60,
      };
      const authorization = p.signCMS(
        { content: c.D('PasskeyBindingChange', command), certificate: raControl.certificate },
        raControl.privateKey,
      );
      registry.change({ authorization });
      assert.throws(() => registry.admitted(staged.bindingID), /PARENT_INACTIVE/);
      const secondRow = journal.get('passkey-enrollment', c.b64u(staged.bindingID));
      const downgrade = p.signCMS(
        {
          content: c.D('PasskeyBindingChange', {
            ...command,
            bindingID: staged.bindingID,
            revision: secondRow.revision,
            status: 'SUSPENDED',
          }),
          certificate: raControl.certificate,
        },
        raControl.privateKey,
      );
      assert.throws(
        () => registry.change({ authorization: downgrade }),
        /PARENT_REVOCATION_TERMINAL/,
      );
      assert.equal(
        journal.get('passkey-enrollment', c.b64u(staged.bindingID)).revision,
        secondRow.revision,
      );
      assert.throws(() => registry.active(bindingID), /BINDING_INACTIVE/);
      assert.throws(() => registry.change({ authorization }), /LIFECYCLE_STATE/);
      const serial = p.parseCertificate(evidence.certificate).serial;
      const invalidityDate = c.now() - 50;
      const existingEntries = [
        { serial: 999, reason: 1, revokedAt: c.now() - 1 },
        { serial, reason: 1, revokedAt: c.now() - 1, invalidityDate },
      ];
      const crl = publishPasskeyCRL({
        registry,
        issuer,
        privateKey: ca.privateKey,
        existingEntries,
      });
      const status = verifyCRL(crl, {
        issuer,
        publicKey: ca.publicKey,
        serial: p.parseCertificate(evidence.certificate).serial,
      });
      assert.equal(status.status, 'REVOKED');
      assert.equal(
        verifyCRL(crl, { issuer, publicKey: ca.publicKey, serial: 999n }).status,
        'REVOKED',
      );
      const next = publishPasskeyCRL({
        registry,
        issuer,
        privateKey: ca.privateKey,
        existingEntries: [
          { serial, reason: 6, revokedAt: c.now() + 5, invalidityDate: invalidityDate + 10 },
        ],
      });
      assert.equal(
        verifyCRL(next, { issuer, publicKey: ca.publicKey, serial: 999n }).status,
        'REVOKED',
      );
      assert.equal(
        verifyCRL(next, { issuer, publicKey: ca.publicKey, serial }).number,
        status.number + 1n,
      );
      const stored = journal.get('passkey-crl', c.b64u(c.H('PasskeyCRLIssuer', issuer))).value;
      assert.equal(stored.entries.find((e) => e.serial === String(serial)).reason, 1);
      assert(stored.entries.find((e) => e.serial === String(serial)).revokedAt <= c.now());
      assert.equal(
        stored.entries.find((e) => e.serial === String(serial)).invalidityDate,
        invalidityDate,
      );
      assert.equal(
        verifyCRL(next, {
          issuer,
          publicKey: ca.publicKey,
          serial,
          at: invalidityDate + 1,
          knowledgeTime: c.now(),
        }).status,
        'REVOKED',
      );
      await assert.rejects(
        () => service.begin({ bindingID, permit: evidence.permit, tbs: evidence.tbs }),
        /BINDING_INACTIVE/,
      );
    },
  });
});

test('reserved operations block concurrent prompts; bad responses leave unknown execution without redispatch', async () => {
  await runPasskeyDemo({
    onComplete: async (x) => {
      const activation = { ...x.activation, operationID: c.random(), serverNonce: c.random() };
      const permit = issuePermit(activation, {
        ...x.permitControl,
        activationEvidenceHash: c.random(64),
        proofMode: 'HUMAN_WEBAUTHN',
      });
      const input = { bindingID: x.bindingID, permit, tbs: x.prepared.tbs };
      const request = await x.service.begin(input);
      await assert.rejects(() => x.service.begin(input), /UNKNOWN_EXECUTION/);
      const another = issuePermit(
        { ...activation, operationID: c.random() },
        { ...x.permitControl, activationEvidenceHash: c.random(64), proofMode: 'HUMAN_WEBAUTHN' },
      );
      await assert.rejects(
        () => x.service.begin({ ...input, permit: another }),
        /KEY_OPERATION_PENDING/,
      );
      const raw = await rawSign({ ...request, credentials: x.authenticator.credentials });
      await assert.rejects(
        () =>
          x.service.complete({
            operationID: request.operationID,
            assertion: raw.assertion,
            signature: c.random(70),
          }),
        /DUAL_BINDING/,
      );
      assert.equal(x.service.getOperationResult(request.operationID).status, 'UNKNOWN_EXECUTION');
      const result = await x.service.complete({
        operationID: request.operationID,
        assertion: raw.assertion,
        signature: Buffer.from(raw.signature),
      });
      assert.deepEqual(result.signature, Buffer.from(raw.signature));
      assert.equal(x.service.getOperationResult(request.operationID).status, 'COMPLETED');
    },
  });
});

for (const [identityType, version, algorithm] of [
  ['photoid', 'previewSign-4', -300],
  ['pid', version5, -65539],
])
  test(
    identityType +
      ': RA qualification -> OpenID4VCI signer mdoc -> Passkey raw COSE -> full evidence',
    async () => {
      const result = await runFoundationDemo({
        identityType,
        documentKeyMode: 'PASSKEY_KEY',
        activationMode: 'HUMAN_WEBAUTHN',
        passkeyVersion: version,
        passkeyAlgorithm: algorithm,
      });
      assert.equal(result.verification.overall, 'VALID_UNDER_POLICY');
      assert.equal(result.verification.documentKeyMode, 'PASSKEY_KEY');
      assert.equal(
        result.bundle.objects.some((o) => o.type === 'Certificate'),
        false,
      );
      assert.throws(
        () =>
          verifyMdocSignaturePackage(result.bundle, {
            ...result.trust,
            passkeyStatus: () => false,
          }),
        /EVIDENCE_TRUST/,
      );
      assert.throws(() =>
        verifyMdocSignaturePackage(
          {
            ...result.bundle,
            objects: result.bundle.objects.filter((o) => o.type !== 'PasskeyRawEvidence'),
          },
          result.trust,
        ),
      );
    },
  );

test('WebKit remote key adapter checks capability, usage, exact public key and real WebCrypto signature', async () => {
  const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'sign',
    'verify',
  ]);
  const publicKeySPKI = await webcrypto.subtle.exportKey('spki', pair.publicKey);
  const handle = {
    extractable: false,
    usages: ['sign'],
    algorithm: { name: 'remote', keyId: 'example-key' },
  };
  const subtle = {
    getRemoteKey: async (params, usages) => {
      assert.deepEqual(params, {
        name: 'remote',
        userIdentifier: 'synthetic',
        keyId: 'example-key',
      });
      assert.deepEqual(usages, ['sign']);
      return handle;
    },
    importKey: webcrypto.subtle.importKey.bind(webcrypto.subtle),
    verify: webcrypto.subtle.verify.bind(webcrypto.subtle),
    sign: (alg, key, tbs) => {
      assert.equal(key, handle);
      return webcrypto.subtle.sign(alg, pair.privateKey, tbs);
    },
  };
  const key = await getRemoteSigningKey(
    { userIdentifier: 'synthetic', keyId: 'example-key' },
    { subtle },
  );
  const signature = await remoteCryptoSign({ key, tbs: c.random(80), publicKeySPKI }, { subtle });
  assert.equal(signature.length, 64);
  await assert.rejects(
    () => getRemoteSigningKey({ userIdentifier: 'synthetic' }, { subtle: webcrypto.subtle }),
    /UNAVAILABLE/,
  );
  await assert.rejects(
    () =>
      remoteCryptoSign(
        { key: { ...key, extractable: true }, tbs: c.random(), publicKeySPKI },
        { subtle },
      ),
    /BINDING/,
  );
  await assert.rejects(
    () =>
      remoteCryptoSign(
        { key, tbs: c.random(), publicKeySPKI: c.spki(c.generate('ec').publicKey) },
        { subtle },
      ),
    /SIGNATURE/,
  );
});

test('mdoc status publication consumes binding revocation and invalidates the issued signing credential', async () => {
  await runFoundationDemo({
    identityType: 'custom',
    documentKeyMode: 'PASSKEY_KEY',
    activationMode: 'HUMAN_WEBAUTHN',
    onComplete: async (x) => {
      const registry = x.passkeyRegistry,
        bindingID = x.passkeyBindingID;
      assert.throws(() => registry.activate(bindingID, {}), /CERTIFICATE_CONFLICT/);
      const row = x.journal.get('passkey-enrollment', c.b64u(bindingID));
      const authorization = p.signCMS(
        {
          certificate: x.ra.certificate,
          content: c.D('PasskeyBindingChange', {
            schemaVersion: 1,
            bindingID,
            revision: row.revision,
            trustDomainID: registry.trustDomainID,
            policyHash: registry.policyHash,
            issuedAt: c.now(),
            expiresAt: c.now() + 60,
            status: 'REVOKED',
            reason: 'KEY_COMPROMISE',
            cascadeParent: true,
          }),
        },
        x.ra.privateKey,
      );
      registry.change({ authorization });
      const statusToken = x.issuer.publishPasskeyStatus();
      assert.throws(
        () => verifyPersonalMdoc(x.credential, { ...x.credentialTrust, seal: x.seal, statusToken }),
        /STATUS_LIST_REVOKED/,
      );
    },
  });
});

test('none attestation cannot create a hardware parent from a separately valid child attestation', async () => {
  const f = examplePasskey(),
    { input, options } = await generation(f);
  const attestation = decode(c.unb64u(input.ceremony.response.attestationObject));
  attestation.set('fmt', 'none');
  attestation.set('attStmt', new Map());
  const ceremony = {
    ...input.ceremony,
    response: { ...input.ceremony.response, attestationObject: c.b64u(encode(attestation)) },
  };
  assert.throws(
    () => verifySigningKeyGeneration({ ...input, ceremony }, options),
    /RAW_PARENT_REGISTRATION/,
  );
});

test('raw browser driver rejects unavailable capability and excessive messages before prompting', async () => {
  await assert.rejects(() => createRawSigningKey({}, { credentials: {} }), /UNAVAILABLE/);
  await assert.rejects(() => rawSign({ credentials: {} }), /UNAVAILABLE/);
  const f = examplePasskey();
  await assert.rejects(
    () =>
      rawSign({
        credentials: f.credentials,
        credentialID: f.credentialID,
        keyHandle: f.keyHandle,
        challenge: c.random(64),
        tbs: Buffer.alloc(1024 * 1024 + 1),
      }),
    /INPUT/,
  );
});

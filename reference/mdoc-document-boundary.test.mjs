import test from 'node:test';
import assert from 'node:assert/strict';
import {
  D,
  H,
  generate,
  sign,
  verify,
  sha512,
  random,
  dcbor,
  decodeCBOR,
  publicFromDER,
} from './core.mjs';
import { encode, decode, get } from './cose.mjs';
import { derToP1363, p1363ToDER } from './ecdsa.mjs';
import { prepareDocumentSignature, verifyDocumentSignature } from './vendor/mdoc-signing/base.mjs';
import {
  prepareMdocDocument,
  verifyMdocDocument,
  DEVICE_SIGN_PROFILE,
  SIGNER_NAMESPACE,
  SIGNER_DOCTYPE,
} from './signer-mdoc.mjs';
import { PASSKEY_SIGN_PROFILE } from './raw-signing.mjs';
import { verifyIssuerSigned } from './mdoc.mjs';
import { runFoundationDemo } from './foundation-demo.mjs';
import { createVerifier } from './sdk/index.mjs';
import { checkpointBody, noteSignature, verifyNote } from './transparency.mjs';
import { verifyCredentialLog } from './credential-log.mjs';
import { leafHash } from './mtc.mjs';

const labels = {
  context: 'urn:certconcord:context:1',
  sim: 'urn:certconcord:sim:1',
  policy: 'urn:certconcord:policy:1',
  credential: 'urn:certconcord:credential:1',
};
const required = (options) =>
  new Map([
    [labels.context, D('SignatureContext', options.context)],
    [labels.sim, options.simHash],
    [labels.policy, options.policyHash],
  ]);
const modes = [
  ['ML-DSA-65', 'ml-dsa-65', 'CERTCONCORD-PERSON-SIGN-v1'],
  ['ML-DSA-87', 'ml-dsa-87', 'CERTCONCORD-PERSON-SIGN-v1'],
  ['P-256 device', 'ec', DEVICE_SIGN_PROFILE],
  ['P-256 passkey', 'ec', PASSKEY_SIGN_PROFILE],
];
const fixtures = new Map();
function fixture(label, algorithm, profileID) {
  if (!fixtures.has(label)) {
    const key = generate(algorithm),
      document = Buffer.from('A detached document with exact original bytes.\r\n'),
      // This primitive hashes the credential bytes. Issuer admission is tested
      // separately by the complete SDK fixture below, not claimed by this input.
      credential = Buffer.from('opaque credential bytes for the document primitive'),
      options = {
        credential,
        publicKey: key.publicKey,
        context: {
          schemaVersion: 1,
          trustDomainID: random(32),
          profileID,
          container: 'COSE',
          adapterID: 'certconcord-mdoc-document-v1',
          credentialType: 'MDOC',
        },
        simHash: random(64),
        policyHash: random(64),
      };
    fixtures.set(label, {
      key,
      document,
      options,
      componentOptions: {
        credential,
        publicKey: key.publicKey,
        requiredProtectedHeaders: required(options),
      },
    });
  }
  return fixtures.get(label);
}
const toWire = (signature, key) =>
  key.asymmetricKeyType === 'ec' ? derToP1363(signature) : signature;
const toProvider = (signature, key) =>
  key.asymmetricKeyType === 'ec' ? p1363ToDER(signature) : signature;
function componentSignature(f) {
  const prepared = prepareDocumentSignature(f.document, f.componentOptions),
    providerSignature = sign(prepared.tbs, f.key.privateKey),
    wire = toWire(providerSignature, f.key.publicKey);
  return { prepared, providerSignature, wire, encoded: prepared.finish(wire) };
}

for (const mode of modes) {
  const [label] = mode;
  test(`${label} framework document is consumed by the pinned component`, () => {
    const f = fixture(...mode),
      prepared = prepareMdocDocument(f.document, f.options),
      providerSignature = sign(prepared.tbs, f.key.privateKey),
      encoded = prepared.finish(providerSignature),
      result = verifyDocumentSignature(encoded, f.document, f.componentOptions),
      component = prepareDocumentSignature(f.document, f.componentOptions);
    assert.deepEqual(result.tbs, prepared.tbs);
    assert.deepEqual(toProvider(result.signature, f.key.publicKey), providerSignature);
    assert.deepEqual(component.tbs, prepared.tbs);
    assert.deepEqual(component.finish(toWire(providerSignature, f.key.publicKey)), encoded);
    assert.deepEqual(get(decode(decode(encoded)[0]), 2), [
      labels.credential,
      labels.sim,
      labels.policy,
      labels.context,
    ]);
  });

  test(`${label} component document is consumed by the framework without rewriting bytes`, () => {
    const f = fixture(...mode),
      signed = componentSignature(f),
      result = verifyMdocDocument(signed.encoded, f.document, f.options);
    assert.deepEqual(result.tbs, signed.prepared.tbs);
    assert.deepEqual(result.signature, signed.providerSignature);
    assert.equal(verify(result.tbs, result.signature, f.key.publicKey), true);
    assert.throws(
      () => verifyMdocDocument(signed.encoded, Buffer.from('a different document'), f.options),
      (error) => error.code === 'MDOC_DOCUMENT_SIGNATURE',
    );
    assert.throws(
      () =>
        verifyMdocDocument(signed.encoded, f.document, { ...f.options, policyHash: random(64) }),
      (error) => error.code === 'MDOC_DOCUMENT_PROTECTED_HEADERS',
    );
  });

  test(`${label} a mathematically valid legacy critical order has no compatibility fallback`, () => {
    const f = fixture(...mode),
      component = componentSignature(f),
      value = decode(component.encoded),
      headers = decode(value[0]);
    headers.set(2, [labels.context, labels.sim, labels.policy, labels.credential]);
    value[0] = encode(headers);
    const tbs = encode(['Signature1', value[0], Buffer.alloc(0), f.document]),
      providerSignature = sign(tbs, f.key.privateKey);
    value[3] = toWire(providerSignature, f.key.publicKey);
    assert.equal(verify(tbs, providerSignature, f.key.publicKey), true);
    const encoded = encode(value);
    assert.throws(
      () => verifyDocumentSignature(encoded, f.document, f.componentOptions),
      (error) => error.code === 'MDOC_DOCUMENT_PROTECTED_HEADERS',
    );
    assert.throws(
      () => verifyMdocDocument(encoded, f.document, f.options),
      (error) => error.code === 'MDOC_DOCUMENT_PROTECTED_HEADERS',
    );
  });

  test(`${label} framework retains component bad mathematics before a protected binding mismatch`, () => {
    const f = fixture(...mode),
      signed = componentSignature(f),
      value = decode(signed.encoded);
    value[3][0] ^= 1;
    const encoded = encode(value),
      options = { ...f.options, simHash: random(64) };
    assert.equal(
      verify(signed.prepared.tbs, toProvider(value[3], f.key.publicKey), f.key.publicKey),
      false,
    );
    assert.throws(
      () => verifyMdocDocument(encoded, f.document, options),
      (error) => error.code === 'MDOC_DOCUMENT_SIGNATURE',
    );
  });
}

test('framework document key-mode restrictions remain independent of component capability', () => {
  const pq = fixture(...modes[0]),
    ec = fixture(...modes[2]);
  for (const [f, profileID] of [
    [pq, DEVICE_SIGN_PROFILE],
    [pq, PASSKEY_SIGN_PROFILE],
    [ec, 'CERTCONCORD-PERSON-SIGN-v1'],
  ]) {
    const options = { ...f.options, context: { ...f.options.context, profileID } },
      signed = componentSignature(f);
    assert.throws(
      () => prepareMdocDocument(f.document, options),
      (error) => error.code === 'MDOC_DOCUMENT_ALGORITHM',
    );
    assert.throws(
      () => verifyMdocDocument(signed.encoded, f.document, options),
      (error) => error.code === 'MDOC_DOCUMENT_ALGORITHM',
    );
  }
});

test('a complete SDK native document uses the same component wire contract', async () => {
  const f = await runFoundationDemo({ activationMode: 'HUMAN_WEBAUTHN' }),
    values = Object.fromEntries(f.bundle.objects.map((object) => [object.type, object.payload])),
    sim = decodeCBOR(values.SIM),
    policy = decodeCBOR(values.SignaturePolicy),
    verified = createVerifier({ format: 'MDOC', trust: f.trust }).verify(dcbor(f.bundle));
  assert.equal(verified.overall, 'VALID', verified.reason);
  const credential = verifyIssuerSigned(values.PersonalMdoc, {
      certificate: f.trust.issuerCertificate,
      issuerKey: f.trust.issuerPublicKey,
      docType: SIGNER_DOCTYPE,
      allowPartial: false,
    }),
    publicKey = publicFromDER(credential.claims.get(SIGNER_NAMESPACE).get('signing_key')),
    options = {
      credential: values.PersonalMdoc,
      publicKey,
      context: {
        schemaVersion: 1,
        trustDomainID: sim.trustDomainID,
        profileID: sim.profileID,
        container: 'COSE',
        adapterID: sim.adapterID,
        credentialType: 'MDOC',
      },
      simHash: H('SIM', sim),
      policyHash: H('SignaturePolicy', policy),
    },
    primitive = verifyDocumentSignature(values.COSE, values.Document, {
      credential: values.PersonalMdoc,
      publicKey,
      requiredProtectedHeaders: required(options),
    }),
    framework = verifyMdocDocument(values.COSE, values.Document, options);
  assert.deepEqual(primitive.tbs, framework.tbs);
  assert.deepEqual(toProvider(primitive.signature, publicKey), framework.signature);
  assert.equal(verify(framework.tbs, framework.signature, publicKey), true);
  assert.deepEqual(
    get(decode(decode(values.COSE)[0]), labels.credential),
    sha512(values.PersonalMdoc),
  );
});

function withWallClock(milliseconds, callback) {
  const original = Date.now;
  try {
    Date.now = () => milliseconds;
    return callback();
  } finally {
    Date.now = original;
  }
}

test('native document verification uses declared knowledge time independently of wall clock', async (t) => {
  const f = await runFoundationDemo({ activationMode: 'HUMAN_WEBAUTHN' }),
    knowledgeTime = Math.floor(Date.now() / 1000),
    verifier = createVerifier({ format: 'MDOC', trust: { ...f.trust, knowledgeTime } }),
    bytes = dcbor(f.bundle),
    expected = verifier.verify(bytes);
  assert.equal(expected.overall, 'VALID', expected.reason);
  for (const milliseconds of [0, Date.UTC(2100, 0, 1)])
    await t.test(String(milliseconds), () => {
      assert.deepEqual(
        withWallClock(milliseconds, () => verifier.verify(bytes)),
        expected,
      );
    });
});

test('timestamped notes retain their future limit at explicit knowledge time', () => {
  const signer = { ...generate('ed25519'), name: 'clock.example/mirror', scheme: 'ed25519-cosign' },
    knowledgeTime = 1_800_000_000,
    body = checkpointBody('clock.example/log', 1, random(32)),
    note = (timestamp) => body + '\n' + noteSignature(body, signer, { timestamp });
  withWallClock(0, () => {
    assert.equal(verifyNote(note(knowledgeTime + 30), signer, { knowledgeTime }).body, body);
  });
  withWallClock(Date.UTC(2100, 0, 1), () => {
    assert.throws(
      () => verifyNote(note(knowledgeTime + 31), signer, { knowledgeTime }),
      (error) => error.code === 'NOTE_UNTRUSTED_SIGNATURE',
    );
    for (const invalid of [null, -1, 1.5, '1800000000'])
      assert.throws(
        () => verifyNote(note(knowledgeTime), signer, { knowledgeTime: invalid }),
        (error) => error.code === 'NOTE_VERIFICATION_TIME',
      );
  });
});

test('credential log checkpoint and mirror checks share explicit knowledge time', () => {
  const log = { ...generate('ed25519'), name: 'clock.example/log', scheme: 'ed25519-cosign' },
    mirror = {
      ...generate('ed25519'),
      name: 'clock.example/mirror',
      operatorID: 'independent-mirror',
      scheme: 'ed25519-cosign',
    },
    knowledgeTime = 1_800_000_000,
    expectedEntry = { schemaVersion: 1, credentialID: random(64) },
    entry = D('PersonalMdocLogEntry', expectedEntry),
    root = leafHash(entry),
    body = checkpointBody(log.name, 1, root),
    proof = (logTime, mirrorTime) => ({
      schemaVersion: 1,
      adapterID: 'certconcord-mdoc-issuance-log-v1',
      entry,
      index: 0,
      size: 1,
      root,
      path: [],
      checkpoint: body + '\n' + noteSignature(body, log, { timestamp: logTime }),
      receipts: [
        {
          operatorID: mirror.operatorID,
          note: body + '\n' + noteSignature(body, mirror, { timestamp: mirrorTime }),
        },
      ],
    }),
    trust = { log, members: [mirror], threshold: 1, knowledgeTime };
  withWallClock(0, () => {
    assert.equal(
      verifyCredentialLog(proof(knowledgeTime, knowledgeTime), expectedEntry, trust).operatorCount,
      1,
    );
  });
  withWallClock(Date.UTC(2100, 0, 1), () => {
    for (const [logTime, mirrorTime] of [
      [knowledgeTime + 31, knowledgeTime],
      [knowledgeTime, knowledgeTime + 31],
    ])
      assert.throws(
        () => verifyCredentialLog(proof(logTime, mirrorTime), expectedEntry, trust),
        (error) => error.code === 'NOTE_UNTRUSTED_SIGNATURE',
      );
  });
});

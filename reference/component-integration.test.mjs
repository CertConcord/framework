import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { deflateSync } from 'node:zlib';
import { b64u, generate, now, sha256 } from './core.mjs';
import { signJWS } from './jose.mjs';
import { verifyStatusList } from './openid.mjs';
import { verifyMdocStatusList } from './mdoc.mjs';
import { evaluateSignedDocument } from './vendor/mdoc-signing/base.mjs';

const read = (path) => readFileSync(new URL('../' + path, import.meta.url));
const vectors = JSON.parse(read('spec/external/mdoc-signing/vectors/base.json'));
// Test configuration supplies this root; neither the credential nor a token can
// replace it. Production issuer authorization additionally evaluates lifecycle.
const trustedRoot = new X509Certificate(Buffer.from(vectors.trust.rootCertificate, 'hex'));

test('locked component snapshots retain the exact reviewed bytes', () => {
  const lock = JSON.parse(read('components.lock.json'));
  for (const component of lock.components)
    for (const file of component.files)
      assert.equal(sha256(read(file.path)).toString('hex'), file.sha256, file.path);
});

for (const id of [
  'independent-ml-dsa-65',
  'independent-ml-dsa-87',
  'explicit-device-document-key',
  'explicit-associated-document-key',
  'protected-x5chain',
  'invalid-issuer-signature',
  'same-key-certificate-substitution',
  'invalid-document-signature',
  'legacy-missing-certificate-binding',
  'status-stale',
  'status-revoked',
  'status-missing',
  'status-wrong-uri',
  'status-bad-signature',
])
  test('component credential with framework status verification: ' + id, () => {
    const vector = vectors.cases.find((item) => item.id === id),
      certificate = Buffer.from(vector.certificate, 'hex'),
      issuerKey = new X509Certificate(certificate).publicKey;
    const actual = evaluateSignedDocument(
      Buffer.from(vector.document, 'hex'),
      Buffer.from(vector.signature, 'hex'),
      Buffer.from(vector.credential, 'hex'),
      {
        certificate,
        issuerKey,
        profileID: vector.profileID,
        documentKeyMode: vector.documentKeyMode,
        stateTime: vector.stateTime,
        knowledgeTime: vector.knowledgeTime,
        statusEvidence: vector.statusEvidence,
        authorizeIssuer: (context) => {
          const leaf = new X509Certificate(context.certificate),
            admitted =
              context.issuer === vectors.trust.issuer &&
              context.purpose === 'DOCUMENT_SIGN' &&
              leaf.issuer === trustedRoot.subject &&
              leaf.verify(trustedRoot.publicKey) &&
              leaf.keyUsage.includes('1.0.18013.5.1.2');
          return { overall: admitted ? 'VALID' : 'INVALID' };
        },
        resolveStatus: (context) => {
          assert.equal(context.reference.uri, vectors.trust.statusURI);
          return verifyMdocStatusList(context.evidence, {
            publicKey: issuerKey,
            uri: vectors.trust.statusURI,
            index: context.reference.idx,
            at: context.knowledgeTime,
            evaluateStatusList: verifyStatusList,
          });
        },
      },
    );
    assert.equal(actual.overall, vector.expected.overall);
    if (vector.expected.reason && id !== 'status-missing')
      assert.equal(actual.reason, vector.expected.reason);
  });

test('mdoc status TTL is authenticated and cannot erase invalid or revoked evidence', () => {
  const key = generate('ec'),
    at = now(),
    uri = 'https://issuer.example/status/1',
    options = { publicKey: key.publicKey, uri, index: 0, at, evaluateStatusList: verifyStatusList },
    claims = {
      iss: uri,
      sub: uri,
      iat: at,
      exp: at + 300,
      ttl: 30,
      status_list: { bits: 1, lst: b64u(deflateSync(Buffer.alloc(8))) },
    },
    token = (changes = {}, privateKey = key.privateKey) =>
      signJWS({ ...claims, ...changes }, privateKey, { typ: 'statuslist+jwt' });
  assert.deepEqual(verifyMdocStatusList(token(), options), { status: 'GOOD', overall: 'VALID' });
  assert.deepEqual(verifyMdocStatusList(token(), { ...options, at: at + 30 }), {
    status: 'STALE',
    overall: 'INDETERMINATE',
    reason: 'MDOC_STATUS_TTL_EXPIRED',
  });
  for (const ttl of [undefined, 0, -1, 301, 0.5, '30'])
    assert.deepEqual(verifyMdocStatusList(token({ ttl }), { ...options, at: at + 400 }), {
      status: 'INVALID',
      overall: 'INVALID',
      reason: 'MDOC_STATUS_TTL',
    });
  assert.equal(
    verifyMdocStatusList(token({}, generate('ec').privateKey), {
      ...options,
      at: at + 400,
    }).status,
    'INVALID',
  );
  const revoked = token({ status_list: { bits: 1, lst: b64u(deflateSync(Buffer.from([1]))) } });
  for (const time of [at, at + 30, at + 400])
    assert.equal(verifyMdocStatusList(revoked, { ...options, at: time }).status, 'REVOKED');
});

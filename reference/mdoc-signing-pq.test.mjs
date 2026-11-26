import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import {
  evaluateExperimentalPqDocumentBundle,
  verifyPqMdocStatusList,
} from './mdoc-signing-pq.mjs';
import { evaluateSignedDocument } from './vendor/mdoc-signing/base.mjs';
import { verifyHolderAuthentication } from './vendor/mdoc-signing/holder-auth.mjs';
import { validateMdocCertificate } from './mdoc-pki.mjs';

const read = (path) => JSON.parse(readFileSync(new URL('../' + path, import.meta.url)));
const vectors = read('spec/external/mdoc-signing/vectors/pqc-base.json');
const holders = read('spec/external/mdoc-signing/vectors/holder-auth.json');
const bytes = (value) => Buffer.from(value, 'hex');
const root = new X509Certificate(bytes(vectors.trust.rootCertificate));

function authorizeIssuer(context, policy) {
  const leaf = new X509Certificate(context.certificate);
  const valid =
    policy !== 'issuer-not-admitted' &&
    context.trustAnchorCertificate?.equals(root.raw) &&
    context.issuer === vectors.trust.issuer &&
    context.purpose === 'DOCUMENT_SIGN' &&
    context.statusAlgorithm === 'ML-DSA-65' &&
    context.profileID === 'MDOC-SIGNING-PERSON-PQ-v3' &&
    context.documentKeyMode === 'INDEPENDENT_PQ' &&
    leaf.issuer === root.subject &&
    leaf.verify(root.publicKey) &&
    leaf.keyUsage.includes('1.0.18013.5.1.2');
  return { overall: valid ? 'VALID' : 'INVALID' };
}

function evaluate(vector, changes = {}) {
  const input = { ...vectors.base, ...vector, ...changes };
  return evaluateExperimentalPqDocumentBundle({
    document: bytes(input.document),
    signature: bytes(input.signature),
    credential: bytes(input.credential),
    deviceSigned: bytes(input.deviceSigned),
    sessionTranscript: bytes(input.sessionTranscript),
    certificate: bytes(input.certificate),
    trustAnchorCertificate:
      input.trustAnchorCertificate === null
        ? undefined
        : bytes(input.trustAnchorCertificate ?? vectors.trust.rootCertificate),
    stateTime: input.stateTime,
    knowledgeTime: input.knowledgeTime,
    statusEvidence: input.statusEvidence,
    statusURI: vectors.trust.statusURI,
    authorizeIssuer: (context) => authorizeIssuer(context, input.policy),
    ...(input.profileID ? { profileID: input.profileID } : {}),
  });
}

for (const vector of vectors.cases) {
  if (vector.id === 'pqc-reject-classic-status-claim') continue;
  test('Framework experimental PQ bundle from exact component vector: ' + vector.id, () => {
    const actual = evaluate(vector);
    const expected =
      vector.id === 'pqc-reject-unselected-profile' ? 'UNSUPPORTED' : vector.expected.overall;
    assert.equal(actual.overall, expected, JSON.stringify({ id: vector.id, actual }));
    if (expected === 'VALID') {
      assert.equal(actual.profileID, 'MDOC-SIGNING-PERSON-PQ-v3');
      assert.equal(actual.holderKeyType, 'ml-dsa-65');
      assert(['ml-dsa-65', 'ml-dsa-87'].includes(actual.documentKeyType));
      assert.equal(actual.status.algorithm, 'ML-DSA-65');
      assert.equal(actual.holderProof.signature.length, 3309);
    }
  });
}

test('Framework PQ bundle binds the exact holder session and explicit authorization', () => {
  const good = evaluate(vectors.cases.find((item) => item.id === 'pqc-complete-ml-dsa-65'));
  assert.equal(good.overall, 'VALID');
  const changed = holders.cases.find((item) => item.id === 'changed-session-transcript');
  assert.deepEqual(
    { overall: evaluate({}, { sessionTranscript: changed.sessionTranscript }).overall },
    { overall: 'INVALID' },
  );
  const absent = evaluateExperimentalPqDocumentBundle({
    document: bytes(vectors.base.document),
    signature: bytes(vectors.base.signature),
    credential: bytes(vectors.base.credential),
    deviceSigned: bytes(vectors.base.deviceSigned),
    sessionTranscript: bytes(vectors.base.sessionTranscript),
    certificate: bytes(vectors.base.certificate),
    trustAnchorCertificate: root.raw,
    stateTime: vectors.base.stateTime,
    knowledgeTime: vectors.base.knowledgeTime,
    statusEvidence: vectors.base.statusEvidence,
    statusURI: vectors.trust.statusURI,
  });
  assert.deepEqual(absent, {
    overall: 'INDETERMINATE',
    reason: 'MDOC_ISSUER_AUTHORIZATION_MISSING',
  });
});

test('Framework PQ status verifier authenticates ML-DSA and rejects classical downgrade', () => {
  const issuerKey = new X509Certificate(bytes(vectors.base.certificate)).publicKey;
  const options = {
    publicKey: issuerKey,
    uri: vectors.trust.statusURI,
    index: 0,
    at: vectors.base.knowledgeTime,
  };
  assert.deepEqual(verifyPqMdocStatusList(vectors.base.statusEvidence, options), {
    status: 'GOOD',
    overall: 'VALID',
    algorithm: 'ML-DSA-65',
  });
  const classical = vectors.cases.find((item) => item.id === 'pqc-reject-classic-status-token');
  assert.equal(verifyPqMdocStatusList(classical.statusEvidence, options).overall, 'INVALID');
  assert.deepEqual(
    verifyPqMdocStatusList(vectors.base.statusEvidence, { ...options, at: undefined }),
    {
      status: 'INVALID',
      overall: 'INVALID',
      reason: 'MDOC_STATUS_TIME',
    },
  );
  assert.deepEqual(verifyPqMdocStatusList(vectors.base.statusEvidence), {
    status: 'INVALID',
    overall: 'INVALID',
    reason: 'MDOC_STATUS_TIME',
  });
});

test('component itself rejects a forged classical GOOD status decision', () => {
  const input = vectors.base,
    certificate = bytes(input.certificate);
  const result = evaluateSignedDocument(
    bytes(input.document),
    bytes(input.signature),
    bytes(input.credential),
    {
      certificate,
      issuerKey: new X509Certificate(certificate).publicKey,
      trustAnchorCertificate: root.raw,
      profileID: input.profileID,
      documentKeyMode: input.documentKeyMode,
      stateTime: input.stateTime,
      knowledgeTime: input.knowledgeTime,
      statusEvidence: input.statusEvidence,
      authorizeIssuer: (context) => authorizeIssuer(context),
      resolveStatus: () => ({ status: 'GOOD', overall: 'VALID', algorithm: 'ES256' }),
    },
  );
  assert.deepEqual(result, { overall: 'INVALID', reason: 'MDOC_PQC_STATUS_REQUIRED' });
});

test('component holder verifier rejects a validly signed classical device proof for v3', () => {
  const vector = {
    ...holders.base,
    ...holders.cases.find(
      (item) => item.id === 'validly-signed-classic-holder-v3-with-legacy-enabled',
    ),
  };
  const certificate = bytes(vector.certificate);
  assert.throws(
    () =>
      verifyHolderAuthentication(bytes(vector.deviceSigned), bytes(vector.credential), {
        issuerKey: new X509Certificate(certificate).publicKey,
        certificate,
        at: vector.at,
        sessionTranscript: bytes(vector.sessionTranscript),
        allowLegacyClassical: true,
      }),
    { code: 'MDOC_HOLDER_PQC_REQUIRED' },
  );
});

test('the existing ISO_MDOC certificate admission remains P-256 only', () => {
  assert.throws(
    () =>
      validateMdocCertificate(bytes(vectors.base.certificate), {
        at: vectors.base.stateTime,
        certificateProfile: 'ISO_MDOC',
      }),
    { code: 'MDOC_CERTIFICATE_PROFILE' },
  );
});

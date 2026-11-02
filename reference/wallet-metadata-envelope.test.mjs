import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, verify, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { OpenIDWallet } from './wallet.mjs';

const vectors = JSON.parse(
  readFileSync(new URL('./vectors/wallet-metadata-envelopes.json', import.meta.url)),
);
const certificates = Object.fromEntries(
  Object.entries(vectors.certificates).map(([id, value]) => [
    id,
    new X509Certificate(Buffer.from(value, 'base64')),
  ]),
);
const holder = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const body = (row) => Buffer.from(row.bodyBase64, 'base64');
const response = (row) =>
  new Response(body(row), {
    status: row.status,
    headers: row.contentType === null ? {} : { 'content-type': row.contentType },
  });
const wallet = (row) =>
  new OpenIDWallet({
    issuer: vectors.issuer,
    clientID: 'synthetic-wallet',
    clientAuthentication: async () => ({ parameters: {}, headers: {} }),
    holderPublicKey: holder.publicKey,
    issuerCertificate: certificates[row.pinnedLeaf].raw,
    issuerRoots: [certificates[row.trustedRoot]],
  });

test('wallet metadata: raw compact and legacy envelopes carry the same independently verified JWT', () => {
  const compact = body(vectors.cases.find((row) => row.id === 'compact-jwt')).toString('utf8');
  const legacy = JSON.parse(body(vectors.cases.find((row) => row.id === 'legacy-json-same-jwt')));
  assert.equal(legacy.signed_metadata, compact);
  const [header, payload, signature] = compact.split('.');
  const decoded = JSON.parse(Buffer.from(header, 'base64url'));
  assert.deepEqual(decoded, {
    alg: 'ES256',
    typ: 'openidvci-issuer-metadata+jwt',
    x5c: [vectors.certificates.issuer],
  });
  assert(certificates.issuer.verify(certificates.root.publicKey));
  assert(certificates.root.verify(certificates.root.publicKey));
  assert(
    verify(
      'sha256',
      Buffer.from(header + '.' + payload, 'ascii'),
      { key: certificates.issuer.publicKey, dsaEncoding: 'ieee-p1363' },
      Buffer.from(signature, 'base64url'),
    ),
  );
  assert.equal(JSON.parse(Buffer.from(payload, 'base64url')).credential_issuer, vectors.issuer);
});

for (const row of vectors.cases) {
  test('wallet metadata: ' + row.id, async (t) => {
    t.mock.timers.enable({ apis: ['Date'], now: row.at * 1000 });
    const bytes = body(row);
    assert.equal(createHash('sha256').update(bytes).digest('hex'), row.sha256);
    const requests = [];
    t.mock.method(globalThis, 'fetch', async (url, options) => {
      requests.push({ url, options });
      return response(row);
    });
    const subject = wallet(row);
    if (row.expectedAcceptance) {
      const result = await subject.discover();
      assert.deepEqual(structuredClone(result), row.expectedClaims);
      assert.equal(subject.metadata, result);
      assert.deepEqual(
        subject.issuerPublicKey.export({ type: 'spki', format: 'der' }),
        certificates.issuer.publicKey.export({ type: 'spki', format: 'der' }),
      );
    } else {
      await assert.rejects(subject.discover(), (error) => error.message === row.expectedError);
      assert.equal(subject.metadata, undefined);
      assert.equal(subject.issuerPublicKey, undefined);
    }
    assert.equal(requests.length, 1);
    assert.equal(requests[0].url, vectors.discoveryURL);
    assert.equal(requests[0].options.method, 'GET');
    assert.equal(requests[0].options.redirect, 'error');
    assert.equal(requests[0].options.headers.accept, 'application/jwt, application/json;q=0.5');
  });
}

test('wallet metadata: failed rediscovery does not replace authenticated metadata or signer', async (t) => {
  const good = vectors.cases.find((row) => row.id === 'compact-jwt');
  const bad = vectors.cases.find((row) => row.id === 'wrong-credential_issuer');
  t.mock.timers.enable({ apis: ['Date'], now: vectors.at * 1000 });
  let calls = 0;
  t.mock.method(globalThis, 'fetch', async () => response(calls++ === 0 ? good : bad));
  const subject = wallet(good);
  const original = await subject.discover(),
    key = subject.issuerPublicKey;
  await assert.rejects(subject.discover(), { message: 'ISSUER_METADATA_BINDING' });
  assert.equal(subject.metadata, original);
  assert.equal(subject.issuerPublicKey, key);
  assert.equal(calls, 2);
});

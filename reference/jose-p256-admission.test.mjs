import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  verify,
  X509Certificate,
} from 'node:crypto';
import { readFileSync } from 'node:fs';
import { importPublicJWK, joseAlgorithm, signJWS, thumbprint, verifyJWS } from './jose.mjs';
import { OpenIDWallet } from './wallet.mjs';

const vectors = JSON.parse(
  readFileSync(new URL('./vectors/jose-p256-admission.json', import.meta.url)),
);
const keys = Object.fromEntries(
  Object.entries(vectors.keys).map(([id, row]) => [
    id,
    createPublicKey({ key: Buffer.from(row.spkiBase64, 'base64'), type: 'spki', format: 'der' }),
  ]),
);
const certificates = Object.fromEntries(
  Object.entries(vectors.certificates).map(([id, raw]) => [
    id,
    new X509Certificate(Buffer.from(raw, 'base64')),
  ]),
);
const hash = (value) => createHash('sha256').update(value).digest('hex');
const byID = (id) => vectors.cases.find((row) => row.id === id);
const options = (row) => ({
  typ: 'openidvci-issuer-metadata+jwt',
  ...(row.mode !== 'compact' ? { detached: Buffer.from(row.payloadBase64, 'base64') } : {}),
});

test('JOSE P-256 raw vectors independently bind curve, signature encoding and signing input', () => {
  assert.equal(new Set(vectors.cases.map((row) => row.id)).size, vectors.cases.length);
  for (const [id, publicKey] of Object.entries(keys)) {
    assert.equal(publicKey.asymmetricKeyDetails.namedCurve, vectors.keys[id].curve);
    assert.deepEqual(
      certificates[id].publicKey.export({ type: 'spki', format: 'der' }),
      publicKey.export({ type: 'spki', format: 'der' }),
    );
    assert(certificates[id].verify(certificates.root.publicKey));
    assert.equal(certificates[id].issuer, certificates.root.subject);
    assert.equal(certificates[id].ca, false);
  }
  assert(certificates.root.verify(certificates.root.publicKey));
  assert.equal(certificates.root.ca, true);
  for (const row of vectors.cases) {
    assert.equal(hash(row.token), row.tokenSHA256, row.id);
    const [header, payload, signature] = row.token.split('.');
    const content = Buffer.from(row.payloadBase64, 'base64');
    assert.equal(payload, row.mode === 'compact' ? content.toString('base64url') : '');
    const input = Buffer.concat([
      Buffer.from(header + '.', 'ascii'),
      row.mode === 'detached-unencoded'
        ? content
        : Buffer.from(content.toString('base64url'), 'ascii'),
    ]);
    assert.deepEqual(input, Buffer.from(row.signingInputBase64, 'base64'), row.id);
    assert.equal(hash(input), row.signingInputSHA256, row.id);
    const raw = Buffer.from(signature, 'base64url');
    assert.equal(raw.toString('base64url'), signature);
    assert.equal(raw.length, row.signatureBytes);
    assert.equal(
      verify('sha256', input, { key: keys[row.keyID], dsaEncoding: row.nativeEncoding }, raw),
      row.nativeSignatureValid,
      row.id,
    );
  }
  for (const id of [
    'p256-compact',
    'p384-compact',
    'p521-compact',
    'k256-compact',
    'p256-signature-der',
  ])
    assert.equal(byID(id).nativeSignatureValid, true, id);
  assert.equal(byID('k256-compact').signatureBytes, 64);
});

for (const row of vectors.cases.filter((row) => !row.id.startsWith('wallet-'))) {
  test('JOSE P-256 raw admission: ' + row.id, () => {
    const before = JSON.stringify(row);
    const settings = options(row);
    const detached = settings.detached && Buffer.from(settings.detached);
    if (row.expectedAcceptance) {
      const result = verifyJWS(row.token, keys[row.keyID], settings);
      assert.equal(result.header.alg, 'ES256');
      assert.deepEqual(result.payload, Buffer.from(row.payloadBase64, 'base64'));
    } else
      assert.throws(() => verifyJWS(row.token, keys[row.keyID], settings), {
        message: row.expectedError,
      });
    if (detached) assert.deepEqual(settings.detached, detached);
    assert.equal(JSON.stringify(row), before);
  });
}

for (const curve of ['secp384r1', 'secp521r1', 'secp256k1']) {
  test('JOSE P-256 producer rejects unsupported curve ' + curve, () => {
    const pair = generateKeyPairSync('ec', { namedCurve: curve });
    assert.equal(joseAlgorithm(pair.publicKey), undefined);
    assert.equal(joseAlgorithm(pair.privateKey), undefined);
    assert.throws(() => signJWS({ value: 'new message' }, pair.privateKey, { alg: 'ES256' }), {
      message: 'JOSE_ALGORITHM',
    });
  });
}
for (const curve of ['P-256', 'prime256v1']) {
  test('JOSE P-256 producer verifies independently for alias ' + curve, () => {
    const pair = generateKeyPairSync('ec', { namedCurve: curve });
    assert.equal(joseAlgorithm(pair.privateKey), 'ES256');
    const token = signJWS({ value: 'fresh signed message' }, pair.privateKey);
    const parts = token.split('.');
    const signature = Buffer.from(parts[2], 'base64url');
    assert.equal(signature.length, 64);
    assert.equal(JSON.parse(Buffer.from(parts[0], 'base64url')).alg, 'ES256');
    assert(
      verify(
        'sha256',
        Buffer.from(parts[0] + '.' + parts[1]),
        { key: pair.publicKey, dsaEncoding: 'ieee-p1363' },
        signature,
      ),
    );
    assert.deepEqual(
      verifyJWS(token, pair.publicKey).payload,
      Buffer.from(JSON.stringify({ value: 'fresh signed message' })),
    );
  });
}
for (const algorithm of ['ed25519', 'ml-dsa-65', 'ml-dsa-87']) {
  test('JOSE P-256 admission preserves ' + algorithm, () => {
    const pair = generateKeyPairSync(algorithm);
    const token = signJWS({ value: algorithm }, pair.privateKey);
    const parts = token.split('.');
    assert(
      verify(
        null,
        Buffer.from(parts[0] + '.' + parts[1]),
        pair.publicKey,
        Buffer.from(parts[2], 'base64url'),
      ),
    );
    assert.deepEqual(
      verifyJWS(token, pair.publicKey).payload,
      Buffer.from(JSON.stringify({ value: algorithm })),
    );
  });
}
test('JOSE P-256 allow-list cannot admit an unsupported curve or absent algorithm', () => {
  assert.throws(
    () => verifyJWS(byID('p384-compact').token, keys.p384, { allowedAlgorithms: ['ES256'] }),
    { message: 'JWS_ALGORITHM' },
  );
  assert.throws(
    () => verifyJWS(byID('p384-alg-missing').token, keys.p384, { allowedAlgorithms: [undefined] }),
    { message: 'JWS_ALGORITHM' },
  );
});
test('JOSE P-256 keeps context errors ahead of signature width errors', () => {
  const row = byID('p256-signature-63');
  assert.throws(() => verifyJWS(row.token, keys.p256, { typ: 'other' }), { message: 'JWS_TYPE' });
  assert.throws(() => verifyJWS(row.token, keys.p256, { detached: Buffer.from('payload') }), {
    message: 'JWS_DETACHED_CONFLICT',
  });
  const parts = row.token.split('.');
  parts[0] = Buffer.from(
    JSON.stringify({ alg: 'ES256', crit: ['unknown'], unknown: true }),
  ).toString('base64url');
  assert.throws(() => verifyJWS(parts.join('.'), keys.p256), { message: 'JWS_CRITICAL' });
});
test('JOSE P-256 raw token admits direct, JWK and certificate keys', () => {
  for (const publicKey of [
    keys.p256,
    importPublicJWK(keys.p256.export({ format: 'jwk' })),
    certificates.p256.publicKey,
  ])
    assert.deepEqual(
      verifyJWS(byID('p256-compact').token, publicKey).payload,
      Buffer.from(JSON.stringify(vectors.claims)),
    );
});

for (const row of vectors.jwkCases) {
  test('JOSE P-256 JWK coordinate admission: ' + row.id, () => {
    const before = JSON.stringify(row.jwk);
    if (row.expectedAcceptance) {
      assert.deepEqual(
        importPublicJWK(row.jwk).export({ type: 'spki', format: 'der' }),
        Buffer.from(row.spkiBase64, 'base64'),
      );
      assert.equal(thumbprint(row.jwk), row.canonicalThumbprint);
    } else {
      assert.throws(() => importPublicJWK(row.jwk), { message: row.expectedError });
      assert.throws(() => thumbprint(row.jwk), { message: row.expectedError });
    }
    if (/-short$|-long$/.test(row.id)) {
      assert.deepEqual(
        createPublicKey({ key: row.jwk, format: 'jwk' }).export({ type: 'spki', format: 'der' }),
        Buffer.from(row.spkiBase64, 'base64'),
      );
      const rawThumbprint = createHash('sha256')
        .update(JSON.stringify({ crv: row.jwk.crv, kty: row.jwk.kty, x: row.jwk.x, y: row.jwk.y }))
        .digest('base64url');
      assert.notEqual(rawThumbprint, row.canonicalThumbprint);
    }
    assert.equal(JSON.stringify(row.jwk), before);
  });
}
test('JOSE P-256 JWK still rejects a full-width point off the curve', () => {
  const jwk = {
    kty: 'EC',
    crv: 'P-256',
    x: Buffer.alloc(32).toString('base64url'),
    y: Buffer.alloc(32).toString('base64url'),
  };
  assert.throws(() => createPublicKey({ key: jwk, format: 'jwk' }));
  assert.throws(() => importPublicJWK(jwk));
  assert.throws(() => thumbprint(jwk));
});

function wallet(keyID = 'p256', { pin = true, roots = [certificates.root] } = {}) {
  return new OpenIDWallet({
    issuer: vectors.issuer,
    clientID: 'synthetic-jose-wallet',
    holderPublicKey: keys.p256,
    clientAuthentication: async () => {
      assert.fail('discovery must not authenticate');
    },
    ...(pin ? { issuerCertificate: certificates[keyID].raw } : {}),
    issuerRoots: roots,
  });
}
for (const row of vectors.cases.filter((row) =>
  /^(p256-compact|p384-compact|p521-compact|k256-compact|p256-signature-corrupt|wallet-.*)$/.test(
    row.id,
  ),
)) {
  test('JOSE P-256 wallet discovery: ' + row.id, async (t) => {
    t.mock.timers.enable({ apis: ['Date'], now: vectors.at * 1000 });
    const requests = [];
    t.mock.method(globalThis, 'fetch', async (url, settings) => {
      requests.push({ url, settings });
      return new Response(row.token, { headers: { 'content-type': 'application/jwt' } });
    });
    const subject = wallet(row.keyID);
    if (row.expectedAcceptance) {
      const result = await subject.discover();
      assert.deepEqual(structuredClone(result), vectors.claims);
      assert.equal(subject.metadata, result);
      assert.deepEqual(
        subject.issuerPublicKey.export({ type: 'spki', format: 'der' }),
        keys.p256.export({ type: 'spki', format: 'der' }),
      );
    } else {
      await assert.rejects(subject.discover(), { message: row.expectedError });
      assert.equal(subject.metadata, undefined);
      assert.equal(subject.issuerPublicKey, undefined);
    }
    assert.equal(requests.length, 1);
    assert.equal(requests[0].url, vectors.discoveryURL);
    assert.equal(requests[0].settings.method, 'GET');
    assert.equal(requests[0].settings.redirect, 'error');
  });
}
test('JOSE P-256 rejected rediscovery preserves authenticated metadata and signer', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: vectors.at * 1000 });
  let calls = 0;
  t.mock.method(
    globalThis,
    'fetch',
    async () =>
      new Response(byID(calls++ ? 'p384-compact' : 'p256-compact').token, {
        headers: { 'content-type': 'application/jwt' },
      }),
  );
  const subject = wallet('p256', { pin: false });
  const metadata = await subject.discover(),
    publicKey = subject.issuerPublicKey;
  await assert.rejects(subject.discover(), { message: 'JWS_ALGORITHM' });
  assert.equal(subject.metadata, metadata);
  assert.equal(subject.issuerPublicKey, publicKey);
  assert.equal(calls, 2);
});
test('JOSE P-256 wallet still checks the pinned leaf and trust root', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: vectors.at * 1000 });
  t.mock.method(
    globalThis,
    'fetch',
    async () =>
      new Response(byID('p256-compact').token, { headers: { 'content-type': 'application/jwt' } }),
  );
  for (const [subject, error] of [
    [wallet('p384'), 'X5C_PIN'],
    [wallet('p256', { roots: [] }), 'X5C_TRUST'],
  ]) {
    await assert.rejects(subject.discover(), { message: error });
    assert.equal(subject.metadata, undefined);
    assert.equal(subject.issuerPublicKey, undefined);
  }
});

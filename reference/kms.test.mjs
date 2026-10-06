import test from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import { GoogleKMSProvider } from './providers.mjs';

// Fixed Google REST endpoint; synthetic responses exercise validation without cloud keys.
test('Google KMS binds the immutable version, HSM mode, SPKI, SHA-256 input and integrity checks', async (t) => {
  const key = c.generate('ec'),
    other = c.generate('ec'),
    keyRef =
      'projects/synthetic/locations/global/keyRings/test/cryptoKeys/holder/cryptoKeyVersions/1',
    pem = key.publicKey.export({ type: 'spki', format: 'pem' }),
    tbs = Buffer.from('Exact synthetic document input');
  const crc = (bytes) => {
    let v = 0xffffffff;
    for (const b of bytes) {
      v ^= b;
      for (let n = 0; n < 8; n++) v = (v >>> 1) ^ (v & 1 ? 0x82f63b78 : 0);
    }
    return String((v ^ 0xffffffff) >>> 0);
  };
  let mode = 'valid',
    calls = 0;
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    assert.equal(options.headers.authorization, 'Bearer synthetic-access');
    assert.equal(options.redirect, 'error');
    calls++;
    if (String(url).endsWith('/publicKey'))
      return new Response(
        JSON.stringify({
          algorithm: 'EC_SIGN_P256_SHA256',
          protectionLevel: mode === 'software' ? 'SOFTWARE' : 'HSM',
          pem:
            mode === 'changed-key' ? other.publicKey.export({ type: 'spki', format: 'pem' }) : pem,
          pemCrc32c: mode === 'bad-pem-crc' ? '0' : crc(Buffer.from(pem)),
        }),
        { headers: { 'content-type': 'application/json' } },
      );
    assert.equal(url, 'https://cloudkms.googleapis.com/v1/' + keyRef + ':asymmetricSign');
    const body = JSON.parse(options.body),
      signature = c.sign(tbs, key.privateKey);
    assert.deepEqual(Buffer.from(body.digest.sha256, 'base64'), c.sha256(tbs));
    assert.equal(body.digestCrc32c, crc(c.sha256(tbs)));
    return new Response(
      JSON.stringify({
        name: mode === 'changed-version' ? keyRef + '2' : keyRef,
        signature: signature.toString('base64'),
        verifiedDigestCrc32c: mode !== 'unverified-digest',
        signatureCrc32c: mode === 'bad-signature-crc' ? '0' : crc(signature),
      }),
      { headers: { 'content-type': 'application/json' } },
    );
  });
  const provider = new GoogleKMSProvider({
    credentials: new Map([[keyRef, { publicKey: key.publicKey }]]),
    accessToken: async () => 'synthetic-access',
  });
  assert(c.verify(tbs, await provider.sign({ keyRef, tbs }), key.publicKey));
  assert.equal(calls, 2);
  for (const value of [
    'software',
    'changed-key',
    'bad-pem-crc',
    'changed-version',
    'unverified-digest',
    'bad-signature-crc',
  ]) {
    mode = value;
    await assert.rejects(provider.sign({ keyRef, tbs }), /KMS_/);
  }
  await assert.rejects(
    provider.sign({ keyRef: keyRef.replace('/1', '/latest'), tbs }),
    /KEY_VERSION/,
  );
});

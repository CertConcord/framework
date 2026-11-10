import assert from 'node:assert/strict';
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  X509Certificate,
} from 'node:crypto';
import { writeFileSync } from 'node:fs';

// Synthetic keys remain in memory. No tested protocol or certificate writer is imported.
const hash = (value) => createHash('sha256').update(value).digest('hex');
const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
const key = (curve) => generateKeyPairSync('ec', { namedCurve: curve });
const pairs = Object.fromEntries(
  Object.entries({
    p256: 'prime256v1',
    p384: 'secp384r1',
    p521: 'secp521r1',
    k256: 'secp256k1',
  }).map(([id, curve]) => [id, key(curve)]),
);
const root = key('prime256v1');
const at = 1793718579;
const issuer = 'https://jose-issuer.example.invalid/tenant';
const claims = {
  iss: issuer,
  sub: issuer,
  credential_issuer: issuer,
  iat: at,
  exp: at + 300,
  credential_endpoint: 'https://jose-issuer.example.invalid/credential',
  nonce_endpoint: 'https://jose-issuer.example.invalid/nonce',
  deferred_credential_endpoint: 'https://jose-issuer.example.invalid/deferred',
  notification_endpoint: 'https://jose-issuer.example.invalid/notification',
  credential_configurations_supported: {
    synthetic: { format: 'mso_mdoc', doctype: 'org.example.synthetic' },
  },
};

function tlv(tag, ...parts) {
  const body = Buffer.concat(parts);
  let length = Buffer.from([body.length]);
  if (body.length >= 128) {
    const octets = [];
    let n = body.length;
    while (n) {
      octets.unshift(n & 255);
      n = Math.floor(n / 256);
    }
    length = Buffer.from([128 + octets.length, ...octets]);
  }
  return Buffer.concat([Buffer.from([tag]), length, body]);
}
const sequence = (...parts) => tlv(0x30, ...parts);
const integer = (raw) => {
  let value = Buffer.from(raw);
  while (value.length > 1 && value[0] === 0) value = value.subarray(1);
  if (value[0] & 128) value = Buffer.concat([Buffer.from([0]), value]);
  return tlv(2, value);
};
const bool = tlv(1, Buffer.from([255]));
const ecdsaSHA256 = sequence(Buffer.from('06082a8648ce3d040302', 'hex'));
const name = (text) =>
  sequence(tlv(0x31, sequence(Buffer.from('0603550403', 'hex'), tlv(12, Buffer.from(text)))));
const rootName = name('Synthetic JOSE admission root');
const time = (seconds) =>
  tlv(
    0x17,
    Buffer.from(
      new Date(seconds * 1000)
        .toISOString()
        .replace(/[-:]/g, '')
        .replace(/\.\d{3}Z$/, 'Z')
        .replace('T', '')
        .slice(2),
    ),
  );
const extension = (oid, value) => sequence(Buffer.from(oid, 'hex'), bool, tlv(4, value));
function certificate(publicKey, serial, ca = false) {
  const tbs = sequence(
    tlv(0xa0, integer(Buffer.from([2]))),
    integer(Buffer.from([serial])),
    ecdsaSHA256,
    rootName,
    sequence(time(at - 3600), time(at + 86400)),
    ca ? rootName : name('Synthetic JOSE signer ' + serial),
    publicKey.export({ type: 'spki', format: 'der' }),
    tlv(
      0xa3,
      sequence(
        extension('0603551d13', ca ? sequence(bool) : sequence()),
        extension('0603551d0f', tlv(3, Buffer.from(ca ? [1, 6] : [7, 128]))),
      ),
    ),
  );
  const raw = sequence(
    tbs,
    ecdsaSHA256,
    tlv(3, Buffer.from([0]), sign('sha256', tbs, root.privateKey)),
  );
  const parsed = new X509Certificate(raw);
  assert(parsed.verify(root.publicKey));
  assert.equal(parsed.ca, ca);
  assert.deepEqual(
    parsed.publicKey.export({ type: 'spki', format: 'der' }),
    publicKey.export({ type: 'spki', format: 'der' }),
  );
  return raw;
}
const certificates = { root: certificate(root.publicKey, 1, true).toString('base64') };
const keys = {};
for (const [index, [id, pair]] of Object.entries(pairs).entries()) {
  keys[id] = {
    spkiBase64: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    curve: pair.publicKey.asymmetricKeyDetails.namedCurve,
  };
  certificates[id] = certificate(pair.publicKey, index + 2).toString('base64');
}
const cases = [];
function add(
  id,
  {
    keyID = 'p256',
    header = {},
    payload = claims,
    mode = 'compact',
    error = null,
    transform,
    nativeEncoding = 'ieee-p1363',
  } = {},
) {
  const h = {
    alg: 'ES256',
    typ: 'openidvci-issuer-metadata+jwt',
    x5c: [certificates[keyID]],
    ...header,
  };
  if (mode === 'detached-unencoded') {
    h.b64 = false;
    h.crit = ['b64'];
  }
  const rawPayload = Buffer.isBuffer(payload) ? payload : Buffer.from(JSON.stringify(payload));
  const protectedHeader = encode(h);
  const signingInput = Buffer.concat([
    Buffer.from(protectedHeader + '.', 'ascii'),
    mode === 'detached-unencoded'
      ? rawPayload
      : Buffer.from(rawPayload.toString('base64url'), 'ascii'),
  ]);
  let signature = sign('sha256', signingInput, {
    key: pairs[keyID].privateKey,
    dsaEncoding: 'ieee-p1363',
  });
  assert(
    verify(
      'sha256',
      signingInput,
      { key: pairs[keyID].publicKey, dsaEncoding: 'ieee-p1363' },
      signature,
    ),
  );
  if (transform) signature = transform(signature);
  const token = [
    protectedHeader,
    mode === 'compact' ? rawPayload.toString('base64url') : '',
    signature.toString('base64url'),
  ].join('.');
  cases.push({
    id,
    keyID,
    mode,
    token,
    tokenSHA256: hash(token),
    payloadBase64: rawPayload.toString('base64'),
    signingInputBase64: signingInput.toString('base64'),
    signingInputSHA256: hash(signingInput),
    signatureBytes: signature.length,
    nativeEncoding,
    nativeSignatureValid: verify(
      'sha256',
      signingInput,
      { key: pairs[keyID].publicKey, dsaEncoding: nativeEncoding },
      signature,
    ),
    expectedAcceptance: error === null,
    expectedError: error,
  });
}
for (const keyID of Object.keys(pairs))
  add(keyID + '-compact', { keyID, error: keyID === 'p256' ? null : 'JWS_ALGORITHM' });
for (const [id, alg] of [
  ['missing', undefined],
  ['null', null],
  ['number', 1],
  ['none', 'none'],
  ['es384', 'ES384'],
]) {
  add('p256-alg-' + id, { header: { alg }, error: 'JWS_ALGORITHM' });
}
add('p384-alg-missing', { keyID: 'p384', header: { alg: undefined }, error: 'JWS_ALGORITHM' });
for (const width of [0, 63, 65, 96])
  add('p256-signature-' + width, {
    error: 'JWS_SIGNATURE',
    transform: (sig) =>
      width <= 64 ? sig.subarray(0, width) : Buffer.concat([sig, Buffer.alloc(width - 64)]),
  });
add('p256-signature-corrupt', {
  error: 'JWS_SIGNATURE',
  transform: (sig) => {
    const b = Buffer.from(sig);
    b[0] ^= 1;
    return b;
  },
});
add('p256-signature-der', {
  error: 'JWS_SIGNATURE',
  nativeEncoding: 'der',
  transform: (sig) => sequence(integer(sig.subarray(0, 32)), integer(sig.subarray(32))),
});
for (const mode of ['detached-encoded', 'detached-unencoded']) {
  add('p256-' + mode, { mode, payload: Buffer.from([0, 46, 255, 1, 32]) });
  add('k256-' + mode, {
    keyID: 'k256',
    mode,
    payload: Buffer.from([0, 46, 255, 1, 32]),
    error: 'JWS_ALGORITHM',
  });
  add('p256-' + mode + '-short', {
    mode,
    payload: Buffer.from([0, 46, 255, 1, 32]),
    error: 'JWS_SIGNATURE',
    transform: (sig) => sig.subarray(0, 63),
  });
}
for (const [id, header, payload, error] of [
  ['wrong-type', { typ: 'JWT' }, claims, 'JWS_TYPE'],
  ['wrong-issuer', {}, { ...claims, iss: 'https://other.example.invalid' }, 'JWT_ISSUER'],
  [
    'wrong-origin',
    {},
    { ...claims, credential_endpoint: 'https://other.example.invalid/credential' },
    'ISSUER_ENDPOINT_ORIGIN',
  ],
  ['expired', {}, { ...claims, exp: at }, 'JWT_EXPIRED'],
])
  add('wallet-' + id, { header, payload, error });

const jwkCases = [];
for (const coordinate of ['x', 'y']) {
  let pair, jwk;
  for (let attempt = 0; attempt < 8192; attempt++) {
    pair = key('prime256v1');
    jwk = pair.publicKey.export({ format: 'jwk' });
    if (Buffer.from(jwk[coordinate], 'base64url')[0] === 0) break;
  }
  const bytes = Buffer.from(jwk[coordinate], 'base64url');
  assert.equal(bytes.length, 32);
  assert.equal(bytes[0], 0);
  const spkiBase64 = pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  const canonicalThumbprint = createHash('sha256')
    .update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }))
    .digest('base64url');
  for (const [id, value, error] of [
    ['canonical', jwk[coordinate], null],
    ['short', bytes.subarray(1).toString('base64url'), 'JWK_COORDINATES'],
    ['long', Buffer.concat([Buffer.from([0]), bytes]).toString('base64url'), 'JWK_COORDINATES'],
    ['empty', '', 'JWK_COORDINATES'],
    ['padded', jwk[coordinate] + '=', 'BAD_BASE64URL'],
    ['missing', undefined, 'BAD_BASE64URL'],
  ]) {
    const valueJWK = { ...jwk, [coordinate]: value };
    if (['canonical', 'short', 'long'].includes(id))
      assert.deepEqual(
        createPublicKey({ key: valueJWK, format: 'jwk' }).export({ type: 'spki', format: 'der' }),
        Buffer.from(spkiBase64, 'base64'),
      );
    jwkCases.push({
      id: coordinate + '-' + id,
      jwk: valueJWK,
      spkiBase64,
      canonicalThumbprint,
      expectedAcceptance: error === null,
      expectedError: error,
    });
  }
}
const data = {
  schema: 'jose-p256-admission-v1',
  at,
  issuer,
  discoveryURL: 'https://jose-issuer.example.invalid/.well-known/openid-credential-issuer/tenant',
  claims,
  keys,
  certificates,
  cases,
  jwkCases,
};
writeFileSync(
  new URL('../reference/vectors/jose-p256-admission.json', import.meta.url),
  JSON.stringify(data, null, 2) + '\n',
);
console.log(
  JSON.stringify({ jws: cases.length, jwk: jwkCases.length, privateKeysPersisted: false }),
);

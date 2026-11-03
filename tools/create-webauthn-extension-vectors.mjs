import { writeFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';

// Independent definite-length CBOR writer; only synthetic public evidence is serialized.
const cat = (...values) => Buffer.concat(values);
const hash = (value) => createHash('sha256').update(value).digest();
const b64 = (value) => value.toString('base64url');
function head(major, value) {
  const n = BigInt(value);
  if (n < 24n) return Buffer.from([major * 32 + Number(n)]);
  const length = n < 256n ? 1 : n < 65536n ? 2 : n < 4294967296n ? 4 : 8;
  const result = Buffer.alloc(length + 1);
  result[0] = major * 32 + { 1: 24, 2: 25, 4: 26, 8: 27 }[length];
  for (let i = 0; i < length; i++) result[length - i] = Number((n >> BigInt(i * 8)) & 255n);
  return result;
}
function cbor(value) {
  if (value === null) return Buffer.from([0xf6]);
  if (typeof value === 'boolean') return Buffer.from([value ? 0xf5 : 0xf4]);
  if (typeof value === 'number' || typeof value === 'bigint')
    return value >= 0 ? head(0, value) : head(1, -1n - BigInt(value));
  if (typeof value === 'string') {
    const bytes = Buffer.from(value);
    return cat(head(3, bytes.length), bytes);
  }
  if (Buffer.isBuffer(value)) return cat(head(2, value.length), value);
  if (Array.isArray(value)) return cat(head(4, value.length), ...value.map(cbor));
  assert(value instanceof Map);
  const entries = [...value].map(([k, v]) => [cbor(k), cbor(v)]);
  entries.sort(([a], [b]) => Buffer.compare(a, b));
  return cat(head(5, entries.length), ...entries.flat());
}
const map = (...entries) => new Map(entries);
const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const jwk = publicKey.export({ format: 'jwk' });
const publicKeySPKI = publicKey.export({ format: 'der', type: 'spki' });
const cose = cbor(
  map(
    [1, 2],
    [3, -7],
    [-1, 1],
    [-2, Buffer.from(jwk.x, 'base64url')],
    [-3, Buffer.from(jwk.y, 'base64url')],
  ),
);
const credentialID = randomBytes(32),
  challenge = randomBytes(32);
const rpID = 'extensions.example.invalid',
  origin = 'https://' + rpID;
const valid = cbor(map(['example.invalid.output', true]));
const cases = [];
function add(
  kind,
  id,
  extension,
  { ed = true, flags = 5, counter = 1, fmt = 'none', badSignature = false, error } = {},
) {
  const registration = kind === 'registration';
  const count = Buffer.alloc(4);
  count.writeUInt32BE(counter);
  const length = Buffer.alloc(2);
  length.writeUInt16BE(credentialID.length);
  const auth = cat(
    hash(Buffer.from(rpID)),
    Buffer.from([flags | (ed ? 128 : 0) | (registration ? 64 : 0)]),
    count,
    ...(registration ? [Buffer.alloc(16), length, credentialID, cose] : []),
    extension,
  );
  const client = Buffer.from(
    JSON.stringify({
      type: registration ? 'webauthn.create' : 'webauthn.get',
      challenge: b64(challenge),
      origin,
      crossOrigin: false,
    }),
  );
  const signed = cat(auth, hash(client));
  const signature = sign('sha256', signed, privateKey);
  assert(verify('sha256', signed, publicKey, signature));
  if (badSignature) signature[signature.length - 1] ^= 1;
  const credential = {
    id: b64(credentialID),
    rawId: b64(credentialID),
    type: 'public-key',
    response: { clientDataJSON: b64(client) },
  };
  if (registration) {
    const statement = fmt === 'packed' ? map(['alg', -7], ['sig', signature]) : map();
    credential.response.attestationObject = b64(
      cbor(map(['fmt', fmt], ['authData', auth], ['attStmt', statement])),
    );
  } else {
    credential.response.authenticatorData = b64(auth);
    credential.response.signature = b64(signature);
  }
  cases.push({
    id: kind + '-' + id,
    kind,
    ...(registration ? { fmt } : {}),
    extensionHex: extension.toString('hex'),
    authenticatorData: b64(auth),
    credential,
    expected: error ? { accepted: false, error } : { accepted: true },
    signatureValid: !registration || fmt === 'packed' ? !badSignature : null,
  });
}
const shapes = [
  ['absent', Buffer.alloc(0), { ed: false }],
  ['empty-map', cbor(map())],
  ['unknown-text', valid],
  [
    'multiple-text',
    cbor(
      map(
        ['1', false],
        ['__proto__', map([1, 'nested integer keys are values'])],
        ['example.invalid.output', [null, 7, Buffer.from('0102', 'hex')]],
      ),
    ),
  ],
  ['integer-key', cbor(map([1, true])), { error: 'AUTHENTICATOR_EXTENSIONS' }],
  ['negative-key', cbor(map([-1, true])), { error: 'AUTHENTICATOR_EXTENSIONS' }],
  [
    'large-integer-key',
    cbor(map([9007199254740992n, true])),
    { error: 'AUTHENTICATOR_EXTENSIONS' },
  ],
  [
    'mixed-keys',
    cbor(map(['example.invalid.output', true], [1, false])),
    { error: 'AUTHENTICATOR_EXTENSIONS' },
  ],
  ['boolean-value', cbor(true), { error: 'AUTHENTICATOR_EXTENSIONS' }],
  ['integer-value', cbor(1), { error: 'AUTHENTICATOR_EXTENSIONS' }],
  ['text-value', cbor('example.invalid.output'), { error: 'AUTHENTICATOR_EXTENSIONS' }],
  ['bytes-value', cbor(Buffer.from([0xa0])), { error: 'AUTHENTICATOR_EXTENSIONS' }],
  ['array-value', cbor([map()]), { error: 'AUTHENTICATOR_EXTENSIONS' }],
  ['null-value', cbor(null), { error: 'AUTHENTICATOR_EXTENSIONS' }],
  ['tagged-map', cat(Buffer.from([0xc0]), cbor(map())), { error: 'AUTHENTICATOR_EXTENSIONS' }],
  ['byte-string-key', cbor(map([Buffer.from('name'), true])), { error: 'CBOR_MAP_KEY' }],
  ['boolean-key', cbor(map([true, true])), { error: 'CBOR_MAP_KEY' }],
  ['null-key', cbor(map([null, true])), { error: 'CBOR_MAP_KEY' }],
  ['duplicate-text-key', Buffer.from('a2616100616101', 'hex'), { error: 'CBOR_DUPLICATE' }],
  ['truncated-value', Buffer.from('a161786361', 'hex'), { error: 'CBOR_TRUNCATED' }],
];
for (const kind of ['registration', 'assertion']) {
  for (const [id, extension, options] of shapes) add(kind, id, extension, options);
  add(kind, 'missing-output', Buffer.alloc(0), {
    error: kind === 'registration' ? 'ATTESTATION_TRAILING' : 'CBOR_LIMIT',
  });
  add(kind, 'trailing-item', cat(valid, cbor(false)), {
    error: kind === 'registration' ? 'ATTESTATION_TRAILING' : 'CBOR_TRAILING',
  });
  add(kind, 'output-without-ed', valid, {
    ed: false,
    error: kind === 'registration' ? 'ATTESTATION_TRAILING' : 'ASSERTION_AUTH_DATA',
  });
  add(kind, 'missing-up', valid, { flags: 4, error: 'USER_PRESENCE_REQUIRED' });
  add(kind, 'missing-uv', valid, { flags: 1, error: 'USER_VERIFICATION_REQUIRED' });
}
add('assertion', 'invalid-signature', valid, { badSignature: true, error: 'ASSERTION_SIGNATURE' });
add('assertion', 'backup-eligibility-changed', valid, {
  flags: 13,
  error: 'BACKUP_ELIGIBILITY_CHANGED',
});
add('registration', 'packed-text', valid, { fmt: 'packed' });
add('registration', 'packed-integer-key', cbor(map([1, true])), {
  fmt: 'packed',
  error: 'AUTHENTICATOR_EXTENSIONS',
});
add('registration', 'packed-non-map', cbor(true), {
  fmt: 'packed',
  error: 'AUTHENTICATOR_EXTENSIONS',
});
add('registration', 'packed-invalid-signature', valid, {
  fmt: 'packed',
  badSignature: true,
  error: 'ATTESTATION_SIGNATURE',
});
assert.equal(new Set(cases.map(({ id }) => id)).size, cases.length);
const output = {
  schema: 'certconcord-webauthn-authenticator-extensions-v1',
  description:
    'Synthetic WebAuthn raw inputs. Fresh ephemeral P-256 keys are not serialized. None and self attestation establish no trusted authenticator identity.',
  rpID,
  origin,
  challenge: b64(challenge),
  credentialID: b64(credentialID),
  publicKeySPKI: b64(publicKeySPKI),
  cosePublicKeyHex: cose.toString('hex'),
  cases,
};
writeFileSync(
  new URL('../reference/vectors/webauthn-authenticator-extensions.json', import.meta.url),
  JSON.stringify(output, null, 2) + '\n',
);
console.log('WebAuthn authenticator extension vectors: ' + cases.length);

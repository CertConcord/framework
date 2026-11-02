import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign, verify, X509Certificate } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { issueCertificate, name } from '../reference/pki.mjs';

// Fresh synthetic keys stay in memory. The vector file contains public evidence only.
const key = () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const root = key(),
  issuer = key(),
  other = key(),
  unrelated = key();
const at = 1793620000;
const issuerID = 'https://issuer.example.invalid/tenant';
const rootName = name('Synthetic wallet metadata root');
const rootCertificate = issueCertificate(
  {
    publicKey: root.publicKey,
    issuer: rootName,
    subject: rootName,
    serial: 1,
    ca: true,
    notBefore: at - 3600,
    notAfter: at + 86400,
  },
  root.privateKey,
);
const leaf = (pair, serial) =>
  issueCertificate(
    {
      publicKey: pair.publicKey,
      issuer: rootName,
      subject: name('Synthetic metadata signer ' + serial),
      serial,
      profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1',
      notBefore: at - 1800,
      notAfter: at + 3600,
    },
    root.privateKey,
  );
const certificate = leaf(issuer, 2),
  otherCertificate = leaf(other, 3);
const unrelatedName = name('Unrelated synthetic metadata root');
const unrelatedRoot = issueCertificate(
  {
    publicKey: unrelated.publicKey,
    issuer: unrelatedName,
    subject: unrelatedName,
    serial: 4,
    ca: true,
    notBefore: at - 3600,
    notAfter: at + 86400,
  },
  unrelated.privateKey,
);
const claims = {
  iss: issuerID,
  sub: issuerID,
  credential_issuer: issuerID,
  iat: at,
  exp: at + 300,
  credential_endpoint: 'https://issuer.example.invalid/credential',
  nonce_endpoint: 'https://issuer.example.invalid/nonce',
  deferred_credential_endpoint: 'https://issuer.example.invalid/deferred',
  notification_endpoint: 'https://issuer.example.invalid/notification',
  credential_configurations_supported: {
    synthetic: { format: 'mso_mdoc', doctype: 'org.example.synthetic' },
  },
};
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
function jwt(value = claims, header = {}, pair = issuer, cert = certificate) {
  const input =
    encode({
      alg: 'ES256',
      typ: 'openidvci-issuer-metadata+jwt',
      x5c: [cert.toString('base64')],
      ...header,
    }) +
    '.' +
    encode(value);
  const signature = sign('sha256', Buffer.from(input, 'ascii'), {
    key: pair.privateKey,
    dsaEncoding: 'ieee-p1363',
  });
  assert(
    verify(
      'sha256',
      Buffer.from(input, 'ascii'),
      { key: pair.publicKey, dsaEncoding: 'ieee-p1363' },
      signature,
    ),
  );
  return input + '.' + signature.toString('base64url');
}
const good = jwt(),
  cases = [];
function add(
  id,
  {
    token = good,
    contentType = 'application/jwt',
    envelope = 'compact',
    value,
    error,
    expected = claims,
    clock = at,
    trustedRoot = 'root',
    pinnedLeaf = 'issuer',
    status = 200,
  } = {},
) {
  const body = Buffer.from(
    value ?? (envelope === 'json' ? JSON.stringify({ signed_metadata: token }) : token),
    'utf8',
  );
  cases.push({
    id,
    contentType,
    bodyBase64: body.toString('base64'),
    sha256: digest(body),
    status,
    at: clock,
    trustedRoot,
    pinnedLeaf,
    expectedAcceptance: !error,
    ...(error ? { expectedError: error } : { expectedClaims: expected }),
  });
}
add('compact-jwt');
add('compact-media-type-case-and-parameter', { contentType: 'Application/JWT; charset=utf-8' });
add('legacy-json-same-jwt', { contentType: 'application/json', envelope: 'json' });
add('legacy-json-unsigned-fields-ignored', {
  contentType: 'application/json; charset=utf-8',
  value: JSON.stringify({
    ...claims,
    credential_endpoint: 'https://untrusted.example.invalid/credential',
    signed_metadata: good,
  }),
});
add('unsigned-json-downgrade', {
  contentType: 'application/json',
  value: JSON.stringify(claims),
  error: 'SIGNED_METADATA_REQUIRED',
});
add('null-json-envelope', {
  contentType: 'application/json',
  value: 'null',
  error: 'SIGNED_METADATA_REQUIRED',
});
add('nonstring-json-signature', {
  contentType: 'application/json',
  value: '{"signed_metadata":false}',
  error: 'SIGNED_METADATA_REQUIRED',
});
for (const [id, type] of [
  ['text', 'text/plain'],
  ['suffix', 'application/jwt+json'],
  ['missing', null],
])
  add('unsupported-media-' + id, { contentType: type, error: 'ISSUER_METADATA_MEDIA_TYPE' });
add('compact-declared-json', { contentType: 'application/json', error: 'JSON_VALUE' });
add('json-declared-compact', { envelope: 'json', error: 'BAD_BASE64URL' });
add('empty-compact', { value: '', error: 'JWS_STRUCTURE' });
add('truncated-compact', { value: good.slice(0, good.lastIndexOf('.')), error: 'JWS_STRUCTURE' });
add('compact-trailing-newline', { value: good + '\n', error: 'BAD_BASE64URL' });
const altered = good.split('.'),
  signature = Buffer.from(altered[2], 'base64url');
signature[0] ^= 1;
altered[2] = signature.toString('base64url');
add('altered-signature', { token: altered.join('.'), error: 'JWS_SIGNATURE' });
add('wrong-typ', { token: jwt(claims, { typ: 'JWT' }), error: 'JWS_TYPE' });
add('wrong-issuer', {
  token: jwt({ ...claims, iss: 'https://other.example.invalid' }),
  error: 'JWT_ISSUER',
});
for (const field of ['sub', 'credential_issuer'])
  add('wrong-' + field, {
    token: jwt({ ...claims, [field]: 'https://other.example.invalid' }),
    error: 'ISSUER_METADATA_BINDING',
  });
add('missing-x5c', { token: jwt(claims, { x5c: [] }), error: 'X5C_REQUIRED' });
add('untrusted-root', { trustedRoot: 'unrelated', error: 'X5C_TRUST' });
add('wrong-pinned-leaf', { pinnedLeaf: 'other', error: 'X5C_PIN' });
add('other-trusted-signer', { token: jwt(claims, {}, other, otherCertificate), error: 'X5C_PIN' });
for (const field of [
  'credential_endpoint',
  'nonce_endpoint',
  'deferred_credential_endpoint',
  'notification_endpoint',
])
  add('cross-origin-' + field, {
    token: jwt({ ...claims, [field]: 'https://other.example.invalid/endpoint' }),
    error: 'ISSUER_ENDPOINT_ORIGIN',
  });
for (const [id, url] of [
  ['http', 'http://issuer.example.invalid/credential'],
  ['userinfo', 'https://user:password@issuer.example.invalid/credential'],
  ['fragment', 'https://issuer.example.invalid/credential#fragment'],
])
  add('unsafe-endpoint-' + id, {
    token: jwt({ ...claims, credential_endpoint: url }),
    error: 'HTTPS_REQUIRED',
  });
for (const [id, updates, error] of [
  ['age-limit', { iat: at - 300 }, null],
  ['too-old', { iat: at - 301 }, 'JWT_AGE'],
  ['future-skew-limit', { iat: at + 30 }, null],
  ['future-skew-exceeded', { iat: at + 31 }, 'JWT_AGE'],
  ['expiry-after-now', { exp: at + 1 }, null],
  ['expiry-at-now', { exp: at }, 'JWT_EXPIRED'],
  ['not-before-at-now', { nbf: at }, null],
  ['not-before-after-now', { nbf: at + 1 }, 'JWT_NOT_YET_VALID'],
]) {
  const payload = { ...claims, ...updates };
  add(id, { token: jwt(payload), expected: payload, error });
}
add('certificate-expired', { clock: at + 3600, error: 'X5C_TIME' });
add('http-error', { status: 500, error: 'ISSUER_DISCOVERY' });
for (const id of ['altered-signature', 'wrong-issuer', 'wrong-sub', 'wrong-credential_issuer']) {
  const original = cases.find((row) => row.id === id);
  add('legacy-json-' + id, {
    contentType: 'application/json',
    envelope: 'json',
    token: Buffer.from(original.bodyBase64, 'base64').toString('utf8'),
    error: original.expectedError,
  });
}
for (const [id, contentType] of [
  ['combined', 'application/jwt, application/json'],
  ['parameter-combined', 'application/jwt; charset=utf-8, application/json'],
  ['comma-parameter', 'application/jwt; extension="a,b"'],
])
  add('media-' + id, { contentType, error: 'ISSUER_METADATA_MEDIA_TYPE' });
assert(new X509Certificate(certificate).verify(root.publicKey));
assert(new X509Certificate(rootCertificate).verify(root.publicKey));
const vectors = {
  schemaVersion: 1,
  description:
    'Synthetic signed issuer metadata HTTP envelopes; fixed public ES256 evidence, no production trust or TLS assertion.',
  issuer: issuerID,
  discoveryURL: 'https://issuer.example.invalid/.well-known/openid-credential-issuer/tenant',
  at,
  certificates: {
    root: rootCertificate.toString('base64'),
    issuer: certificate.toString('base64'),
    other: otherCertificate.toString('base64'),
    unrelated: unrelatedRoot.toString('base64'),
  },
  cases,
};
writeFileSync(
  new URL('../reference/vectors/wallet-metadata-envelopes.json', import.meta.url),
  JSON.stringify(vectors, null, 2) + '\n',
);
console.log(
  JSON.stringify({
    cases: cases.length,
    positive: cases.filter((row) => row.expectedAcceptance).length,
    negative: cases.filter((row) => !row.expectedAcceptance).length,
  }),
);

import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { issueCertificate, name } from '../reference/pki.mjs';

// Only synthetic public evidence is written; all private keys remain in memory.
const at = Date.parse('2026-11-02T00:00:00Z') / 1000;
const audience = 'https://self-issued.me/v2';
const origin = 'https://reader.example.invalid';
const key = () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const root = key(),
  reader = key(),
  otherRoot = key(),
  otherReader = key(),
  encryption = key();
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
function chain(ca, leaf, label, serial) {
  const subject = name(label);
  return {
    root: issueCertificate(
      {
        publicKey: ca.publicKey,
        issuer: subject,
        subject,
        serial,
        ca: true,
        notBefore: at - 3600,
        notAfter: at + 86400,
      },
      ca.privateKey,
    ),
    reader: issueCertificate(
      {
        publicKey: leaf.publicKey,
        issuer: subject,
        subject: name(label + ' reader'),
        serial: serial + 1,
        notBefore: at - 1800,
        notAfter: at + 3600,
      },
      ca.privateKey,
    ),
  };
}
const trusted = chain(root, reader, 'Synthetic request audience root', 1);
const untrusted = chain(otherRoot, otherReader, 'Unrelated synthetic request root', 3);
const clientID = (certificate) =>
  'x509_hash:' + createHash('sha256').update(certificate).digest('base64url');
const claims = {
  client_id: clientID(trusted.reader),
  aud: audience,
  response_type: 'vp_token',
  response_mode: 'direct_post.jwt',
  nonce: randomBytes(24).toString('base64url'),
  state: randomBytes(24).toString('base64url'),
  response_uri: origin + '/response/synthetic',
  dcql_query: {
    credentials: [
      {
        id: 'qualification',
        format: 'dc+sd-jwt',
        meta: {
          vct_values: [
            'https://github.com/CertConcord/framework/credentials/trust-qualification/v1',
          ],
        },
        claims: [{ id: 'c0', path: ['qualification'] }],
      },
    ],
  },
  client_metadata: {
    jwks: {
      keys: [
        {
          ...encryption.publicKey.export({ format: 'jwk' }),
          kid: 'synthetic-recipient',
          alg: 'ECDH-ES',
          use: 'enc',
        },
      ],
    },
    encrypted_response_enc_values_supported: ['A128GCM', 'A256GCM'],
  },
  iat: at,
  exp: at + 120,
};
const header = (certificate) => ({
  alg: 'ES256',
  typ: 'oauth-authz-req+jwt',
  x5c: [certificate.toString('base64')],
});
function signed(payload, protectedHeader, pair = reader) {
  const input = encode(protectedHeader) + '.' + encode(payload);
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
const dcClaims = () => {
  const result = { ...claims, response_mode: 'dc_api.jwt', expected_origins: [origin] };
  delete result.state;
  delete result.response_uri;
  return result;
};
const cases = [];
function add(
  id,
  payload,
  {
    mode = 'compact',
    error = null,
    headers = {},
    wrongOrigin = false,
    badSignature = false,
    unprotected = false,
  } = {},
) {
  payload = structuredClone(payload);
  let wire,
    oracleTokens,
    expectedClaims = payload;
  if (mode === 'multi') {
    const tokens = [
      signed(
        payload,
        { ...header(untrusted.reader), client_id: clientID(untrusted.reader), ...headers },
        otherReader,
      ),
      signed(payload, {
        ...header(trusted.reader),
        client_id: clientID(trusted.reader),
        ...headers,
      }),
    ];
    const signatures = tokens.map((token) => {
      const [protectedHeader, , signature] = token.split('.');
      return {
        protected: protectedHeader,
        signature,
        ...(unprotected ? { header: { client_id: claims.client_id } } : {}),
      };
    });
    const body = tokens[0].split('.')[1];
    assert(tokens.every((token) => token.split('.')[1] === body));
    wire = JSON.stringify({
      protocol: 'openid4vp-v1-multisigned',
      data: { request: { payload: body, signatures } },
    });
    oracleTokens = tokens.map((token, i) => ({
      token,
      certificate: i === 0 ? 'otherReader' : 'reader',
      valid: true,
    }));
    expectedClaims = { ...payload, client_id: claims.client_id };
  } else {
    let token = signed(payload, { ...header(trusted.reader), ...headers });
    if (badSignature) {
      const parts = token.split('.');
      const signature = Buffer.from(parts[2], 'base64url');
      signature[0] ^= 1;
      parts[2] = signature.toString('base64url');
      token = parts.join('.');
    }
    wire =
      mode === 'dc-signed'
        ? JSON.stringify({ protocol: 'openid4vp-v1-signed', data: { request: token } })
        : token;
    oracleTokens = [{ token, certificate: 'reader', valid: !badSignature }];
  }
  const bytes = Buffer.from(wire);
  cases.push({
    id,
    mode,
    wireBase64: bytes.toString('base64'),
    bytes: bytes.length,
    sha256: hash(bytes),
    at,
    options: {
      expectedResponseOrigin: origin,
      origin: wrongOrigin ? 'https://other.example.invalid' : origin,
    },
    expectedAcceptance: error === null,
    expectedError: error,
    expectedClaims,
    oracleTokens,
  });
}
const shapes = [
  ['static', audience, true],
  ['static-array', [audience], true],
  ['static-plus-other', [audience, 'urn:example:other-wallet'], true],
  ['other-plus-static', ['urn:example:other-wallet', audience], true],
  ['duplicate-static', [audience, audience], true],
  ['static-plus-empty-string', [audience, ''], true],
  ['missing', undefined, false],
  ['foreign', 'https://wallet.example.invalid', false],
  ['empty-string', '', false],
  ['case-variant', 'https://SELF-issued.me/v2', false],
  ['trailing-slash', audience + '/', false],
  ['null', null, false],
  ['number', 7, false],
  ['boolean', true, false],
  ['object', { value: audience }, false],
  ['empty-array', [], false],
  ['foreign-array', ['urn:example:other-wallet'], false],
  ['mixed-type-array', [audience, 7], false],
  ['nested-array', [[audience]], false],
];
for (const [id, aud, accepted] of shapes) {
  const payload = { ...claims, aud };
  if (aud === undefined) delete payload.aud;
  add('compact-' + id, payload, { error: accepted ? null : 'VP_REQUEST_AUDIENCE' });
}
add('compact-expired', { ...claims, exp: at }, { error: 'JWT_EXPIRED' });
add('compact-bad-signature', claims, { badSignature: true, error: 'JWS_SIGNATURE' });
add('compact-wrong-type', claims, { headers: { typ: 'JWT' }, error: 'JWS_TYPE' });
add(
  'compact-wrong-client-id',
  { ...claims, client_id: 'x509_hash:other' },
  { error: 'VP_CLIENT_ID' },
);
for (const [id, aud] of [
  ['header-only-audience', undefined],
  ['foreign-header-static', 'urn:example:other-wallet'],
]) {
  const payload = { ...claims, aud };
  if (aud === undefined) delete payload.aud;
  add('compact-' + id, payload, { headers: { aud: audience }, error: 'VP_REQUEST_AUDIENCE' });
}
for (const [id, aud, error] of [
  ['static', audience, null],
  ['static-array', [audience, 'urn:example:other-wallet'], null],
  ['missing', undefined, 'VP_REQUEST_AUDIENCE'],
  ['foreign', 'urn:example:other-wallet', 'VP_REQUEST_AUDIENCE'],
]) {
  const payload = { ...dcClaims(), aud };
  if (aud === undefined) delete payload.aud;
  add('dc-signed-' + id, payload, { mode: 'dc-signed', error });
  delete payload.client_id;
  add('multi-' + (id === 'static-array' ? id : id + '-first-untrusted'), payload, {
    mode: 'multi',
    error,
  });
}
add('dc-signed-wrong-origin', dcClaims(), {
  mode: 'dc-signed',
  wrongOrigin: true,
  error: 'VP_DC_ORIGIN',
});
const shared = dcClaims();
delete shared.client_id;
const noAudience = { ...shared };
delete noAudience.aud;
add('multi-header-only-audience', noAudience, {
  mode: 'multi',
  headers: { aud: audience },
  error: 'VP_REQUEST_AUDIENCE',
});
add('multi-unprotected-header', shared, {
  mode: 'multi',
  unprotected: true,
  error: 'VP_NO_TRUSTED_SIGNATURE',
});
add('multi-payload-client-id', dcClaims(), {
  mode: 'multi',
  error: 'VP_MULTISIGNATURE_PARAMETERS',
});
const output = {
  schemaVersion: 1,
  synthetic: true,
  privateKeysRetained: false,
  standards: [
    'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.8',
    'https://www.rfc-editor.org/rfc/rfc9101.html#section-4',
    'https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.3',
  ],
  at,
  audience,
  origin,
  claims,
  certificates: {
    root: trusted.root.toString('base64'),
    reader: trusted.reader.toString('base64'),
    otherRoot: untrusted.root.toString('base64'),
    otherReader: untrusted.reader.toString('base64'),
  },
  cases,
};
writeFileSync(
  new URL('../reference/vectors/oid4vp-request-audience.json', import.meta.url),
  JSON.stringify(output, null, 2) + '\n',
  { flag: 'wx' },
);
console.log(JSON.stringify({ vectors: cases.length, synthetic: true, privateKeysRetained: false }));

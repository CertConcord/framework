import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { CSCProvider } from './providers.mjs';
import { readBody, sendJSON } from './transport.mjs';

const credentialID = 'synthetic-key',
  signAlgo = '1.2.840.10045.4.3.2',
  hashAlgorithmOID = '2.16.840.1.101.3.4.2.1',
  authData = [{ id: 'PIN', value: 'synthetic-password' }];

async function fixture(t) {
  const key = c.generate('ec'),
    root = c.generate('ec'),
    certificate = p.issueCertificate(
      {
        publicKey: key.publicKey,
        issuer: p.name('Synthetic CSC issuer'),
        subject: p.name('Synthetic CSC key'),
        serial: 1,
      },
      root.privateKey,
    ),
    message = Buffer.from('CSC exact message'),
    f = { key, certificate, message, requests: [], transform: (path, value) => value },
    server = createServer(async (req, res) => {
      try {
        assert.equal(req.method, 'POST');
        assert.equal(req.headers.authorization, 'Bearer synthetic-test-token');
        const body = JSON.parse((await readBody(req)).toString('utf8')),
          path = req.url.slice('/csc/v2/'.length);
        assert(req.url.startsWith('/csc/v2/'));
        f.requests.push({ path, body });
        const responses = {
          info: {
            specs: '2.2.0.0',
            methods: ['credentials/info', 'credentials/authorize', 'signatures/signHash'],
          },
          'credentials/info': {
            key: { status: 'enabled', algo: [signAlgo], len: 256, curve: '1.2.840.10045.3.1.7' },
            cert: {
              status: 'valid',
              certificates: [certificate.toString('base64')],
              qcStatements: [],
            },
            auth: { mode: 'explicit', objects: [{ id: 'PIN', type: 'Password' }] },
            SCAL: '2',
            multisign: 1,
          },
          'credentials/authorize': { SAD: 'synthetic-one-use-SAD', expiresIn: 60 },
          'signatures/signHash': {
            signatures: [c.sign(message, key.privateKey).toString('base64')],
          },
        };
        assert(Object.hasOwn(responses, path));
        const response = f.transform(path, responses[path]);
        sendJSON(res, f.status ?? 200, response);
      } catch {
        sendJSON(res, 400, { error: 'invalid_request' });
      }
    });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  f.provider = new CSCProvider({
    url: 'http://127.0.0.1:' + server.address().port,
    accessToken: 'synthetic-test-token',
    allowLoopback: true,
    credentials: new Map([[credentialID, { publicKey: key.publicKey, certificate }]]),
    authorize: async ({ keyRef, hash, permit, auth }) => {
      assert.equal(permit, 'synthetic-verified-permit');
      assert.equal(auth.mode, 'explicit');
      assert.deepEqual(
        auth.objects.map((a) => ({ ...a })),
        [{ id: 'PIN', type: 'Password' }],
      );
      return f.provider.authorizeCredential({ credentialID: keyRef, hash, authData });
    },
  });
  f.operation = {
    keyRef: credentialID,
    tbs: message,
    operationID: 'synthetic-operation',
    permit: 'synthetic-verified-permit',
  };
  return f;
}

test('CSC 2.2 synchronous ES256 binds identical authorization and signing digests', async (t) => {
  const f = await fixture(t),
    signature = await f.provider.sign(f.operation),
    hashes = [c.sha256(f.message).toString('base64')];
  assert.equal(f.provider.id, 'csc-v2.2.0.0-es256');
  assert(c.verify(f.message, signature, f.key.publicKey));
  assert.deepEqual(f.requests, [
    { path: 'info', body: {} },
    {
      path: 'credentials/info',
      body: { credentialID, certificates: 'chain', certInfo: true, authInfo: true },
    },
    {
      path: 'credentials/authorize',
      body: { credentialID, numSignatures: 1, hashes, hashAlgorithmOID, authData },
    },
    {
      path: 'signatures/signHash',
      body: {
        credentialID,
        SAD: 'synthetic-one-use-SAD',
        hashes,
        hashAlgorithmOID,
        signAlgo,
        operationMode: 'S',
        clientData: 'synthetic-operation',
      },
    },
  ]);
});

for (const [label, path, transform, code] of [
  ['legacy version', 'info', (r) => ({ ...r, specs: '2.0.0.2' }), 'CSC_VERSION'],
  ['unselected version', 'info', (r) => ({ ...r, specs: '2.3.0.0' }), 'CSC_VERSION'],
  [
    'missing authorization endpoint',
    'info',
    (r) => ({ ...r, methods: ['credentials/info', 'signatures/signHash'] }),
    'CSC_METHODS',
  ],
  [
    'disabled key',
    'credentials/info',
    (r) => ({ ...r, key: { ...r.key, status: 'disabled' } }),
    'CSC_UNSUPPORTED_CAPABILITY',
  ],
  [
    'wrong algorithm',
    'credentials/info',
    (r) => ({ ...r, key: { ...r.key, algo: ['1.2.840.113549.1.1.11'] } }),
    'CSC_UNSUPPORTED_CAPABILITY',
  ],
  [
    'wrong curve',
    'credentials/info',
    (r) => ({ ...r, key: { ...r.key, curve: '1.3.132.0.34' } }),
    'CSC_UNSUPPORTED_CAPABILITY',
  ],
  [
    'certificate substitution',
    'credentials/info',
    (r) => ({
      ...r,
      cert: { certificates: [Buffer.from('another certificate').toString('base64')] },
    }),
    'CSC_CERTIFICATE_PIN',
  ],
  [
    'revoked certificate',
    'credentials/info',
    (r) => ({ ...r, cert: { ...r.cert, status: 'revoked' } }),
    'CSC_CERTIFICATE_STATUS',
  ],
  [
    'OAuth credential mode',
    'credentials/info',
    (r) => ({ ...r, auth: { mode: 'oauth2code' } }),
    'CSC_AUTHORIZATION_PROFILE',
  ],
  ['unbound SAD', 'credentials/info', (r) => ({ ...r, SCAL: '1' }), 'CSC_AUTHORIZATION_PROFILE'],
  [
    'default unbound SAD',
    'credentials/info',
    (r) => ({ ...r, SCAL: undefined }),
    'CSC_AUTHORIZATION_PROFILE',
  ],
  [
    'invalid signature limit',
    'credentials/info',
    (r) => ({ ...r, multisign: 0 }),
    'CSC_AUTHORIZATION_PROFILE',
  ],
  [
    'pending authorization',
    'credentials/authorize',
    () => ({ handle: 'pending' }),
    'CSC_SAD_REQUIRED',
  ],
  ['empty SAD', 'credentials/authorize', () => ({ SAD: '' }), 'CSC_SAD_REQUIRED'],
  [
    'expired SAD',
    'credentials/authorize',
    () => ({ SAD: 'expired', expiresIn: 0 }),
    'CSC_SAD_REQUIRED',
  ],
  [
    'two signatures',
    'signatures/signHash',
    (r) => ({ signatures: [...r.signatures, ...r.signatures] }),
    'CSC_SIGNATURE_COUNT',
  ],
  [
    'asynchronous signature handle',
    'signatures/signHash',
    (r) => ({ ...r, responseID: 'pending' }),
    'CSC_SIGNATURE_COUNT',
  ],
  [
    'noncanonical Base64',
    'signatures/signHash',
    (r) => ({ signatures: [r.signatures[0] + '\n'] }),
    'CSC_BASE64',
  ],
  [
    'signature over other bytes',
    'signatures/signHash',
    (r, f) => ({
      signatures: [c.sign(Buffer.from('other message'), f.key.privateKey).toString('base64')],
    }),
    'CSC_SIGNATURE',
  ],
]) {
  test('CSC 2.2 rejects ' + label, async (t) => {
    const f = await fixture(t);
    f.transform = (actual, response) => (actual === path ? transform(response, f) : response);
    await assert.rejects(f.provider.sign(f.operation), { code });
    assert.equal(f.requests.at(-1).path, path);
    assert.equal(f.requests.filter((r) => r.path === path).length, 1);
  });
}

test('CSC 2.2 rejects HTTP 202 even if a SAD is present and does not retry', async (t) => {
  const f = await fixture(t);
  f.transform = (path, response) => {
    if (path === 'credentials/authorize') f.status = 202;
    return response;
  };
  await assert.rejects(f.provider.sign(f.operation), { code: 'CSC_HTTP_202' });
  assert.equal(f.requests.at(-1).path, 'credentials/authorize');
  assert.equal(f.requests.length, 3);
});

test('CSC 2.2 checks the pinned public key against the pinned certificate', async (t) => {
  const f = await fixture(t);
  f.provider.credentials.get(credentialID).publicKey = c.generate('ec').publicKey;
  await assert.rejects(f.provider.sign(f.operation), { code: 'CSC_PUBLIC_KEY_PIN' });
  assert.equal(f.requests.at(-1).path, 'credentials/info');
});

test('CSC 2.2 rejects unknown credentials, legacy factors and malformed digests before sending', async (t) => {
  const f = await fixture(t),
    hash = c.sha256(f.message).toString('base64');
  await assert.rejects(f.provider.sign({ ...f.operation, keyRef: 'unknown' }), {
    code: 'CSC_KEY_PIN',
  });
  for (const [request, code] of [
    [{ credentialID, hash, PIN: 'legacy' }, 'CSC_LEGACY_AUTH'],
    [{ credentialID, hash: c.sha256(f.message).toString('base64url') }, 'CSC_BASE64'],
    [{ credentialID, hash: Buffer.alloc(64).toString('base64') }, 'CSC_HASH'],
    [{ credentialID, hash, authData: [{ id: 'PIN' }, { id: 'PIN' }] }, 'CSC_AUTH_DATA'],
    [{ credentialID, hash, authData: [{ value: 'missing ID' }] }, 'CSC_AUTH_DATA'],
  ])
    await assert.rejects(f.provider.authorizeCredential(request), { code });
  assert.equal(f.requests.length, 0);
});

test('CSC 2.2 authorization cannot mutate the message retained for dispatch verification', async (t) => {
  const f = await fixture(t),
    authorize = f.provider.authorize;
  f.provider.authorize = (input) => {
    input.tbs.fill(0);
    return authorize(input);
  };
  const signature = await f.provider.sign(f.operation);
  assert(c.verify(f.message, signature, f.key.publicKey));
});

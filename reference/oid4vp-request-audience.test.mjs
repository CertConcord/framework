import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createHash,
  createPrivateKey,
  generateKeyPairSync,
  verify,
  X509Certificate,
} from 'node:crypto';
import { readFileSync } from 'node:fs';
import { Encoder } from 'cbor-x';
import {
  PresentationVerifier,
  parseVPRequest,
  walletPresentation,
  walletMdocPresentation,
  VC_TYPE,
} from './openid.mjs';
import { issueCertificate, name } from './pki.mjs';
import { Journal } from './state.mjs';
import { signJWS, verifyJWT, publicJWK, issueSDJWT, decryptJWE } from './jose.mjs';
import { openidTranscript } from './mdoc.mjs';

const vectors = JSON.parse(
  readFileSync(new URL('./vectors/oid4vp-request-audience.json', import.meta.url)),
);
const A = 'https://self-issued.me/v2';
const origin = 'https://reader.example.invalid';
const key = () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
// Compare JSON claim values independently of the safe parser's null prototypes.
const jsonClaims = (value) => JSON.parse(JSON.stringify(value));
const certificates = Object.fromEntries(
  Object.entries(vectors.certificates).map(([id, value]) => [
    id,
    new X509Certificate(Buffer.from(value, 'base64')),
  ]),
);
const roots = [certificates.root];
function independentlyVerify(token, publicKey, valid = true) {
  const [header, payload, signature] = token.split('.');
  assert.equal(
    verify(
      'sha256',
      Buffer.from(header + '.' + payload, 'ascii'),
      { key: publicKey, dsaEncoding: 'ieee-p1363' },
      Buffer.from(signature, 'base64url'),
    ),
    valid,
  );
  return {
    header: JSON.parse(Buffer.from(header, 'base64url')),
    claims: JSON.parse(Buffer.from(payload, 'base64url')),
  };
}
function fixture(t) {
  t.mock.timers.enable({ apis: ['Date'], now: vectors.at * 1000 });
  const ca = key(),
    reader = key(),
    rootName = name('Synthetic audience test root');
  const root = issueCertificate(
    {
      publicKey: ca.publicKey,
      issuer: rootName,
      subject: rootName,
      serial: 11,
      ca: true,
      notBefore: vectors.at - 3600,
      notAfter: vectors.at + 86400,
    },
    ca.privateKey,
  );
  const certificate = issueCertificate(
    {
      publicKey: reader.publicKey,
      issuer: rootName,
      subject: name('Synthetic audience test reader'),
      serial: 12,
      notBefore: vectors.at - 1800,
      notAfter: vectors.at + 3600,
    },
    ca.privateKey,
  );
  const journal = new Journal();
  t.after(() => journal.close());
  const verifier = new PresentationVerifier({
    baseURL: origin,
    journal,
    privateKey: reader.privateKey,
    certificate,
    issuerRegistry: new Map(),
    trustRoots: [new X509Certificate(root)],
  });
  return { reader, certificate, journal, verifier, roots: [new X509Certificate(root)] };
}
function signedPayload(f, payload) {
  return signJWS(payload, f.reader.privateKey, {
    typ: 'oauth-authz-req+jwt',
    x5c: [f.certificate.toString('base64')],
  });
}
function replaceSaved(f, id, request, extra = {}) {
  const row = f.journal.get('vp', id);
  f.journal.put('vp', id, { ...row.value, request, ...extra }, row.revision);
}

for (const mode of ['direct_post.jwt', 'dc_api.jwt']) {
  test('OID4VP request audience: request emits and stores static audience for ' + mode, (t) => {
    const f = fixture(t),
      r = f.verifier.request({
        sessionID: 'synthetic-session',
        mode,
        origin,
        aud: 'urn:untrusted:override',
      });
    assert.equal(r.request.aud, A);
    const decoded = independentlyVerify(r.signed, f.reader.publicKey).claims;
    assert.deepEqual(decoded, r.request);
    assert.deepEqual(jsonClaims(f.journal.get('vp', r.id).value.request), r.request);
    assert.deepEqual(
      independentlyVerify(f.verifier.signedRequest(r.id), f.reader.publicKey).claims,
      decoded,
    );
    if (mode === 'dc_api.jwt') {
      assert(!Object.hasOwn(decoded, 'state'));
      assert(!Object.hasOwn(decoded, 'response_uri'));
      assert.deepEqual(decoded.expected_origins, [origin]);
    } else {
      assert.equal(decoded.state, r.request.state);
      assert.equal(decoded.response_uri, origin + '/response/' + r.id);
    }
  });
}
for (const [id, aud] of [
  ['static-string', A],
  ['static-array', [A]],
  ['static-plus-other-array', [A, 'urn:example:other']],
]) {
  test('OID4VP request audience: signedRequest preserves ' + id, (t) => {
    const f = fixture(t),
      r = f.verifier.request({ sessionID: 'synthetic-session' });
    replaceSaved(f, r.id, { ...r.request, aud });
    const before = f.journal.get('vp', r.id);
    assert.deepEqual(
      independentlyVerify(f.verifier.signedRequest(r.id), f.reader.publicKey).claims,
      jsonClaims(before.value.request),
    );
    assert.deepEqual(f.journal.get('vp', r.id), before);
  });
}
for (const [id, aud] of [
  ['missing', undefined],
  ['foreign', 'urn:example:other'],
  ['non-string', 7],
  ['foreign-array', ['urn:example:other']],
  ['mixed-type-array', [A, 7]],
]) {
  test(
    'OID4VP request audience: signedRequest rejects ' + id + ' before key access and writes',
    (t) => {
      const f = fixture(t),
        r = f.verifier.request({ sessionID: 'synthetic-session' });
      assert.equal(
        independentlyVerify(f.verifier.signedRequest(r.id), f.reader.publicKey).claims.aud,
        A,
      );
      const request = { ...r.request, aud };
      if (aud === undefined) delete request.aud;
      replaceSaved(f, r.id, request);
      const before = f.journal.get('vp', r.id);
      let keyReads = 0;
      Object.defineProperty(f.verifier, 'privateKey', {
        get() {
          keyReads++;
          throw new Error('unexpected private key access');
        },
      });
      const writes = ['put', 'reserve', 'complete']
        .filter((name) => typeof f.journal[name] === 'function')
        .map((name) => t.mock.method(f.journal, name));
      assert.throws(() => f.verifier.signedRequest(r.id), { code: 'VP_REQUEST_AUDIENCE' });
      assert.equal(keyReads, 0);
      for (const write of writes) assert.equal(write.mock.callCount(), 0);
      assert.deepEqual(f.journal.get('vp', r.id), before);
    },
  );
}
test('OID4VP request audience: signedRequest retains state and expiry guards', (t) => {
  const f = fixture(t),
    r = f.verifier.request({ sessionID: 'synthetic-session' });
  let keyReads = 0;
  Object.defineProperty(f.verifier, 'privateKey', {
    get() {
      keyReads++;
      throw new Error('unexpected private key access');
    },
  });
  replaceSaved(f, r.id, { ...r.request, exp: vectors.at });
  const expired = f.journal.get('vp', r.id);
  assert.throws(() => f.verifier.signedRequest(r.id), { code: 'VP_STATE' });
  assert.deepEqual(f.journal.get('vp', r.id), expired);
  replaceSaved(f, r.id, r.request, { status: 'COMPLETED' });
  const completed = f.journal.get('vp', r.id);
  assert.throws(() => f.verifier.signedRequest(r.id), { code: 'VP_STATE' });
  assert.equal(keyReads, 0);
  assert.deepEqual(f.journal.get('vp', r.id), completed);
});

const shapeIDs = [
  'static',
  'static-array',
  'static-plus-other',
  'other-plus-static',
  'duplicate-static',
  'static-plus-empty-string',
  'missing',
  'foreign',
  'empty-string',
  'case-variant',
  'trailing-slash',
  'null',
  'number',
  'boolean',
  'object',
  'empty-array',
  'foreign-array',
  'mixed-type-array',
  'nested-array',
];
test('OID4VP request audience: raw vectors have independent signatures and isolated claim differences', () => {
  assert.equal(vectors.synthetic, true);
  assert.equal(vectors.privateKeysRetained, false);
  assert.equal(vectors.audience, A);
  assert(certificates.root.verify(certificates.root.publicKey));
  assert(certificates.reader.verify(certificates.root.publicKey));
  assert(certificates.otherReader.verify(certificates.otherRoot.publicKey));
  assert(!certificates.otherReader.verify(certificates.root.publicKey));
  assert.equal(new Set(vectors.cases.map((row) => row.id)).size, vectors.cases.length);
  const { aud: ignored, ...base } = vectors.claims;
  for (const [index, id] of shapeIDs.entries()) {
    const row = vectors.cases.find((row) => row.id === 'compact-' + id);
    assert(row, id);
    assert.equal(row.expectedAcceptance, index < 6);
    const token = Buffer.from(row.wireBase64, 'base64').toString('utf8');
    const { aud, ...other } = independentlyVerify(token, certificates.reader.publicKey).claims;
    assert.deepEqual(other, base, id);
    if (index >= 6) assert.equal(row.expectedError, 'VP_REQUEST_AUDIENCE');
  }
});
for (const row of vectors.cases) {
  test('OID4VP request audience raw: ' + row.id, (t) => {
    t.mock.timers.enable({ apis: ['Date'], now: row.at * 1000 });
    const bytes = Buffer.from(row.wireBase64, 'base64');
    assert.equal(bytes.length, row.bytes);
    assert.equal(digest(bytes), row.sha256);
    const wire = bytes.toString('utf8'),
      input = row.mode === 'compact' ? wire : JSON.parse(wire);
    const tokens =
      row.mode === 'multi'
        ? input.data.request.signatures.map(
            (s) => s.protected + '.' + input.data.request.payload + '.' + s.signature,
          )
        : [row.mode === 'compact' ? wire : input.data.request];
    assert.deepEqual(
      tokens,
      row.oracleTokens.map((entry) => entry.token),
    );
    for (const entry of row.oracleTokens) {
      const decoded = independentlyVerify(
        entry.token,
        certificates[entry.certificate].publicKey,
        entry.valid,
      );
      assert.deepEqual(decoded.header.x5c, [vectors.certificates[entry.certificate]]);
    }
    const parse = () => parseVPRequest(input, { verifierRoots: roots, ...row.options });
    if (row.expectedAcceptance) assert.deepEqual(jsonClaims(parse()), row.expectedClaims);
    else assert.throws(parse, { code: row.expectedError });
  });
}

for (const kind of ['unsigned', 'multisigned']) {
  test(
    'OID4VP request audience: signed wrapper rejects nested ' +
      kind +
      ' request before consent and holder use',
    (t) => {
      const f = fixture(t);
      let inner;
      if (kind === 'unsigned') {
        const r = f.verifier.request({
          sessionID: 'synthetic-session',
          mode: 'dc_api.jwt',
          origin,
          format: 'dc+sd-jwt',
          activationHash: Buffer.alloc(64, 3),
        });
        const data = { ...r.request };
        delete data.aud;
        inner = { protocol: 'openid4vp-v1-unsigned', data };
      } else {
        const row = vectors.cases.find((row) => row.id === 'multi-static-first-untrusted');
        inner = JSON.parse(Buffer.from(row.wireBase64, 'base64'));
      }
      const verifierRoots = kind === 'unsigned' ? f.roots : roots;
      const options = { verifierRoots, origin, expectedResponseOrigin: origin };
      assert.equal(parseVPRequest(inner, options).response_mode, 'dc_api.jwt');
      const wrapped = { protocol: 'openid4vp-v1-signed', data: { request: inner } };
      assert.throws(() => parseVPRequest(wrapped, options), { code: 'VP_REQUEST_PROTOCOL' });
      let approvals = 0,
        keyUses = 0;
      const holderKey = new Proxy(
        {},
        {
          get() {
            keyUses++;
            throw new Error('unexpected holder key use');
          },
        },
      );
      assert.throws(
        () =>
          walletPresentation(wrapped, {
            ...options,
            credential: 'unused before request validation',
            holderKey,
            approveTransaction: () => {
              approvals++;
              return false;
            },
          }),
        { code: 'VP_REQUEST_PROTOCOL' },
      );
      assert.equal(approvals, 0);
      assert.equal(keyUses, 0);
    },
  );
}

for (const [id, embedded] of [
  ['same-host-different-value', A + '?unexpected=1'],
  ['foreign-host-with-audience-in-query', 'https://attacker.example.invalid/?next=' + A],
]) {
  for (const array of [false, true]) {
    test('OID4VP request audience: rejects ' + id + ' as ' + (array ? 'array' : 'string'), (t) => {
      const f = fixture(t),
        r = f.verifier.request({ sessionID: 'synthetic-session' }),
        options = { verifierRoots: f.roots, expectedResponseOrigin: origin };
      assert.equal(parseVPRequest(r.signed, options).aud, A);
      const input = signedPayload(f, { ...r.request, aud: array ? [embedded] : embedded });
      assert.throws(() => parseVPRequest(input, options), { code: 'VP_REQUEST_AUDIENCE' });
    });
  }
}

test('OID4VP request audience: generic JWT audience membership remains unchanged', (t) => {
  const f = fixture(t),
    payload = { aud: ['urn:example:first', 'urn:example:second'], iat: vectors.at };
  const token = signJWS(payload, f.reader.privateKey);
  assert.deepEqual(
    jsonClaims(verifyJWT(token, f.reader.publicKey, { audience: 'urn:example:second' }).claims),
    payload,
  );
  assert.throws(() => verifyJWT(token, f.reader.publicKey, { audience: 'urn:example:third' }), {
    code: 'JWT_AUDIENCE',
  });
});
test('OID4VP request audience: unsigned DC ignores audience and client identity fields', (t) => {
  const f = fixture(t),
    r = f.verifier.request({ sessionID: 'synthetic-session', mode: 'dc_api.jwt', origin });
  const allowed = ['response_type', 'response_mode', 'nonce', 'client_metadata', 'dcql_query'];
  const expected = Object.fromEntries(allowed.map((name) => [name, r.request[name]]));
  expected.exp = vectors.at + 120;
  for (const aud of [undefined, A, [A], { arbitrary: true }]) {
    const input = {
      protocol: 'openid4vp-v1-unsigned',
      data: {
        ...r.request,
        aud,
        client_id: 'untrusted',
        state: 'untrusted',
        expected_origins: ['https://other.example.invalid'],
      },
    };
    const parsed = parseVPRequest(input, { verifierRoots: f.roots, origin });
    assert.deepEqual(parsed, expected);
    for (const name of ['aud', 'client_id', 'state', 'expected_origins'])
      assert(!Object.hasOwn(parsed, name));
  }
});
test('OID4VP request audience: unsigned DC still rejects an invalid platform origin', (t) => {
  const f = fixture(t),
    r = f.verifier.request({ sessionID: 'synthetic-session', mode: 'dc_api.jwt', origin });
  for (const badOrigin of ['http://reader.example.invalid', origin + '/path', undefined]) {
    assert.throws(
      () =>
        parseVPRequest(
          { protocol: 'openid4vp-v1-unsigned', data: { ...r.request, aud: A } },
          { verifierRoots: f.roots, origin: badOrigin },
        ),
      { code: 'VP_DC_ORIGIN' },
    );
  }
});
test('OID4VP request audience: SD-JWT rejects before consent and holder key use', (t) => {
  const f = fixture(t),
    r = f.verifier.request({
      sessionID: 'synthetic-session',
      format: 'dc+sd-jwt',
      activationHash: Buffer.alloc(64, 1),
      displayText: 'Synthetic consent',
    });
  let approvals = 0,
    keyUses = 0;
  const holderKey = new Proxy(
    {},
    {
      get() {
        keyUses++;
        throw new Error('unexpected holder key use');
      },
    },
  );
  const options = {
    credential: 'unused before consent',
    holderKey,
    verifierRoots: f.roots,
    expectedResponseOrigin: origin,
    approveTransaction: () => {
      approvals++;
      return false;
    },
  };
  const bad = signedPayload(f, { ...r.request, aud: 'urn:example:foreign-wallet' });
  assert.throws(() => walletPresentation(bad, options), { code: 'VP_REQUEST_AUDIENCE' });
  assert.equal(approvals, 0);
  assert.equal(keyUses, 0);
  assert.throws(() => walletPresentation(r.signed, options), { code: 'TRANSACTION_DECLINED' });
  assert.equal(approvals, 1);
  assert.equal(keyUses, 0);
});
test('OID4VP request audience: mdoc rejects before consent and device signer', async (t) => {
  const f = fixture(t),
    r = f.verifier.request({
      sessionID: 'synthetic-session',
      format: 'mso_mdoc',
      activationHash: Buffer.alloc(64, 2),
      displayText: 'Synthetic consent',
    });
  let approvals = 0,
    signatures = 0;
  const options = {
    credential: 'unused before consent',
    verifierRoots: f.roots,
    expectedResponseOrigin: origin,
    approveTransaction: async () => {
      approvals++;
      return false;
    },
    signer: async () => {
      signatures++;
      throw new Error('unexpected device signing');
    },
  };
  await assert.rejects(
    walletMdocPresentation(
      signedPayload(f, { ...r.request, aud: 'urn:example:foreign-wallet' }),
      options,
    ),
    { code: 'VP_REQUEST_AUDIENCE' },
  );
  assert.equal(approvals, 0);
  assert.equal(signatures, 0);
  await assert.rejects(walletMdocPresentation(r.signed, options), { code: 'TRANSACTION_DECLINED' });
  assert.equal(approvals, 1);
  assert.equal(signatures, 0);
});
for (const mode of ['direct_post.jwt', 'dc_api.jwt']) {
  test(
    'OID4VP request audience: ' +
      (mode === 'dc_api.jwt' ? 'DC' : 'direct') +
      ' SD-JWT response retains ' +
      (mode === 'dc_api.jwt' ? 'origin' : 'verifier') +
      ' audience',
    (t) => {
      const f = fixture(t),
        holder = key(),
        issuer = key();
      const credential = issueSDJWT(
        {
          claims: { qualification: 'SYNTHETIC' },
          issuer: 'https://issuer.example.invalid',
          holderJWK: publicJWK(holder.publicKey),
          vct: VC_TYPE,
        },
        issuer.privateKey,
      ).credential;
      const r = f.verifier.request({
        sessionID: 'synthetic-session',
        format: 'dc+sd-jwt',
        mode,
        origin,
      });
      const input =
        mode === 'dc_api.jwt'
          ? { protocol: 'openid4vp-v1-signed', data: { request: r.signed } }
          : r.signed;
      const response = walletPresentation(input, {
        credential,
        holderKey: holder.privateKey,
        verifierRoots: f.roots,
        expectedResponseOrigin: origin,
        origin,
      });
      const row = f.journal.get('vp', r.id);
      const privateKey = createPrivateKey({
        key: Buffer.from(row.value.privateKey),
        format: 'der',
        type: 'pkcs8',
      });
      const decoded = decryptJWE(response.response, privateKey);
      assert.equal(decoded.state, r.request.state);
      const token = decoded.vp_token.qualification[0].split('~').at(-1);
      const kb = independentlyVerify(token, holder.publicKey).claims;
      const expected = mode === 'dc_api.jwt' ? 'origin:' + origin : f.verifier.clientID;
      assert.equal(kb.aud, expected);
      assert.notEqual(kb.aud, A);
      assert.equal(kb.nonce, r.request.nonce);
      assert.throws(() => verifyJWT(token, holder.publicKey, { audience: A }), {
        code: 'JWT_AUDIENCE',
      });
      assert.deepEqual(f.journal.get('vp', r.id), row);
    },
  );
  test('OID4VP request audience: mdoc keeps ' + mode + ' transcript bindings', (t) => {
    const f = fixture(t),
      r = f.verifier.request({ sessionID: 'synthetic-session', mode, origin });
    const parsed = parseVPRequest(r.signed, {
      verifierRoots: f.roots,
      expectedResponseOrigin: origin,
      origin,
    });
    const jwk = parsed.client_metadata.jwks.keys[0];
    const th = createHash('sha256')
      .update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }))
      .digest();
    const dc = mode === 'dc_api.jwt';
    const input = {
      clientID: parsed.client_id,
      nonce: parsed.nonce,
      responseURI: parsed.response_uri,
      encryptionJWK: jwk,
      ...(dc ? { origin } : {}),
    };
    const bytes = new Encoder({ useRecords: false, mapsAsObjects: false }).encode(
      dc ? [origin, parsed.nonce, th] : [parsed.client_id, parsed.nonce, th, parsed.response_uri],
    );
    const expected = [
      null,
      null,
      [
        dc ? 'OpenID4VPDCAPIHandover' : 'OpenID4VPHandover',
        createHash('sha256').update(bytes).digest(),
      ],
    ];
    assert.deepEqual(openidTranscript(input), expected);
    assert.notDeepEqual(openidTranscript({ ...input, nonce: parsed.nonce + 'changed' }), expected);
    assert.throws(
      () =>
        parseVPRequest(r.signed, {
          verifierRoots: f.roots,
          expectedResponseOrigin: dc ? origin : 'https://other.example.invalid',
          origin: dc ? 'https://other.example.invalid' : origin,
        }),
      { code: dc ? 'VP_DC_ORIGIN' : 'VP_RESPONSE_ORIGIN' },
    );
  });
}

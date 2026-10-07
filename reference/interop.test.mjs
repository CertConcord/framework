import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createPublicKey,
  createPrivateKey,
  X509Certificate,
  sign as nodeSign,
  verify as nodeVerify,
} from 'node:crypto';
import { Encoder } from 'cbor-x';
import * as c from './core.mjs';
import * as j from './jose.mjs';
import * as w from './webauthn.mjs';
import * as b from './browser.mjs';
import * as p from './protection.mjs';
import { name, issueCertificate } from './pki.mjs';
import { Journal } from './state.mjs';
import {
  CredentialIssuer,
  PresentationVerifier,
  walletPresentation,
  verifyStatusList,
  CONFIG_ID,
} from './openid.mjs';
import { parseJSON } from './json.mjs';

test('strict JSON rejects escaped duplicate members and excessive depth', () => {
  assert.throws(() => parseJSON('{"a":1,"\\u0061":2}'), /DUPLICATE/);
  assert.throws(() => parseJSON('[[[[0]]]]', { maxDepth: 2 }));
  assert.throws(() => parseJSON('{"a":01}'));
  assert.equal(parseJSON('{"valid":true}').valid, true);
});
for (const alg of ['ec', 'ed25519', 'ml-dsa-65', 'ml-dsa-87'])
  test(`JOSE ${alg} verifies with exact algorithm and public JWK`, () => {
    const k = c.generate(alg),
      jwk = j.publicJWK(k.publicKey),
      token = j.signJWS({ aud: 'verifier', iat: c.now(), exp: c.now() + 60 }, k.privateKey, {
        typ: 'test+jwt',
      });
    j.verifyJWT(token, j.importPublicJWK(jwk), { typ: 'test+jwt', audience: 'verifier' });
    assert.throws(() => j.verifyJWT(token, k.publicKey, { audience: 'other' }));
    assert.throws(() => j.importPublicJWK({ ...jwk, priv: 'AA' }));
    assert(j.thumbprint(jwk));
  });
test('JWS detached unencoded payload, critical headers, tampering', () => {
  const k = c.generate(),
    p = Buffer.from('raw.binary.payload'),
    t = j.signJWS(p, k.privateKey, { typ: 'JOSE' }, { detached: true, unencoded: true });
  j.verifyJWS(t, k.publicKey, { detached: p });
  assert.throws(() => j.verifyJWS(t, k.publicKey, { detached: Buffer.from('changed') }));
  const critical = j.signJWS(p, k.privateKey, { crit: ['unknown'], unknown: true });
  assert.throws(() => j.verifyJWS(critical, k.publicKey), /CRITICAL/);
});
test('SD-JWT selective disclosure, key binding and unreferenced disclosure rejection', () => {
  const issuer = c.generate('ec'),
    holder = c.generate('ec'),
    vct = 'urn:example:credential',
    i = j.issueSDJWT(
      {
        claims: { qualification: 'identity-verified', privateName: 'Synthetic Person' },
        issuer: 'https://issuer.example',
        holderJWK: j.publicJWK(holder.publicKey),
        vct,
      },
      issuer.privateKey,
    );
  const vp = j.presentSDJWT(i.credential, holder.privateKey, {
      audience: 'verifier',
      nonce: 'nonce',
      claimNames: ['qualification'],
    }),
    r = j.verifySDJWT(vp, issuer.publicKey, {
      issuer: 'https://issuer.example',
      vct,
      requireKeyBinding: true,
      audience: 'verifier',
      nonce: 'nonce',
    });
  assert.equal(r.claims.qualification, 'identity-verified');
  assert(!Object.hasOwn(r.claims, 'privateName'));
  assert.throws(() =>
    j.verifySDJWT(vp, issuer.publicKey, {
      requireKeyBinding: true,
      audience: 'other',
      nonce: 'nonce',
    }),
  );
  const extra = c.b64u(Buffer.from(JSON.stringify(['salt', 'notInCredential', true])));
  assert.throws(() => j.verifySDJWT(i.credential + extra + '~', issuer.publicKey), /UNREFERENCED/);
});
for (const enc of ['A128GCM', 'A256GCM'])
  test(`JWE ECDH-ES ${enc} authenticated response`, () => {
    const k = c.generate('ec'),
      e = j.encryptJWE({ state: 'bound-state' }, j.publicJWK(k.publicKey), {
        enc,
        apv: Buffer.from('nonce'),
        kid: 'ephemeral',
      });
    assert.equal(
      j.decryptJWE(e, k.privateKey, { expectedAPV: Buffer.from('nonce'), kid: 'ephemeral' }).state,
      'bound-state',
    );
    assert.throws(() => j.decryptJWE(e, k.privateKey, { expectedAPV: Buffer.from('changed') }));
    const parts = e.split('.'),
      tag = c.unb64u(parts[4]);
    tag[0] ^= 1;
    parts[4] = c.b64u(tag);
    assert.throws(() => j.decryptJWE(parts.join('.'), k.privateKey));
  });
test('DPoP validates access-token hash, method, endpoint, key and replay', () => {
  const journal = new Journal(),
    k = c.generate('ec'),
    url = 'https://issuer.example/token',
    proof = j.dpopProof(k.privateKey, { method: 'POST', url, accessToken: 'token' });
  try {
    j.verifyDPoP(proof, { method: 'POST', url, accessToken: 'token', journal });
    assert.throws(
      () => j.verifyDPoP(proof, { method: 'POST', url, accessToken: 'token', journal }),
      /REPLAY/,
    );
    assert.throws(
      () =>
        j.verifyDPoP(j.dpopProof(k.privateKey, { method: 'POST', url, accessToken: 'wrong' }), {
          method: 'POST',
          url,
          accessToken: 'token',
          journal,
        }),
      /ATH/,
    );
  } finally {
    journal.close();
  }
});
test('browser WebCrypto wrapper agrees with server encoding, HKDF, GCM and PRFInput', async () => {
  const header = p.wrapperHeader({
      trustDomainID: c.random(),
      subjectID: c.random(),
      credentialIDHash: c.random(),
      rpID: 'example.org',
      purpose: 'ACCOUNT_WRAP',
      contextID: c.random(),
    }),
    prf = c.random(),
    root = c.random();
  assert(c.equal(Buffer.from(b.encode(header)), c.dcbor(header)));
  assert(c.equal(Buffer.from(b.prfInput(header)), p.prfInput(header)));
  const wrapped = await b.wrapRoot(prf, root, header);
  assert(
    c.equal(
      p.unwrapRoot(prf, {
        ...wrapped,
        nonce: Buffer.from(wrapped.nonce),
        tag: Buffer.from(wrapped.tag),
        ciphertext: Buffer.from(wrapped.ciphertext),
      }),
      root,
    ),
  );
  assert(c.equal(Buffer.from(await b.unwrapRoot(prf, p.wrapRoot(prf, root, header))), root));
});
test('WebAuthn registration and assertion verify exact client bytes, RP, UV, signature and counter', () => {
  const key = c.generate('ec'),
    jwk = j.publicJWK(key.publicKey),
    challenge = c.random(),
    credentialID = c.random(),
    rpID = 'example.org',
    origin = 'https://example.org',
    enc = new Encoder({ useRecords: false, mapsAsObjects: false });
  const publicKey = enc.encode(
      new Map([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, c.unb64u(jwk.x)],
        [-3, c.unb64u(jwk.y)],
      ]),
    ),
    count = Buffer.alloc(4);
  count.writeUInt32BE(1);
  const len = Buffer.alloc(2);
  len.writeUInt16BE(credentialID.length);
  const auth = Buffer.concat([
      c.sha256(Buffer.from(rpID)),
      Buffer.from([69]),
      count,
      Buffer.alloc(16),
      len,
      credentialID,
      publicKey,
    ]),
    client = Buffer.from(
      JSON.stringify({
        type: 'webauthn.create',
        challenge: c.b64u(challenge),
        origin,
        crossOrigin: false,
      }),
    );
  const response = {
    id: c.b64u(credentialID),
    rawId: c.b64u(credentialID),
    type: 'public-key',
    response: {
      clientDataJSON: c.b64u(client),
      attestationObject: c.b64u(
        enc.encode(
          new Map([
            ['fmt', 'none'],
            ['authData', auth],
            ['attStmt', new Map()],
          ]),
        ),
      ),
    },
  };
  const registration = w.verifyRegistration(response, { challenge, origin, rpID });
  assert.equal(registration.attestationVerified, false);
  const ac = c.random(),
    ad = Buffer.concat([c.sha256(Buffer.from(rpID)), Buffer.from([5]), Buffer.from([0, 0, 0, 2])]),
    cd = Buffer.from(
      JSON.stringify({ type: 'webauthn.get', challenge: c.b64u(ac), origin, crossOrigin: false }),
    );
  const assertion = {
    ...response,
    response: {
      clientDataJSON: c.b64u(cd),
      authenticatorData: c.b64u(ad),
      signature: c.b64u(c.sign(Buffer.concat([ad, c.sha256(cd)]), key.privateKey)),
    },
  };
  assert.equal(w.verifyAssertion(assertion, registration, { challenge: ac }).counter, 2);
  assert.throws(() => w.verifyAssertion(assertion, registration, { challenge: c.random() }));
  assert.throws(() =>
    w.verifyAssertion(assertion, registration, { challenge: ac, origin: 'https://evil.example' }),
  );
});
test('browser PRF driver routes evalByCredential and excludes local secrets from serialized assertion', async () => {
  const id = c.random(),
    secret = c.random(),
    calls = [],
    fake = {
      get: async (input) => {
        calls.push(input);
        return {
          id: c.b64u(id),
          rawId: id,
          type: 'public-key',
          response: {
            clientDataJSON: c.random(10),
            authenticatorData: c.random(37),
            signature: c.random(70),
          },
          getClientExtensionResults: () => ({ prf: { results: { first: secret } } }),
        };
      },
    };
  const r = await b.evaluatePRF({
    credentialID: id,
    rpID: 'example.org',
    challenge: c.random(),
    first: c.random(),
    credentials: fake,
  });
  assert(c.equal(Buffer.from(r.first), secret));
  assert(calls[0].publicKey.extensions.prf.evalByCredential[c.b64u(id)]);
  assert(!JSON.stringify(r.assertion).includes(c.b64u(secret)));
  assert.equal(calls[0].publicKey.userVerification, 'required');
});
test('PRF serialization rejects cleartext results in signed assertion and attestation bytes', async () => {
  const id = c.random(),
    first = c.random(),
    second = c.random(),
    encoder = new Encoder({ useRecords: false, mapsAsObjects: false }),
    auth = Buffer.concat([
      c.random(32),
      Buffer.from([0x85]),
      Buffer.alloc(4),
      encoder.encode(new Map([['prf', new Map([['results', new Map([['first', first]])]])]])),
    ]),
    credential = {
      id: c.b64u(id),
      rawId: id,
      type: 'public-key',
      response: { clientDataJSON: c.random(), authenticatorData: auth, signature: c.random(70) },
      getClientExtensionResults: () => ({ prf: { results: { first, second } } }),
      toJSON: () => {
        throw Error('GENERIC_SERIALIZER_FORBIDDEN');
      },
    };
  const original = Buffer.from(auth);
  assert.throws(() => b.publicAssertion(credential), /PRF_CLEARTEXT_IN_SIGNED_DATA/);
  await assert.rejects(
    b.evaluatePRF({
      credentialID: id,
      rpID: 'example.org',
      challenge: c.random(),
      first: c.random(),
      second: c.random(),
      credentials: { get: async () => credential },
    }),
    /PRF_CLEARTEXT_IN_SIGNED_DATA/,
  );
  assert.deepEqual(auth, original);
  credential.response.authenticatorData = Buffer.concat([
    c.random(37),
    encoder.encode(new Map([['hmac-secret', c.random(80)]])),
  ]);
  const exported = b.publicAssertion(credential);
  assert.deepEqual(
    c.unb64u(exported.response.authenticatorData),
    credential.response.authenticatorData,
  );
  assert(!Object.hasOwn(exported, 'clientExtensionResults'));
  credential.response.attestationObject = encoder.encode(
    new Map([
      [
        'authData',
        Buffer.concat([
          c.random(55),
          encoder.encode(new Map([['prf', new Map([['second', second]])]])),
        ]),
      ],
    ]),
  );
  assert.throws(() => b.publicRegistration(credential), /PRF_CLEARTEXT_IN_SIGNED_DATA/);
});
test('local raw-signing enrollment does not enable remote-client-data delegation', async () => {
  let calls = 0;
  const credentials = {
    create: async () => {
      calls++;
    },
    get: async () => {
      calls++;
    },
  };
  for (const value of ['', '{}']) {
    const options = {
      challenge: c.random(),
      allowCredentials: [{ id: c.random(), type: 'public-key' }],
      extensions: { remoteClientDataJSON: value },
    };
    await assert.rejects(
      b.createRawSigningKey(options, { credentials }),
      /REMOTE_CLIENT_DATA_PROFILE_REQUIRED/,
    );
    await assert.rejects(
      b.generateRawSigningKey(options, { credentials }),
      /REMOTE_CLIENT_DATA_PROFILE_REQUIRED/,
    );
  }
  assert.equal(calls, 0);
});
test('WebAuthn counter absence and rollback retain distinct acceptance rules', () => {
  const key = c.generate('ec'),
    id = c.random(),
    rpID = 'example.org',
    origin = 'https://example.org',
    challenge = c.random(),
    client = Buffer.from(
      JSON.stringify({
        type: 'webauthn.get',
        challenge: c.b64u(challenge),
        origin,
        crossOrigin: false,
      }),
    );
  const registration = {
    credentialID: id,
    publicKey: key.publicKey,
    rpID,
    origin,
    counter: 0,
    backupEligible: false,
  };
  for (const [previous, current, accepted] of [
    [0, 0, true],
    [0, 1, true],
    [1, 2, true],
    [1, 0, false],
    [1, 1, false],
    [2, 1, false],
  ]) {
    const count = Buffer.alloc(4);
    count.writeUInt32BE(current);
    const auth = Buffer.concat([c.sha256(Buffer.from(rpID)), Buffer.from([5]), count]),
      assertion = {
        id: c.b64u(id),
        rawId: c.b64u(id),
        type: 'public-key',
        response: {
          clientDataJSON: c.b64u(client),
          authenticatorData: c.b64u(auth),
          signature: c.b64u(c.sign(Buffer.concat([auth, c.sha256(client)]), key.privateKey)),
        },
      };
    const verify = () =>
      w.verifyAssertion(assertion, { ...registration, counter: previous }, { challenge });
    if (accepted) assert.equal(verify().counter, current);
    else assert.throws(verify, /SIGN_COUNT_ROLLBACK/);
  }
});
test('previewSign5 creation requires UV and preserves the independent key and parent registration', async () => {
  const id = c.random(),
    key = { algorithm: -9, keyHandle: c.random(), publicKey: c.random() };
  const credential = {
    id: c.b64u(id),
    rawId: id,
    type: 'public-key',
    response: { clientDataJSON: c.random(), attestationObject: c.random() },
    getClientExtensionResults: () => ({ previewSign5: { generatedKey: key } }),
  };
  const result = await b.createRawSigningKey(
    { challenge: c.random(), extensions: { credProps: true } },
    {
      algorithms: [-9, -300],
      credentials: {
        create: async ({ publicKey }) => {
          assert.equal(publicKey.authenticatorSelection.userVerification, 'required');
          assert.deepEqual(publicKey.extensions.previewSign5.generateKey.algorithms, [-9, -300]);
          assert.equal(publicKey.extensions.credProps, true);
          return credential;
        },
      },
    },
  );
  assert.equal(result.key, key);
  assert.equal(result.registration.id, credential.id);
  await assert.rejects(
    b.createRawSigningKey({}, { credentials: { create: async () => null } }),
    /RAW_SIGNING_UNAVAILABLE/,
  );
});

for (const algorithm of [-9, -300])
  test(`previewSign5 ${algorithm} preserves message versus split-input semantics and returns a verifiable signature`, async () => {
    const id = c.random(),
      keyHandle = c.random(),
      tbs = Buffer.from('A specific document input'),
      challenge = c.random(),
      key = c.generate('ec');
    const result = await b.rawSign({
      credentialID: id,
      rpID: 'example.org',
      challenge,
      keyHandle,
      tbs,
      algorithm,
      credentials: {
        get: async ({ publicKey }) => {
          assert.equal(publicKey.rpId, 'example.org');
          assert.equal(publicKey.userVerification, 'required');
          assert.deepEqual(Buffer.from(publicKey.challenge), challenge);
          assert.deepEqual(Buffer.from(publicKey.allowCredentials[0].id), id);
          const input = publicKey.extensions.previewSign5.signByCredential[c.b64u(id)];
          assert.deepEqual(Buffer.from(input.keyHandle), keyHandle);
          assert.deepEqual(Buffer.from(input.tbs), algorithm === -300 ? c.sha256(tbs) : tbs);
          return {
            id: c.b64u(id),
            rawId: id,
            type: 'public-key',
            response: {
              clientDataJSON: c.random(),
              authenticatorData: c.random(37),
              signature: c.random(70),
            },
            getClientExtensionResults: () => ({
              previewSign5: { signature: nodeSign('sha256', tbs, key.privateKey) },
            }),
          };
        },
      },
    });
    assert(nodeVerify('sha256', tbs, key.publicKey, result.signature));
    assert(!nodeVerify('sha256', Buffer.from('another document'), key.publicKey, result.signature));
    assert.equal(result.assertion.id, c.b64u(id));
  });

test('previewSign5 rejects unavailable capabilities, a different parent credential and unknown algorithms', async () => {
  const request = {
    credentialID: c.random(),
    rpID: 'example.org',
    challenge: c.random(),
    keyHandle: c.random(),
    tbs: c.random(),
  };
  await assert.rejects(b.rawSign({ ...request, algorithm: -7 }), /RAW_SIGNING_ALGORITHM/);
  await assert.rejects(
    b.rawSign({ ...request, credentials: { get: async () => ({ rawId: c.random() }) } }),
    /CREDENTIAL_BINDING/,
  );
  await assert.rejects(
    b.rawSign({
      ...request,
      credentials: {
        get: async () => ({ rawId: request.credentialID, getClientExtensionResults: () => ({}) }),
      },
    }),
    /RAW_SIGNING_UNAVAILABLE/,
  );
});

test('OpenID4VCI -> selective VP -> session redirect -> one-use activation qualification', async () => {
  const journal = new Journal(),
    ca = c.generate('ec'),
    issuerKey = c.generate('ec'),
    verifierKey = c.generate('ec'),
    wallet = c.generate('ec'),
    holder = c.generate('ec'),
    dpop = c.generate('ec');
  const root = issueCertificate(
      {
        publicKey: ca.publicKey,
        issuer: name('Example Root'),
        subject: name('Example Root'),
        serial: 1,
        ca: true,
      },
      ca.privateKey,
    ),
    roots = [new X509Certificate(root)];
  const cert = (k) =>
      issueCertificate(
        {
          publicKey: k.publicKey,
          issuer: name('Example Root'),
          subject: name('Example Service'),
          serial: BigInt(c.random(8).readBigUInt64BE()),
        },
        ca.privateKey,
      ),
    issuerCert = cert(issuerKey),
    verifierCert = cert(verifierKey),
    issuerURL = 'https://issuer.example',
    clientID = 'https://wallet.example',
    redirectURI = 'https://wallet.example/callback';
  const issuer = new CredentialIssuer({
    issuer: issuerURL,
    journal,
    privateKey: issuerKey.privateKey,
    certificate: issuerCert,
    clients: new Map([[clientID, { publicKey: wallet.publicKey, redirectURIs: [redirectURI] }]]),
  });
  const auth = () => ({
    client_id: clientID,
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion: j.signJWS(
      {
        iss: clientID,
        sub: clientID,
        aud: issuerURL,
        iat: c.now(),
        exp: c.now() + 60,
        jti: c.b64u(c.random()),
      },
      wallet.privateKey,
      { typ: 'JWT' },
    ),
  });
  try {
    const offer = issuer.offer({
        configurationID: CONFIG_ID,
        claims: { qualification: 'CERTCONCORD-IAL2', privateName: 'Synthetic Person' },
        subjectID: 'test-subject',
      }),
      verifier = c.b64u(c.random(48)),
      state = c.b64u(c.random());
    const par = issuer.par({
      ...auth(),
      response_type: 'code',
      scope: CONFIG_ID,
      redirect_uri: redirectURI,
      code_challenge_method: 'S256',
      code_challenge: c.b64u(c.sha256(Buffer.from(verifier))),
      state,
      issuer_state: offer.grants.authorization_code.issuer_state,
    });
    const a = issuer.authorize(
      { request_uri: par.request_uri, client_id: clientID },
      { approved: true, subjectID: 'test-subject' },
    );
    assert.equal(a.state, state);
    assert.equal(a.iss, issuerURL);
    const token = issuer.token(
      {
        ...auth(),
        grant_type: 'authorization_code',
        code: a.code,
        redirect_uri: redirectURI,
        code_verifier: verifier,
      },
      { dpop: j.dpopProof(dpop.privateKey, { method: 'POST', url: issuerURL + '/token' }) },
    );
    const nonce = issuer.nonce().c_nonce,
      proof = j.signJWS({ iss: clientID, aud: issuerURL, iat: c.now(), nonce }, holder.privateKey, {
        typ: 'openid4vci-proof+jwt',
        jwk: j.publicJWK(holder.publicKey),
      }),
      headers = {
        authorization: 'DPoP ' + token.access_token,
        dpop: j.dpopProof(dpop.privateKey, {
          method: 'POST',
          url: issuerURL + '/credential',
          accessToken: token.access_token,
        }),
      };
    const issued = issuer.credential(
        { credential_configuration_id: CONFIG_ID, proofs: { jwt: [proof] } },
        headers,
      ),
      credential = issued.credentials[0].credential;
    assert.throws(
      () =>
        issuer.credential(
          { credential_configuration_id: CONFIG_ID, proofs: { jwt: [proof] } },
          {
            ...headers,
            dpop: j.dpopProof(dpop.privateKey, {
              method: 'POST',
              url: issuerURL + '/credential',
              accessToken: token.access_token,
            }),
          },
        ),
      /REPLAY/,
    );
    const pv = new PresentationVerifier({
      baseURL: 'https://verifier.example',
      journal,
      privateKey: verifierKey.privateKey,
      certificate: verifierCert,
      trustRoots: roots,
      issuerRegistry: new Map([
        [
          issuerURL,
          {
            certificate: issuerCert,
            publicKey: issuerKey.publicKey,
            statusURI: issuerURL + '/status/1',
            fetchStatus: async () => issuer.status.token(),
          },
        ],
      ]),
    });
    const activationHash = c.random(64),
      r = pv.request({ sessionID: 'test-session', activationHash, format: 'dc+sd-jwt' }),
      response = walletPresentation(r.signed, {
        approveTransaction: () => true,
        credential,
        holderKey: holder.privateKey,
        verifierRoots: roots,
        expectedResponseOrigin: 'https://verifier.example',
      }),
      result = await pv.response(r.id, response.response),
      responseCode = new URL(result.redirect_uri).searchParams.get('response_code');
    const decodedRequest = j.decodeJWS(r.signed),
      malformedRequest = parseJSON(decodedRequest.payload.toString('utf8'));
    const expectedType = malformedRequest.dcql_query.credentials[0].meta.vct_values[0];
    for (const types of [
      'prefix' + expectedType + 'suffix',
      ['prefix' + expectedType + 'suffix'],
    ]) {
      malformedRequest.dcql_query.credentials[0].meta.vct_values = types;
      const signed = j.signJWS(malformedRequest, verifierKey.privateKey, decodedRequest.header);
      assert.throws(
        () =>
          walletPresentation(signed, {
            approveTransaction: () => true,
            credential,
            holderKey: holder.privateKey,
            verifierRoots: roots,
            expectedResponseOrigin: 'https://verifier.example',
          }),
        /DCQL_QUERY/,
      );
    }
    assert.throws(() => pv.complete(r.id, { sessionID: 'wrong-session', responseCode }), /SESSION/);
    const complete = pv.complete(r.id, { sessionID: 'test-session', responseCode });
    assert.equal(complete.claims.qualification, 'CERTCONCORD-IAL2');
    assert(!complete.claims.privateName);
    pv.consumeQualification(r.id, { sessionID: 'test-session', activationHash });
    assert.throws(() =>
      pv.consumeQualification(r.id, { sessionID: 'test-session', activationHash }),
    );
    const status = j.verifySDJWT(credential, issuerKey.publicKey).claims.status.status_list;
    issuer.status.revoke(status.idx);
    assert.equal(
      verifyStatusList(issuer.status.token(), {
        publicKey: issuerKey.publicKey,
        uri: status.uri,
        index: status.idx,
      }).status,
      'REVOKED',
    );
  } finally {
    journal.close();
  }
});

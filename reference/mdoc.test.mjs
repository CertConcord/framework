import { issueIACA, issueMdocCertificate } from './mdoc-pki.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { Encoder, decode as externalDecode } from 'cbor-x';
import { generate, random, sha256, equal, b64u, unb64u } from './core.mjs';
import { publicJWK } from './jose.mjs';
import { encode, decode, Tag, get, unembed, sign1 } from './cose.mjs';
import { issueCertificate, name } from './pki.mjs';
import * as m from './mdoc.mjs';
import { X509Certificate } from 'node:crypto';
import { Journal } from './state.mjs';
import { CredentialIssuer, PresentationVerifier, walletMdocPresentation } from './openid.mjs';
import { signJWS, dpopProof } from './jose.mjs';
import { now } from './core.mjs';
function fixture() {
  const ca = generate('ec'),
    root = issueIACA({
      publicKey: ca.publicKey,
      privateKey: ca.privateKey,
      subject: name('Synthetic IACA'),
      serial: 99,
      issuerAltName: 'https://issuer.example',
      crlURL: 'https://issuer.example/iaca.crl',
    }),
    issuer = generate('ec'),
    holder = generate('ec'),
    reader = generate('ec'),
    cert = issueMdocCertificate({
      publicKey: issuer.publicKey,
      subject: name('Synthetic Document Signer'),
      serial: 1,
      issuerCertificate: root,
      issuerKey: ca.privateKey,
    }),
    readerCert = issueMdocCertificate({
      publicKey: reader.publicKey,
      subject: name('Synthetic Reader'),
      serial: 2,
      issuerCertificate: root,
      issuerKey: ca.privateKey,
      reader: true,
    }),
    credential = m.issueMdoc({
      claims: { qualification: 'CERTCONCORD-IAL2', privateName: 'Synthetic Holder' },
      holderJWK: publicJWK(holder.publicKey),
      certificate: cert,
      privateKey: issuer.privateKey,
    });
  return {
    issuer,
    holder,
    reader,
    cert,
    readerCert,
    credential,
    requested: new Map([[m.NAMESPACE, ['qualification']]]),
  };
}
test('ISO CBOR agrees with external CBOR and rejects ambiguous duplicate labels', () => {
  const value = new Map([
      [1, -7],
      ['tag', new Tag(24, Buffer.from('a0', 'hex'))],
    ]),
    b = encode(value);
  assert.equal(externalDecode(b)[1], -7);
  const external = new Encoder({ useRecords: false, mapsAsObjects: false }).encode(
    new Map([
      [1, -7],
      [2, Buffer.from('00', 'hex')],
    ]),
  );
  assert.equal(get(decode(external), 1), -7);
  assert.throws(() => decode(Buffer.from('a201010102', 'hex')), /DUPLICATE/);
  assert.throws(() => decode(Buffer.from('9fff', 'hex')), /INDEFINITE/);
});
test('mdoc issuer digest, selective disclosure and OpenID4VP device binding', async () => {
  const f = fixture(),
    recipient = generate('ec'),
    transcript = m.openidTranscript({
      clientID: 'x509_hash:synthetic',
      nonce: b64u(random()),
      responseURI: 'https://verifier.example/response',
      encryptionJWK: publicJWK(recipient.publicKey),
    }),
    r = m.verifyIssuerSigned(f.credential, {
      issuerKey: f.issuer.publicKey,
      certificate: f.cert,
      allowPartial: false,
    });
  assert.equal(r.claims.get(m.NAMESPACE).get('qualification'), 'CERTCONCORD-IAL2');
  const response = await m.presentMdoc(f.credential, {
      holderKey: f.holder.privateKey,
      sessionTranscript: transcript,
      requested: f.requested,
    }),
    options = {
      issuerKey: f.issuer.publicKey,
      certificate: f.cert,
      sessionTranscript: transcript,
      requested: f.requested,
    };
  const verified = m.verifyMdoc(response, options);
  assert(!verified.claims.get(m.NAMESPACE).has('privateName'));
  assert.throws(
    () =>
      m.verifyMdoc(response, {
        ...options,
        sessionTranscript: [null, null, ['OpenID4VPHandover', random()]],
      }),
    /SIGNATURE/,
  );
  const bad = decode(response),
    doc = get(bad, 'documents')[0],
    item = get(get(doc, 'issuerSigned'), 'nameSpaces').get(m.NAMESPACE)[0],
    data = unembed(item);
  data.set('elementValue', 'forged');
  item.value = encode(data);
  assert.throws(() => m.verifyMdoc(encode(bad), options), /DIGEST/);
  const wrong = await m.presentMdoc(f.credential, {
    holderKey: f.reader.privateKey,
    sessionTranscript: transcript,
    requested: f.requested,
  });
  assert.throws(() => m.verifyMdoc(wrong, options), /SIGNATURE/);
});

test('mdoc public keys are bound to their certificate and holder roles', async () => {
  const f = fixture(),
    stranger = generate('ec'),
    issue = {
      claims: { name: 'Synthetic Holder' },
      holderJWK: publicJWK(f.holder.publicKey),
      certificate: f.cert,
      privateKey: f.issuer.privateKey,
    };
  assert.throws(() => m.issueMdoc({ ...issue, privateKey: stranger.privateKey }), /ISSUER_KEY/);
  assert.throws(
    () => m.issueMdoc({ ...issue, holderJWK: publicJWK(f.issuer.publicKey) }),
    /KEY_ROLE_COLLISION/,
  );
  assert.throws(
    () => m.issueMdoc({ ...issue, holderJWK: f.holder.privateKey.export({ format: 'jwk' }) }),
    /COSE_KEY/,
  );
  const forged = decode(f.credential),
    original = get(forged, 'issuerAuth');
  forged.set('issuerAuth', sign1(original[2], stranger.privateKey, { certificate: f.cert }));
  assert.throws(
    () =>
      m.verifyIssuerSigned(encode(forged), { issuerKey: stranger.publicKey, certificate: f.cert }),
    /ISSUER_KEY/,
  );
  const swapped = decode(f.credential),
    auth = get(swapped, 'issuerAuth'),
    mso = unembed(decode(auth[2]));
  get(mso, 'deviceKeyInfo').set(
    'deviceKey',
    get(unembed(decode(original[2])), 'deviceKeyInfo').get('deviceKey'),
  );
  get(get(mso, 'deviceKeyInfo'), 'deviceKey').set(-2, unb64u(publicJWK(stranger.publicKey).x));
  auth[2] = encode(new Tag(24, encode(mso)));
  assert.throws(
    () =>
      m.verifyIssuerSigned(encode(swapped), { issuerKey: f.issuer.publicKey, certificate: f.cert }),
    /SIGNATURE/,
  );
  const transcript = m.openidTranscript({
    clientID: 'x509_hash:synthetic',
    nonce: b64u(random()),
    responseURI: 'https://verifier.example/response',
  });
  const wrongRole = await m.presentMdoc(f.credential, {
    holderKey: f.issuer.privateKey,
    sessionTranscript: transcript,
    requested: f.requested,
  });
  assert.throws(
    () =>
      m.verifyMdoc(wrongRole, {
        issuerKey: f.issuer.publicKey,
        certificate: f.cert,
        sessionTranscript: transcript,
        requested: f.requested,
      }),
    /SIGNATURE/,
  );
});
test('Annex C reader authentication and HPKE binds exact origin and encryptionInfo', async () => {
  const f = fixture(),
    session = m.annexCRequest({
      origin: 'https://verifier.example',
      requested: f.requested,
      readerKey: f.reader.privateKey,
      readerCertificate: f.readerCert,
    }),
    options = {
      origin: session.origin,
      credential: f.credential,
      holderKey: f.holder.privateKey,
      readerPublicKey: f.reader.publicKey,
      readerCertificate: f.readerCert,
    };
  const response = await m.annexCPresent(session.request, options),
    result = await m.annexCVerify(response, session, {
      issuerKey: f.issuer.publicKey,
      certificate: f.cert,
    });
  assert.equal(result.claims.get(m.NAMESPACE).get('qualification'), 'CERTCONCORD-IAL2');
  await assert.rejects(
    m.annexCPresent(session.request, { ...options, origin: 'https://other.example' }),
    /SIGNATURE/,
  );
  await assert.rejects(
    m.annexCVerify(
      response,
      {
        ...session,
        sessionTranscript: m.annexCTranscript(
          session.request.encryptionInfo,
          'https://other.example',
        ),
      },
      { issuerKey: f.issuer.publicKey, certificate: f.cert },
    ),
  );
  const data = decode(unb64u(response.response));
  get(data[1], 'cipherText')[0] ^= 1;
  await assert.rejects(
    m.annexCVerify({ response: b64u(encode(data)) }, session, {
      issuerKey: f.issuer.publicKey,
      certificate: f.cert,
    }),
  );
});
test('OpenID issuance -> mdoc holder -> encrypted website presentation -> RRA activation', async () => {
  const journal = new Journal(),
    ca = generate('ec'),
    issuerKey = generate('ec'),
    reader = generate('ec'),
    wallet = generate('ec'),
    holder = generate('ec'),
    dp = generate('ec');
  const root = issueIACA({
      publicKey: ca.publicKey,
      privateKey: ca.privateKey,
      subject: name('Test IACA'),
      serial: 1,
      issuerAltName: 'https://issuer.example',
      crlURL: 'https://issuer.example/iaca.crl',
    }),
    cert = (key, serial) =>
      issueMdocCertificate({
        publicKey: key,
        subject: name('Test Leaf'),
        serial,
        issuerCertificate: root,
        issuerKey: ca.privateKey,
        reader: serial === 3,
      }),
    issuerCert = cert(issuerKey.publicKey, 2),
    readerCert = cert(reader.publicKey, 3),
    roots = [new X509Certificate(root)],
    issuerURL = 'https://issuer.example',
    clientID = 'https://wallet.example';
  const issuer = new CredentialIssuer({
    issuer: issuerURL,
    journal,
    privateKey: issuerKey.privateKey,
    certificate: issuerCert,
    clients: new Map([
      [clientID, { publicKey: wallet.publicKey, redirectURIs: ['https://wallet.example/return'] }],
    ]),
  });
  const auth = () => ({
    client_id: clientID,
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion: signJWS(
      {
        iss: clientID,
        sub: clientID,
        aud: issuerURL,
        iat: now(),
        exp: now() + 60,
        jti: b64u(random()),
      },
      wallet.privateKey,
      { typ: 'JWT' },
    ),
  });
  try {
    const bypass = issuer.offer({ claims: { qualification: 'CERTCONCORD-IAL2' }, subjectID: 'synthetic' });
    assert.throws(
      () =>
        issuer.token(
          {
            ...auth(),
            grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
            'pre-authorized_code': bypass.grants.authorization_code.issuer_state,
          },
          { dpop: dpopProof(dp.privateKey, { method: 'POST', url: issuerURL + '/token' }) },
        ),
      /invalid_grant/,
    );
    const offer = issuer.offer({
        claims: { qualification: 'CERTCONCORD-IAL2', privateName: 'Synthetic Holder' },
        subjectID: 'synthetic',
        preAuthorized: true,
        txCode: '123456',
      }),
      code =
        offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'];
    const token = issuer.token(
      {
        ...auth(),
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': code,
        tx_code: '123456',
      },
      { dpop: dpopProof(dp.privateKey, { method: 'POST', url: issuerURL + '/token' }) },
    );
    const nonce = issuer.nonce().c_nonce,
      proof = signJWS({ iss: clientID, aud: issuerURL, iat: now(), nonce }, holder.privateKey, {
        typ: 'openid4vci-proof+jwt',
        jwk: publicJWK(holder.publicKey),
      }),
      credential = issuer.credential(
        { credential_configuration_id: m.MDOC_CONFIG, proofs: { jwt: [proof] } },
        {
          authorization: 'DPoP ' + token.access_token,
          dpop: dpopProof(dp.privateKey, {
            method: 'POST',
            url: issuerURL + '/credential',
            accessToken: token.access_token,
          }),
        },
      ).credentials[0].credential;
    const verifier = new PresentationVerifier({
        baseURL: 'https://verifier.example',
        journal,
        privateKey: reader.privateKey,
        certificate: readerCert,
        trustRoots: roots,
        issuerRegistry: new Map([
          [
            issuerURL,
            {
              publicKey: issuerKey.publicKey,
              certificate: issuerCert,
              statusURI: issuerURL + '/status/1',
              fetchStatus: async () => issuer.status.token(),
            },
          ],
        ]),
      }),
      activationHash = random(64);
    const request = verifier.request({
        sessionID: 'local-browser-session',
        activationHash,
        mode: 'dc_api.jwt',
        origin: 'https://verifier.example',
        displayText: 'Approve the synthetic test document',
      }),
      opts = {
        credential,
        holderKey: holder.privateKey,
        verifierRoots: roots,
        origin: 'https://verifier.example',
      };
    await assert.rejects(walletMdocPresentation(request.signed, opts), /CONSENT/);
    const response = await walletMdocPresentation(request.signed, {
      ...opts,
      approveTransaction: async (t) => t.activation_hash === b64u(activationHash),
    });
    await verifier.response(request.id, response.response, {
      sessionID: 'local-browser-session',
      mode: 'dc_api.jwt',
    });
    assert.throws(
      () =>
        verifier.consumeQualification(request.id, {
          sessionID: 'local-browser-session',
          activationHash: random(64),
        }),
      /BINDING/,
    );
    const result = verifier.consumeQualification(request.id, {
      sessionID: 'local-browser-session',
      activationHash,
    });
    assert.equal(result.claims.qualification, 'CERTCONCORD-IAL2');
    assert(!Object.hasOwn(result.claims, 'privateName'));
    assert.throws(() =>
      verifier.consumeQualification(request.id, {
        sessionID: 'local-browser-session',
        activationHash,
      }),
    );
  } finally {
    journal.close();
  }
});

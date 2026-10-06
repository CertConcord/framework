import { validateMdocCertificate } from './mdoc-pki.mjs';
import { createPublicKey, webcrypto } from 'node:crypto';
import { CipherSuite, DhkemP256HkdfSha256, HkdfSha256, Aes128Gcm } from '@hpke/core';
import {
  encode,
  decode,
  Tag,
  embedded,
  unembed,
  get,
  coseKey,
  coseJWK,
  sign1,
  verify1,
  prepareSign1,
} from './cose.mjs';
import { random, sha256, now, requireThat, equal, b64u, unb64u, generate, spki } from './core.mjs';
import { publicJWK, thumbprint } from './jose.mjs';

export const DOCTYPE = 'org.certconcord.rra.1';
export const NAMESPACE = 'org.certconcord.rra.1';
export const MDOC_CONFIG = 'certconcord_mdoc';
const stamp = (t) => new Tag(0, new Date(t * 1000).toISOString().replace('.000Z', 'Z'));
const time = (v) => {
  requireThat(
    v instanceof Tag &&
      v.tag === 0 &&
      typeof v.value === 'string' &&
      /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(v.value),
    'MDOC_TIME',
  );
  const n = Date.parse(v.value) / 1000;
  requireThat(Number.isSafeInteger(n), 'MDOC_TIME');
  return n;
};
export function issueMdoc({
  claims,
  holderJWK,
  certificate,
  privateKey,
  docType = DOCTYPE,
  namespace = NAMESPACE,
  additionalNamespaces = {},
  certificateProfile = 'ISO_MDOC',
  validFrom = now(),
  validUntil = validFrom + 86400,
}) {
  requireThat(validUntil > validFrom && validUntil - validFrom <= 86400 * 30, 'MDOC_VALIDITY');
  const ds = validateMdocCertificate(certificate, { certificateProfile }),
    deviceKey = coseKey(holderJWK);
  requireThat(equal(spki(ds.publicKey), spki(createPublicKey(privateKey))), 'MDOC_ISSUER_KEY');
  requireThat(
    !equal(spki(ds.publicKey), spki(createPublicKey({ key: holderJWK, format: 'jwk' }))),
    'MDOC_KEY_ROLE_COLLISION',
  );
  requireThat(!Object.hasOwn(additionalNamespaces, namespace), 'MDOC_NAMESPACE_COLLISION');
  const nameSpaces = new Map(),
    valueDigests = new Map();
  for (const [ns, nsClaims] of Object.entries({ ...additionalNamespaces, [namespace]: claims })) {
    requireThat(typeof ns === 'string' && ns.length > 0, 'MDOC_NAMESPACE');
    const items = [],
      digests = new Map();
    let id = 0;
    for (const [key, value] of Object.entries(nsClaims)) {
      requireThat(typeof key === 'string' && key.length > 0, 'MDOC_ELEMENT');
      const item = embedded({
        digestID: id,
        random: random(32),
        elementIdentifier: key,
        elementValue: value,
      });
      items.push(item);
      digests.set(id++, sha256(encode(item)));
    }
    nameSpaces.set(ns, items);
    valueDigests.set(ns, digests);
  }
  const mso = {
    version: '1.0',
    digestAlgorithm: 'SHA-256',
    valueDigests,
    deviceKeyInfo: { deviceKey },
    docType,
    validityInfo: {
      signed: stamp(now()),
      validFrom: stamp(validFrom),
      validUntil: stamp(validUntil),
    },
  };
  return encode({
    nameSpaces,
    issuerAuth: sign1(encode(embedded(mso)), privateKey, { certificate }),
  });
}
export function issuerCertificate(credential) {
  const is = Buffer.isBuffer(credential) ? decode(credential) : credential,
    c = get(is, 'issuerAuth'),
    a = c instanceof Tag ? c.value : c;
  requireThat(Array.isArray(a), 'MDOC_ISSUER_AUTH');
  const cert = get(a[1], 33);
  return Array.isArray(cert) ? cert[0] : cert;
}
export function verifyIssuerSigned(
  credential,
  {
    issuerKey,
    certificate,
    docType = DOCTYPE,
    certificateProfile = 'ISO_MDOC',
    at = now(),
    allowPartial = true,
  } = {},
) {
  const ds = validateMdocCertificate(certificate, { at, certificateProfile });
  requireThat(equal(spki(ds.publicKey), spki(issuerKey)), 'MDOC_ISSUER_KEY');
  const is = Buffer.isBuffer(credential) ? decode(credential) : credential;
  requireThat(equal(issuerCertificate(is), certificate), 'MDOC_ISSUER_PIN');
  const auth = verify1(get(is, 'issuerAuth'), issuerKey),
    mso = unembed(decode(auth.payload));
  requireThat(
    get(mso, 'version') === '1.0' &&
      get(mso, 'digestAlgorithm') === 'SHA-256' &&
      get(mso, 'docType') === docType,
    'MDOC_MSO',
  );
  const validity = get(mso, 'validityInfo');
  requireThat(
    time(get(validity, 'signed')) <= at &&
      time(get(validity, 'signed')) <= time(get(validity, 'validUntil')) &&
      time(get(validity, 'validFrom')) < time(get(validity, 'validUntil')) &&
      time(get(validity, 'validFrom')) <= at &&
      time(get(validity, 'validUntil')) > at,
    'MDOC_EXPIRED',
  );
  const claims = new Map(),
    digests = get(mso, 'valueDigests');
  for (const [ns, items] of get(is, 'nameSpaces')) {
    requireThat(Array.isArray(items) && digests.has(ns), 'MDOC_NAMESPACE');
    const values = new Map(),
      ids = new Set();
    for (const item of items) {
      const data = unembed(item),
        id = get(data, 'digestID'),
        name = get(data, 'elementIdentifier'),
        salt = get(data, 'random');
      requireThat(
        Number.isSafeInteger(id) &&
          id >= 0 &&
          typeof name === 'string' &&
          !ids.has(id) &&
          !values.has(name) &&
          Buffer.isBuffer(salt) &&
          salt.length >= 16,
        'MDOC_ITEM',
      );
      requireThat(equal(get(digests, ns).get(id), sha256(encode(item))), 'MDOC_DIGEST');
      ids.add(id);
      values.set(name, get(data, 'elementValue'));
    }
    if (!allowPartial) requireThat(ids.size === get(digests, ns).size, 'MDOC_INCOMPLETE_ISSUANCE');
    claims.set(ns, values);
  }
  const holderJWK = coseJWK(get(get(mso, 'deviceKeyInfo'), 'deviceKey'));
  requireThat(
    !equal(spki(ds.publicKey), spki(createPublicKey({ key: holderJWK, format: 'jwk' }))),
    'MDOC_KEY_ROLE_COLLISION',
  );
  if (!allowPartial) requireThat(claims.size === digests.size, 'MDOC_INCOMPLETE_ISSUANCE');
  return { mso, claims, holderJWK, issuerSigned: is };
}
export function openidTranscript({ clientID, nonce, responseURI, origin, encryptionJWK }) {
  requireThat(typeof nonce === 'string' && nonce.length >= 16, 'MDOC_NONCE');
  const th = encryptionJWK ? unb64u(thumbprint(encryptionJWK)) : null;
  return [
    null,
    null,
    [
      origin ? 'OpenID4VPDCAPIHandover' : 'OpenID4VPHandover',
      sha256(encode(origin ? [origin, nonce, th] : [clientID, nonce, th, responseURI])),
    ],
  ];
}
export async function presentMdoc(
  credential,
  { holderKey, signer, sessionTranscript, requested, deviceClaims = new Map(), docType = DOCTYPE },
) {
  const is = decode(credential),
    names = new Map();
  for (const [ns, wanted] of requested) {
    const available = get(is, 'nameSpaces').get(ns);
    requireThat(Array.isArray(available), 'MDOC_NAMESPACE');
    const selected = available.filter((i) => wanted.includes(get(unembed(i), 'elementIdentifier')));
    requireThat(selected.length === new Set(wanted).size, 'MDOC_REQUESTED_CLAIM');
    names.set(ns, selected);
  }
  const deviceNameSpaces = embedded(deviceClaims),
    payload = encode(
      embedded(['DeviceAuthentication', sessionTranscript, docType, deviceNameSpaces]),
    ),
    p = prepareSign1(payload, { detached: true });
  const deviceSignature = signer
    ? p.finish(await signer(p.tbs))
    : sign1(payload, holderKey, { detached: true });
  return encode({
    version: '1.0',
    documents: [
      {
        docType,
        issuerSigned: { nameSpaces: names, issuerAuth: get(is, 'issuerAuth') },
        deviceSigned: { nameSpaces: deviceNameSpaces, deviceAuth: { deviceSignature } },
      },
    ],
    status: 0,
  });
}
export function verifyMdoc(
  response,
  {
    issuerKey,
    certificate,
    sessionTranscript,
    requested,
    docType = DOCTYPE,
    at = now(),
    expectedDeviceClaims = new Map(),
    certificateProfile = 'ISO_MDOC',
  },
) {
  const r = decode(response);
  requireThat(
    get(r, 'version') === '1.0' && get(r, 'status') === 0 && get(r, 'documents').length === 1,
    'MDOC_RESPONSE',
  );
  const doc = get(r, 'documents')[0];
  requireThat(get(doc, 'docType') === docType && !doc.has('errors'), 'MDOC_DOCUMENT');
  const signed = verifyIssuerSigned(get(doc, 'issuerSigned'), {
    issuerKey,
    certificate,
    docType,
    at,
    certificateProfile,
  });
  for (const [ns, names] of requested)
    for (const name of names) requireThat(signed.claims.get(ns)?.has(name), 'MDOC_CLAIM_MISSING');
  const device = get(doc, 'deviceSigned'),
    names = get(device, 'nameSpaces'),
    deviceClaims = unembed(names),
    auth = get(device, 'deviceAuth');
  requireThat(auth.size === 1 && auth.has('deviceSignature'), 'MDOC_DEVICE_AUTH');
  verify1(get(auth, 'deviceSignature'), createPublicKey({ key: signed.holderJWK, format: 'jwk' }), {
    detached: encode(embedded(['DeviceAuthentication', sessionTranscript, docType, names])),
  });
  for (const [ns, values] of expectedDeviceClaims)
    for (const [name, value] of values)
      requireThat(
        equal(encode(deviceClaims.get(ns)?.get(name)), encode(value)),
        'MDOC_DEVICE_CLAIM',
      );
  return { ...signed, deviceClaims };
}

export function annexCTranscript(encryptionInfo, origin) {
  requireThat(new URL(origin).origin === origin && origin.startsWith('https://'), 'DCAPI_ORIGIN');
  return [null, null, ['dcapi', sha256(encode([encryptionInfo, origin]))]];
}
export function annexCRequest({
  origin,
  requested,
  readerKey,
  readerCertificate,
  docType = DOCTYPE,
  activationHash,
  displayText,
}) {
  const keys = generate('ec'),
    info = b64u(
      encode([
        'dcapi',
        { nonce: random(16), recipientPublicKey: coseKey(publicJWK(keys.publicKey)) },
      ]),
    ),
    transcript = annexCTranscript(info, origin),
    items = embedded({
      docType,
      ...(activationHash
        ? {
            requestInfo: {
              'org.certconcord.rra.1': {
                activation_hash: activationHash,
                display_text: displayText,
              },
            },
          }
        : {}),
      nameSpaces: new Map(
        [...requested].map(([ns, names]) => [ns, new Map(names.map((n) => [n, false]))]),
      ),
    });
  const readerAuth = sign1(
    encode(embedded(['ReaderAuthentication', transcript, items])),
    readerKey,
    { certificate: readerCertificate, detached: true },
  );
  return {
    request: {
      deviceRequest: b64u(
        encode({ version: '1.0', docRequests: [{ itemsRequest: items, readerAuth }] }),
      ),
      encryptionInfo: info,
    },
    privateKey: keys.privateKey,
    sessionTranscript: transcript,
    origin,
    requested,
    docType,
    ...(activationHash ? { activationHash } : {}),
  };
}
const hpke = () =>
  new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
export async function annexCPresent(
  request,
  {
    origin,
    credential,
    holderKey,
    signer,
    readerPublicKey,
    readerCertificate,
    readerCertificateProfile = 'ISO_MDOC',
    deviceClaims = new Map(),
    approveTransaction,
  },
) {
  validateMdocCertificate(readerCertificate, {
    reader: true,
    certificateProfile: readerCertificateProfile,
  });
  const transcript = annexCTranscript(request.encryptionInfo, origin),
    info = decode(unb64u(request.encryptionInfo));
  requireThat(
    info.length === 2 && info[0] === 'dcapi' && get(info[1], 'nonce').length >= 16,
    'ANNEX_C_ENCRYPTION_INFO',
  );
  const dr = decode(unb64u(request.deviceRequest));
  requireThat(
    get(dr, 'version') === '1.0' && get(dr, 'docRequests').length === 1,
    'ANNEX_C_REQUEST',
  );
  const doc = get(dr, 'docRequests')[0],
    items = get(doc, 'itemsRequest'),
    req = unembed(items),
    auth = verify1(get(doc, 'readerAuth'), readerPublicKey, {
      detached: encode(embedded(['ReaderAuthentication', transcript, items])),
    });
  requireThat(equal(auth.certificate, readerCertificate), 'ANNEX_C_READER_PIN');
  const transaction = req.get('requestInfo')?.get('org.certconcord.rra.1');
  if (transaction) {
    const activationHash = get(transaction, 'activation_hash'),
      displayText = get(transaction, 'display_text');
    requireThat(
      Buffer.isBuffer(activationHash) &&
        activationHash.length === 64 &&
        typeof displayText === 'string' &&
        displayText.length > 0 &&
        typeof approveTransaction === 'function' &&
        (await approveTransaction({ activationHash, displayText })) === true,
      'ANNEX_C_TRANSACTION_CONSENT',
    );
    deviceClaims = new Map(deviceClaims);
    deviceClaims.set(NAMESPACE, new Map([['activation_hash', activationHash]]));
  }
  const requested = new Map(
    [...get(req, 'nameSpaces')].map(([ns, values]) => {
      requireThat(
        [...values.values()].every((v) => v === false),
        'MDOC_RETENTION_POLICY',
      );
      return [ns, [...values.keys()]];
    }),
  );
  const plaintext = await presentMdoc(credential, {
    holderKey,
    signer,
    sessionTranscript: transcript,
    requested,
    deviceClaims,
    docType: get(req, 'docType'),
  });
  const key = await webcrypto.subtle.importKey(
      'jwk',
      coseJWK(get(info[1], 'recipientPublicKey')),
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      [],
    ),
    ctx = await hpke().createSenderContext({ recipientPublicKey: key, info: encode(transcript) });
  const ciphertext = Buffer.from(await ctx.seal(plaintext, new Uint8Array()));
  return {
    response: b64u(encode(['dcapi', { enc: Buffer.from(ctx.enc), cipherText: ciphertext }])),
  };
}
export async function annexCVerify(response, session, issuer) {
  const v = decode(unb64u(response.response));
  requireThat(Array.isArray(v) && v.length === 2 && v[0] === 'dcapi', 'ANNEX_C_RESPONSE');
  const key = await webcrypto.subtle.importKey(
    'pkcs8',
    session.privateKey.export({ format: 'der', type: 'pkcs8' }),
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'],
  );
  const ctx = await hpke().createRecipientContext({
      recipientKey: key,
      enc: get(v[1], 'enc'),
      info: encode(session.sessionTranscript),
    }),
    plain = Buffer.from(await ctx.open(get(v[1], 'cipherText'), new Uint8Array()));
  return verifyMdoc(plain, {
    ...issuer,
    sessionTranscript: session.sessionTranscript,
    requested: session.requested,
    docType: session.docType ?? DOCTYPE,
    ...(session.activationHash
      ? {
          expectedDeviceClaims: new Map([
            [NAMESPACE, new Map([['activation_hash', session.activationHash]])],
          ]),
        }
      : {}),
  });
}

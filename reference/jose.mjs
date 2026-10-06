import * as crypto from 'node:crypto';
import { parseJSON } from './json.mjs';
import {
  ALG,
  requireThat,
  b64u,
  unb64u,
  sha256,
  sha512,
  random,
  now,
  spki,
  parseDER,
  seq,
  oid,
  bit,
  publicFromDER,
  equal,
  seal,
  open,
  D,
} from './core.mjs';
import { uint, vector } from './mtc.mjs';
export const joseAlgorithm = (key) =>
  ({ ec: 'ES256', ed25519: 'Ed25519', 'ml-dsa-65': 'ML-DSA-65', 'ml-dsa-87': 'ML-DSA-87' })[
    key.asymmetricKeyType
  ];
export function publicJWK(key) {
  if (key.asymmetricKeyType.startsWith('ml-dsa-'))
    return {
      kty: 'AKP',
      alg: joseAlgorithm(key),
      pub: b64u(parseDER(spki(key)).children[1].value.subarray(1)),
    };
  return key.export({ format: 'jwk' });
}
export function importPublicJWK(jwk) {
  requireThat(
    jwk &&
      typeof jwk === 'object' &&
      !['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k', 'priv'].some((k) => Object.hasOwn(jwk, k)),
    'PUBLIC_JWK_REQUIRED',
  );
  if (jwk.kty === 'AKP') {
    const algorithm = jwk.alg?.toLowerCase(),
      pub = unb64u(jwk.pub);
    requireThat(
      ['ml-dsa-65', 'ml-dsa-87'].includes(algorithm) &&
        pub.length === { 'ml-dsa-65': 1952, 'ml-dsa-87': 2592 }[algorithm],
      'AKP_PARAMETERS',
    );
    return publicFromDER(seq(seq(oid(ALG[algorithm].oid)), bit(pub)));
  }
  requireThat(
    (jwk.kty === 'EC' && jwk.crv === 'P-256') || (jwk.kty === 'OKP' && jwk.crv === 'Ed25519'),
    'JWK_ALGORITHM',
  );
  return crypto.createPublicKey({ key: jwk, format: 'jwk' });
}
export function thumbprint(jwk) {
  importPublicJWK(jwk);
  const keys =
    jwk.kty === 'AKP'
      ? ['alg', 'kty', 'pub']
      : jwk.kty === 'EC'
        ? ['crv', 'kty', 'x', 'y']
        : ['crv', 'kty', 'x'];
  return b64u(
    sha256(Buffer.from(JSON.stringify(Object.fromEntries(keys.map((k) => [k, jwk[k]]))))),
  );
}
function signBytes(data, key) {
  const alg = joseAlgorithm(key);
  requireThat(alg, 'JOSE_ALGORITHM');
  return crypto.sign(
    alg === 'ES256' ? 'sha256' : null,
    data,
    alg === 'ES256' ? { key, dsaEncoding: 'ieee-p1363' } : key,
  );
}
function verifyBytes(data, sig, key) {
  const alg = joseAlgorithm(key);
  return crypto.verify(
    alg === 'ES256' ? 'sha256' : null,
    data,
    alg === 'ES256' ? { key, dsaEncoding: 'ieee-p1363' } : key,
    sig,
  );
}
export function signJWS(payload, key, header = {}, { detached = false, unencoded = false } = {}) {
  payload = Buffer.isBuffer(payload) ? payload : Buffer.from(JSON.stringify(payload));
  const h = { ...header, alg: joseAlgorithm(key) };
  if (unencoded) {
    h.b64 = false;
    h.crit = [...new Set([...(h.crit ?? []), 'b64'])];
    requireThat(detached, 'UNENCODED_REQUIRES_DETACHED');
  }
  const protectedHeader = b64u(Buffer.from(JSON.stringify(h))),
    encoded = unencoded ? payload : Buffer.from(b64u(payload)),
    tbs = Buffer.concat([Buffer.from(protectedHeader + '.'), encoded]);
  return (
    protectedHeader +
    '.' +
    (detached ? '' : encoded.toString('ascii')) +
    '.' +
    b64u(signBytes(tbs, key))
  );
}
export function decodeJWS(token) {
  requireThat(typeof token === 'string' && token.length <= 4 * 1024 * 1024, 'JWS_SIZE');
  const parts = token.split('.');
  requireThat(parts.length === 3, 'JWS_STRUCTURE');
  return {
    parts,
    header: parseJSON(unb64u(parts[0]).toString('utf8'), { maxBytes: 65536 }),
    payload: parts[1] ? unb64u(parts[1]) : Buffer.alloc(0),
  };
}
export function verifyJWS(
  token,
  key,
  { typ, detached, critical = [], allowedAlgorithms = [joseAlgorithm(key)] } = {},
) {
  const { parts, header, payload } = decodeJWS(token);
  requireThat(
    allowedAlgorithms.includes(header.alg) && header.alg === joseAlgorithm(key),
    'JWS_ALGORITHM',
  );
  if (typ) requireThat(header.typ === typ, 'JWS_TYPE');
  if (header.crit !== undefined) {
    requireThat(
      Array.isArray(header.crit) &&
        header.crit.length > 0 &&
        new Set(header.crit).size === header.crit.length &&
        header.crit.every((n) => ['b64', ...critical].includes(n) && Object.hasOwn(header, n)),
      'JWS_CRITICAL',
    );
  }
  if (header.b64 === false)
    requireThat(
      header.crit?.includes('b64') && detached !== undefined && !parts[1],
      'JWS_UNENCODED',
    );
  else requireThat(header.b64 === undefined || header.b64 === true, 'JWS_B64');
  if (detached !== undefined) requireThat(!parts[1], 'JWS_DETACHED_CONFLICT');
  const content = detached ?? payload,
    tbs = Buffer.concat([
      Buffer.from(parts[0] + '.'),
      header.b64 === false
        ? content
        : Buffer.from(detached !== undefined ? b64u(content) : parts[1]),
    ]);
  requireThat(verifyBytes(tbs, unb64u(parts[2]), key), 'JWS_SIGNATURE');
  return { header, payload: content };
}
export function verifyJWT(
  token,
  key,
  { typ, audience, issuer, at = now(), maxAge, critical } = {},
) {
  const r = verifyJWS(token, key, { typ, critical }),
    claims = parseJSON(r.payload.toString('utf8'));
  if (audience !== undefined)
    requireThat(
      claims.aud === audience || (Array.isArray(claims.aud) && claims.aud.includes(audience)),
      'JWT_AUDIENCE',
    );
  if (issuer !== undefined) requireThat(claims.iss === issuer, 'JWT_ISSUER');
  if (claims.exp !== undefined)
    requireThat(Number.isSafeInteger(claims.exp) && claims.exp > at, 'JWT_EXPIRED');
  if (claims.nbf !== undefined)
    requireThat(Number.isSafeInteger(claims.nbf) && claims.nbf <= at, 'JWT_NOT_YET_VALID');
  if (maxAge !== undefined)
    requireThat(
      Number.isSafeInteger(claims.iat) && claims.iat <= at + 30 && claims.iat >= at - maxAge,
      'JWT_AGE',
    );
  return { ...r, claims };
}
const certconcordCritical = ['certconcord_ctx', 'certconcord_sim', 'certconcord_policy', 'certconcord_cert', 'sigT'];
export function signJAdES(
  payload,
  key,
  { certificate, context, simHash, policyHash, detached = false, unencoded = false },
) {
  return signJWS(
    payload,
    key,
    {
      typ: 'JOSE',
      x5c: [certificate.toString('base64')],
      'x5t#S256': b64u(sha256(certificate)),
      certconcord_ctx: b64u(D('SignatureContext', context)),
      certconcord_sim: b64u(simHash),
      certconcord_policy: b64u(policyHash),
      certconcord_cert: b64u(sha512(certificate)),
      sigT: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
      crit: certconcordCritical,
    },
    { detached, unencoded },
  );
}
export function verifyJAdES(
  token,
  publicKey,
  { certificate, context, simHash, policyHash, detached },
) {
  const r = verifyJWS(token, publicKey, { typ: 'JOSE', detached, critical: certconcordCritical }),
    h = r.header;
  requireThat(
    certconcordCritical.every((n) => h.crit?.includes(n)),
    'JADES_CRIT',
  );
  requireThat(
    h.x5c?.length === 1 &&
      h.x5c[0] === certificate.toString('base64') &&
      h['x5t#S256'] === b64u(sha256(certificate)) &&
      h.certconcord_cert === b64u(sha512(certificate)) &&
      h.certconcord_ctx === b64u(D('SignatureContext', context)) &&
      h.certconcord_sim === b64u(simHash) &&
      h.certconcord_policy === b64u(policyHash),
    'JADES_BINDING',
  );
  return r;
}

export function issueSDJWT(
  {
    claims,
    disclose = Object.keys(claims),
    issuer,
    holderJWK,
    vct,
    expiresAt = now() + 3600,
    status,
  },
  key,
  { x5c } = {},
) {
  importPublicJWK(holderJWK);
  requireThat(
    new Set(disclose).size === disclose.length &&
      disclose.every(
        (k) =>
          Object.hasOwn(claims, k) &&
          !['_sd', '_sd_alg', 'cnf', 'iss', 'iat', 'exp', 'vct', 'status'].includes(k),
      ),
    'SD_DISCLOSURE_NAMES',
  );
  const disclosures = disclose.map((k) =>
      b64u(Buffer.from(JSON.stringify([b64u(random(16)), k, claims[k]]))),
    ),
    payload = {
      ...Object.fromEntries(Object.entries(claims).filter(([k]) => !disclose.includes(k))),
      iss: issuer,
      iat: now(),
      exp: expiresAt,
      vct,
      cnf: { jwk: holderJWK },
      _sd_alg: 'sha-256',
      _sd: disclosures.map((d) => b64u(sha256(Buffer.from(d)))).sort(),
    };
  if (status) payload.status = status;
  return {
    credential:
      signJWS(payload, key, { typ: 'dc+sd-jwt', ...(x5c ? { x5c } : {}) }) +
      '~' +
      disclosures.join('~') +
      '~',
    disclosures,
  };
}
export function verifySDJWT(
  credential,
  issuerKey,
  {
    issuer,
    vct,
    at = now(),
    requireKeyBinding = false,
    audience,
    nonce,
    maxAge = 120,
    transactionData,
  } = {},
) {
  requireThat(typeof credential === 'string' && credential.length <= 2 * 1024 * 1024, 'SD_SIZE');
  const parts = credential.split('~'),
    issuerJWT = parts.shift(),
    kb = parts.pop();
  requireThat(kb !== undefined, 'SD_SERIALIZATION');
  const r = verifyJWT(issuerJWT, issuerKey, { typ: 'dc+sd-jwt', issuer, at });
  requireThat(
    r.claims._sd_alg === 'sha-256' && r.claims.cnf?.jwk && (!vct || r.claims.vct === vct),
    'SD_FORMAT',
  );
  importPublicJWK(r.claims.cnf.jwk);
  const pending = new Map();
  for (const d of parts) {
    const h = b64u(sha256(Buffer.from(d))),
      v = parseJSON(unb64u(d).toString('utf8'));
    requireThat(
      !pending.has(h) && Array.isArray(v) && [2, 3].includes(v.length) && typeof v[0] === 'string',
      'SD_DISCLOSURE',
    );
    pending.set(h, v);
  }
  const used = new Set(),
    references = new Set();
  function resolve(value, depth = 0) {
    requireThat(depth < 32, 'SD_DEPTH');
    if (value === null || typeof value !== 'object') return value;
    if (Array.isArray(value)) {
      const a = [];
      for (const item of value) {
        if (item && Object.hasOwn(item, '...')) {
          requireThat(Object.keys(item).length === 1, 'SD_ARRAY_PLACEHOLDER');
          const d = lookup(item['...'], 2);
          if (d) a.push(resolve(d[1], depth + 1));
        } else a.push(resolve(item, depth + 1));
      }
      return a;
    }
    const out = Object.create(null);
    for (const [k, v] of Object.entries(value))
      if (k !== '_sd' && k !== '_sd_alg') out[k] = resolve(v, depth + 1);
    if (value._sd) {
      requireThat(Array.isArray(value._sd), 'SD_DIGESTS');
      for (const h of value._sd) {
        const d = lookup(h, 3);
        if (d) {
          requireThat(
            typeof d[1] === 'string' &&
              !['_sd', '...', '_sd_alg'].includes(d[1]) &&
              !Object.hasOwn(out, d[1]),
            'SD_OVERWRITE',
          );
          out[d[1]] = resolve(d[2], depth + 1);
        }
      }
    }
    return out;
  }
  function lookup(h, n) {
    requireThat(typeof h === 'string' && !references.has(h), 'SD_DUPLICATE_DIGEST');
    references.add(h);
    const d = pending.get(h);
    if (d) {
      requireThat(d.length === n, 'SD_DISCLOSURE_TYPE');
      used.add(h);
    }
    return d;
  }
  const claims = resolve(r.claims);
  requireThat(used.size === pending.size, 'SD_UNREFERENCED_DISCLOSURE');
  if (requireKeyBinding || kb) {
    requireThat(kb && audience && nonce, 'KEY_BINDING_REQUIRED');
    const base = [issuerJWT, ...parts, ''].join('~'),
      k = verifyJWT(kb, importPublicJWK(r.claims.cnf.jwk), { typ: 'kb+jwt', audience, at, maxAge });
    requireThat(
      k.claims.nonce === nonce && k.claims.sd_hash === b64u(sha256(Buffer.from(base))),
      'SD_KEY_BINDING',
    );
    if (transactionData) {
      const hashes = transactionData.map((t) => b64u(sha256(Buffer.from(t))));
      requireThat(
        k.claims.transaction_data_hashes_alg === 'sha-256' &&
          JSON.stringify(k.claims.transaction_data_hashes) === JSON.stringify(hashes),
        'SD_TRANSACTION_BINDING',
      );
    }
  }
  return { claims, header: r.header, holderJWK: r.claims.cnf.jwk };
}
export function presentSDJWT(
  credential,
  holderKey,
  { audience, nonce, claimNames, transactionData },
) {
  const p = credential.split('~');
  requireThat(p.pop() === '', 'SD_ISSUANCE_FORM');
  const signed = p.shift(),
    selected = claimNames
      ? p.filter((d) => {
          const a = parseJSON(unb64u(d).toString('utf8'));
          return a.length === 3 && claimNames.includes(a[1]);
        })
      : p;
  const base = [signed, ...selected, ''].join('~');
  return (
    base +
    signJWS(
      {
        iat: now(),
        aud: audience,
        nonce,
        sd_hash: b64u(sha256(Buffer.from(base))),
        ...(transactionData
          ? {
              transaction_data_hashes_alg: 'sha-256',
              transaction_data_hashes: transactionData.map((t) => b64u(sha256(Buffer.from(t)))),
            }
          : {}),
      },
      holderKey,
      { typ: 'kb+jwt' },
    )
  );
}

export function dpopProof(privateKey, { method, url, accessToken, nonce, jti = b64u(random()) }) {
  const u = new URL(url);
  u.search = '';
  u.hash = '';
  return signJWS(
    {
      jti,
      htm: method.toUpperCase(),
      htu: u.href,
      iat: now(),
      ...(accessToken ? { ath: b64u(sha256(Buffer.from(accessToken))) } : {}),
      ...(nonce ? { nonce } : {}),
    },
    privateKey,
    { typ: 'dpop+jwt', jwk: publicJWK(crypto.createPublicKey(privateKey)) },
  );
}
export function verifyDPoP(
  token,
  { method, url, accessToken, nonce, expectedThumbprint, journal },
) {
  const h = decodeJWS(token).header,
    key = importPublicJWK(h.jwk),
    r = verifyJWT(token, key, { typ: 'dpop+jwt', maxAge: 120 }),
    c = r.claims,
    u = new URL(url);
  u.search = '';
  u.hash = '';
  requireThat(
    c.htm === method.toUpperCase() &&
      c.htu === u.href &&
      typeof c.jti === 'string' &&
      c.jti.length >= 16 &&
      (!nonce || c.nonce === nonce),
    'DPOP_BINDING',
  );
  if (accessToken) requireThat(c.ath === b64u(sha256(Buffer.from(accessToken))), 'DPOP_ATH');
  const jkt = thumbprint(h.jwk);
  if (expectedThumbprint) requireThat(jkt === expectedThumbprint, 'DPOP_KEY');
  requireThat(!journal.get('dpop', jkt + ':' + c.jti), 'DPOP_REPLAY');
  journal.put('dpop', jkt + ':' + c.jti, { expiresAt: now() + 120 });
  return jkt;
}
function concatKDF(shared, enc, apu, apv, length) {
  return sha256(
    Buffer.concat([
      uint(1, 4),
      shared,
      vector(Buffer.from(enc), 4),
      vector(apu, 4),
      vector(apv, 4),
      uint(length * 8, 4),
    ]),
  ).subarray(0, length);
}
export function encryptJWE(
  value,
  recipientJWK,
  { enc = 'A256GCM', apu = random(16), apv = Buffer.alloc(0), kid } = {},
) {
  requireThat(
    ['A128GCM', 'A256GCM'].includes(enc) &&
      recipientJWK.kty === 'EC' &&
      recipientJWK.crv === 'P-256',
    'JWE_ALGORITHM',
  );
  const recipient = importPublicJWK(recipientJWK),
    ephemeral = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }),
    shared = crypto.diffieHellman({ privateKey: ephemeral.privateKey, publicKey: recipient });
  const header = {
      alg: 'ECDH-ES',
      enc,
      epk: publicJWK(ephemeral.publicKey),
      apu: b64u(apu),
      apv: b64u(apv),
      ...(kid ? { kid } : {}),
    },
    protectedHeader = b64u(Buffer.from(JSON.stringify(header))),
    k = concatKDF(shared, enc, apu, apv, enc === 'A128GCM' ? 16 : 32);
  try {
    const e = seal(k, Buffer.from(JSON.stringify(value)), Buffer.from(protectedHeader));
    return [protectedHeader, '', b64u(e.nonce), b64u(e.ciphertext), b64u(e.tag)].join('.');
  } finally {
    k.fill(0);
    shared.fill(0);
  }
}
export function decryptJWE(token, privateKey, { expectedAPV, kid } = {}) {
  requireThat(typeof token === 'string' && token.length <= 4 * 1024 * 1024, 'JWE_SIZE');
  const a = token.split('.');
  requireThat(a.length === 5 && !a[1], 'JWE_STRUCTURE');
  const h = parseJSON(unb64u(a[0]).toString('utf8'));
  requireThat(
    h.alg === 'ECDH-ES' &&
      ['A128GCM', 'A256GCM'].includes(h.enc) &&
      h.epk?.crv === 'P-256' &&
      !h.zip &&
      !h.crit &&
      (!kid || h.kid === kid),
    'JWE_HEADER',
  );
  const apu = unb64u(h.apu ?? ''),
    apv = unb64u(h.apv ?? '');
  if (expectedAPV) requireThat(equal(apv, expectedAPV), 'JWE_APV');
  const shared = crypto.diffieHellman({ privateKey, publicKey: importPublicJWK(h.epk) }),
    k = concatKDF(shared, h.enc, apu, apv, h.enc === 'A128GCM' ? 16 : 32);
  try {
    return parseJSON(
      open(
        k,
        { nonce: unb64u(a[2]), ciphertext: unb64u(a[3]), tag: unb64u(a[4]) },
        Buffer.from(a[0]),
      ).toString('utf8'),
    );
  } finally {
    k.fill(0);
    shared.fill(0);
  }
}

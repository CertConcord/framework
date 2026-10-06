import {
  seq,
  oid,
  octet,
  integer,
  der,
  parseDER,
  intValue,
  oidText,
  requireThat,
  random,
  sha256,
  sha512,
  equal,
  now,
} from './core.mjs';
import { algID, OID, generalizedTime, signCMS, verifyCMS, attribute } from './pki.mjs';
import { verifyExternalCMS } from './external-cms.mjs';
import { readBody } from './transport.mjs';
const hashes = { [OID.sha256]: sha256, [OID.sha512]: sha512 };
export function timestampRequest(
  imprint,
  { hashOID = OID.sha512, policy, nonce = BigInt('0x' + random(16).toString('hex')) } = {},
) {
  requireThat(
    hashes[hashOID] && imprint.length === hashes[hashOID](Buffer.alloc(0)).length,
    'TSA_IMPRINT',
  );
  return {
    der: seq(
      integer(1),
      seq(algID(hashOID), octet(imprint)),
      ...(policy ? [oid(policy)] : []),
      integer(nonce),
      der(1, Buffer.from([255])),
    ),
    imprint,
    hashOID,
    policy,
    nonce,
  };
}
export function parseTimestampRequest(raw) {
  const a = parseDER(raw).children;
  requireThat(a?.length >= 2 && intValue(a[0]) === 1n, 'TSA_VERSION');
  const hashOID = oidText(a[1].children[0].children[0]),
    imprint = a[1].children[1].value;
  requireThat(
    hashes[hashOID] &&
      equal(a[1].children[0].raw, algID(hashOID)) &&
      imprint.length === hashes[hashOID](Buffer.alloc(0)).length,
    'TSA_HASH',
  );
  let policy,
    nonce,
    certReq = false;
  for (const n of a.slice(2)) {
    if (n.tag === 6) {
      requireThat(!policy, 'TSA_DUPLICATE_POLICY');
      policy = oidText(n);
    } else if (n.tag === 2) {
      requireThat(nonce === undefined, 'TSA_DUPLICATE_NONCE');
      nonce = intValue(n);
    } else if (n.tag === 1) {
      requireThat(equal(n.raw, Buffer.from('0101ff', 'hex')), 'TSA_CERT_REQ');
      certReq = true;
    } else throw Error('TSA_UNSUPPORTED_EXTENSION');
  }
  return { hashOID, imprint, policy, nonce, certReq };
}
export class TimestampAuthority {
  constructor({ certificate, privateKey, policy, journal, clock = now, accuracySeconds = 1 }) {
    requireThat(Number.isSafeInteger(accuracySeconds) && accuracySeconds >= 0, 'TST_ACCURACY');
    Object.assign(this, { certificate, privateKey, policy, journal, clock, accuracySeconds });
  }
  issue(requestDER) {
    const r = parseTimestampRequest(requestDER);
    requireThat(!r.policy || r.policy === this.policy, 'unacceptedPolicy');
    const serial = BigInt('0x' + random(20).toString('hex')),
      genTime = this.clock();
    this.journal.put('tsa-serial', serial.toString(), { genTime });
    const info = seq(
      integer(1),
      oid(this.policy),
      seq(algID(r.hashOID), octet(r.imprint)),
      integer(serial),
      generalizedTime(genTime),
      seq(integer(this.accuracySeconds)),
      ...(r.nonce !== undefined ? [integer(r.nonce)] : []),
    );
    const token = signCMS(
      { content: info, contentType: OID.tstInfo, certificate: this.certificate },
      this.privateKey,
    );
    return seq(seq(integer(0)), token);
  }
}
export function tokenFromResponse(response) {
  const a = parseDER(response).children;
  requireThat(a?.length === 2 && [0n, 1n].includes(intValue(a[0].children[0])), 'TSA_REJECTED');
  return a[1].raw;
}
export function parseTSTInfo(raw) {
  const a = parseDER(raw).children;
  requireThat(a?.length >= 5 && intValue(a[0]) === 1n, 'TST_VERSION');
  const policy = oidText(a[1]),
    hashOID = oidText(a[2].children[0].children[0]),
    imprint = a[2].children[1].value;
  requireThat(
    hashes[hashOID] &&
      (equal(a[2].children[0].raw, algID(hashOID)) ||
        equal(a[2].children[0].raw, seq(oid(hashOID), der(5, Buffer.alloc(0))))) &&
      imprint.length === hashes[hashOID](Buffer.alloc(0)).length,
    'TST_HASH',
  );
  const time = a[4].value.toString('ascii'),
    match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z$/.exec(time);
  requireThat(a[4].tag === 24 && match, 'TST_TIME');
  const genTime =
    Date.parse(
      `${match[1]}-${match[2]}-${match[3]}T${match[4]}:${match[5]}:${match[6]}${match[7] ?? ''}Z`,
    ) / 1000;
  requireThat(Number.isFinite(genTime), 'TST_TIME');
  let nonce, accuracy;
  const optionalTags = new Set();
  for (const n of a.slice(5)) {
    requireThat(!optionalTags.has(n.tag), 'TST_DUPLICATE_FIELD');
    optionalTags.add(n.tag);
    if (n.tag === 48) {
      accuracy = 0;
      let previous = -1;
      for (const t of n.children) {
        const rank = [2, 0x80, 0x81].indexOf(t.tag);
        requireThat(rank > previous, 'TST_ACCURACY');
        previous = rank;
        if (t.tag === 2) {
          const seconds = Number(intValue(t));
          requireThat(Number.isSafeInteger(seconds) && seconds >= 0, 'TST_ACCURACY');
          accuracy += seconds;
        } else if ([0x80, 0x81].includes(t.tag)) {
          const v = intValue({ tag: 2, value: t.value });
          requireThat(v >= 1n && v <= 999n, 'TST_ACCURACY');
          accuracy += Number(v) / (t.tag === 0x80 ? 1000 : 1000000);
        } else throw Error('TST_ACCURACY');
      }
    } else if (n.tag === 2) nonce = intValue(n);
    else if (n.tag === 1) requireThat(equal(n.raw, Buffer.from('0101ff', 'hex')), 'TST_ORDERING');
    else if (n.tag === 0xa0) {
    } else throw Error('TST_UNSUPPORTED_EXTENSION');
  }
  return {
    policy,
    hashOID,
    imprint,
    serial: intValue(a[3]),
    genTime,
    accuracy,
    nonce,
    poeUpperBound: accuracy === undefined ? undefined : genTime + accuracy,
  };
}
export function verifyTimestampToken(
  token,
  {
    imprint,
    hashOID = OID.sha512,
    nonce,
    policy,
    certificate,
    issuerKey,
    at = now(),
    maxFutureSkew = 30,
    revokedAt = Infinity,
    signatureProfile = 'CERTCONCORD-PQ',
  },
) {
  if (signatureProfile === 'EXTERNAL-RFC3161')
    return verifyExternalTimestampToken(token, {
      imprint,
      hashOID,
      nonce,
      policy,
      certificate,
      issuerKey,
      at,
      maxFutureSkew,
      revokedAt,
    });
  requireThat(signatureProfile === 'CERTCONCORD-PQ', 'TSA_SIGNATURE_PROFILE');
  const initial = verifyCMS(token, {
      expectedCertificate: certificate,
      expectedContentType: OID.tstInfo,
    }),
    info = parseTSTInfo(initial.content);
  requireThat(
    info.hashOID === hashOID &&
      equal(info.imprint, imprint) &&
      (nonce === undefined || info.nonce === nonce) &&
      (!policy || info.policy === policy),
    'TSA_REQUEST_BINDING',
  );
  requireThat(
    info.genTime <= at + maxFutureSkew && info.genTime < revokedAt,
    'TSA_TIME_OR_REVOCATION',
  );
  requireThat(certificate && issuerKey, 'TSA_TRUST_REQUIRED');
  verifyCMS(token, {
    expectedCertificate: certificate,
    expectedContentType: OID.tstInfo,
    issuerKey,
    at: info.genTime,
    profileID: 'CERTCONCORD-TSA-v1',
  });
  return info;
}
export async function requestTimestamp(
  imprint,
  { endpoint, hashOID = OID.sha512, policy, fetchImpl = fetch, authorization, ...trust },
) {
  const request = timestampRequest(imprint, { hashOID, policy });
  requireThat(new URL(endpoint).protocol === 'https:', 'TSA_HTTPS_REQUIRED');
  const response = await fetchImpl(endpoint, {
    method: 'POST',
    headers: {
      'content-type': 'application/timestamp-query',
      accept: 'application/timestamp-reply',
      ...(authorization ? { authorization } : {}),
    },
    body: request.der,
    redirect: 'error',
    signal: AbortSignal.timeout(15000),
  });
  requireThat(
    response.ok &&
      response.headers.get('content-type')?.split(';')[0] === 'application/timestamp-reply',
    'TSA_HTTP',
  );
  const raw = await readBody(response.body, { maxBytes: 1048576 });
  requireThat(raw.length <= 1048576, 'TSA_RESPONSE_SIZE');
  const token = tokenFromResponse(raw);
  verifyTimestampToken(token, { ...trust, ...request });
  return token;
}
export function cmsTimestampAttribute(token) {
  return attribute(OID.timestamp, token);
}
export function verifyExternalTimestampToken(
  token,
  {
    imprint,
    hashOID = OID.sha512,
    nonce,
    policy,
    certificate,
    issuerKey,
    at = now(),
    maxFutureSkew = 30,
    revokedAt = Infinity,
    signatureProfile = 'CERTCONCORD-PQ',
  },
) {
  const result = verifyExternalCMS(token, { certificate, expectedContentType: OID.tstInfo }),
    info = parseTSTInfo(result.content),
    cert = result.x509;
  requireThat(
    info.hashOID === hashOID &&
      equal(info.imprint, imprint) &&
      (nonce === undefined || info.nonce === nonce) &&
      (!policy || info.policy === policy),
    'TSA_REQUEST_BINDING',
  );
  requireThat(
    info.genTime <= at + maxFutureSkew &&
      info.genTime < revokedAt &&
      info.genTime * 1000 >= Date.parse(cert.validFrom) &&
      info.genTime * 1000 < Date.parse(cert.validTo),
    'TSA_TIME_OR_REVOCATION',
  );
  requireThat(
    !cert.ca &&
      cert.keyUsage?.length === 1 &&
      cert.keyUsage[0] === '1.3.6.1.5.5.7.3.8' &&
      cert.verify(issuerKey),
    'TSA_TRUST_OR_EKU',
  );
  const t = parseDER(certificate).children[0].children,
    extensions = t.find((n) => n.tag === 0xa3)?.children[0].children,
    eku = extensions?.find((n) => oidText(n.children[0]) === '2.5.29.37');
  requireThat(
    eku?.children.length === 3 && equal(eku.children[1].raw, Buffer.from('0101ff', 'hex')),
    'TSA_EKU_NOT_CRITICAL',
  );
  return info;
}

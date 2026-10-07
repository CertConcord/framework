import { createHash } from 'node:crypto';
import { statusResult, evaluateStatusEvidence } from './status-result.mjs';
import {
  seq,
  set,
  oid,
  octet,
  bit,
  integer,
  der,
  parseDER,
  oidText,
  intValue,
  sha256,
  sign,
  verify,
  equal,
  requireThat,
  now,
  spki,
  random,
  ALG,
} from './core.mjs';
import { algID, generalizedTime, extension, parseCertificate } from './pki.mjs';
const nonceOID = '1.3.6.1.5.5.7.48.1.2',
  basicOID = '1.3.6.1.5.5.7.48.1.1';
function parseTime(n) {
  const s = n.value.toString('ascii');
  requireThat(n.tag === 24 && /^\d{14}Z$/.test(s), 'STATUS_TIME');
  const t =
    Date.parse(
      `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}T${s.slice(8, 10)}:${s.slice(10, 12)}:${s.slice(12, 14)}Z`,
    ) / 1000;
  requireThat(Number.isSafeInteger(t), 'STATUS_TIME');
  return t;
}
function extMap(node) {
  const out = new Map();
  for (const e of node.children) {
    requireThat([2, 3].includes(e.children.length), 'STATUS_EXTENSION');
    const id = oidText(e.children[0]);
    requireThat(!out.has(id), 'STATUS_DUPLICATE_EXTENSION');
    const critical = e.children.length === 3;
    requireThat(
      !critical || ['2.5.29.20', '2.5.29.21', '2.5.29.24', nonceOID].includes(id),
      'STATUS_CRITICAL_EXTENSION',
    );
    out.set(id, e.children.at(-1).value);
  }
  return out;
}
export function issueCRL({
  issuer,
  privateKey,
  number,
  entries = [],
  thisUpdate = now(),
  nextUpdate = thisUpdate + 300,
}) {
  requireThat(nextUpdate > thisUpdate && nextUpdate - thisUpdate <= 86400, 'CRL_INTERVAL');
  const alg = algID(privateKey.asymmetricKeyType),
    seen = new Set();
  const revoked = entries.map((e) => {
    const id = BigInt(e.serial).toString();
    requireThat(
      !seen.has(id) &&
        Number.isInteger(e.reason) &&
        e.reason >= 0 &&
        e.reason <= 10 &&
        e.reason !== 7,
      'CRL_ENTRY',
    );
    seen.add(id);
    const extensions = [extension('2.5.29.21', der(10, Buffer.from([e.reason])))];
    if (e.invalidityDate !== undefined)
      extensions.push(extension('2.5.29.24', generalizedTime(e.invalidityDate)));
    return seq(integer(e.serial), generalizedTime(e.revokedAt), seq(...extensions));
  });
  const tbs = seq(
    integer(1),
    alg,
    issuer,
    generalizedTime(thisUpdate),
    generalizedTime(nextUpdate),
    ...(revoked.length ? [seq(...revoked)] : []),
    der(0xa0, seq(extension('2.5.29.20', integer(number)))),
  );
  return seq(tbs, alg, bit(sign(tbs, privateKey)));
}
export function verifyCRL(
  raw, options,
) {
  if (raw === undefined || raw === null) return statusResult('UNKNOWN', 'CRL_MISSING');
  return evaluateStatusEvidence(() => inspectCRL(raw, options), 'CRL');
}
function inspectCRL(
  raw,
  { issuer, publicKey, at = now(), knowledgeTime = at, serial, minNumber = 0n },
) {
  const root = parseDER(raw),
    [tbs, algorithm, signature] = root.children;
  requireThat(
    equal(algorithm.raw, algID(publicKey.asymmetricKeyType)) &&
      signature.tag === 3 &&
      signature.value[0] === 0 &&
      verify(tbs.raw, signature.value.subarray(1), publicKey),
    'CRL_SIGNATURE',
  );
  const a = tbs.children;
  requireThat(
    intValue(a[0]) === 1n && equal(a[1].raw, algorithm.raw) && equal(a[2].raw, issuer),
    'CRL_SCOPE',
  );
  const thisUpdate = parseTime(a[3]),
    nextUpdate = parseTime(a[4]);
  requireThat(nextUpdate > thisUpdate, 'CRL_INTERVAL');
  const extensions = extMap(a.at(-1).children[0]),
    number = intValue(parseDER(extensions.get('2.5.29.20')));
  requireThat(number >= BigInt(minNumber), 'CRL_ROLLBACK');
  const records = a.length === 7 ? a[5].children : [];
  let result = 'GOOD';
  const seen = new Set();
  for (const record of records) {
    const [sn, when, ex] = record.children,
      s = intValue(sn),
      id = s.toString();
    requireThat(!seen.has(id), 'CRL_DUPLICATE_SERIAL');
    seen.add(id);
    const ext = ex ? extMap(ex) : new Map(),
      revokedAt = parseTime(when),
      invalidityDate = ext.has('2.5.29.24') ? parseTime(parseDER(ext.get('2.5.29.24'))) : revokedAt,
      reason = ext.has('2.5.29.21') ? parseDER(ext.get('2.5.29.21')).value[0] : 0;
    requireThat(reason !== 8, 'DELTA_CRL_UNSUPPORTED');
    if (s === BigInt(serial) && Math.min(revokedAt, invalidityDate) <= at) result = 'REVOKED';
  }
  if (thisUpdate > knowledgeTime) result = 'NOT_YET_KNOWN';
  else if (result !== 'REVOKED' && nextUpdate <= knowledgeTime) result = 'STALE';
  return statusResult(result, result === 'GOOD' ? undefined : 'CRL_' + result,
    { number, thisUpdate, nextUpdate, scope: 'COMPLETE_ISSUER_CRL' });
}
export function ocspCertID({ issuer, issuerPublicKey, serial }) {
  const rawKey = parseDER(spki(issuerPublicKey)).children[1].value.subarray(1);
  return seq(
    algID('2.16.840.1.101.3.4.2.1'),
    octet(sha256(issuer)),
    octet(sha256(rawKey)),
    integer(serial),
  );
}
export function ocspRequest(options, { nonce = random() } = {}) {
  const certID = ocspCertID(options);
  requireThat(nonce.length >= 16 && nonce.length <= 32, 'OCSP_NONCE');
  return {
    raw: seq(seq(seq(seq(certID)), der(0xa2, seq(extension(nonceOID, octet(nonce)))))),
    nonce,
    certID,
  };
}
export function parseOCSPRequest(raw) {
  const t = parseDER(raw).children[0].children;
  requireThat(t.length === 2 && t[0].children.length === 1 && t[1].tag === 0xa2, 'OCSP_REQUEST');
  const certID = t[0].children[0].children[0],
    extensions = extMap(t[1].children[0]),
    nonce = parseDER(extensions.get(nonceOID)).value;
  requireThat(nonce.length >= 16 && nonce.length <= 32, 'OCSP_NONCE');
  return { certID: certID.raw, nonce };
}
export function issueOCSP(
  request,
  {
    issuer,
    issuerPublicKey,
    privateKey,
    records,
    thisUpdate = now(),
    nextUpdate = thisUpdate + 300,
  },
) {
  const r = parseOCSPRequest(request),
    id = parseDER(r.certID),
    serial = intValue(id.children[3]);
  requireThat(equal(r.certID, ocspCertID({ issuer, issuerPublicKey, serial })), 'OCSP_ISSUER');
  const record = records.get(serial.toString()),
    status = record?.status ?? 'UNKNOWN';
  let value;
  if (status === 'GOOD') value = der(0x80, Buffer.alloc(0));
  else if (status === 'REVOKED')
    value = der(
      0xa1,
      Buffer.concat([
        generalizedTime(record.revokedAt),
        der(0xa0, der(10, Buffer.from([record.reason ?? 0]))),
      ]),
    );
  else value = der(0x82, Buffer.alloc(0));
  const rawKey = parseDER(spki(issuerPublicKey)).children[1].value.subarray(1),
    byKey = createHash('sha1').update(rawKey).digest();
  const tbs = seq(
    der(0xa2, octet(byKey)),
    generalizedTime(thisUpdate),
    seq(seq(r.certID, value, generalizedTime(thisUpdate), der(0xa0, generalizedTime(nextUpdate)))),
    der(0xa1, seq(extension(nonceOID, octet(r.nonce)))),
  );
  const basic = seq(tbs, algID(privateKey.asymmetricKeyType), bit(sign(tbs, privateKey)));
  return seq(der(10, Buffer.from([0])), der(0xa0, seq(oid(basicOID), octet(basic))));
}
export function verifyOCSP(raw, options) {
  if (raw === undefined || raw === null) return statusResult('UNKNOWN', 'OCSP_MISSING');
  return evaluateStatusEvidence(() => inspectOCSP(raw, options), 'OCSP');
}
function inspectOCSP(raw, { request, issuerPublicKey, at = now(), knowledgeTime = at }) {
  const expected = parseOCSPRequest(request),
    r = parseDER(raw).children;
  requireThat(r.length === 2 && r[0].tag === 10 && r[0].value[0] === 0, 'OCSP_STATUS');
  const responseBytes = r[1].children[0].children;
  requireThat(oidText(responseBytes[0]) === basicOID, 'OCSP_TYPE');
  const [tbs, algorithm, signature] = parseDER(responseBytes[1].value).children;
  requireThat(
    equal(algorithm.raw, algID(issuerPublicKey.asymmetricKeyType)) &&
      signature.value[0] === 0 &&
      verify(tbs.raw, signature.value.subarray(1), issuerPublicKey),
    'OCSP_SIGNATURE',
  );
  const a = tbs.children,
    rawKey = parseDER(spki(issuerPublicKey)).children[1].value.subarray(1);
  requireThat(
    a.length === 4 &&
      a[0].tag === 0xa2 &&
      equal(a[0].children[0].value, createHash('sha1').update(rawKey).digest()) &&
      a[2].children.length === 1,
    'OCSP_RESPONDER',
  );
  const s = a[2].children[0].children;
  requireThat(
    s.length === 4 &&
      equal(s[0].raw, expected.certID),
    'OCSP_CONTEXT',
  );
  const nonce = parseDER(extMap(a[3].children[0]).get(nonceOID)).value;
  requireThat(equal(nonce, expected.nonce), 'OCSP_NONCE');
  requireThat([0x80, 0x82, 0xa1].includes(s[1].tag), 'OCSP_CERT_STATUS');
  const thisUpdate = parseTime(s[2]), nextUpdate = parseTime(s[3].children[0]),
    producedAt = parseTime(a[1]), revokedAt = s[1].tag === 0xa1 ? parseTime(s[1].children[0]) : undefined;
  requireThat(nextUpdate > thisUpdate && producedAt >= thisUpdate, 'OCSP_INTERVAL');
  let status = s[1].tag === 0x80 ? 'GOOD' : s[1].tag === 0x82 ? 'UNKNOWN' : revokedAt <= at ? 'REVOKED' : 'GOOD';
  if (producedAt > knowledgeTime || thisUpdate > knowledgeTime) status = 'NOT_YET_KNOWN';
  else if (status !== 'REVOKED' && nextUpdate <= knowledgeTime) status = 'STALE';
  return statusResult(status, status === 'GOOD' ? undefined : 'OCSP_' + status,
    { thisUpdate, nextUpdate, producedAt, ...(revokedAt === undefined ? {} : { revokedAt }) });
}

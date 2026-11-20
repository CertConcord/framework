import { constants, createHash, createPublicKey, verify as verifySignature } from 'node:crypto';
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
  basicOID = '1.3.6.1.5.5.7.48.1.1',
  sha256OID = '2.16.840.1.101.3.4.2.1',
  sha256WithRSAEncryptionOID = '1.2.840.113549.1.1.11';
function sha256AlgorithmIdentifier(node) {
  return node.tag === 0x30 && [1, 2].includes(node.children.length) &&
    node.children[0].tag === 6 && oidText(node.children[0]) === sha256OID &&
    (node.children.length === 1 ||
      (node.children[1].tag === 5 && node.children[1].value.length === 0));
}
function matchingOCSPCertID(actual, expectedRaw) {
  if (equal(actual.raw, expectedRaw)) return true;
  const expected = parseDER(expectedRaw);
  return actual.tag === 0x30 && expected.tag === 0x30 &&
    actual.children.length === 4 && expected.children.length === 4 &&
    sha256AlgorithmIdentifier(actual.children[0]) &&
    sha256AlgorithmIdentifier(expected.children[0]) &&
    [4, 4, 2].every((tag, i) => actual.children[i + 1].tag === tag &&
      expected.children[i + 1].tag === tag &&
      equal(actual.children[i + 1].raw, expected.children[i + 1].raw));
}
function validOCSPSignature(tbs, algorithm, signature, issuerPublicKey) {
  if (signature.tag !== 3 || signature.value.length < 2 || signature.value[0] !== 0)
    return false;
  const bytes = signature.value.subarray(1);
  if (issuerPublicKey.asymmetricKeyType === 'rsa') {
    return algorithm.tag === 0x30 && [1, 2].includes(algorithm.children.length) &&
      algorithm.children[0].tag === 6 &&
      oidText(algorithm.children[0]) === sha256WithRSAEncryptionOID &&
      (algorithm.children.length === 1 ||
        (algorithm.children[1].tag === 5 && algorithm.children[1].value.length === 0)) &&
      verifySignature('sha256', tbs.raw,
        { key: issuerPublicKey, padding: constants.RSA_PKCS1_PADDING }, bytes);
  }
  return equal(algorithm.raw, algID(issuerPublicKey.asymmetricKeyType)) &&
    verify(tbs.raw, bytes, issuerPublicKey);
}
function parseTime(n) {
  const s = n.value.toString('ascii');
  requireThat(n.tag === 24 && /^\d{14}Z$/.test(s), 'STATUS_TIME');
  const t =
    Date.parse(
      `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}T${s.slice(8, 10)}:${s.slice(10, 12)}:${s.slice(12, 14)}Z`,
    ) / 1000;
  requireThat(Number.isSafeInteger(t), 'STATUS_TIME');
  const normalized = new Date(t * 1000).toISOString();
  requireThat(normalized.slice(0, 19).replace(/[-:T]/g, '') + 'Z' === s, 'STATUS_TIME');
  return t;
}
function crlTime(seconds) {
  const encoded = generalizedTime(seconds),
    value = parseDER(encoded).value;
  const year = Number(value.subarray(0, 4).toString('ascii'));
  return year >= 1950 && year <= 2049 ? der(23, value.subarray(2)) : encoded;
}
function parseCRLTime(n) {
  if (n.tag !== 23) return parseTime(n);
  const s = n.value.toString('utf8');
  requireThat(/^\d{12}Z$/.test(s), 'STATUS_TIME');
  const century = Number(s.slice(0, 2)) >= 50 ? '19' : '20';
  return parseTime({ tag: 24, value: Buffer.from(century + s, 'ascii') });
}
function parseCRLReason(raw) {
  const reason = parseDER(raw);
  requireThat(
    reason.tag === 10 && reason.value.length === 1 &&
      reason.value[0] <= 10 && reason.value[0] !== 7,
    'CRL_REASON',
  );
  return reason.value[0];
}
function extMap(node, allowedCritical = ['2.5.29.20', '2.5.29.21', '2.5.29.24', nonceOID]) {
  requireThat(node.tag === 0x30 && node.children.length > 0, 'STATUS_EXTENSION');
  const out = new Map();
  for (const e of node.children) {
    requireThat(e.tag === 0x30 && [2, 3].includes(e.children.length), 'STATUS_EXTENSION');
    const id = oidText(e.children[0]);
    requireThat(!out.has(id), 'STATUS_DUPLICATE_EXTENSION');
    const critical = e.children.length === 3;
    requireThat(
      !critical || (e.children[1].tag === 1 && e.children[1].value.length === 1 &&
        e.children[1].value[0] === 0xff),
      'STATUS_EXTENSION',
    );
    requireThat(
      !critical || allowedCritical.includes(id),
      'STATUS_CRITICAL_EXTENSION',
    );
    requireThat(e.children.at(-1).tag === 4, 'STATUS_EXTENSION');
    out.set(id, e.children.at(-1).value);
  }
  return out;
}
export function issueCRL({
  issuer,
  privateKey,
  authorityKeyIdentifier,
  number,
  entries = [],
  thisUpdate = now(),
  nextUpdate = thisUpdate + 300,
}) {
  requireThat(nextUpdate > thisUpdate && nextUpdate - thisUpdate <= 86400, 'CRL_INTERVAL');
  const keyIdentifier = authorityKeyIdentifier === undefined
    ? sha256(spki(createPublicKey(privateKey))) : authorityKeyIdentifier;
  requireThat(
    keyIdentifier instanceof Uint8Array && keyIdentifier.length > 0,
    'CRL_AUTHORITY_KEY_IDENTIFIER',
  );
  const alg = algID(privateKey.asymmetricKeyType),
    seen = new Set();
  const revoked = entries.map((e) => {
    const id = BigInt(e.serial).toString();
    requireThat(
      !seen.has(id) &&
        Number.isInteger(e.reason) &&
        e.reason >= 0 &&
        e.reason <= 10 &&
        e.reason !== 7 &&
        e.reason !== 8,
      'CRL_ENTRY',
    );
    seen.add(id);
    const extensions = [extension('2.5.29.21', der(10, Buffer.from([e.reason])))];
    if (e.invalidityDate !== undefined)
      extensions.push(extension('2.5.29.24', generalizedTime(e.invalidityDate)));
    return seq(integer(e.serial), crlTime(e.revokedAt), seq(...extensions));
  });
  const tbs = seq(
    integer(1),
    alg,
    issuer,
    crlTime(thisUpdate),
    crlTime(nextUpdate),
    ...(revoked.length ? [seq(...revoked)] : []),
    der(0xa0, seq(
      extension('2.5.29.20', integer(number)),
      extension('2.5.29.35', seq(der(0x80, Buffer.from(keyIdentifier)))),
    )),
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
  const root = parseDER(raw);
  requireThat(root.tag === 0x30 && root.children?.length === 3, 'CRL_STRUCTURE');
  const [tbs, algorithm, signature] = root.children;
  requireThat(tbs.tag === 0x30, 'CRL_STRUCTURE');
  requireThat(
    equal(algorithm.raw, algID(publicKey.asymmetricKeyType)) &&
      signature.tag === 3 &&
      signature.value[0] === 0 &&
      verify(tbs.raw, signature.value.subarray(1), publicKey),
    'CRL_SIGNATURE',
  );
  const a = tbs.children;
  requireThat([6, 7].includes(a.length), 'CRL_STRUCTURE');
  requireThat(
    intValue(a[0]) === 1n && equal(a[1].raw, algorithm.raw) && equal(a[2].raw, issuer),
    'CRL_SCOPE',
  );
  const thisUpdate = parseCRLTime(a[3]),
    nextUpdate = parseCRLTime(a[4]);
  requireThat(nextUpdate > thisUpdate, 'CRL_INTERVAL');
  requireThat(
    a.at(-1).tag === 0xa0 && a.at(-1).children.length === 1,
    'CRL_STRUCTURE',
  );
  const extensions = extMap(a.at(-1).children[0], ['2.5.29.20']);
  requireThat(!extensions.has('2.5.29.27'), 'DELTA_CRL_UNSUPPORTED');
  requireThat(!extensions.has('2.5.29.28'), 'SCOPED_CRL_UNSUPPORTED');
  const number = intValue(parseDER(extensions.get('2.5.29.20')));
  requireThat(number >= BigInt(minNumber), 'CRL_ROLLBACK');
  requireThat(a.length !== 7 || a[5].tag === 0x30, 'CRL_STRUCTURE');
  const records = a.length === 7 ? a[5].children : [];
  let result = 'GOOD';
  const seen = new Set();
  for (const record of records) {
    requireThat(record.tag === 0x30 && [2, 3].includes(record.children.length), 'CRL_STRUCTURE');
    const [sn, when, ex] = record.children,
      s = intValue(sn),
      id = s.toString();
    requireThat(!seen.has(id), 'CRL_DUPLICATE_SERIAL');
    seen.add(id);
    requireThat(!ex || ex.tag === 0x30, 'CRL_STRUCTURE');
    const ext = ex ? extMap(ex, ['2.5.29.21', '2.5.29.24']) : new Map(),
      revokedAt = parseCRLTime(when),
      invalidityDate = ext.has('2.5.29.24') ? parseTime(parseDER(ext.get('2.5.29.24'))) : revokedAt,
      reason = ext.has('2.5.29.21') ? parseCRLReason(ext.get('2.5.29.21')) : 0;
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
  requireThat(nonce instanceof Uint8Array && nonce.byteLength === 32, 'OCSP_NONCE');
  return {
    raw: seq(seq(seq(seq(certID)), der(0xa2, seq(extension(nonceOID, octet(nonce)))))),
    nonce,
    certID,
  };
}
export function parseOCSPRequest(raw) {
  const envelope = parseDER(raw);
  requireThat(envelope.tag === 0x30 && envelope.children[0]?.tag === 0x30, 'OCSP_REQUEST');
  const t = envelope.children[0].children;
  requireThat(
    t.length === 2 && t[0].tag === 0x30 && t[0].children.length === 1 &&
      t[0].children[0].tag === 0x30 && t[1].tag === 0xa2,
    'OCSP_REQUEST',
  );
  const certID = t[0].children[0].children[0],
    extensions = extMap(t[1].children[0]),
    nonceNode = parseDER(extensions.get(nonceOID));
  requireThat(nonceNode.tag === 4, 'OCSP_NONCE');
  const nonce = nonceNode.value;
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
  else if (status === 'REVOKED') {
    const reason = record.reason ?? 0;
    requireThat(
      Number.isInteger(reason) && reason >= 0 && reason <= 10 && reason !== 7,
      'OCSP_REVOCATION_REASON',
    );
    requireThat(reason !== 8, 'OCSP_REVOCATION_REASON_UNSUPPORTED');
    value = der(
      0xa1,
      Buffer.concat([
        generalizedTime(record.revokedAt),
        der(0xa0, der(10, Buffer.from([reason]))),
      ]),
    );
  } else value = der(0x82, Buffer.alloc(0));
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
function parseOCSPRevokedInfo(node) {
  requireThat([1, 2].includes(node.children.length), 'OCSP_REVOKED_INFO');
  const revokedAt = parseTime(node.children[0]);
  if (node.children.length === 1) return { revokedAt };
  const wrapper = node.children[1];
  requireThat(
    wrapper.tag === 0xa0 && wrapper.children.length === 1,
    'OCSP_REVOCATION_REASON',
  );
  const reason = wrapper.children[0];
  requireThat(
    reason.tag === 10 && reason.value.length === 1 &&
      reason.value[0] <= 10 && reason.value[0] !== 7,
    'OCSP_REVOCATION_REASON',
  );
  return { revokedAt, revocationReason: reason.value[0] };
}
function isCertificateEnvelope(cert) {
  const fields = cert.children;
  return cert.tag === 0x30 && fields.length === 3 &&
    fields[0].tag === 0x30 && fields[0].children.length >= 6 &&
    fields[1].tag === 0x30 && fields[1].children.length >= 1 &&
    fields[1].children[0].tag === 6 &&
    fields[2].tag === 3 && fields[2].value.length > 1 && fields[2].value[0] === 0;
}
function inspectOCSP(raw, { request, issuerPublicKey, at = now(), knowledgeTime = at }) {
  const expected = parseOCSPRequest(request),
    envelope = parseDER(raw);
  requireThat(envelope.tag === 0x30, 'OCSP_TYPE');
  const r = envelope.children;
  requireThat(
    r.length === 2 && r[0].tag === 10 && r[0].value.length === 1 && r[0].value[0] === 0,
    'OCSP_STATUS',
  );
  requireThat(
    r[1].tag === 0xa0 && r[1].children.length === 1 &&
      r[1].children[0].tag === 0x30,
    'OCSP_TYPE',
  );
  const responseBytes = r[1].children[0].children;
  requireThat(
    responseBytes.length === 2 && responseBytes[0].tag === 6 &&
      responseBytes[1].tag === 4 && oidText(responseBytes[0]) === basicOID,
    'OCSP_TYPE',
  );
  const basic = parseDER(responseBytes[1].value);
  requireThat(basic.tag === 0x30 && [3, 4].includes(basic.children.length), 'OCSP_SIGNATURE');
  const [tbs, algorithm, signature, certs] = basic.children;
  requireThat(
    tbs.tag === 0x30 && algorithm.tag === 0x30 &&
      (!certs || (certs.tag === 0xa0 && certs.children.length === 1 &&
        certs.children[0].tag === 0x30 &&
        certs.children[0].children.every(isCertificateEnvelope))),
    'OCSP_SIGNATURE',
  );
  requireThat(validOCSPSignature(tbs, algorithm, signature, issuerPublicKey), 'OCSP_SIGNATURE');
  const a = tbs.children,
    rawKey = parseDER(spki(issuerPublicKey)).children[1].value.subarray(1);
  requireThat(
    a.length === 4 &&
      a[0].tag === 0xa2 && a[0].children.length === 1 &&
      a[0].children[0].tag === 4 &&
      equal(a[0].children[0].value, createHash('sha1').update(rawKey).digest()) &&
      a[2].tag === 0x30 && a[2].children.length === 1 &&
      a[2].children[0].tag === 0x30,
    'OCSP_RESPONDER',
  );
  const s = a[2].children[0].children;
  requireThat(
    s.length === 4 &&
      matchingOCSPCertID(s[0], expected.certID),
    'OCSP_CONTEXT',
  );
  requireThat(
    a[3].tag === 0xa1 && a[3].children.length === 1 && a[3].children[0].tag === 0x30,
    'OCSP_NONCE',
  );
  const nonceNode = parseDER(extMap(a[3].children[0]).get(nonceOID));
  requireThat(nonceNode.tag === 4 && equal(nonceNode.value, expected.nonce), 'OCSP_NONCE');
  requireThat([0x80, 0x82, 0xa1].includes(s[1].tag), 'OCSP_CERT_STATUS');
  requireThat(s[1].tag === 0xa1 || s[1].value.length === 0, 'OCSP_CERT_STATUS');
  requireThat(
    s[3].tag === 0xa0 && s[3].children.length === 1,
    'OCSP_INTERVAL',
  );
  const thisUpdate = parseTime(s[2]), nextUpdate = parseTime(s[3].children[0]),
    producedAt = parseTime(a[1]),
    revocation = s[1].tag === 0xa1 ? parseOCSPRevokedInfo(s[1]) : {},
    { revokedAt, revocationReason } = revocation;
  requireThat(nextUpdate > thisUpdate && producedAt >= thisUpdate, 'OCSP_INTERVAL');
  const details = { thisUpdate, nextUpdate, producedAt, ...revocation };
  let status = s[1].tag === 0x80 ? 'GOOD' : s[1].tag === 0x82 ? 'UNKNOWN' : revokedAt <= at ? 'REVOKED' : 'GOOD';
  if (producedAt > knowledgeTime || thisUpdate > knowledgeTime) status = 'NOT_YET_KNOWN';
  else if (revocationReason === 8)
    return statusResult('UNSUPPORTED', 'OCSP_REVOCATION_REASON_UNSUPPORTED', details);
  else if ((status !== 'REVOKED' || revocationReason === 6) && nextUpdate <= knowledgeTime)
    status = 'STALE';
  return statusResult(status, status === 'GOOD' ? undefined : 'OCSP_' + status,
    details);
}

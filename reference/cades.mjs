import { X509Certificate, createHash, verify as verifySignature } from 'node:crypto';
import {
  ProtocolError,
  parseDER,
  der,
  seq,
  set,
  oid,
  oidText,
  octet,
  integer,
  intValue,
  equal,
  keyID,
} from './core.mjs';
import { OID, algID, attribute } from './pki.mjs';
import { parseTSTInfo, timestampRequest } from './timestamp.mjs';
import { validateCAdESMaterial } from './cades-validation.mjs';

// EN 319 122-1 V1.3.1, clauses 5.5.2 and 5.5.3. These are standard CMS
// attributes; the original SignerInfo's six signed fields are never re-encoded.
const SIGNING_TIME = '1.2.840.113549.1.9.5';
const ALGORITHM_PROTECTION = '1.2.840.113549.1.9.52';
const MIME_TYPE = '0.4.0.1733.2.1';
const ARCHIVE = '0.4.0.1733.2.4';
const INDEX = '0.4.0.19122.1.5';
const ECDSA_SHA256 = '1.2.840.10045.4.3.2';
const HASHES = { [OID.sha256]: 'sha256', [OID.sha512]: 'sha512' };
const LEVELS = ['B', 'T', 'LT', 'LTA'];
const LEGACY = new Set([
  '1.2.840.113549.1.9.6', // countersignature
  '1.2.840.113549.1.9.16.2.21', // complete-certificate-references
  '1.2.840.113549.1.9.16.2.22', // complete-revocation-references
  '1.2.840.113549.1.9.16.2.23', // certificate-values
  '1.2.840.113549.1.9.16.2.24', // revocation-values
  '1.2.840.113549.1.9.16.2.25', // ES-C timestamp
  '1.2.840.113549.1.9.16.2.26', // timestamped references
  '1.2.840.113549.1.9.16.2.27', // archive timestamp
  '1.2.840.113549.1.9.16.2.48', // archive timestamp v2
  '1.2.840.113549.1.9.16.2.44', // attribute certificate references
  '1.2.840.113549.1.9.16.2.45', // attribute revocation references
  '1.2.840.113549.1.9.16.2.49', // internal evidence records
  '1.2.840.113549.1.9.16.2.50', // external evidence records
  '1.2.840.113549.1.9.16.2.18', // signer attributes
  '0.4.0.19122.1.1', // signer attributes v2 (including certified assertions)
  '1.2.840.113549.1.9.16.2.4', // content hints
  '1.2.840.113549.1.9.16.2.7', // content identifier
  '1.2.840.113549.1.9.16.2.10', // content reference
  '1.2.840.113549.1.9.16.2.12', // SHA-1 signing certificate
  '1.2.840.113549.1.9.16.2.15', // signature policy identifier
  '1.2.840.113549.1.9.16.2.16', // commitment type indication
  '1.2.840.113549.1.9.16.2.17', // signer location
  '1.2.840.113549.1.9.16.2.19', // other signing certificate
  '1.2.840.113549.1.9.16.2.20', // content timestamp
  '0.4.0.19122.1.2', // claimed SAML assertion
  '0.4.0.19122.1.3', // signature policy store
  '0.4.0.1733.2.2', // long-term validation (legacy)
  '0.4.0.1733.2.5', // legacy ATS hash index
]);
const instant = (n) => Number.isFinite(n) && n >= 0 && n <= Number.MAX_SAFE_INTEGER;
const digest = (id, input) => {
  if (!HASHES[id]) throw failure('UNSUPPORTED', 'CADES_HASH_UNSUPPORTED');
  return createHash(HASHES[id]).update(input).digest();
};
const result = (overall, reason, extra = {}) => Object.freeze({ overall, reason, ...extra });
function failure(overall, code) {
  const error = new ProtocolError(code);
  error.overall = overall;
  return error;
}
function check(condition, reason, overall = 'INVALID') {
  if (!condition) throw failure(overall, reason);
}
function record(error) {
  return result(error.overall ?? 'INVALID', error.code ?? error.message ?? 'CADES_MALFORMED');
}
function attempt(failures, fn) {
  try {
    return fn();
  } catch (error) {
    failures.push(record(error));
  }
}
function outcome(failures) {
  for (const kind of ['INVALID', 'UNSUPPORTED', 'INDETERMINATE']) {
    const found = failures.find((f) => f?.overall === kind);
    if (found) return found;
  }
  return result('VALID', 'CADES_VALID');
}
function copy(value) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return Buffer.from(value);
  if (Array.isArray(value)) return value.map(copy);
  if (value && typeof value === 'object')
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, copy(v)]));
  return value;
}
function unique(values, reason) {
  const seen = new Set();
  for (const value of values) {
    check(Buffer.isBuffer(value), reason);
    const id = value.toString('hex');
    check(!seen.has(id), reason);
    seen.add(id);
  }
  return values;
}
const includes = (values, value) => values.some((b) => equal(b, value));
const union = (...arrays) => arrays.flat().filter((b, i, all) => !includes(all.slice(0, i), b));
function canonicalImplicit(node, tag, reason) {
  check(node?.tag === tag, reason);
  parseDER(der(0x31, node.value));
}
function algorithm(node) {
  check(
    node?.tag === 0x30 && node.children.length >= 1 && node.children.length <= 2,
    'CADES_ALGORITHM_ENCODING',
  );
  return oidText(node.children[0]);
}
function hashAlgorithm(node) {
  const id = algorithm(node);
  check(
    !node.children[1] || equal(node.children[1].raw, Buffer.from('0500', 'hex')),
    'CADES_HASH_PARAMETERS',
  );
  check(HASHES[id], 'CADES_HASH_UNSUPPORTED', 'UNSUPPORTED');
  return id;
}
function attributes(node, signed) {
  if (!node) return [];
  canonicalImplicit(node, signed ? 0xa0 : 0xa1, 'CADES_ATTRIBUTES_ENCODING');
  check(node.children.length <= 256, 'CADES_ATTRIBUTE_LIMIT');
  const seen = new Set();
  return node.children.map((entry) => {
    check(
      entry.tag === 0x30 &&
        entry.children.length === 2 &&
        entry.children[1].tag === 0x31 &&
        entry.children[1].children.length > 0,
      'CADES_ATTRIBUTE_ENCODING',
    );
    const id = oidText(entry.children[0]);
    check(!signed || !seen.has(id), 'CADES_DUPLICATE_SIGNED_ATTRIBUTE');
    check(!signed || entry.children[1].children.length === 1, 'CADES_SIGNED_ATTRIBUTE_VALUES');
    if (id === ARCHIVE || id === INDEX || id === OID.timestamp)
      check(entry.children[1].children.length === 1, 'CADES_TIMESTAMP_ATTRIBUTE_VALUES');
    seen.add(id);
    return { id, raw: entry.raw, type: entry.children[0].raw, values: entry.children[1].children };
  });
}

function parseCMS(raw, content, expectedType = OID.data) {
  check(Buffer.isBuffer(raw), 'CADES_CMS_REQUIRED');
  const root = parseDER(raw);
  check(
    root.tag === 0x30 &&
      root.children.length === 2 &&
      oidText(root.children[0]) === OID.signed &&
      root.children[1].tag === 0xa0 &&
      root.children[1].children.length === 1,
    'CADES_CONTENT_INFO',
  );
  const signedData = root.children[1].children[0];
  check(
    signedData.tag === 0x30 && signedData.children.length >= 4 && signedData.children.length <= 6,
    'CADES_SIGNED_DATA',
  );
  const sd = signedData.children,
    version = intValue(sd[0]);
  check(sd[1].tag === 0x31 && sd[1].children.length > 0, 'CADES_DIGEST_ALGORITHMS');
  check(
    sd[2].tag === 0x30 && sd[2].children.length >= 1 && sd[2].children.length <= 2,
    'CADES_CONTENT_ENCODING',
  );
  const eci = sd[2].children,
    contentType = oidText(eci[0]);
  check(contentType === expectedType, 'CADES_CONTENT_TYPE_UNSUPPORTED', 'UNSUPPORTED');
  check(version === (contentType === OID.data ? 1n : 3n), 'CADES_SIGNED_DATA_VERSION');
  let embedded;
  if (eci[1]) {
    check(
      eci[1].tag === 0xa0 && eci[1].children.length === 1 && eci[1].children[0].tag === 4,
      'CADES_CONTENT_ENCODING',
    );
    embedded = eci[1].children[0].value;
  }
  if (embedded !== undefined && content !== undefined)
    check(equal(embedded, content), 'CADES_CONTENT_CONFLICT');
  content = embedded ?? content;
  let at = 3,
    certificates = [],
    crls = [],
    unsupported = [];
  if (sd[at]?.tag === 0xa0) {
    canonicalImplicit(sd[at], 0xa0, 'CADES_CERTIFICATE_SET');
    certificates = sd[at++].children.map((n) => {
      if (n.tag !== 0x30) unsupported.push(result('UNSUPPORTED', 'CADES_CERTIFICATE_CHOICE'));
      return n.raw;
    });
    unique(certificates, 'CADES_DUPLICATE_CERTIFICATE');
    check(certificates.length <= 128, 'CADES_CERTIFICATE_LIMIT');
  }
  if (sd[at]?.tag === 0xa1) {
    canonicalImplicit(sd[at], 0xa1, 'CADES_REVOCATION_SET');
    crls = sd[at++].children.map((n) => {
      if (n.tag !== 0x30) unsupported.push(result('UNSUPPORTED', 'CADES_REVOCATION_CHOICE'));
      return n.raw;
    });
    unique(crls, 'CADES_DUPLICATE_CRL');
    check(crls.length <= 128, 'CADES_CRL_LIMIT');
  }
  check(at === sd.length - 1 && sd[at].tag === 0x31, 'CADES_SIGNER_INFOS');
  check(sd[at].children.length <= 16, 'CADES_SIGNER_LIMIT');
  check(sd[at].children.length === 1, 'CADES_MULTIPLE_SIGNERS', 'UNSUPPORTED');
  const signer = sd[at].children[0];
  check(
    signer.tag === 0x30 && signer.children.length >= 6 && signer.children.length <= 7,
    'CADES_SIGNER_INFO',
  );
  const si = signer.children;
  check(
    intValue(si[0]) === 1n &&
      si[1].tag === 0x30 &&
      si[1].children.length === 2 &&
      si[1].children[1].tag === 2 &&
      si[5].tag === 4,
    'CADES_SIGNER_IDENTIFIER',
  );
  const signed = attributes(si[3], true),
    unsigned = attributes(si[6], false);
  check(
    unsigned.filter((a) => a.id === ARCHIVE || a.id === OID.timestamp).length <= 32,
    'CADES_TIMESTAMP_LIMIT',
  );
  for (const attr of [...signed, ...unsigned]) {
    if (LEGACY.has(attr.id)) unsupported.push(result('UNSUPPORTED', 'CADES_ATTRIBUTE_UNSUPPORTED'));
    if (signed.includes(attr) && [ARCHIVE, INDEX, OID.timestamp].includes(attr.id))
      throw failure('INVALID', 'CADES_ATTRIBUTE_LOCATION');
    if (
      unsigned.includes(attr) &&
      [
        ALGORITHM_PROTECTION,
        MIME_TYPE,
        SIGNING_TIME,
        OID.ess,
        OID.contentType,
        OID.messageDigest,
      ].includes(attr.id)
    )
      throw failure('INVALID', 'CADES_ATTRIBUTE_LOCATION');
  }
  return {
    raw,
    root,
    sd,
    si,
    eci,
    contentType,
    content,
    certificates,
    crls,
    signed,
    unsigned,
    unsupported,
    core: si.slice(0, 6).map((n) => n.raw),
    tbs: der(0x31, si[3].value),
  };
}
function one(parsed, id) {
  const attrs = parsed.signed.filter((a) => a.id === id);
  return attrs[0]?.values[0];
}
function certificateIdentity(raw) {
  const x509 = new X509Certificate(raw),
    tbs = parseDER(raw).children[0].children;
  const offset = tbs[0].tag === 0xa0 ? 1 : 0;
  return { x509, sid: seq(tbs[offset + 2].raw, tbs[offset].raw) };
}
function essBinding(parsed) {
  const value = one(parsed, OID.ess);
  check(value, 'CADES_SIGNING_CERTIFICATE_MISSING', 'INDETERMINATE');
  check(
    value.tag === 0x30 &&
      value.children.length >= 1 &&
      value.children.length <= 2 &&
      value.children[0].tag === 0x30 &&
      value.children[0].children.length > 0,
    'CADES_SIGNING_CERTIFICATE_ENCODING',
  );
  check(
    value.children[0].children.length === 1 && value.children.length === 1,
    'CADES_SIGNING_CERTIFICATE_PROFILE',
    'UNSUPPORTED',
  );
  const id = value.children[0].children[0];
  check(
    id.tag === 0x30 && id.children.length >= 1 && id.children.length <= 3,
    'CADES_SIGNING_CERTIFICATE_ENCODING',
  );
  let at = 0,
    hashOID = OID.sha256;
  if (id.children[0].tag === 0x30) hashOID = hashAlgorithm(id.children[at++]);
  const hash = id.children[at++];
  check(
    hash?.tag === 4 && hash.value.length === digest(hashOID, Buffer.alloc(0)).length,
    'CADES_SIGNING_CERTIFICATE_HASH',
  );
  const issuerSerial = id.children[at++];
  check(at - (issuerSerial ? 0 : 1) === id.children.length, 'CADES_SIGNING_CERTIFICATE_ENCODING');
  return { hashOID, hash: hash.value, issuerSerial };
}
function signingTime(value) {
  check(value, 'CADES_SIGNING_TIME_MISSING', 'INDETERMINATE');
  const text = value.value.toString('ascii');
  let full;
  if (value.tag === 23) {
    check(/^\d{12}Z$/.test(text), 'CADES_SIGNING_TIME_ENCODING');
    full = (Number(text.slice(0, 2)) >= 50 ? '19' : '20') + text;
  } else {
    check(value.tag === 24 && /^\d{14}Z$/.test(text), 'CADES_SIGNING_TIME_ENCODING');
    full = text;
    check(
      Number(text.slice(0, 4)) < 1950 || Number(text.slice(0, 4)) > 2049,
      'CADES_SIGNING_TIME_ENCODING',
    );
  }
  const seconds =
    Date.parse(
      `${full.slice(0, 4)}-${full.slice(4, 6)}-${full.slice(6, 8)}T` +
        `${full.slice(8, 10)}:${full.slice(10, 12)}:${full.slice(12, 14)}Z`,
    ) / 1000;
  check(
    instant(seconds) &&
      new Date(seconds * 1000).toISOString().replace(/[-:T]/g, '').replace('.000Z', 'Z') === full,
    'CADES_SIGNING_TIME_ENCODING',
  );
  return seconds;
}

// Signature mathematics is deliberately evaluated even if a baseline attribute
// or a validation object is missing. An available bad signature remains INVALID.
function inspectSignature(parsed, failures, isTimestamp = false) {
  failures.push(...parsed.unsupported);
  const hashOID = attempt(failures, () => hashAlgorithm(parsed.si[2]));
  const signatureOID = attempt(failures, () => algorithm(parsed.si[4]));
  const algorithmProtection = one(parsed, ALGORITHM_PROTECTION);
  if (algorithmProtection)
    attempt(failures, () => {
      const fields = algorithmProtection.children;
      check(
        algorithmProtection.tag === 0x30 && fields?.length === 2 && fields[1].tag === 0xa1,
        'CADES_ALGORITHM_PROTECTION_ENCODING',
      );
      check(
        algorithm(fields[0]) === hashOID && equal(der(0x30, fields[1].value), parsed.si[4].raw),
        'CADES_ALGORITHM_PROTECTION_BINDING',
      );
      hashAlgorithm(fields[0]);
    });
  const mediaType = one(parsed, MIME_TYPE);
  if (mediaType)
    attempt(failures, () => {
      check(
        mediaType.tag === 12 &&
          mediaType.value.length <= 256 &&
          /^[A-Za-z0-9!#$&^_.+-]+\/[A-Za-z0-9!#$&^_.+-]+(?:;[\x20-\x7e]+)?$/.test(
            mediaType.value.toString('utf8'),
          ),
        'CADES_MIME_TYPE_ENCODING',
      );
    });
  if (hashOID)
    attempt(failures, () => {
      check(
        parsed.sd[1].children.some((a) => algorithm(a) === hashOID),
        'CADES_DIGEST_SET',
      );
    });
  attempt(failures, () => {
    const contentType = one(parsed, OID.contentType);
    check(contentType, 'CADES_CONTENT_TYPE_MISSING', 'INDETERMINATE');
    check(oidText(contentType) === parsed.contentType, 'CADES_CONTENT_TYPE_BINDING');
  });
  attempt(failures, () => {
    const messageDigest = one(parsed, OID.messageDigest);
    check(messageDigest, 'CADES_MESSAGE_DIGEST_MISSING', 'INDETERMINATE');
    check(messageDigest.tag === 4, 'CADES_MESSAGE_DIGEST_ENCODING');
    check(Buffer.isBuffer(parsed.content), 'CADES_DETACHED_CONTENT_MISSING', 'INDETERMINATE');
    if (hashOID)
      check(equal(messageDigest.value, digest(hashOID, parsed.content)), 'CADES_CONTENT_DIGEST');
  });
  const ess = attempt(failures, () => essBinding(parsed));
  const candidates = [];
  for (const cert of parsed.certificates) {
    if (cert[0] !== 0x30) continue;
    const identity = attempt(failures, () => certificateIdentity(cert));
    if (identity && equal(identity.sid, parsed.si[1].raw)) candidates.push({ cert, ...identity });
  }
  let selected = ess
    ? candidates.find((c) => equal(digest(ess.hashOID, c.cert), ess.hash))
    : candidates[0];
  if (!selected && candidates.length) {
    failures.push(result('INVALID', 'CADES_SIGNING_CERTIFICATE_BINDING'));
    selected = candidates[0]; // Still check the available signature.
  }
  if (!selected) {
    const replacement =
      signatureOID === ECDSA_SHA256 &&
      parsed.certificates.some((raw) => {
        try {
          const key = new X509Certificate(raw).publicKey;
          return (
            key.asymmetricKeyType === 'ec' &&
            verifySignature('sha256', parsed.tbs, key, parsed.si[5].value)
          );
        } catch {
          return false;
        }
      });
    failures.push(
      result(
        replacement ? 'INVALID' : 'INDETERMINATE',
        replacement ? 'CADES_SIGNING_CERTIFICATE_BINDING' : 'CADES_SIGNER_CERTIFICATE_MISSING',
      ),
    );
  }
  if (ess?.issuerSerial && selected)
    attempt(failures, () => {
      const binding = ess.issuerSerial.children,
        sid = parseDER(selected.sid).children;
      check(
        ess.issuerSerial.tag === 0x30 &&
          binding?.length === 2 &&
          binding[0].tag === 0x30 &&
          binding[0].children.some(
            (n) =>
              n.tag === 0xa4 && n.children.length === 1 && equal(n.children[0].raw, sid[0].raw),
          ) &&
          equal(binding[1].raw, sid[1].raw),
        'CADES_ESS_ISSUER_SERIAL',
      );
    });
  if (selected) {
    const key = selected.x509.publicKey;
    attempt(failures, () => {
      check(
        signatureOID === ECDSA_SHA256 &&
          hashOID === OID.sha256 &&
          key.asymmetricKeyType === 'ec' &&
          key.asymmetricKeyDetails?.namedCurve === 'prime256v1',
        'CADES_SIGNATURE_SUITE_UNSUPPORTED',
        'UNSUPPORTED',
      );
      check(parsed.si[4].children.length === 1, 'CADES_ECDSA_PARAMETERS');
    });
    if (signatureOID === ECDSA_SHA256 && key.asymmetricKeyType === 'ec')
      attempt(failures, () =>
        check(
          verifySignature('sha256', parsed.tbs, key, parsed.si[5].value),
          'CADES_SIGNATURE_INVALID',
        ),
      );
  }
  if (!isTimestamp || one(parsed, SIGNING_TIME))
    attempt(failures, () => signingTime(one(parsed, SIGNING_TIME)));
  return {
    certificate: selected?.cert,
    x509: selected?.x509,
    hashOID,
    signatureOID,
    essHash: ess?.hashOID,
  };
}

// Multiple signers remain outside this profile. A bounded scan still detects
// known failures in SignerInfos whose mathematical signature suite is selected;
// unsupported multiplicity must not conceal an available bad digest/signature.
function inspectMultipleSigners(raw, content, expectedType, failures, isTimestamp = false) {
  attempt(failures, () => {
    const root = parseDER(raw),
      sd = root.children[1].children[0].children;
    const signers = sd.at(-1).children;
    check(signers.length <= 16, 'CADES_SIGNER_LIMIT');
    for (const signer of signers) {
      const fields = signer.children;
      if (
        signer.tag !== 0x30 ||
        !fields ||
        fields.length < 6 ||
        fields.length > 7 ||
        fields[0].tag !== 2 ||
        intValue(fields[0]) !== 1n ||
        fields[1].tag !== 0x30
      )
        continue;
      attempt(failures, () => {
        const single = seq(
          root.children[0].raw,
          der(0xa0, seq(...sd.slice(0, -1).map((n) => n.raw), set(signer.raw))),
        );
        inspectSignature(parseCMS(single, content, expectedType), failures, isTimestamp);
      });
    }
  });
}

function encodeCMS(
  parsed,
  {
    certificates = parsed.certificates,
    crls = parsed.crls,
    unsigned = parsed.unsigned.map((a) => a.raw),
    hashOID,
  } = {},
) {
  const algorithms = [...parsed.sd[1].children.map((n) => n.raw)];
  if (hashOID && !parsed.sd[1].children.some((n) => algorithm(n) === hashOID))
    algorithms.push(algID(hashOID));
  const signer = seq(
    ...parsed.core,
    ...(unsigned.length ? [der(0xa1, parseDER(set(...unsigned)).value)] : []),
  );
  return seq(
    oid(OID.signed),
    der(
      0xa0,
      seq(
        parsed.sd[0].raw,
        set(...algorithms),
        parsed.sd[2].raw,
        ...(certificates.length ? [der(0xa0, parseDER(set(...certificates)).value)] : []),
        ...(crls.length ? [der(0xa1, parseDER(set(...crls)).value)] : []),
        set(signer),
      ),
    ),
  );
}

/** Create a new baseline-capable signature; no existing signed field is repaired. */
export function prepareCAdESSignature({
  content,
  certificate,
  certificates = [],
  detached = false,
  signingTime: time,
  additionalSignedAttributes = [],
  algorithmProfile = 'ES256',
}) {
  check(algorithmProfile === 'ES256', 'CADES_SIGNATURE_SUITE_UNSUPPORTED', 'UNSUPPORTED');
  check(
    Buffer.isBuffer(content) && Buffer.isBuffer(certificate) && typeof detached === 'boolean',
    'CADES_SIGNATURE_INPUT',
  );
  check(Number.isSafeInteger(time) && instant(time), 'CADES_SIGNING_TIME_REQUIRED');
  content = Buffer.from(content);
  certificate = Buffer.from(certificate);
  certificates = union([certificate], copy(certificates));
  const { x509, sid } = certificateIdentity(certificate),
    key = x509.publicKey;
  check(
    key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails?.namedCurve === 'prime256v1',
    'CADES_SIGNATURE_SUITE_UNSUPPORTED',
    'UNSUPPORTED',
  );
  const encodedTime = new Date(time * 1000)
    .toISOString()
    .replace(/[-:T]/g, '')
    .replace('.000Z', 'Z');
  const year = Number(encodedTime.slice(0, 4));
  const attrs = [
    attribute(OID.contentType, oid(OID.data)),
    attribute(OID.messageDigest, octet(digest(OID.sha256, content))),
    attribute(OID.ess, seq(seq(seq(octet(digest(OID.sha256, certificate)))))),
    attribute(
      SIGNING_TIME,
      der(
        year >= 1950 && year <= 2049 ? 23 : 24,
        Buffer.from(year >= 1950 && year <= 2049 ? encodedTime.slice(2) : encodedTime),
      ),
    ),
    ...copy(additionalSignedAttributes),
  ];
  const tbs = set(...attrs);
  attributes(parseDER(der(0xa0, parseDER(tbs).value)), true);
  return Object.freeze({
    tbs: Buffer.from(tbs),
    finish(signature) {
      signature = Buffer.from(signature);
      check(verifySignature('sha256', tbs, key, signature), 'CADES_SIGNATURE_INVALID');
      const si = seq(
        integer(1),
        sid,
        algID(OID.sha256),
        der(0xa0, parseDER(tbs).value),
        algID(ECDSA_SHA256),
        octet(signature),
      );
      const cms = seq(
        oid(OID.signed),
        der(
          0xa0,
          seq(
            integer(1),
            set(algID(OID.sha256)),
            seq(oid(OID.data), ...(detached ? [] : [der(0xa0, octet(content))])),
            der(0xa0, parseDER(set(...certificates)).value),
            set(si),
          ),
        ),
      );
      const failures = [];
      inspectSignature(parseCMS(cms, content), failures);
      const checked = outcome(failures);
      if (checked.overall !== 'VALID') throw failure(checked.overall, checked.reason);
      return cms;
    },
  });
}

function unsignedValues(parsed) {
  return parsed.unsigned.flatMap((a) =>
    a.values.map((value) => ({
      id: a.id,
      type: a.type,
      raw: value.raw,
      input: Buffer.concat([a.type, value.raw]),
      attr: a,
    })),
  );
}
function createIndex(parsed, hashOID) {
  return seq(
    algID(hashOID),
    seq(...parsed.certificates.map((b) => octet(digest(hashOID, b)))),
    seq(...parsed.crls.map((b) => octet(digest(hashOID, b)))),
    seq(...unsignedValues(parsed).map((v) => octet(digest(hashOID, v.input)))),
  );
}
function archiveImprint(parsed, hashOID, index) {
  check(Buffer.isBuffer(parsed.content), 'CADES_DETACHED_CONTENT_MISSING', 'INDETERMINATE');
  return digest(
    hashOID,
    Buffer.concat([parsed.eci[0].raw, digest(hashOID, parsed.content), ...parsed.core, index]),
  );
}
function matchIndex(index, parsed, info, token) {
  check(index.tag === 0x30 && index.children.length === 4, 'CADES_ARCHIVE_INDEX_ENCODING');
  const hashOID = hashAlgorithm(index.children[0]);
  check(hashOID === info.hashOID, 'CADES_ARCHIVE_INDEX_ALGORITHM');
  const values = unsignedValues(parsed);
  const candidates = [
    parsed.certificates.map((raw) => ({ raw, input: raw })),
    parsed.crls.map((raw) => ({ raw, input: raw })),
    values,
  ];
  const matches = index.children.slice(1).map((list, i) => {
    check(list.tag === 0x30, 'CADES_ARCHIVE_INDEX_ENCODING');
    const consumed = new Set();
    return list.children.map((hash) => {
      check(
        hash.tag === 4 && hash.value.length === digest(hashOID, Buffer.alloc(0)).length,
        'CADES_ARCHIVE_INDEX_HASH',
      );
      const position = candidates[i].findIndex(
        (v, position) => !consumed.has(position) && equal(digest(hashOID, v.input), hash.value),
      );
      check(position >= 0, 'CADES_ARCHIVE_INDEX_BINDING');
      consumed.add(position);
      const item = candidates[i][position];
      check(i !== 2 || !equal(item.raw, token), 'CADES_ARCHIVE_SELF_COVERAGE');
      return item;
    });
  });
  check(equal(info.imprint, archiveImprint(parsed, hashOID, index.raw)), 'CADES_ARCHIVE_IMPRINT');
  return {
    certificates: matches[0].map((v) => v.raw),
    crls: matches[1].map((v) => v.raw),
    values: matches[2],
    index: index.raw,
  };
}

function deadline(map, id, failures, kind) {
  const value = map?.[id];
  if (!instant(value)) {
    failures.push(result('INDETERMINATE', `CADES_${kind}_DEADLINE_MISSING`));
    return undefined;
  }
  return value;
}
function protection(signature, policy, failures, imprintHash) {
  const values = [
    deadline(policy.algorithmDeadlines, signature.signatureOID, failures, 'ALGORITHM'),
    deadline(policy.hashDeadlines, signature.hashOID, failures, 'HASH'),
    deadline(policy.hashDeadlines, signature.essHash, failures, 'HASH'),
  ];
  if (imprintHash) values.push(deadline(policy.hashDeadlines, imprintHash, failures, 'HASH'));
  if (signature.x509)
    values.push(
      deadline(
        policy.keyDeadlines,
        keyID(signature.x509.publicKey).toString('hex'),
        failures,
        'KEY',
      ),
    );
  return values.every(instant) ? Math.min(...values) : undefined;
}
function policyCheck(policy) {
  check(
    policy && Array.isArray(policy.trustedRoots) && policy.trustedRoots.length > 0,
    'CADES_TRUST_ROOTS_MISSING',
    'INDETERMINATE',
  );
  check(
    policy.scope &&
      Buffer.isBuffer(policy.scope.trustDomainID) &&
      policy.scope.trustDomainID.length === 32 &&
      typeof policy.scope.issuerID === 'string' &&
      policy.scope.issuerID.length > 0 &&
      policy.scope.representation === 'X509',
    'CADES_POLICY_SCOPE',
  );
  check(
    typeof policy.authorityResolver === 'function',
    'AUTHORITY_RESOLVER_REQUIRED',
    'INDETERMINATE',
  );
}
function parseTimestampInfo(raw) {
  const root = parseDER(raw),
    fields = root.children;
  check(
    root.tag === 0x30 &&
      fields?.length >= 5 &&
      fields[0].tag === 2 &&
      intValue(fields[0]) === 1n &&
      fields[1].tag === 6 &&
      fields[2].tag === 0x30 &&
      fields[2].children.length === 2 &&
      fields[2].children[0].tag === 0x30 &&
      fields[2].children[1].tag === 4 &&
      fields[3].tag === 2 &&
      intValue(fields[3]) > 0n &&
      fields[4].tag === 24,
    'CADES_TSTINFO_ENCODING',
  );
  let previous = -1;
  for (const field of fields.slice(5)) {
    const rank = [0x30, 0x01, 0x02, 0xa0, 0xa1].indexOf(field.tag);
    check(rank > previous, 'CADES_TSTINFO_FIELD_ORDER');
    previous = rank;
  }
  if (fields.some((field) => field.tag === 0xa1))
    throw failure('UNSUPPORTED', 'CADES_TSTINFO_EXTENSIONS_UNSUPPORTED');
  // Classify a recognized unselected imprint before the older timestamp parser
  // reports its deliberately narrower SHA-256/SHA-512 constraint as malformed.
  hashAlgorithm(fields[2].children[0]);
  return parseTSTInfo(raw);
}
function timestamp(parsed, value, failures, policy, times, archive) {
  const local = [];
  const cms = attempt(local, () => parseCMS(value.raw, undefined, OID.tstInfo));
  if (!cms) {
    if (local.some((f) => f.reason === 'CADES_MULTIPLE_SIGNERS'))
      inspectMultipleSigners(value.raw, undefined, OID.tstInfo, local, true);
    failures.push(...local);
    return undefined;
  }
  const signature = inspectSignature(cms, local, true);
  const info = attempt(local, () => parseTimestampInfo(cms.content));
  let coverage;
  if (info) {
    attempt(local, () => {
      const encoded = parseDER(cms.content),
        timeNode = encoded.children[4];
      const timeText = timeNode.value.toString('ascii');
      const fraction = /\.(\d+)Z$/.exec(timeText)?.[1];
      check(
        !fraction || (fraction.length <= 3 && !fraction.endsWith('0')),
        'CADES_TIMESTAMP_PRECISION_UNSUPPORTED',
        'UNSUPPORTED',
      );
      const canonical = new Date(info.genTime * 1000)
        .toISOString()
        .replace(/[-:T]/g, '')
        .replace(/\.000Z$/, 'Z')
        .replace(/(\.\d*?[1-9])0+Z$/, '$1Z');
      check(canonical === timeText, 'CADES_TIMESTAMP_TIME_ENCODING');
      const tsaName = encoded.children.slice(5).find((n) => n.tag === 0xa0);
      if (tsaName && signature.certificate) {
        check(
          tsaName.children.length === 1 && tsaName.children[0].tag === 0xa4,
          'CADES_TSA_NAME_UNSUPPORTED',
          'UNSUPPORTED',
        );
        const names = tsaName.children[0].children;
        const certFields = parseDER(signature.certificate).children[0].children;
        const offset = certFields[0].tag === 0xa0 ? 1 : 0;
        check(
          names.length === 1 && equal(names[0].raw, certFields[offset + 4].raw),
          'CADES_TSA_NAME_BINDING',
        );
      }
      check(
        Array.isArray(policy.timestampPolicies) && policy.timestampPolicies.length > 0,
        'CADES_TIMESTAMP_POLICIES_MISSING',
        'INDETERMINATE',
      );
      check(policy.timestampPolicies.includes(info.policy), 'CADES_TIMESTAMP_POLICY');
      check(
        instant(info.accuracy) && instant(info.poeUpperBound),
        'CADES_TIMESTAMP_ACCURACY_MISSING',
        'INDETERMINATE',
      );
      check(info.genTime - info.accuracy >= 0, 'CADES_TIMESTAMP_TIME');
      check(
        info.poeUpperBound <= times.knowledgeTime &&
          (archive || info.poeUpperBound <= times.validationTime),
        'CADES_TIMESTAMP_NOT_YET_KNOWN',
        'INDETERMINATE',
      );
    });
    if (archive)
      coverage = attempt(local, () => {
        const indexes = cms.unsigned.filter((a) => a.id === INDEX);
        check(indexes.length > 0, 'CADES_ARCHIVE_INDEX_MISSING', 'INDETERMINATE');
        check(indexes.length === 1, 'CADES_ARCHIVE_INDEX_DUPLICATE');
        return matchIndex(indexes[0].values[0], parsed, info, value.raw);
      });
    else
      attempt(local, () =>
        check(
          equal(info.imprint, digest(info.hashOID, parsed.si[5].value)),
          'CADES_SIGNATURE_TIMESTAMP_IMPRINT',
        ),
      );
  }
  for (const a of cms.unsigned)
    if (!(archive && a.id === INDEX))
      local.push(result('UNSUPPORTED', 'CADES_TSA_UNSIGNED_ATTRIBUTE'));
  const validUntil = protection(signature, policy, local, info?.hashOID);
  const item = { token: value.raw, cms, signature, info, coverage, failures: local, validUntil };
  failures.push(...local);
  return item;
}
function originalLink(parsed, originalCMS, content, failures) {
  if (originalCMS === undefined) return undefined;
  return attempt(failures, () => {
    const original = parseCMS(originalCMS, content);
    const priorFailures = [],
      prior = inspectSignature(original, priorFailures);
    failures.push(...priorFailures);
    check(
      equal(original.content, parsed.content) &&
        original.contentType === parsed.contentType &&
        original.core.every((raw, i) => equal(raw, parsed.core[i])),
      'CADES_ORIGINAL_SIGNATURE_MISMATCH',
    );
    const currentFailures = [],
      current = inspectSignature(parsed, currentFailures);
    check(equal(prior.certificate, current.certificate), 'CADES_ORIGINAL_CERTIFICATE_MISMATCH');
    // AttributeValue instances may be appended to an existing unsigned Attribute
    // (5.5.2 notes 4 and 5), but every old type/value pair must remain byte exact.
    const currentValues = unsignedValues(parsed),
      retained = new Set();
    check(
      unsignedValues(original).every((old) => {
        const position = currentValues.findIndex(
          (value, i) => !retained.has(i) && equal(old.input, value.input),
        );
        if (position < 0) return false;
        retained.add(position);
        return true;
      }),
      'CADES_ORIGINAL_UNSIGNED_ATTRIBUTE_MISMATCH',
    );
    return 'MATCHED';
  });
}
function materialFor(
  signature,
  purpose,
  stateTime,
  parsed,
  policy,
  times,
  failures,
  coverage,
  unprovenSignerTime = false,
) {
  if (!signature.certificate || !instant(stateTime) || stateTime > times.knowledgeTime)
    return undefined;
  const evaluate = (covered) => {
    const certificates = covered?.certificates ?? parsed.certificates;
    const crls = covered?.crls ?? parsed.crls;
    let response = validateCAdESMaterial({
      certificate: Buffer.from(signature.certificate),
      certificates: copy(certificates),
      crls: copy(crls),
      knownCRLs: copy(parsed.crls),
      purpose,
      stateTime,
      knowledgeTime: times.knowledgeTime,
      ...(covered ? { evidenceTime: covered.time } : {}),
      policy: copy(policy),
    });
    if (purpose === 'SIGNER' && unprovenSignerTime && stateTime === times.validationTime) {
      const rootTimeMissing = response.checks.some((item) => item.reason === 'CADES_ROOT_TIME');
      const checks = response.checks.map((item) =>
        item.overall === 'INVALID' &&
        (['CADES_CERTIFICATE_TIME', 'CADES_ROOT_TIME'].includes(item.reason) ||
          (rootTimeMissing &&
            item.authorityRole === 'ISSUER' &&
            item.authorityStateTime === stateTime &&
            ['AUTHORITY_EXPIRED', 'AUTHORITY_NOT_YET_VALID'].includes(item.reason)))
          ? result('INDETERMINATE', 'CADES_SIGNER_POE_MISSING')
          : item,
      );
      // Only normal certificate/issuer time availability is reclassified. In
      // particular, bad signatures, revoked keys and protection cutoffs remain
      // in the same aggregate and retain their INVALID precedence.
      response = { ...response, ...outcome(checks), checks };
    }
    if (
      covered &&
      response.overall === 'VALID' &&
      !(
        response.usedCertificates.every((b) => includes(certificates, b)) &&
        response.usedCRLs.every((b) => includes(crls, b))
      )
    )
      return result('INDETERMINATE', 'CADES_HISTORICAL_MATERIAL_NOT_COVERED');
    return response;
  };
  let response = attempt(failures, () => evaluate(coverage));
  // An incomplete historical slice does not defeat currently authenticated,
  // fresh validation data. This alternative grants no historical evidenceTime.
  if (coverage && response?.overall === 'INDETERMINATE') {
    const current = attempt(failures, () => evaluate(undefined));
    if (current && current.overall !== 'INDETERMINATE') response = current;
  }
  if (response && response.overall !== 'VALID') failures.push(response);
  return response;
}
function coveredBy(item, next) {
  return next?.authenticated && next.coverage?.values.some((v) => equal(v.raw, item.token))
    ? { ...next.coverage, time: next.info.poeUpperBound }
    : undefined;
}
function coveringArchive(item, archives) {
  return archives.find((archive) => coveredBy(item, archive));
}
function materialClosure(material, parsed) {
  return (
    material?.overall === 'VALID' &&
    material.usedCertificates.every((b) => includes(parsed.certificates, b)) &&
    material.usedCRLs.every((b) => includes(parsed.crls, b))
  );
}

/** Verify the selected direct-root/full-CRL CAdES profile with external policy. */
export function verifyCAdES(
  cms,
  { content, minimumLevel = 'B', originalCMS, validationTime, knowledgeTime, policy } = {},
) {
  const failures = [],
    materials = [];
  let parsed,
    signer,
    timestamps = [],
    archives = [],
    linkage;
  try {
    check(LEVELS.includes(minimumLevel), 'CADES_LEVEL_UNSUPPORTED', 'UNSUPPORTED');
    check(
      instant(validationTime) && instant(knowledgeTime) && validationTime <= knowledgeTime,
      'CADES_VALIDATION_TIME',
    );
    cms = Buffer.from(cms);
    content = content === undefined ? undefined : Buffer.from(content);
    policy = copy(policy ?? {});
    parsed = parseCMS(cms, content);
    signer = inspectSignature(parsed, failures);
    attempt(failures, () => policyCheck(policy));
    linkage = originalLink(
      parsed,
      originalCMS === undefined ? undefined : Buffer.from(originalCMS),
      content,
      failures,
    );
    const times = { validationTime, knowledgeTime };
    for (const attr of parsed.unsigned) {
      if (attr.id === OID.timestamp || attr.id === ARCHIVE) {
        const item = timestamp(
          parsed,
          attr.values[0],
          failures,
          policy,
          times,
          attr.id === ARCHIVE,
        );
        if (item) (attr.id === ARCHIVE ? archives : timestamps).push(item);
      } else if (attr.id === INDEX)
        failures.push(result('INVALID', 'CADES_ARCHIVE_INDEX_LOCATION'));
    }
    archives.sort((a, b) => (a.info?.genTime ?? 0) - (b.info?.genTime ?? 0));
    timestamps.sort(
      (a, b) => (a.info?.poeUpperBound ?? Infinity) - (b.info?.poeUpperBound ?? Infinity),
    );
    const allTokenCertificates = union(
      parsed.certificates,
      ...[...timestamps, ...archives].map((t) => t.cms.certificates),
    );
    const currentParsed = { ...parsed, certificates: allTokenCertificates };
    // Work backwards: the newest timestamp needs fresh current status. An older
    // timestamp may use historical CRLs only after a later trusted index covers
    // its exact token and all positive certificate/status dependencies.
    // Any uncovered signature/hash/key layer must still be authentic at actual
    // knowledgeTime, even when the requested signature validation is historical.
    for (let i = archives.length - 1; i >= 0; i--) {
      const item = archives[i],
        next = archives[i + 1],
        local = [];
      const coverage = coveredBy(item, next);
      if (next && item.info && next.info)
        attempt(local, () =>
          check(
            item.info.poeUpperBound <= next.info.genTime - next.info.accuracy,
            'CADES_ARCHIVE_TIME_ORDER',
          ),
        );
      if (item.info && item.signature.certificate) {
        const low = materialFor(
          item.signature,
          'TSA',
          item.info.genTime - item.info.accuracy,
          currentParsed,
          policy,
          times,
          local,
          coverage,
        );
        const high = materialFor(
          item.signature,
          'TSA',
          item.info.poeUpperBound,
          currentParsed,
          policy,
          times,
          local,
          coverage,
        );
        item.material = high;
        materials.push(low, high);
        if (high?.overall === 'VALID' && instant(item.validUntil))
          item.validUntil = Math.min(item.validUntil, high.validUntil);
      }
      if (instant(item.validUntil))
        attempt(local, () =>
          check(
            (next?.info?.poeUpperBound ?? knowledgeTime) < item.validUntil,
            'CADES_PROTECTION_GAP',
          ),
        );
      else local.push(result('INDETERMINATE', 'CADES_PROTECTION_DEADLINE_MISSING'));
      if (item.coverage)
        attempt(local, () => {
          check(
            archives
              .slice(0, i)
              .every((t) => item.coverage.values.some((v) => equal(v.raw, t.token))),
            'CADES_PREVIOUS_ARCHIVE_NOT_COVERED',
          );
          check(
            !archives
              .slice(i + 1)
              .some((t) => item.coverage.values.some((v) => equal(v.raw, t.token))),
            'CADES_ARCHIVE_FUTURE_REFERENCE',
          );
        });
      item.authenticated = outcome([...item.failures, ...local]).overall === 'VALID';
      failures.push(...local);
    }
    for (const item of timestamps) {
      const local = [],
        nextArchive = coveringArchive(item, archives),
        coverage = coveredBy(item, nextArchive);
      if (item.info && item.signature.certificate) {
        const low = materialFor(
          item.signature,
          'TSA',
          item.info.genTime - item.info.accuracy,
          currentParsed,
          policy,
          times,
          local,
          coverage,
        );
        const high = materialFor(
          item.signature,
          'TSA',
          item.info.poeUpperBound,
          currentParsed,
          policy,
          times,
          local,
          coverage,
        );
        item.material = high;
        materials.push(low, high);
        if (high?.overall === 'VALID' && instant(item.validUntil))
          item.validUntil = Math.min(item.validUntil, high.validUntil);
      }
      if (nextArchive?.info && item.info)
        attempt(local, () =>
          check(
            item.info.poeUpperBound <= nextArchive.info.genTime - nextArchive.info.accuracy,
            'CADES_TIMESTAMP_TIME_ORDER',
          ),
        );
      if (instant(item.validUntil))
        attempt(local, () =>
          check(
            (nextArchive?.info?.poeUpperBound ?? knowledgeTime) < item.validUntil,
            'CADES_PROTECTION_GAP',
          ),
        );
      else local.push(result('INDETERMINATE', 'CADES_PROTECTION_DEADLINE_MISSING'));
      item.authenticated = outcome([...item.failures, ...local]).overall === 'VALID';
      failures.push(...local);
    }
    const trustedTimestamp = timestamps.find((t) => t.authenticated);
    // A mathematically valid but currently unavailable timestamp is not a POE.
    // Its candidate time is used only to discover other known failures; its
    // accumulated availability failure still prevents any VALID result. Falling
    // back to the present would incorrectly report ordinary historic expiry as
    // a known invalidity when the actual missing object is current TSA status.
    const candidateTimestamp =
      trustedTimestamp ??
      timestamps.find(
        (t) =>
          instant(t.info?.poeUpperBound) &&
          t.info.poeUpperBound <= validationTime &&
          t.info.poeUpperBound <= knowledgeTime &&
          outcome(t.failures).overall === 'VALID',
      );
    const stateTime = candidateTimestamp?.info.poeUpperBound ?? validationTime;
    const signerCoverage =
      trustedTimestamp && coveredBy(trustedTimestamp, coveringArchive(trustedTimestamp, archives));
    const signerMaterial = materialFor(
      signer,
      'SIGNER',
      stateTime,
      currentParsed,
      policy,
      times,
      failures,
      signerCoverage,
      !candidateTimestamp,
    );
    materials.push(signerMaterial);
    // Every carried signature timestamp must meet baseline timing requirements,
    // even when another, earlier timestamp already establishes a stronger POE.
    for (const item of timestamps) {
      if (!instant(item.info?.poeUpperBound) || item.info.poeUpperBound === stateTime) continue;
      const material = materialFor(
        signer,
        'SIGNER',
        item.info.poeUpperBound,
        currentParsed,
        policy,
        times,
        failures,
        coveredBy(item, coveringArchive(item, archives)),
      );
      materials.push(material);
    }
    const signerDeadline = protection(signer, policy, failures);
    if (instant(signerDeadline) && signerMaterial?.overall === 'VALID')
      attempt(failures, () =>
        check(
          (trustedTimestamp ? stateTime : knowledgeTime) <
            Math.min(signerDeadline, signerMaterial.validUntil),
          'CADES_SIGNER_PROTECTION_GAP',
        ),
      );
    // All certificates used for B path validation must already be carried in the
    // CMS. CurrentMaterial is external trust input, never embedded LT evidence.
    if (signerMaterial?.overall === 'VALID')
      attempt(failures, () =>
        check(
          signerMaterial.usedCertificates.every((b) => includes(parsed.certificates, b)),
          'CADES_BASELINE_CERTIFICATE_MISSING',
          'INDETERMINATE',
        ),
      );
    const completeMaterial = materials.filter(Boolean).every((m) => materialClosure(m, parsed));
    const newest = archives.at(-1);
    const completeArchiveCoverage =
      newest?.authenticated &&
      newest.coverage &&
      parsed.certificates.every((b) => includes(newest.coverage.certificates, b)) &&
      parsed.crls.every((b) => includes(newest.coverage.crls, b)) &&
      unsignedValues(parsed)
        .filter((v) => !equal(v.raw, newest.token))
        .every((v) => newest.coverage.values.some((covered) => equal(v.input, covered.input)));
    let verifiedLevel;
    if (outcome(failures).overall === 'VALID')
      verifiedLevel =
        completeArchiveCoverage && trustedTimestamp && completeMaterial
          ? 'LTA'
          : trustedTimestamp
            ? completeMaterial
              ? 'LT'
              : 'T'
            : 'B';
    // Indexes remain valid when unprotected objects are appended (5.5.2 note 5).
    // The selected LTA policy requires current closure, without reclassifying a
    // correctly authenticated earlier index or a provable lower level as bad.
    if (LEVELS.indexOf(minimumLevel) >= 1 && !timestamps.length)
      failures.push(result('INDETERMINATE', 'CADES_SIGNATURE_TIMESTAMP_MISSING'));
    if (LEVELS.indexOf(minimumLevel) >= 2 && !completeMaterial)
      failures.push(result('INDETERMINATE', 'CADES_LT_MATERIAL_MISSING'));
    if (minimumLevel === 'LTA') {
      if (!archives.length)
        failures.push(result('INDETERMINATE', 'CADES_ARCHIVE_TIMESTAMP_MISSING'));
      else if (!completeArchiveCoverage)
        failures.push(result('INDETERMINATE', 'CADES_ARCHIVE_COVERAGE_MISSING'));
    }
    const final = outcome(failures);
    return result(final.overall, final.reason, {
      requestedLevel: minimumLevel,
      ...(verifiedLevel ? { verifiedLevel } : {}),
      ...(linkage ? { originalCMSLinkage: linkage } : {}),
      ...(trustedTimestamp ? { stateTime, poeUpperBound: stateTime } : {}),
      ...(newest?.authenticated ? { preservationTime: newest.info.poeUpperBound } : {}),
      failures: Object.freeze(failures.map((f) => result(f.overall, f.reason))),
    });
  } catch (error) {
    failures.push(record(error));
    if (error.code === 'CADES_MULTIPLE_SIGNERS')
      inspectMultipleSigners(cms, content, OID.data, failures);
    const final = outcome(failures);
    return result(final.overall, final.reason, {
      requestedLevel: minimumLevel,
      failures: Object.freeze(failures.map((f) => result(f.overall, f.reason))),
    });
  }
}

/** Prepare an immutable candidate and a standard external RFC 3161 request. */
export function prepareCAdESAugmentation(
  cms,
  { content, targetLevel, validationMaterial = {}, timestampRequestOptions = {}, policy } = {},
) {
  check(['T', 'LT', 'LTA'].includes(targetLevel), 'CADES_LEVEL_UNSUPPORTED', 'UNSUPPORTED');
  cms = Buffer.from(cms);
  content = content === undefined ? undefined : Buffer.from(content);
  policy = copy(policy ?? {});
  let parsed = parseCMS(cms, content);
  const failures = [];
  inspectSignature(parsed, failures);
  const initial = outcome(failures);
  if (initial.overall !== 'VALID') throw failure(initial.overall, initial.reason);
  const certificates = union(parsed.certificates, copy(validationMaterial.certificates ?? []));
  const crls = union(parsed.crls, copy(validationMaterial.crls ?? []));
  for (const certificate of certificates) certificateIdentity(certificate);
  for (const crl of crls) check(parseDER(crl).tag === 0x30, 'CADES_CRL_ENCODING');
  const candidate = encodeCMS(parsed, { certificates, crls });
  parsed = parseCMS(candidate, content);
  const options = copy(timestampRequestOptions);
  const hashOID = options.hashOID ?? OID.sha256;
  let index, request;
  if (targetLevel === 'LTA') {
    check(
      parsed.unsigned.some((a) => a.id === OID.timestamp),
      'CADES_SIGNATURE_TIMESTAMP_MISSING',
      'INDETERMINATE',
    );
    index = createIndex(parsed, hashOID);
  }
  if (targetLevel !== 'LT')
    request = timestampRequest(
      targetLevel === 'T'
        ? digest(hashOID, parsed.si[5].value)
        : archiveImprint(parsed, hashOID, index),
      { ...options, hashOID },
    );
  return Object.freeze({
    ...(request
      ? { requestDER: Buffer.from(request.der), imprint: Buffer.from(request.imprint), hashOID }
      : {}),
    finish(token, { validationTime, knowledgeTime, policy: updatedPolicy } = {}) {
      let augmented = candidate;
      if (request) {
        check(Buffer.isBuffer(token), 'CADES_TIMESTAMP_MISSING', 'INDETERMINATE');
        token = Buffer.from(token);
        const timestampCMS = parseCMS(token, undefined, OID.tstInfo);
        const timestampFailures = [];
        inspectSignature(timestampCMS, timestampFailures, true);
        const info = attempt(timestampFailures, () => parseTimestampInfo(timestampCMS.content));
        if (info)
          attempt(timestampFailures, () =>
            check(
              info.hashOID === request.hashOID &&
                equal(info.imprint, request.imprint) &&
                (request.nonce === undefined || info.nonce === request.nonce) &&
                (!request.policy || info.policy === request.policy),
              'CADES_TIMESTAMP_REQUEST_BINDING',
            ),
          );
        const tokenOutcome = outcome(timestampFailures);
        if (tokenOutcome.overall !== 'VALID')
          throw failure(tokenOutcome.overall, tokenOutcome.reason);
        if (index) {
          check(
            !timestampCMS.unsigned.some((a) => a.id === INDEX),
            'CADES_ARCHIVE_INDEX_DUPLICATE',
          );
          token = encodeCMS(timestampCMS, {
            unsigned: [...timestampCMS.unsigned.map((a) => a.raw), attribute(INDEX, index)],
          });
        }
        augmented = encodeCMS(parsed, {
          unsigned: [
            ...parsed.unsigned.map((a) => a.raw),
            attribute(targetLevel === 'T' ? OID.timestamp : ARCHIVE, token),
          ],
          hashOID: index ? hashOID : undefined,
        });
      } else check(token === undefined, 'CADES_UNEXPECTED_TIMESTAMP');
      const verified = verifyCAdES(augmented, {
        content,
        minimumLevel: targetLevel,
        originalCMS: cms,
        validationTime,
        knowledgeTime,
        policy: updatedPolicy === undefined ? policy : copy(updatedPolicy),
      });
      if (verified.overall !== 'VALID') throw failure(verified.overall, verified.reason);
      return Buffer.from(augmented);
    },
  });
}

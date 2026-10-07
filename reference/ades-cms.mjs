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
import { parseTSTInfo } from './timestamp.mjs';

// EN 319 122-1 V1.3.1, clauses 5.5.2 and 5.5.3. These are standard CMS
// attributes; the original SignerInfo's six signed fields are never re-encoded.
const SIGNING_TIME = '1.2.840.113549.1.9.5';
const ALGORITHM_PROTECTION = '1.2.840.113549.1.9.52';
const MIME_TYPE = '0.4.0.1733.2.1';
const ARCHIVE = '0.4.0.1733.2.4';
const INDEX = '0.4.0.19122.1.5';
const ECDSA_SHA256 = '1.2.840.10045.4.3.2';
const HASHES = { [OID.sha256]: 'sha256', [OID.sha512]: 'sha512' };
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

function signerIdentifierVersion(signer) {
  check(
    signer?.tag === 0x30 && signer.children.length >= 6 && signer.children.length <= 7,
    'CADES_SIGNER_INFO',
  );
  const si = signer.children,
    version = intValue(si[0]);
  check(
    si[5].tag === 4 &&
      ((version === 1n &&
        si[1].tag === 0x30 &&
        si[1].children.length === 2 &&
        si[1].children[1].tag === 2) ||
        (version === 3n && si[1].tag === 0x80 && si[1].value.length > 0)),
    'CADES_SIGNER_IDENTIFIER',
  );
  return version;
}
function signedDataVersion(certificates, crls, signers, contentType) {
  // RFC 5652 section 5.1 derives the container version from every raw Choice
  // and SignerInfo, including recognized choices outside the selected profile.
  const versions = signers.map(signerIdentifierVersion);
  if (certificates.some((raw) => raw[0] === 0xa3) || crls.some((raw) => raw[0] === 0xa1)) return 5n;
  if (certificates.some((raw) => raw[0] === 0xa2)) return 4n;
  if (
    certificates.some((raw) => raw[0] === 0xa1) ||
    versions.includes(3n) ||
    contentType !== OID.data
  )
    return 3n;
  return 1n;
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
  const certificatesPresent = sd[at]?.tag === 0xa0;
  if (contentType !== expectedType)
    unsupported.push(result('UNSUPPORTED', 'CADES_CONTENT_TYPE_UNSUPPORTED'));
  if (sd[at]?.tag === 0xa0) {
    canonicalImplicit(sd[at], 0xa0, 'CADES_CERTIFICATE_SET');
    certificates = sd[at++].children.map((n) => {
      check([0x30, 0xa0, 0xa1, 0xa2, 0xa3].includes(n.tag), 'CADES_CERTIFICATE_CHOICE_ENCODING');
      if (n.tag !== 0x30) unsupported.push(result('UNSUPPORTED', 'CADES_CERTIFICATE_CHOICE'));
      return n.raw;
    });
    unique(certificates, 'CADES_DUPLICATE_CERTIFICATE');
    check(certificates.length <= 128, 'CADES_CERTIFICATE_LIMIT');
  }
  if (sd[at]?.tag === 0xa1) {
    canonicalImplicit(sd[at], 0xa1, 'CADES_REVOCATION_SET');
    crls = sd[at++].children.map((n) => {
      check([0x30, 0xa1].includes(n.tag), 'CADES_REVOCATION_CHOICE_ENCODING');
      if (n.tag !== 0x30) unsupported.push(result('UNSUPPORTED', 'CADES_REVOCATION_CHOICE'));
      return n.raw;
    });
    unique(crls, 'CADES_DUPLICATE_CRL');
    check(crls.length <= 128, 'CADES_CRL_LIMIT');
  }
  check(at === sd.length - 1 && sd[at].tag === 0x31, 'CADES_SIGNER_INFOS');
  check(sd[at].children.length <= 16, 'CADES_SIGNER_LIMIT');
  check(
    version === signedDataVersion(certificates, crls, sd[at].children, contentType),
    'CADES_SIGNED_DATA_VERSION',
  );
  check(sd[at].children.length === 1, 'CADES_MULTIPLE_SIGNERS', 'UNSUPPORTED');
  const si = sd[at].children[0].children;
  if (si[1].tag === 0x80)
    unsupported.push(result('UNSUPPORTED', 'CADES_SIGNER_IDENTIFIER_UNSUPPORTED'));
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
    certificatesPresent,
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
function inspectSignature(parsed, failures, profile = 'CADES', externalCertificates = []) {
  const isTimestamp = profile !== 'CADES';
  if (profile === 'PADES') inspectPAdESAttributes(parsed, failures);
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
  const unselectedIdentifier = parsed.si[1].tag === 0x80;
  const certificateCandidates = union(parsed.certificates, externalCertificates);
  for (const cert of certificateCandidates) {
    if (cert[0] !== 0x30) continue;
    const identity = attempt(failures, () => certificateIdentity(cert));
    // SKI identification remains unsupported. An exact ESS-bound certificate
    // still supplies a key for the bounded mathematical scan; it never grants
    // profile acceptance or an unimplemented SKI binding decision.
    if (
      identity &&
      (unselectedIdentifier
        ? ess && equal(digest(ess.hashOID, cert), ess.hash)
        : equal(identity.sid, parsed.si[1].raw))
    )
      candidates.push({ cert, ...identity });
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
      !unselectedIdentifier &&
      signatureOID === ECDSA_SHA256 &&
      certificateCandidates.some((raw) => {
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
    certificateSource: selected
      ? includes(parsed.certificates, selected.cert) ? 'EMBEDDED' : 'EXTERNAL'
      : undefined,
    x509: selected?.x509,
    hashOID,
    signatureOID,
    essHash: ess?.hashOID,
  };
}

// Multiple signers remain outside this profile. A bounded scan still detects
// known failures in SignerInfos whose mathematical signature suite is selected;
// unsupported multiplicity must not conceal an available bad digest/signature.
function inspectMultipleSigners(raw, content, expectedType, failures, profile = 'CADES', externalCertificates = []) {
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
        ![1n, 3n].includes(intValue(fields[0])) ||
        ![0x30, 0x80].includes(fields[1].tag)
      )
        continue;
      attempt(failures, () => {
        const certificates = sd.slice(3, -1).find((n) => n.tag === 0xa0)?.children ?? [],
          crls = sd.slice(3, -1).find((n) => n.tag === 0xa1)?.children ?? [];
        const single = seq(
          root.children[0].raw,
          der(
            0xa0,
            seq(
              integer(
                signedDataVersion(
                  certificates.map((n) => n.raw),
                  crls.map((n) => n.raw),
                  [signer],
                  oidText(sd[2].children[0]),
                ),
              ),
              ...sd.slice(1, -1).map((n) => n.raw),
              set(signer.raw),
            ),
          ),
        );
        inspectSignature(parseCMS(single, content, expectedType), failures, profile, externalCertificates);
      });
    }
  });
}

// These are the optional CMS services listed in EN 319 142-1 V1.2.1
// Table 1, but not implemented by the selected document-timestamp route.
const PADES_OPTIONAL = new Set([
  '1.2.840.113549.1.9.16.2.12',
  '1.2.840.113549.1.9.16.2.15',
  '1.2.840.113549.1.9.16.2.16',
  '1.2.840.113549.1.9.16.2.20',
  '0.4.0.19122.1.1',
  OID.timestamp,
]);
const PADES_FORBIDDEN = new Set([
  SIGNING_TIME,
  ALGORITHM_PROTECTION,
  MIME_TYPE,
  ARCHIVE,
  INDEX,
  '1.2.840.113549.1.9.16.2.4', // EN319122-1 5.2.4.1 content hints
  '1.2.840.113549.1.9.16.2.17', // 5.2.5 signer location
  '0.4.0.19122.1.2', // 5.2.6.2 claimed SAML assertion
  '1.2.840.113549.1.9.6', // 5.2.7 countersignature
  '0.4.0.19122.1.3', // 5.2.10 signature policy store
  '1.2.840.113549.1.9.16.2.10', // 5.2.11 content reference
  '1.2.840.113549.1.9.16.2.7', // 5.2.12 content identifier
]);
function inspectPAdESAttributes(parsed, failures) {
  if (parsed.contentType !== OID.data) failures.push(result('INVALID', 'PADES_CONTENT_TYPE'));
  if (parsed.eci.length !== 1) failures.push(result('INVALID', 'PADES_DETACHED_CONTENT_REQUIRED'));
  for (const attr of [...parsed.signed, ...parsed.unsigned]) {
    if (PADES_FORBIDDEN.has(attr.id)) failures.push(result('INVALID', 'PADES_ATTRIBUTE_FORBIDDEN'));
    else if (![OID.contentType, OID.messageDigest, OID.ess].includes(attr.id))
      failures.push(result('UNSUPPORTED', 'PADES_ATTRIBUTE_UNSUPPORTED'));
  }
}

/** Internal mathematical inspection. No path, authority or baseline verdict. */
export function inspectAdESSignature(cms, { content, profile, externalCertificates = [] } = {}) {
  const failures = [];
  let parsed, signature;
  try {
    check(
      ['CADES', 'PADES', 'RFC3161'].includes(profile),
      'ADES_PROFILE_UNSUPPORTED',
      'UNSUPPORTED',
    );
    cms = Buffer.from(cms);
    content = content === undefined ? undefined : Buffer.from(content);
    check(Array.isArray(externalCertificates) && externalCertificates.length <= 128 &&
      externalCertificates.every(Buffer.isBuffer), 'ADES_EXTERNAL_CERTIFICATES');
    check(profile === 'RFC3161' || externalCertificates.length === 0,
      'ADES_EXTERNAL_CERTIFICATES_PROFILE', 'UNSUPPORTED');
    externalCertificates = copy(externalCertificates);
    parsed = parseCMS(cms, content, profile === 'RFC3161' ? OID.tstInfo : OID.data);
    signature = inspectSignature(parsed, failures, profile, externalCertificates);
  } catch (error) {
    failures.push(record(error));
    if (error.code === 'CADES_MULTIPLE_SIGNERS') {
      inspectMultipleSigners(
        cms,
        content,
        profile === 'RFC3161' ? OID.tstInfo : OID.data,
        failures,
        profile,
        externalCertificates,
      );
      // EN 319 142-1 4.1(a) requires exactly one SignerInfo. Scan known
      // mathematical failures first so this PDF constraint cannot hide them.
      if (profile === 'PADES') failures.push(result('INVALID', 'PADES_MULTIPLE_SIGNERS'));
    }
  }
  return Object.freeze({
    ...outcome(failures),
    failures: Object.freeze(failures),
    parsed,
    signature,
  });
}
/** Create a new baseline-capable signature; no existing signed field is repaired. */
export function prepareAdESSignature({
  profile,
  content,
  certificate,
  certificates = [],
  detached = profile === 'PADES',
  signingTime: time,
  additionalSignedAttributes = [],
  algorithmProfile = 'ES256',
  includeCertificates = true,
}) {
  check(['CADES', 'PADES', 'RFC3161'].includes(profile), 'ADES_PROFILE_UNSUPPORTED', 'UNSUPPORTED');
  check(profile !== 'PADES' || detached, 'PADES_DETACHED_CONTENT_REQUIRED');
  check(typeof includeCertificates === 'boolean' &&
    (profile === 'RFC3161' || includeCertificates), 'ADES_CERTIFICATE_EMBEDDING');
  check(profile !== 'RFC3161' || !detached, 'TSP_EMBEDDED_CONTENT_REQUIRED');
  check(algorithmProfile === 'ES256', 'CADES_SIGNATURE_SUITE_UNSUPPORTED', 'UNSUPPORTED');
  check(
    Buffer.isBuffer(content) && Buffer.isBuffer(certificate) && typeof detached === 'boolean',
    'CADES_SIGNATURE_INPUT',
  );
  if (profile === 'CADES')
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
  const encodedTime = new Date((time ?? 0) * 1000)
    .toISOString()
    .replace(/[-:T]/g, '')
    .replace('.000Z', 'Z');
  const year = Number(encodedTime.slice(0, 4));
  const contentType = profile === 'RFC3161' ? OID.tstInfo : OID.data;
  const attrs = [
    attribute(OID.contentType, oid(contentType)),
    attribute(OID.messageDigest, octet(digest(OID.sha256, content))),
    attribute(OID.ess, seq(seq(seq(octet(digest(OID.sha256, certificate)))))),
    ...(profile === 'CADES'
      ? [
          attribute(
            SIGNING_TIME,
            der(
              year >= 1950 && year <= 2049 ? 23 : 24,
              Buffer.from(year >= 1950 && year <= 2049 ? encodedTime.slice(2) : encodedTime),
            ),
          ),
        ]
      : []),
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
            integer(profile === 'RFC3161' ? 3 : 1),
            set(algID(OID.sha256)),
            seq(oid(contentType), ...(detached ? [] : [der(0xa0, octet(content))])),
            ...(includeCertificates ? [der(0xa0, parseDER(set(...certificates)).value)] : []),
            set(si),
          ),
        ),
      );
      const failures = [];
      inspectSignature(parseCMS(cms, content, contentType), failures, profile,
        includeCertificates ? [] : [certificate]);
      const checked = outcome(failures);
      if (checked.overall !== 'VALID') throw failure(checked.overall, checked.reason);
      return cms;
    },
  });
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

/** Internal RFC3161 math/schema inspection. The caller must authenticate trust. */
export function inspectRFC3161Token(token, { request, externalCertificates = [] } = {}) {
  const inspected = inspectAdESSignature(token, { profile: 'RFC3161', externalCertificates });
  const failures = [...inspected.failures],
    cms = inspected.parsed,
    signature = inspected.signature;
  const info =
    cms?.contentType === OID.tstInfo
      ? attempt(failures, () => parseTimestampInfo(cms.content))
      : undefined;
  if (info) {
    attempt(failures, () => {
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
        instant(info.accuracy) && instant(info.poeUpperBound),
        'CADES_TIMESTAMP_ACCURACY_MISSING',
        'INDETERMINATE',
      );
      check(info.genTime - info.accuracy >= 0, 'CADES_TIMESTAMP_TIME');
    });
    if (request)
      attempt(failures, () =>
        check(
          info.hashOID === request.hashOID &&
            equal(info.imprint, request.imprint) &&
            (request.nonce === undefined || info.nonce === request.nonce) &&
            (!request.policy || info.policy === request.policy),
          'CADES_TIMESTAMP_REQUEST_BINDING',
        ),
      );
  }
  return Object.freeze({
    ...outcome(failures),
    failures: Object.freeze(failures),
    parsed: cms,
    signature,
    info,
  });
}

/** Explicit finite crypto protection horizon, independent of certificate expiry. */
export function proofProtectionDeadline(signature, { policy, imprintHashOID } = {}) {
  const failures = [];
  const validUntil = protection(signature, copy(policy ?? {}), failures, imprintHashOID);
  return Object.freeze({ ...outcome(failures), failures: Object.freeze(failures), validUntil });
}

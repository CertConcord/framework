import { X509Certificate, verify as verifySignature } from 'node:crypto';
import {
  parseDER,
  oidText,
  intValue,
  equal,
  keyID,
  sha256,
  requireThat,
  ProtocolError,
} from './core.mjs';
import { parseCertificate, validateKeyUsage, generalizedTime } from './pki.mjs';

const ES256 = '1.2.840.10045.4.3.2';
const SHA256 = '2.16.840.1.101.3.4.2.1';
const TSA_EKU = '1.3.6.1.5.5.7.3.8';
const EMAIL_EKU = '1.3.6.1.5.5.7.3.4';
const EMAIL_NAME = '1.2.840.113549.1.9.1';
const SMTP_UTF8_NAME = '1.3.6.1.5.5.7.8.9';
const RSA_KEY = '1.2.840.113549.1.1.1';
const mailPurpose = (purpose) => ['SMIME_SIGNING', 'SMIME_RECIPIENT_ENCRYPTION'].includes(purpose);
const outcome = (overall, reason, details = {}) => ({ overall, reason, ...details });
const instant = (value) => Number.isFinite(value) && value >= 0 && value <= Number.MAX_SAFE_INTEGER;
const deadline = (value) => Number.isSafeInteger(value) && value > 0;
const unique = (values) => [
  ...new Map(values.map((raw) => [raw.toString('hex'), Buffer.from(raw)])).values(),
];
const classified = (error) =>
  outcome(
    error.overall ??
      (/UNSUPPORTED/.test(error.code)
        ? 'UNSUPPORTED'
        : /MISSING|REQUIRED|UNAVAILABLE|STALE|CONFLICT/.test(error.code)
          ? 'INDETERMINATE'
          : 'INVALID'),
    error.code ?? 'CADES_MATERIAL_MALFORMED',
  );

function extensions(node) {
  requireThat(node?.tag === 0x30 && node.children, 'CADES_EXTENSION_STRUCTURE');
  const values = new Map();
  for (const entry of node.children) {
    const parts = entry.children;
    requireThat(
      entry.tag === 0x30 &&
        [2, 3].includes(parts?.length) &&
        parts[0].tag === 6 &&
        parts.at(-1).tag === 4,
      'CADES_EXTENSION_STRUCTURE',
    );
    const id = oidText(parts[0]),
      critical = parts.length === 3;
    requireThat(!values.has(id), 'CADES_DUPLICATE_EXTENSION');
    requireThat(
      !critical || equal(parts[1].raw, Buffer.from('0101ff', 'hex')),
      'CADES_EXTENSION_CRITICAL',
    );
    values.set(id, { critical, value: parts.at(-1).value });
  }
  return values;
}

function time(node) {
  requireThat(node && [23, 24].includes(node.tag), 'CADES_TIME_ENCODING');
  let text = node.value.toString('ascii');
  if (node.tag === 23) {
    requireThat(/^\d{12}Z$/.test(text), 'CADES_TIME_ENCODING');
    text = (Number(text.slice(0, 2)) >= 50 ? '19' : '20') + text;
  }
  requireThat(/^\d{14}Z$/.test(text), 'CADES_TIME_ENCODING');
  const seconds =
    Date.parse(
      `${text.slice(0, 4)}-${text.slice(4, 6)}-${text.slice(6, 8)}T` +
        `${text.slice(8, 10)}:${text.slice(10, 12)}:${text.slice(12, 14)}Z`,
    ) / 1000;
  requireThat(Number.isSafeInteger(seconds), 'CADES_TIME_ENCODING');
  requireThat(
    parseDER(generalizedTime(seconds)).value.toString('ascii') === text,
    'CADES_TIME_ENCODING',
  );
  return seconds;
}

function p256(key) {
  requireThat(
    key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails?.namedCurve === 'prime256v1',
    'CADES_KEY_ALGORITHM_UNSUPPORTED',
  );
}

function certificate(raw) {
  requireThat(Buffer.isBuffer(raw), 'CADES_CERTIFICATE_STRUCTURE');
  const parsed = parseCertificate(raw),
    native = new X509Certificate(raw);
  requireThat(parsed.serial > 0n, 'CADES_CERTIFICATE_SERIAL');
  return { ...parsed, native };
}

function mailRequire(condition, reason, overall = 'INVALID') {
  if (!condition) throw Object.assign(new ProtocolError(reason), { overall });
}

function recipientKey(cert) {
  mailRequire(
    cert.publicKey.asymmetricKeyType === 'rsa' &&
      [3072, 4096].includes(cert.publicKey.asymmetricKeyDetails?.modulusLength),
    'SMIME_RECIPIENT_KEY_ALGORITHM_UNSUPPORTED',
    'UNSUPPORTED',
  );
  const algorithm = parseDER(cert.spki).children[0];
  mailRequire(
    algorithm?.tag === 0x30 &&
      algorithm.children?.[0]?.tag === 6 &&
      oidText(algorithm.children[0]) === RSA_KEY,
    'SMIME_RECIPIENT_KEY_ALGORITHM_UNSUPPORTED',
    'UNSUPPORTED',
  );
  mailRequire(
    algorithm.children.length === 2 && equal(algorithm.children[1].raw, Buffer.from('0500', 'hex')),
    'SMIME_RSA_KEY_PARAMETERS',
  );
}

function certificateProfile(cert, purpose) {
  const permitted = new Set(['2.5.29.19', '2.5.29.15', '2.5.29.14', '2.5.29.35', '2.5.29.37']);
  if (mailPurpose(purpose)) permitted.add('2.5.29.17');
  for (const [id, extension] of cert.extensions) {
    requireThat(
      !extension.critical || permitted.has(id),
      'CADES_CERTIFICATE_EXTENSION_UNSUPPORTED',
    );
    requireThat(
      !['2.5.29.30', '2.5.29.36', '2.5.29.54'].includes(id),
      'CADES_CERTIFICATE_CONSTRAINTS_UNSUPPORTED',
    );
  }
  if (purpose === 'SMIME_RECIPIENT_ENCRYPTION') recipientKey(cert);
  else p256(cert.publicKey);
  requireThat(
    cert.algorithm === ES256 && parseDER(cert.algorithmRaw).children.length === 1,
    'CADES_CERTIFICATE_ALGORITHM_UNSUPPORTED',
  );
}

function keyIdentifier(cert) {
  const value = cert.extensions.get('2.5.29.14');
  if (!value) return undefined;
  const parsed = parseDER(value.value);
  requireThat(
    parsed.tag === 4 && parsed.value.length > 0 && !value.critical,
    'CADES_SUBJECT_KEY_IDENTIFIER',
  );
  return parsed.value;
}

function authorityKeyBinding(value, issuer) {
  requireThat(value && !value.critical, 'CADES_AUTHORITY_KEY_IDENTIFIER_REQUIRED');
  const parsed = parseDER(value.value);
  requireThat(
    parsed.tag === 0x30 && parsed.children?.length === 1 && parsed.children[0].tag === 0x80,
    'CADES_AUTHORITY_KEY_IDENTIFIER_UNSUPPORTED',
  );
  const expected = keyIdentifier(issuer);
  requireThat(expected && equal(parsed.children[0].value, expected), 'CADES_AUTHORITY_KEY_BINDING');
}

function certificateUsage(cert, purpose, mail = false) {
  const usage = validateKeyUsage(
    cert.extensions.get('2.5.29.15'),
    undefined,
    'CADES_CERTIFICATE_KEY_USAGE',
  );
  const basic = cert.extensions.get('2.5.29.19');
  if (mail) mailRequire(cert.extensions.get('2.5.29.15')?.critical, 'SMIME_KEY_USAGE_CRITICAL');
  if (purpose === 'ROOT') {
    requireThat(
      cert.native.ca && basic?.critical && (usage[0] & 6) === 6,
      'CADES_ROOT_CONSTRAINTS',
    );
    const constraints = parseDER(basic.value);
    requireThat(
      constraints.tag === 0x30 &&
        [1, 2].includes(constraints.children?.length) &&
        equal(constraints.children[0].raw, Buffer.from('0101ff', 'hex')) &&
        (!constraints.children[1] ||
          (constraints.children[1].tag === 2 && intValue(constraints.children[1]) >= 0n)),
      'CADES_ROOT_CONSTRAINTS',
    );
    requireThat(!cert.extensions.has('2.5.29.37'), 'CADES_ROOT_EKU_UNSUPPORTED');
  } else {
    const requiredUsage = purpose === 'SMIME_RECIPIENT_ENCRYPTION' ? 0x20 : 0x80;
    requireThat(
      !cert.native.ca && (usage[0] & requiredUsage) !== 0 && (usage[0] & 6) === 0,
      purpose === 'SMIME_RECIPIENT_ENCRYPTION'
        ? 'SMIME_RECIPIENT_KEY_USAGE'
        : 'CADES_SIGNER_KEY_USAGE',
    );
    if (basic) {
      const constraints = parseDER(basic.value);
      requireThat(
        constraints.tag === 0x30 && constraints.children?.length === 0,
        'CADES_END_ENTITY_CONSTRAINTS',
      );
    }
    const eku = cert.extensions.get('2.5.29.37');
    if (purpose === 'TSA') {
      const values = eku && parseDER(eku.value);
      requireThat(
        eku?.critical &&
          values.tag === 0x30 &&
          values.children?.length === 1 &&
          values.children[0].tag === 6 &&
          oidText(values.children[0]) === TSA_EKU,
        'CADES_TSA_EKU',
      );
    } else if (mailPurpose(purpose)) {
      const values = eku && parseDER(eku.value);
      mailRequire(
        values?.tag === 0x30 &&
          values.children?.length > 0 &&
          values.children.every((value) => value.tag === 6),
        'SMIME_EMAIL_PROTECTION_REQUIRED',
      );
      const identifiers = values.children.map(oidText);
      mailRequire(identifiers.includes(EMAIL_EKU), 'SMIME_EMAIL_PROTECTION_REQUIRED');
    } else {
      requireThat(!eku, 'CADES_SIGNER_EKU_UNSUPPORTED');
    }
  }
}

function certificateMailNames(cert) {
  const extension = cert.extensions.get('2.5.29.17'),
    rfc822Names = [],
    otherGeneralNames = [];
  let legacySubjectEmailPresent = false;
  const subject = parseDER(cert.subject);
  mailRequire(subject.tag === 0x30 && subject.children, 'SMIME_CERTIFICATE_NAME_ENCODING');
  for (const rdn of subject.children) {
    mailRequire(rdn.tag === 0x31 && rdn.children?.length > 0, 'SMIME_CERTIFICATE_NAME_ENCODING');
    for (const attribute of rdn.children) {
      const values = attribute.children;
      mailRequire(
        attribute.tag === 0x30 && values?.length === 2 && values[0].tag === 6,
        'SMIME_CERTIFICATE_NAME_ENCODING',
      );
      if (oidText(values[0]) === EMAIL_NAME) {
        mailRequire(
          values[1].tag === 0x16 &&
            values[1].value.length > 0 &&
            values[1].value.length <= 255 &&
            values[1].value.every((octet) => octet <= 0x7f),
          'SMIME_CERTIFICATE_NAME_ENCODING',
        );
        legacySubjectEmailPresent = true;
      }
    }
  }
  if (extension) {
    const names = parseDER(extension.value);
    mailRequire(
      names.tag === 0x30 && names.children?.length > 0,
      'SMIME_CERTIFICATE_NAME_ENCODING',
    );
    for (const name of names.children) {
      mailRequire(
        [0xa0, 0x81, 0x82, 0xa3, 0xa4, 0xa5, 0x86, 0x87, 0x88].includes(name.tag),
        'SMIME_CERTIFICATE_NAME_ENCODING',
      );
      if (name.tag === 0x81) {
        mailRequire(
          name.value.length > 0 && name.value.every((octet) => octet <= 0x7f),
          'SMIME_CERTIFICATE_NAME_ENCODING',
        );
        rfc822Names.push(
          Object.freeze({
            rawDER: Buffer.from(name.raw),
            valueBytes: Buffer.from(name.value),
            value: name.value.toString('ascii'),
          }),
        );
      } else {
        let typeOID = null;
        if (name.tag === 0xa0) {
          mailRequire(
            name.children?.length === 2 &&
              name.children[0].tag === 6 &&
              name.children[1].tag === 0xa0 &&
              name.children[1].children?.length === 1,
            'SMIME_CERTIFICATE_NAME_ENCODING',
          );
          typeOID = oidText(name.children[0]);
        }
        otherGeneralNames.push(
          Object.freeze({ tag: name.tag, rawDER: Buffer.from(name.raw), typeOID }),
        );
      }
    }
  }
  return Object.freeze({
    sanPresent: Boolean(extension),
    rfc822Names: Object.freeze(rfc822Names),
    legacySubjectEmailPresent,
    otherGeneralNames: Object.freeze(otherGeneralNames),
    preferredSource: rfc822Names.length ? 'SAN_RFC822' : 'NONE',
  });
}

function mailNameProfile(cert, names) {
  mailRequire(
    !cert.extensions.get('2.5.29.17')?.critical || names.otherGeneralNames.length === 0,
    'SMIME_CRITICAL_SAN_UNSUPPORTED',
    'UNSUPPORTED',
  );
  mailRequire(
    !names.otherGeneralNames.some((name) => name.typeOID === SMTP_UTF8_NAME),
    'SMIME_EMAIL_NAME_UNSUPPORTED',
    'UNSUPPORTED',
  );
  mailRequire(
    names.rfc822Names.length > 0 || !names.legacySubjectEmailPresent,
    'SMIME_LEGACY_EMAIL_NAME_UNSUPPORTED',
    'UNSUPPORTED',
  );
}

function authority(policy, cert, role, stateTime, knowledgeTime) {
  if (typeof policy.authorityResolver !== 'function')
    return outcome('INDETERMINATE', 'CADES_AUTHORITY_RESOLVER_REQUIRED');
  try {
    const decision = policy.authorityResolver({
      certificate: Buffer.from(cert.raw),
      role,
      scope: { ...policy.scope, trustDomainID: Buffer.from(policy.scope.trustDomainID) },
      stateTime,
      knowledgeTime,
    });
    if (
      !decision ||
      decision.then ||
      !['VALID', 'INVALID', 'INDETERMINATE', 'UNSUPPORTED'].includes(decision.overall)
    )
      return outcome('INDETERMINATE', 'CADES_AUTHORITY_DECISION_MISSING');
    return {
      ...decision,
      authorityRole: role,
      authorityStateTime: stateTime,
      authorityKnowledgeTime: knowledgeTime,
    };
  } catch {
    return outcome('INDETERMINATE', 'CADES_AUTHORITY_UNAVAILABLE');
  }
}

function protectionDeadline(policy, cert) {
  const values = [
    policy.algorithmDeadlines?.[ES256],
    policy.hashDeadlines?.[SHA256],
    policy.keyDeadlines?.[keyID(cert.publicKey).toString('hex')],
  ];
  requireThat(values.every(deadline), 'CADES_PROTECTION_POLICY_REQUIRED');
  return Math.min(...values);
}

function parseCRL(raw, issuer) {
  const root = parseDER(raw),
    parts = root.children;
  requireThat(
    root.tag === 0x30 &&
      parts?.length === 3 &&
      parts[0].tag === 0x30 &&
      parts[1].tag === 0x30 &&
      parts[2].tag === 3 &&
      parts[2].value.length > 1 &&
      parts[2].value[0] === 0,
    'CADES_CRL_STRUCTURE',
  );
  const tbs = parts[0],
    fields = tbs.children;
  requireThat(
    fields?.length >= 5 && fields[0].tag === 2 && intValue(fields[0]) === 1n,
    'CADES_CRL_VERSION_UNSUPPORTED',
  );
  requireThat(
    fields[1].tag === 0x30 && equal(fields[1].raw, parts[1].raw) && fields[2].tag === 0x30,
    'CADES_CRL_ALGORITHM',
  );
  if (!equal(fields[2].raw, issuer.subject)) return undefined;
  requireThat(
    parts[1].children?.length === 1 &&
      parts[1].children[0].tag === 6 &&
      oidText(parts[1].children[0]) === ES256,
    'CADES_CRL_ALGORITHM_UNSUPPORTED',
  );
  requireThat(
    verifySignature('sha256', tbs.raw, issuer.publicKey, parts[2].value.subarray(1)),
    'CADES_CRL_SIGNATURE',
  );
  const thisUpdate = time(fields[3]);
  requireThat([23, 24].includes(fields[4]?.tag), 'CADES_CRL_NEXTUPDATE_REQUIRED');
  const nextUpdate = time(fields[4]);
  requireThat(nextUpdate > thisUpdate, 'CADES_CRL_INTERVAL');
  let index = 5,
    records = [];
  if (fields[index]?.tag === 0x30) records = fields[index++].children;
  requireThat(
    fields[index]?.tag === 0xa0 &&
      fields[index].children?.length === 1 &&
      index + 1 === fields.length,
    'CADES_CRL_EXTENSIONS',
  );
  const ext = extensions(fields[index].children[0]);
  for (const [id, value] of ext) {
    requireThat(
      !['2.5.29.27', '2.5.29.28', '2.5.29.46'].includes(id),
      'CADES_CRL_PROFILE_UNSUPPORTED',
    );
    requireThat(
      !value.critical || ['2.5.29.20', '2.5.29.35'].includes(id),
      'CADES_CRL_EXTENSION_UNSUPPORTED',
    );
  }
  authorityKeyBinding(ext.get('2.5.29.35'), issuer);
  requireThat(ext.has('2.5.29.20') && !ext.get('2.5.29.20').critical, 'CADES_CRL_NUMBER_REQUIRED');
  const numberNode = parseDER(ext.get('2.5.29.20').value);
  requireThat(
    numberNode.tag === 2 && numberNode.value.length <= 20 && intValue(numberNode) >= 0n,
    'CADES_CRL_NUMBER',
  );
  const revoked = new Map();
  for (const record of records) {
    const fields = record.children;
    requireThat(
      record.tag === 0x30 &&
        [2, 3].includes(fields?.length) &&
        fields[0].tag === 2 &&
        intValue(fields[0]) > 0n,
      'CADES_CRL_ENTRY',
    );
    const serial = intValue(fields[0]).toString();
    requireThat(!revoked.has(serial), 'CADES_CRL_DUPLICATE_SERIAL');
    const revokedAt = time(fields[1]),
      ext = fields[2] ? extensions(fields[2]) : new Map();
    for (const [id, value] of ext) {
      requireThat(id !== '2.5.29.29', 'CADES_INDIRECT_CRL_UNSUPPORTED');
      requireThat(
        !value.critical || ['2.5.29.21', '2.5.29.24'].includes(id),
        'CADES_CRL_ENTRY_EXTENSION_UNSUPPORTED',
      );
    }
    let reason = 0,
      invalidityDate = revokedAt;
    if (ext.has('2.5.29.21')) {
      const value = parseDER(ext.get('2.5.29.21').value);
      requireThat(
        value.tag === 10 &&
          value.value.length === 1 &&
          [0, 1, 2, 3, 4, 5, 6, 8, 9, 10].includes(value.value[0]),
        'CADES_CRL_REASON',
      );
      reason = value.value[0];
      requireThat(reason !== 8, 'CADES_CRL_REMOVAL_UNSUPPORTED');
    }
    if (ext.has('2.5.29.24')) {
      const value = parseDER(ext.get('2.5.29.24').value);
      requireThat(value.tag === 24, 'CADES_INVALIDITY_DATE');
      invalidityDate = time(value);
      requireThat(invalidityDate <= revokedAt, 'CADES_INVALIDITY_DATE');
    }
    revoked.set(serial, {
      effectiveTime: Math.min(revokedAt, invalidityDate),
      revocationTime: revokedAt,
      reasonPresent: ext.has('2.5.29.21'),
      reason,
    });
  }
  return {
    raw: Buffer.from(raw),
    tbs: Buffer.from(tbs.raw),
    number: intValue(numberNode),
    thisUpdate,
    nextUpdate,
    revoked,
  };
}

/** Selected direct-root PKI and full-CRL validation; embedded objects are never trust anchors. */
export function validateCAdESMaterial(input) {
  return validateMaterial(input);
}

/** Current-use mail material admission; this does not authenticate a mailbox. */
export function validateSmimeMaterial(input) {
  const allowed = new Set([
    'certificate',
    'certificates',
    'crls',
    'knowledgeTime',
    'purpose',
    'policy',
  ]);
  const validInput =
    input !== null &&
    typeof input === 'object' &&
    !Array.isArray(input) &&
    Object.keys(input).every((key) => allowed.has(key));
  return validateMaterial(
    {
      ...input,
      certificate: Buffer.isBuffer(input?.certificate)
        ? Buffer.from(input.certificate)
        : input?.certificate,
      stateTime: input?.knowledgeTime,
      knownCRLs: [],
      evidenceTime: undefined,
      signatureEvidenceTime: undefined,
    },
    { mail: true, validInput },
  );
}

function validateMaterial(
  {
    certificate: raw,
    certificates = [],
    crls = [],
    knownCRLs = [],
    purpose,
    stateTime,
    knowledgeTime,
    evidenceTime,
    signatureEvidenceTime,
    policy = {},
  },
  { mail = false, validInput: validMailInput = true } = {},
) {
  const checks = [],
    usedCertificates = [],
    usedCRLs = [],
    ordinaryTimeCheckIndexes = [];
  let validUntil,
    rootValidUntil,
    leaf,
    root,
    identity = null;
  const capture = (operation) => {
    try {
      return operation();
    } catch (error) {
      checks.push(classified(error));
      return undefined;
    }
  };
  const finish = () => {
    const failure = ['INVALID', 'UNSUPPORTED', 'INDETERMINATE']
      .map((kind) => checks.find((check) => check.overall === kind))
      .find(Boolean);
    if (mail) {
      const validity = (cert) =>
        cert
          ? Object.freeze({
              certificateHash: sha256(cert.raw),
              notBefore: cert.notBefore,
              notAfter: cert.notAfter,
              atKnowledgeTime:
                knowledgeTime < cert.notBefore
                  ? 'NOT_YET_VALID'
                  : knowledgeTime >= cert.notAfter
                    ? 'EXPIRED'
                    : 'WITHIN',
            })
          : null;
      const knownInvalidCheckIndexes = checks.flatMap((check, index) =>
        check.overall === 'INVALID' && !ordinaryTimeCheckIndexes.includes(index) ? [index] : [],
      );
      return Object.freeze({
        overall: failure?.overall ?? 'VALID',
        reason: failure?.reason ?? (failure ? 'SMIME_MATERIAL_INVALID' : 'SMIME_MATERIAL_VALID'),
        purpose,
        stateTime,
        knowledgeTime,
        validUntil: validUntil ?? null,
        identity,
        currentValidity: Object.freeze({ leaf: validity(leaf), root: validity(root) }),
        usedCertificates: Object.freeze(unique(usedCertificates)),
        usedCRLs: Object.freeze(unique(usedCRLs)),
        checks: Object.freeze(checks.map((check) => Object.freeze({ ...check }))),
        ordinaryTimeCheckIndexes: Object.freeze([...ordinaryTimeCheckIndexes]),
        knownInvalidCheckIndexes: Object.freeze(knownInvalidCheckIndexes),
      });
    }
    return Object.freeze({
      ...(failure ?? outcome('VALID', 'CADES_MATERIAL_VALID')),
      purpose,
      stateTime,
      knowledgeTime,
      validUntil,
      usedCertificates: unique(usedCertificates),
      usedCRLs: unique(usedCRLs),
      checks,
    });
  };
  const validInput = capture(() => {
    if (mail)
      mailRequire(
        validMailInput && Number.isSafeInteger(knowledgeTime) && knowledgeTime >= 0,
        'SMIME_MATERIAL_INPUT_INVALID',
      );
    requireThat(
      (mail ? mailPurpose(purpose) : ['SIGNER', 'TSA'].includes(purpose)) &&
        instant(stateTime) &&
        instant(knowledgeTime) &&
        stateTime <= knowledgeTime &&
        (evidenceTime === undefined ||
          (instant(evidenceTime) && stateTime <= evidenceTime && evidenceTime <= knowledgeTime)) &&
        (signatureEvidenceTime === undefined ||
          (instant(signatureEvidenceTime) &&
            stateTime <= signatureEvidenceTime &&
            signatureEvidenceTime <= knowledgeTime)),
      'CADES_VALIDATION_TIME',
    );
    for (const values of [
      certificates,
      crls,
      knownCRLs,
      policy.currentMaterial?.certificates ?? [],
      policy.currentMaterial?.crls ?? [],
      policy.trustedRoots ?? [],
    ])
      requireThat(
        Array.isArray(values) && values.length <= 128 && values.every(Buffer.isBuffer),
        'CADES_MATERIAL_LIMIT',
      );
    requireThat(
      Buffer.isBuffer(policy.scope?.trustDomainID) &&
        policy.scope.trustDomainID.length === 32 &&
        typeof policy.scope.issuerID === 'string' &&
        policy.scope.issuerID.length > 0 &&
        policy.scope.representation === 'X509',
      'CADES_AUTHORITY_SCOPE_REQUIRED',
    );
    if (mail)
      mailRequire(
        policy.scope.profileID === 'certconcord-smime-application-v1' &&
          policy.scope.purpose === purpose &&
          Object.entries(policy.scope).every(
            ([key, value]) =>
              ['trustDomainID', 'profileID', 'issuerID', 'representation', 'purpose'].includes(
                key,
              ) &&
              (key === 'trustDomainID' || (typeof value === 'string' && value.length > 0)),
          ),
        'SMIME_AUTHORITY_SCOPE',
      );
    // Resolver callbacks cannot replace the caller's inputs or protection policy mid-validation.
    certificates = unique(certificates);
    crls = unique(crls);
    knownCRLs = unique(knownCRLs);
    policy = {
      ...policy,
      scope: { ...policy.scope, trustDomainID: Buffer.from(policy.scope.trustDomainID) },
      trustedRoots: unique(policy.trustedRoots ?? []),
      currentMaterial: {
        certificates: unique(policy.currentMaterial?.certificates ?? []),
        crls: unique(policy.currentMaterial?.crls ?? []),
      },
      algorithmDeadlines: { ...policy.algorithmDeadlines },
      hashDeadlines: { ...policy.hashDeadlines },
      keyDeadlines: { ...policy.keyDeadlines },
    };
    return true;
  });
  if (!validInput) return finish();
  leaf = capture(() => certificate(raw));
  if (!leaf) return finish();
  usedCertificates.push(leaf.raw);
  capture(() => certificateProfile(leaf, purpose));
  capture(() => certificateUsage(leaf, purpose, mail));
  if (mail) {
    const names = capture(() => certificateMailNames(leaf));
    if (names) {
      identity = Object.freeze({
        certificateHash: sha256(leaf.raw),
        keyID: keyID(leaf.publicKey),
        publicKeyDER: Buffer.from(leaf.spki),
        certificateNames: names,
      });
      capture(() => mailNameProfile(leaf, names));
    }
  }
  const leafTimeIndex = checks.length;
  capture(() =>
    requireThat(stateTime >= leaf.notBefore && stateTime < leaf.notAfter, 'CADES_CERTIFICATE_TIME'),
  );
  if (mail && stateTime >= leaf.notAfter && checks.length > leafTimeIndex)
    ordinaryTimeCheckIndexes.push(leafTimeIndex);
  const anchors = (policy.trustedRoots ?? [])
    .map((raw) => capture(() => certificate(raw)))
    .filter(Boolean);
  const matches = anchors.filter((candidate) => equal(candidate.subject, leaf.issuer));
  if (matches.length !== 1) {
    const intermediate =
      !matches.length &&
      [...certificates, ...policy.currentMaterial.certificates].some((raw) => {
        const candidate = capture(() => certificate(raw));
        return (
          candidate?.native.ca &&
          !equal(candidate.subject, candidate.issuer) &&
          equal(candidate.subject, leaf.issuer)
        );
      });
    checks.push(
      intermediate
        ? outcome('UNSUPPORTED', 'CADES_INTERMEDIATE_PATH_UNSUPPORTED')
        : outcome('INDETERMINATE', matches.length ? 'CADES_ROOT_CONFLICT' : 'CADES_ROOT_MISSING'),
    );
    return finish();
  }
  root = matches[0];
  usedCertificates.push(root.raw);
  capture(() => certificateProfile(root));
  capture(() => certificateUsage(root, 'ROOT', mail));
  capture(() =>
    requireThat(
      equal(root.subject, root.issuer) && root.native.verify(root.publicKey),
      'CADES_ROOT_SIGNATURE',
    ),
  );
  capture(() => requireThat(leaf.native.verify(root.publicKey), 'CADES_CERTIFICATE_SIGNATURE'));
  capture(() => authorityKeyBinding(leaf.extensions.get('2.5.29.35'), root));
  const rootTimeIndex = checks.length;
  capture(() =>
    requireThat(stateTime >= root.notBefore && stateTime < root.notAfter, 'CADES_ROOT_TIME'),
  );
  if (mail && stateTime >= root.notAfter && checks.length > rootTimeIndex)
    ordinaryTimeCheckIndexes.push(rootTimeIndex);
  const issuerCheck = authority(policy, root, 'ISSUER', stateTime, knowledgeTime);
  if (
    mail &&
    stateTime >= root.notAfter &&
    issuerCheck.overall === 'INVALID' &&
    issuerCheck.reason === 'AUTHORITY_EXPIRED' &&
    issuerCheck.authorityStateTime === stateTime
  )
    ordinaryTimeCheckIndexes.push(checks.length);
  checks.push(issuerCheck);
  if (purpose === 'TSA')
    checks.push(authority(policy, leaf, 'TIMESTAMP_AUTHORITY', stateTime, knowledgeTime));
  capture(() => {
    rootValidUntil = protectionDeadline(policy, root);
    validUntil = Math.min(protectionDeadline(policy, leaf), rootValidUntil);
    requireThat(stateTime < validUntil, 'CADES_KEY_PROTECTION_EXPIRED');
  });
  const positive = unique([
    ...crls,
    ...(evidenceTime === undefined ? (policy.currentMaterial?.crls ?? []) : []),
  ]);
  const available = unique([...positive, ...knownCRLs, ...(policy.currentMaterial?.crls ?? [])]);
  const records = available.map((raw) => capture(() => parseCRL(raw, root))).filter(Boolean);
  const known = records.filter((record) => record.thisUpdate <= knowledgeTime);
  let revoked = false;
  const decisions = new Map();
  for (const record of known) {
    capture(() =>
      requireThat(
        record.thisUpdate >= root.notBefore && record.thisUpdate < root.notAfter,
        'CADES_CRL_SIGNER_TIME',
      ),
    );
    const authorityResult = authority(
      policy,
      root,
      'STATUS_AUTHORITY',
      record.thisUpdate,
      knowledgeTime,
    );
    const covered =
      evidenceTime !== undefined &&
      record.thisUpdate <= evidenceTime &&
      crls.some((raw) => equal(raw, record.raw));
    const authenticationTime = covered ? evidenceTime : knowledgeTime;
    const authenticity =
      Number.isFinite(rootValidUntil) && authenticationTime < rootValidUntil
        ? authorityResult
        : outcome('INDETERMINATE', 'CADES_CRL_AUTHENTICITY_UNPROVEN');
    decisions.set(record, authenticity);
    const entry = record.revoked.get(leaf.serial.toString());
    if (entry) {
      const revokedAtUse = entry.effectiveTime <= stateTime;
      // RFC 3161 section 4 distinguishes an absent reason from explicit 0.
      // EN 319 102-1 past validation may recover an old token only with a
      // separate proof of its signature before the key-risk cutoff. Material
      // evidenceTime and the token's own asserted genTime do not supply it.
      const unprovenTSA =
        purpose === 'TSA' &&
        !(entry.reasonPresent && [0, 3, 4, 5].includes(entry.reason)) &&
        !(signatureEvidenceTime !== undefined && signatureEvidenceTime < entry.effectiveTime);
      if (revokedAtUse || unprovenTSA) {
        if (authenticity.overall !== 'VALID') checks.push(authenticity);
        else if (revokedAtUse) revoked = true;
        else checks.push(outcome('INDETERMINATE', 'CADES_TSA_REVOKED_NO_POE'));
      }
    }
  }
  if (revoked) checks.push(outcome('INVALID', 'CADES_CERTIFICATE_REVOKED'));
  const groups = new Map();
  for (const record of known) {
    const number = record.number.toString();
    if (groups.has(number) && !equal(groups.get(number), record.tbs))
      checks.push(outcome('INDETERMINATE', 'CADES_CRL_CONFLICT'));
    groups.set(number, record.tbs);
  }
  const freshnessTime = evidenceTime ?? knowledgeTime;
  const eligible = records.filter(
    (record) =>
      positive.some((raw) => equal(raw, record.raw)) &&
      record.thisUpdate <= freshnessTime &&
      freshnessTime < record.nextUpdate &&
      record.thisUpdate <= knowledgeTime &&
      record.thisUpdate < leaf.notAfter,
  );
  eligible.sort((a, b) =>
    a.number === b.number ? b.thisUpdate - a.thisUpdate : a.number > b.number ? -1 : 1,
  );
  if (!eligible.length)
    checks.push(outcome('INDETERMINATE', records.length ? 'CADES_CRL_STALE' : 'CADES_CRL_MISSING'));
  else {
    checks.push(decisions.get(eligible[0]));
    usedCRLs.push(eligible[0].raw);
  }
  return finish();
}

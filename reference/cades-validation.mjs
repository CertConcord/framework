import { X509Certificate, verify as verifySignature } from 'node:crypto';
import { parseDER, oidText, intValue, equal, keyID, requireThat } from './core.mjs';
import { parseCertificate, validateKeyUsage, generalizedTime } from './pki.mjs';

const ES256 = '1.2.840.10045.4.3.2';
const SHA256 = '2.16.840.1.101.3.4.2.1';
const TSA_EKU = '1.3.6.1.5.5.7.3.8';
const outcome = (overall, reason, details = {}) => ({ overall, reason, ...details });
const instant = (value) => Number.isFinite(value) && value >= 0 && value <= Number.MAX_SAFE_INTEGER;
const deadline = (value) => Number.isSafeInteger(value) && value > 0;
const unique = (values) => [...new Map(values.map((raw) => [raw.toString('hex'), Buffer.from(raw)])).values()];
const classified = (error) => outcome(error.overall ??
  (/UNSUPPORTED/.test(error.code) ? 'UNSUPPORTED' :
    /MISSING|REQUIRED|UNAVAILABLE|STALE|CONFLICT/.test(error.code) ? 'INDETERMINATE' : 'INVALID'),
error.code ?? 'CADES_MATERIAL_MALFORMED');

function extensions(node) {
  requireThat(node?.tag === 0x30 && node.children, 'CADES_EXTENSION_STRUCTURE');
  const values = new Map();
  for (const entry of node.children) {
    const parts = entry.children;
    requireThat(entry.tag === 0x30 && [2, 3].includes(parts?.length) &&
      parts[0].tag === 6 && parts.at(-1).tag === 4, 'CADES_EXTENSION_STRUCTURE');
    const id = oidText(parts[0]), critical = parts.length === 3;
    requireThat(!values.has(id), 'CADES_DUPLICATE_EXTENSION');
    requireThat(!critical || equal(parts[1].raw, Buffer.from('0101ff', 'hex')),
      'CADES_EXTENSION_CRITICAL');
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
  const seconds = Date.parse(`${text.slice(0, 4)}-${text.slice(4, 6)}-${text.slice(6, 8)}T` +
    `${text.slice(8, 10)}:${text.slice(10, 12)}:${text.slice(12, 14)}Z`) / 1000;
  requireThat(Number.isSafeInteger(seconds), 'CADES_TIME_ENCODING');
  requireThat(parseDER(generalizedTime(seconds)).value.toString('ascii') === text, 'CADES_TIME_ENCODING');
  return seconds;
}

function p256(key) {
  requireThat(key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails?.namedCurve === 'prime256v1',
    'CADES_KEY_ALGORITHM_UNSUPPORTED');
}

function certificate(raw) {
  requireThat(Buffer.isBuffer(raw), 'CADES_CERTIFICATE_STRUCTURE');
  const parsed = parseCertificate(raw), native = new X509Certificate(raw);
  requireThat(parsed.serial > 0n, 'CADES_CERTIFICATE_SERIAL');
  return { ...parsed, native };
}

function certificateProfile(cert) {
  const permitted = new Set(['2.5.29.19', '2.5.29.15', '2.5.29.14', '2.5.29.35', '2.5.29.37']);
  for (const [id, extension] of cert.extensions) {
    requireThat(!extension.critical || permitted.has(id), 'CADES_CERTIFICATE_EXTENSION_UNSUPPORTED');
    requireThat(!['2.5.29.30', '2.5.29.36', '2.5.29.54'].includes(id),
      'CADES_CERTIFICATE_CONSTRAINTS_UNSUPPORTED');
  }
  p256(cert.publicKey);
  requireThat(cert.algorithm === ES256 && parseDER(cert.algorithmRaw).children.length === 1,
    'CADES_CERTIFICATE_ALGORITHM_UNSUPPORTED');
}

function keyIdentifier(cert) {
  const value = cert.extensions.get('2.5.29.14');
  if (!value) return undefined;
  const parsed = parseDER(value.value);
  requireThat(parsed.tag === 4 && parsed.value.length > 0 && !value.critical,
    'CADES_SUBJECT_KEY_IDENTIFIER');
  return parsed.value;
}

function authorityKeyBinding(value, issuer) {
  requireThat(value && !value.critical, 'CADES_AUTHORITY_KEY_IDENTIFIER_REQUIRED');
  const parsed = parseDER(value.value);
  requireThat(parsed.tag === 0x30 && parsed.children?.length === 1 && parsed.children[0].tag === 0x80,
    'CADES_AUTHORITY_KEY_IDENTIFIER_UNSUPPORTED');
  const expected = keyIdentifier(issuer);
  requireThat(expected && equal(parsed.children[0].value, expected), 'CADES_AUTHORITY_KEY_BINDING');
}

function certificateUsage(cert, purpose) {
  const usage = validateKeyUsage(cert.extensions.get('2.5.29.15'), undefined, 'CADES_CERTIFICATE_KEY_USAGE');
  const basic = cert.extensions.get('2.5.29.19');
  if (purpose === 'ROOT') {
    requireThat(cert.native.ca && basic?.critical && (usage[0] & 6) === 6,
      'CADES_ROOT_CONSTRAINTS');
    const constraints = parseDER(basic.value);
    requireThat(constraints.tag === 0x30 && [1, 2].includes(constraints.children?.length) &&
      equal(constraints.children[0].raw, Buffer.from('0101ff', 'hex')) &&
      (!constraints.children[1] || (constraints.children[1].tag === 2 && intValue(constraints.children[1]) >= 0n)),
    'CADES_ROOT_CONSTRAINTS');
    requireThat(!cert.extensions.has('2.5.29.37'), 'CADES_ROOT_EKU_UNSUPPORTED');
  } else {
    requireThat(!cert.native.ca && (usage[0] & 0x80) !== 0 && (usage[0] & 6) === 0,
      'CADES_SIGNER_KEY_USAGE');
    if (basic) {
      const constraints = parseDER(basic.value);
      requireThat(constraints.tag === 0x30 && constraints.children?.length === 0,
        'CADES_END_ENTITY_CONSTRAINTS');
    }
    const eku = cert.extensions.get('2.5.29.37');
    if (purpose === 'TSA') {
      const values = eku && parseDER(eku.value);
      requireThat(eku?.critical && values.tag === 0x30 && values.children?.length === 1 &&
        values.children[0].tag === 6 && oidText(values.children[0]) === TSA_EKU, 'CADES_TSA_EKU');
    } else {
      requireThat(!eku, 'CADES_SIGNER_EKU_UNSUPPORTED');
    }
  }
}

function authority(policy, cert, role, stateTime, knowledgeTime) {
  if (typeof policy.authorityResolver !== 'function')
    return outcome('INDETERMINATE', 'CADES_AUTHORITY_RESOLVER_REQUIRED');
  try {
    const decision = policy.authorityResolver({ certificate: Buffer.from(cert.raw), role,
      scope: { ...policy.scope, trustDomainID: Buffer.from(policy.scope.trustDomainID) }, stateTime, knowledgeTime });
    if (!decision || decision.then || !['VALID', 'INVALID', 'INDETERMINATE', 'UNSUPPORTED'].includes(decision.overall))
      return outcome('INDETERMINATE', 'CADES_AUTHORITY_DECISION_MISSING');
    return { ...decision };
  } catch {
    return outcome('INDETERMINATE', 'CADES_AUTHORITY_UNAVAILABLE');
  }
}

function protectionDeadline(policy, cert) {
  const values = [policy.algorithmDeadlines?.[ES256], policy.hashDeadlines?.[SHA256],
    policy.keyDeadlines?.[keyID(cert.publicKey).toString('hex')]];
  requireThat(values.every(deadline), 'CADES_PROTECTION_POLICY_REQUIRED');
  return Math.min(...values);
}

function parseCRL(raw, issuer) {
  const root = parseDER(raw), parts = root.children;
  requireThat(root.tag === 0x30 && parts?.length === 3 && parts[0].tag === 0x30 &&
    parts[1].tag === 0x30 && parts[2].tag === 3 && parts[2].value.length > 1 && parts[2].value[0] === 0,
  'CADES_CRL_STRUCTURE');
  const tbs = parts[0], fields = tbs.children;
  requireThat(fields?.length >= 5 && fields[0].tag === 2 && intValue(fields[0]) === 1n,
    'CADES_CRL_VERSION_UNSUPPORTED');
  requireThat(fields[1].tag === 0x30 && equal(fields[1].raw, parts[1].raw) && fields[2].tag === 0x30,
    'CADES_CRL_ALGORITHM');
  if (!equal(fields[2].raw, issuer.subject)) return undefined;
  requireThat(parts[1].children?.length === 1 && parts[1].children[0].tag === 6 &&
    oidText(parts[1].children[0]) === ES256, 'CADES_CRL_ALGORITHM_UNSUPPORTED');
  requireThat(verifySignature('sha256', tbs.raw, issuer.publicKey, parts[2].value.subarray(1)),
    'CADES_CRL_SIGNATURE');
  const thisUpdate = time(fields[3]);
  requireThat([23, 24].includes(fields[4]?.tag), 'CADES_CRL_NEXTUPDATE_REQUIRED');
  const nextUpdate = time(fields[4]);
  requireThat(nextUpdate > thisUpdate, 'CADES_CRL_INTERVAL');
  let index = 5, records = [];
  if (fields[index]?.tag === 0x30) records = fields[index++].children;
  requireThat(fields[index]?.tag === 0xa0 && fields[index].children?.length === 1 &&
    index + 1 === fields.length, 'CADES_CRL_EXTENSIONS');
  const ext = extensions(fields[index].children[0]);
  for (const [id, value] of ext) {
    requireThat(!['2.5.29.27', '2.5.29.28', '2.5.29.46'].includes(id), 'CADES_CRL_PROFILE_UNSUPPORTED');
    requireThat(!value.critical || ['2.5.29.20', '2.5.29.35'].includes(id),
      'CADES_CRL_EXTENSION_UNSUPPORTED');
  }
  authorityKeyBinding(ext.get('2.5.29.35'), issuer);
  requireThat(ext.has('2.5.29.20') && !ext.get('2.5.29.20').critical, 'CADES_CRL_NUMBER_REQUIRED');
  const numberNode = parseDER(ext.get('2.5.29.20').value);
  requireThat(numberNode.tag === 2 && numberNode.value.length <= 20 && intValue(numberNode) >= 0n,
    'CADES_CRL_NUMBER');
  const revoked = new Map();
  for (const record of records) {
    const fields = record.children;
    requireThat(record.tag === 0x30 && [2, 3].includes(fields?.length) && fields[0].tag === 2 &&
      intValue(fields[0]) > 0n, 'CADES_CRL_ENTRY');
    const serial = intValue(fields[0]).toString();
    requireThat(!revoked.has(serial), 'CADES_CRL_DUPLICATE_SERIAL');
    const revokedAt = time(fields[1]), ext = fields[2] ? extensions(fields[2]) : new Map();
    for (const [id, value] of ext) {
      requireThat(id !== '2.5.29.29', 'CADES_INDIRECT_CRL_UNSUPPORTED');
      requireThat(!value.critical || ['2.5.29.21', '2.5.29.24'].includes(id),
        'CADES_CRL_ENTRY_EXTENSION_UNSUPPORTED');
    }
    let reason = 0, invalidityDate = revokedAt;
    if (ext.has('2.5.29.21')) {
      const value = parseDER(ext.get('2.5.29.21').value);
      requireThat(value.tag === 10 && value.value.length === 1 &&
        [0, 1, 2, 3, 4, 5, 6, 8, 9, 10].includes(value.value[0]), 'CADES_CRL_REASON');
      reason = value.value[0];
      requireThat(reason !== 8, 'CADES_CRL_REMOVAL_UNSUPPORTED');
    }
    if (ext.has('2.5.29.24')) {
      const value = parseDER(ext.get('2.5.29.24').value);
      requireThat(value.tag === 24, 'CADES_INVALIDITY_DATE');
      invalidityDate = time(value);
      requireThat(invalidityDate <= revokedAt, 'CADES_INVALIDITY_DATE');
    }
    revoked.set(serial, { effectiveTime: Math.min(revokedAt, invalidityDate), reason });
  }
  return { raw: Buffer.from(raw), tbs: Buffer.from(tbs.raw), number: intValue(numberNode), thisUpdate, nextUpdate, revoked };
}

/** Selected direct-root PKI and full-CRL validation; embedded objects are never trust anchors. */
export function validateCAdESMaterial({ certificate: raw, certificates = [], crls = [], knownCRLs = [],
  purpose, stateTime, knowledgeTime, evidenceTime, policy = {} }) {
  const checks = [], usedCertificates = [], usedCRLs = [];
  let validUntil, rootValidUntil, leaf, root;
  const capture = (operation) => {
    try { return operation(); } catch (error) { checks.push(classified(error)); return undefined; }
  };
  const finish = () => {
    const failure = ['INVALID', 'UNSUPPORTED', 'INDETERMINATE'].map((kind) =>
      checks.find((check) => check.overall === kind)).find(Boolean);
    return Object.freeze({ ...(failure ?? outcome('VALID', 'CADES_MATERIAL_VALID')),
      purpose, stateTime, knowledgeTime, validUntil,
      usedCertificates: unique(usedCertificates), usedCRLs: unique(usedCRLs), checks });
  };
  const validInput = capture(() => {
    requireThat(['SIGNER', 'TSA'].includes(purpose) && instant(stateTime) && instant(knowledgeTime) &&
      stateTime <= knowledgeTime && (evidenceTime === undefined ||
        (instant(evidenceTime) && stateTime <= evidenceTime && evidenceTime <= knowledgeTime)), 'CADES_VALIDATION_TIME');
    for (const values of [certificates, crls, knownCRLs, policy.currentMaterial?.certificates ?? [],
      policy.currentMaterial?.crls ?? [], policy.trustedRoots ?? []])
      requireThat(Array.isArray(values) && values.length <= 128 && values.every(Buffer.isBuffer), 'CADES_MATERIAL_LIMIT');
    requireThat(Buffer.isBuffer(policy.scope?.trustDomainID) && policy.scope.trustDomainID.length === 32 &&
      typeof policy.scope.issuerID === 'string' && policy.scope.issuerID.length > 0 &&
      policy.scope.representation === 'X509', 'CADES_AUTHORITY_SCOPE_REQUIRED');
    // Resolver callbacks cannot replace the caller's inputs or protection policy mid-validation.
    certificates = unique(certificates);
    crls = unique(crls);
    knownCRLs = unique(knownCRLs);
    policy = { ...policy, scope: { ...policy.scope, trustDomainID: Buffer.from(policy.scope.trustDomainID) },
      trustedRoots: unique(policy.trustedRoots ?? []),
      currentMaterial: { certificates: unique(policy.currentMaterial?.certificates ?? []),
        crls: unique(policy.currentMaterial?.crls ?? []) },
      algorithmDeadlines: { ...policy.algorithmDeadlines }, hashDeadlines: { ...policy.hashDeadlines },
      keyDeadlines: { ...policy.keyDeadlines } };
    return true;
  });
  if (!validInput) return finish();
  leaf = capture(() => certificate(raw));
  if (!leaf) return finish();
  usedCertificates.push(leaf.raw);
  capture(() => certificateProfile(leaf));
  capture(() => certificateUsage(leaf, purpose));
  capture(() => requireThat(stateTime >= leaf.notBefore && stateTime < leaf.notAfter, 'CADES_CERTIFICATE_TIME'));
  const anchors = (policy.trustedRoots ?? []).map((raw) => capture(() => certificate(raw))).filter(Boolean);
  const matches = anchors.filter((candidate) => equal(candidate.subject, leaf.issuer));
  if (matches.length !== 1) {
    const intermediate = !matches.length && [...certificates, ...policy.currentMaterial.certificates]
      .some((raw) => {
        const candidate = capture(() => certificate(raw));
        return candidate?.native.ca && !equal(candidate.subject, candidate.issuer) &&
          equal(candidate.subject, leaf.issuer);
      });
    checks.push(intermediate ? outcome('UNSUPPORTED', 'CADES_INTERMEDIATE_PATH_UNSUPPORTED') :
      outcome('INDETERMINATE', matches.length ? 'CADES_ROOT_CONFLICT' : 'CADES_ROOT_MISSING'));
    return finish();
  }
  root = matches[0];
  usedCertificates.push(root.raw);
  capture(() => certificateProfile(root));
  capture(() => certificateUsage(root, 'ROOT'));
  capture(() => requireThat(equal(root.subject, root.issuer) && root.native.verify(root.publicKey), 'CADES_ROOT_SIGNATURE'));
  capture(() => requireThat(leaf.native.verify(root.publicKey), 'CADES_CERTIFICATE_SIGNATURE'));
  capture(() => authorityKeyBinding(leaf.extensions.get('2.5.29.35'), root));
  capture(() => requireThat(stateTime >= root.notBefore && stateTime < root.notAfter, 'CADES_ROOT_TIME'));
  checks.push(authority(policy, root, 'ISSUER', stateTime, knowledgeTime));
  if (purpose === 'TSA') checks.push(authority(policy, leaf, 'TIMESTAMP_AUTHORITY', stateTime, knowledgeTime));
  capture(() => {
    rootValidUntil = protectionDeadline(policy, root);
    validUntil = Math.min(protectionDeadline(policy, leaf), rootValidUntil);
    requireThat(stateTime < validUntil, 'CADES_KEY_PROTECTION_EXPIRED');
  });
  const positive = unique([...crls, ...(evidenceTime === undefined ? policy.currentMaterial?.crls ?? [] : [])]);
  const available = unique([...positive, ...knownCRLs, ...(policy.currentMaterial?.crls ?? [])]);
  const records = available.map((raw) => capture(() => parseCRL(raw, root))).filter(Boolean);
  const known = records.filter((record) => record.thisUpdate <= knowledgeTime);
  let revoked = false;
  const decisions = new Map();
  for (const record of known) {
    capture(() => requireThat(record.thisUpdate >= root.notBefore && record.thisUpdate < root.notAfter,
      'CADES_CRL_SIGNER_TIME'));
    const authorityResult = authority(policy, root, 'STATUS_AUTHORITY', record.thisUpdate, knowledgeTime);
    const covered = evidenceTime !== undefined && record.thisUpdate <= evidenceTime &&
      crls.some((raw) => equal(raw, record.raw));
    const authenticationTime = covered ? evidenceTime : knowledgeTime;
    const authenticity = Number.isFinite(rootValidUntil) && authenticationTime < rootValidUntil
      ? authorityResult : outcome('INDETERMINATE', 'CADES_CRL_AUTHENTICITY_UNPROVEN');
    decisions.set(record, authenticity);
    if (record.revoked.get(leaf.serial.toString())?.effectiveTime <= stateTime) {
      if (authenticity.overall === 'VALID') revoked = true;
      else checks.push(authenticity);
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
  const eligible = records.filter((record) => positive.some((raw) => equal(raw, record.raw)) &&
    record.thisUpdate <= freshnessTime && freshnessTime < record.nextUpdate && record.thisUpdate <= knowledgeTime &&
    record.thisUpdate < leaf.notAfter);
  eligible.sort((a, b) => a.number === b.number ? b.thisUpdate - a.thisUpdate : a.number > b.number ? -1 : 1);
  if (!eligible.length) checks.push(outcome('INDETERMINATE', records.length ? 'CADES_CRL_STALE' : 'CADES_CRL_MISSING'));
  else {
    checks.push(decisions.get(eligible[0]));
    usedCRLs.push(eligible[0].raw);
  }
  return finish();
}

import { X509Certificate, createHash } from 'node:crypto';
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
import { timestampRequest } from './timestamp.mjs';
import {
  prepareAdESSignature,
  inspectAdESSignature,
  inspectRFC3161Token,
  proofProtectionDeadline,
} from './ades-cms.mjs';
import { validateCAdESMaterial } from './cades-validation.mjs';

// EN 319 122-1 V1.3.1, clauses 5.5.2 and 5.5.3. These are standard CMS
// attributes; the original SignerInfo's six signed fields are never re-encoded.
const ARCHIVE = '0.4.0.1733.2.4';
const INDEX = '0.4.0.19122.1.5';
const HASHES = { [OID.sha256]: 'sha256', [OID.sha512]: 'sha512' };
const LEVELS = ['B', 'T', 'LT', 'LTA'];
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
const includes = (values, value) => values.some((b) => equal(b, value));
const union = (...arrays) => arrays.flat().filter((b, i, all) => !includes(all.slice(0, i), b));
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
function certificateIdentity(raw) {
  const x509 = new X509Certificate(raw),
    tbs = parseDER(raw).children[0].children;
  const offset = tbs[0].tag === 0xa0 ? 1 : 0;
  return { x509, sid: seq(tbs[offset + 2].raw, tbs[offset].raw) };
}
function parseCMS(raw, content, expectedType = OID.data) {
  const inspection =
    expectedType === OID.tstInfo
      ? inspectRFC3161Token(raw)
      : inspectAdESSignature(raw, { content, profile: 'CADES' });
  if (!inspection.parsed) throw failure(inspection.overall, inspection.reason);
  Object.defineProperty(inspection.parsed, 'signatureInspection', { value: inspection });
  return inspection.parsed;
}
function inspectSignature(parsed, failures) {
  failures.push(...parsed.signatureInspection.failures);
  return parsed.signatureInspection.signature;
}
function inspectMultipleSigners(raw, content, expectedType, failures) {
  const inspection = inspectAdESSignature(raw, {
    content,
    profile: expectedType === OID.tstInfo ? 'RFC3161' : 'CADES',
  });
  failures.push(...inspection.failures);
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
export function prepareCAdESSignature(options) {
  return prepareAdESSignature({ ...options, profile: 'CADES' });
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

function protection(signature, policy, failures, imprintHash) {
  const checked = proofProtectionDeadline(signature, { policy, imprintHashOID: imprintHash });
  failures.push(...checked.failures);
  return checked.validUntil;
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
  const info = cms.signatureInspection.info;
  let coverage;
  if (info) {
    attempt(local, () => {
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
    // Preserve all original CMS Choice TLVs for ATS coverage, but do not hand
    // recognized unselected choices to the X.509/full-CRL material parser.
    const certificates = (covered?.certificates ?? parsed.certificates).filter(
      (b) => b[0] === 0x30,
    );
    const crls = (covered?.crls ?? parsed.crls).filter((b) => b[0] === 0x30);
    let response = validateCAdESMaterial({
      certificate: Buffer.from(signature.certificate),
      certificates: copy(certificates),
      crls: copy(crls),
      knownCRLs: copy(parsed.crls.filter((b) => b[0] === 0x30)),
      purpose,
      stateTime,
      knowledgeTime: times.knowledgeTime,
      ...(covered ? { evidenceTime: covered.time } : {}),
      ...(purpose === 'TSA' && coverage ? { signatureEvidenceTime: coverage.time } : {}),
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
        const info = timestampCMS.signatureInspection.info;
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

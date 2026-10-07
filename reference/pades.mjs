import { createHash } from 'node:crypto';
import { ProtocolError, equal } from './core.mjs';
import { OID } from './pki.mjs';
import { timestampRequest } from './timestamp.mjs';
import {
  prepareAdESSignature,
  inspectAdESSignature,
  inspectRFC3161Token,
  proofProtectionDeadline,
} from './ades-cms.mjs';
import { validateCAdESMaterial } from './cades-validation.mjs';
import { preparePAdESContainer, appendPAdESDSS, inspectPAdESContainer } from './pades-io.mjs';

const LEVELS = ['B', 'T', 'LT', 'LTA'];
const HASHES = { [OID.sha256]: 'sha256', [OID.sha512]: 'sha512' };
const KINDS = ['VALID', 'INVALID', 'UNSUPPORTED', 'INDETERMINATE'];
const instant = (value) => Number.isFinite(value) && value >= 0 && value <= Number.MAX_SAFE_INTEGER;
const includes = (values, value) => values.some((item) => equal(item, value));
const union = (...arrays) =>
  arrays.flat().filter((value, index, all) => !includes(all.slice(0, index), value));
const result = (overall, reason, extra = {}) => Object.freeze({ overall, reason, ...extra });
function failure(overall, code) {
  const error = new ProtocolError(code);
  error.overall = overall;
  return error;
}
function check(condition, code, overall = 'INVALID') {
  if (!condition) throw failure(overall, code);
}
function record(error) {
  const reason = error.code ?? error.message ?? 'PADES_MALFORMED';
  const overall = KINDS.includes(error.overall)
    ? error.overall
    : /(?:TIMEOUT|RESOURCE_LIMIT|WORKER_(?:UNAVAILABLE|ERROR|EXIT|FAILURE))/.test(reason)
      ? 'INDETERMINATE'
      : 'INVALID';
  return result(overall, reason);
}
function attempt(failures, operation) {
  try {
    return operation();
  } catch (error) {
    failures.push(record(error));
  }
}
function outcome(failures) {
  for (const kind of ['INVALID', 'UNSUPPORTED', 'INDETERMINATE']) {
    const found = failures.find((item) => item?.overall === kind);
    if (found) return found;
  }
  return result('VALID', 'PADES_VALID');
}
function copy(value) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return Buffer.from(value);
  if (Array.isArray(value)) return value.map(copy);
  if (value && typeof value === 'object')
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, copy(item)]));
  return value;
}
function bytes(value, code) {
  check(Buffer.isBuffer(value) || value instanceof Uint8Array, code);
  return Buffer.from(value);
}
function digest(hashOID, content) {
  check(HASHES[hashOID], 'PADES_HASH_UNSUPPORTED', 'UNSUPPORTED');
  return createHash(HASHES[hashOID]).update(content).digest();
}
function signedContent(pdf, byteRange, signedRevisionLength) {
  check(
    Array.isArray(byteRange) &&
      byteRange.length === 4 &&
      byteRange.every((value) => Number.isSafeInteger(value) && value >= 0) &&
      byteRange[0] === 0 &&
      byteRange[1] < byteRange[2] &&
      byteRange[2] + byteRange[3] === signedRevisionLength &&
      signedRevisionLength <= pdf.length,
    'PADES_BYTE_RANGE',
  );
  return Buffer.concat([
    pdf.subarray(0, byteRange[1]),
    pdf.subarray(byteRange[2], signedRevisionLength),
  ]);
}
function preparedContainer(prepared) {
  prepared = copy(prepared);
  check(
    Buffer.isBuffer(prepared.output) &&
      Number.isSafeInteger(prepared.contentsAt) &&
      Number.isSafeInteger(prepared.signatureBytes) &&
      prepared.signatureBytes > 0 &&
      prepared.signedRevisionLength === prepared.output.length &&
      prepared.byteRange[1] === prepared.contentsAt - 1 &&
      prepared.byteRange[2] === prepared.contentsAt + prepared.signatureBytes * 2 + 1 &&
      prepared.output[prepared.contentsAt - 1] === 0x3c &&
      prepared.output[prepared.contentsAt + prepared.signatureBytes * 2] === 0x3e,
    'PADES_PREPARED_CONTENTS',
  );
  const content = signedContent(prepared.output, prepared.byteRange, prepared.signedRevisionLength);
  check(equal(content, prepared.content), 'PADES_PREPARED_CONTENT_BINDING');
  return { ...prepared, content };
}
function fill(prepared, cms) {
  cms = bytes(cms, 'PADES_CMS_REQUIRED');
  check(cms.length <= prepared.signatureBytes, 'PADES_CONTENTS_CAPACITY');
  const output = Buffer.from(prepared.output);
  const value = cms.toString('hex').padEnd(prepared.signatureBytes * 2, '0');
  output.write(value, prepared.contentsAt, value.length, 'ascii');
  check(
    equal(
      signedContent(output, prepared.byteRange, prepared.signedRevisionLength),
      prepared.content,
    ),
    'PADES_PREPARED_CONTENT_BINDING',
  );
  return output;
}
function structuralDecisions(structure, failures) {
  check(structure?.modificationPolicy, 'PADES_MODIFICATION_POLICY_MISSING');
  for (const item of [structure.modificationPolicy, ...(structure.diagnostics ?? [])]) {
    if (!item) continue;
    const overall = item.overall ?? item.status;
    check(KINDS.includes(overall), 'PADES_STRUCTURE_RESULT');
    if (overall !== 'VALID')
      failures.push(result(overall, item.reason ?? 'PADES_STRUCTURE_RESULT'));
  }
}
function policyCheck(policy) {
  check(
    Array.isArray(policy.trustedRoots) && policy.trustedRoots.length > 0,
    'PADES_TRUST_ROOTS_MISSING',
    'INDETERMINATE',
  );
  check(
    policy.scope &&
      Buffer.isBuffer(policy.scope.trustDomainID) &&
      policy.scope.trustDomainID.length === 32 &&
      typeof policy.scope.issuerID === 'string' &&
      policy.scope.issuerID.length > 0 &&
      policy.scope.representation === 'X509',
    'PADES_POLICY_SCOPE',
  );
  check(
    typeof policy.authorityResolver === 'function',
    'AUTHORITY_RESOLVER_REQUIRED',
    'INDETERMINATE',
  );
}
function protection(signature, policy, failures, imprintHashOID) {
  if (!signature) return undefined;
  const checked = proofProtectionDeadline(signature, { policy, imprintHashOID });
  failures.push(...checked.failures);
  return checked.validUntil;
}
function materialsAt(structure, entries, revisionIndex, excludeEntry) {
  const revision = structure.revisions[revisionIndex];
  check(
    revision && Array.isArray(revision.certificates) && Array.isArray(revision.crls),
    'PADES_REVISION_MATERIAL',
  );
  const embedded = entries.filter(
    (entry) => entry !== excludeEntry && entry.revisionIndex <= revisionIndex,
  );
  return {
    certificates: union(
      revision.certificates,
      ...embedded.map((entry) => entry.parsed?.certificates ?? []),
    ).filter((value) => value[0] === 0x30),
    crls: union(revision.crls, ...embedded.map((entry) => entry.parsed?.crls ?? [])).filter(
      (value) => value[0] === 0x30,
    ),
    dssPresent: revision.dssPresent === true,
  };
}
function covers(proof, entry) {
  return (
    proof.authenticated &&
    proof.revisionIndex > entry.revisionIndex &&
    proof.byteRange[1] >= entry.signedRevisionLength
  );
}
function materialFor(
  signature,
  purpose,
  stateTime,
  current,
  policy,
  times,
  failures,
  coverages = [],
  noPOE = false,
) {
  if (!signature?.certificate || !instant(stateTime) || stateTime > times.knowledgeTime)
    return undefined;
  const evaluate = (covered) => {
    const material = covered ?? current;
    let checked = validateCAdESMaterial({
      certificate: Buffer.from(signature.certificate),
      certificates: copy(material.certificates),
      crls: copy(material.crls),
      knownCRLs: copy(current.crls),
      purpose,
      stateTime,
      knowledgeTime: times.knowledgeTime,
      ...(covered ? { evidenceTime: covered.time } : {}),
      policy: copy(policy),
    });
    if (purpose === 'SIGNER' && noPOE && stateTime === times.validationTime) {
      const rootTimeMissing = checked.checks.some((item) => item.reason === 'CADES_ROOT_TIME');
      const checks = checked.checks.map((item) =>
        item.overall === 'INVALID' &&
        (['CADES_CERTIFICATE_TIME', 'CADES_ROOT_TIME'].includes(item.reason) ||
          (rootTimeMissing &&
            item.authorityRole === 'ISSUER' &&
            item.authorityStateTime === stateTime &&
            ['AUTHORITY_EXPIRED', 'AUTHORITY_NOT_YET_VALID'].includes(item.reason)))
          ? result('INDETERMINATE', 'PADES_SIGNER_POE_MISSING')
          : item,
      );
      checked = { ...checked, ...outcome(checks), checks };
    }
    if (
      covered &&
      checked.overall === 'VALID' &&
      !(
        checked.usedCertificates.every((value) => includes(material.certificates, value)) &&
        checked.usedCRLs.every((value) => includes(material.crls, value))
      )
    )
      return result('INDETERMINATE', 'PADES_HISTORICAL_MATERIAL_NOT_COVERED');
    return checked;
  };
  let checked;
  // Signature existence and material existence need not share the same proof.
  // Each candidate is an independently authenticated revision covering this
  // object's bytes. An unavailable slice may be completed by a later proof.
  // Retain unsupported dependencies while still looking for an authenticated
  // known invalidity, which has stronger precedence than capability uncertainty.
  for (const coverage of [...coverages, undefined]) {
    const candidate = attempt(failures, () => evaluate(coverage));
    if (!candidate) continue;
    checked ??= candidate;
    if (candidate.overall === 'INVALID') {
      checked = candidate;
      break;
    }
    if (candidate.overall === 'UNSUPPORTED') checked = candidate;
    if (candidate.overall === 'VALID' && checked.overall !== 'UNSUPPORTED') {
      checked = candidate;
      break;
    }
  }
  if (checked && checked.overall !== 'VALID') failures.push(checked);
  return checked;
}
function materialClosure(material, embedded) {
  return (
    material?.overall === 'VALID' &&
    material.usedCertificates.every((value) => includes(embedded.certificates, value)) &&
    material.usedCRLs.every((value) => includes(embedded.crls, value))
  );
}

/** Construct a new detached approval; this primitive grants no trust verdict. */
export async function preparePAdESSignature(
  pdf,
  {
    certificate,
    certificates = [],
    signingTime,
    signatureBytes = 32768,
    fieldName,
    algorithmProfile = 'ES256',
  } = {},
) {
  pdf = bytes(pdf, 'PADES_PDF_REQUIRED');
  certificate = bytes(certificate, 'PADES_SIGNER_CERTIFICATE_REQUIRED');
  certificates = copy(certificates);
  check(Number.isSafeInteger(signingTime) && instant(signingTime), 'PADES_SIGNING_TIME_REQUIRED');
  const prepared = preparedContainer(
    await preparePAdESContainer(pdf, {
      kind: 'SIGNATURE',
      signingTime,
      signatureBytes,
      fieldName,
    }),
  );
  const signing = prepareAdESSignature({
    profile: 'PADES',
    content: prepared.content,
    certificate,
    certificates,
    detached: true,
    algorithmProfile,
  });
  return Object.freeze({
    tbs: Buffer.from(signing.tbs),
    byteRange: [...prepared.byteRange],
    contentHash: digest(OID.sha256, prepared.content),
    async finish(signature) {
      signature = bytes(signature, 'PADES_SIGNATURE_REQUIRED');
      const cms = signing.finish(signature),
        output = fill(prepared, cms);
      const inspected = await inspectPAdESContainer(output),
        failures = [];
      structuralDecisions(inspected, failures);
      const approvals = inspected.signatures.filter((entry) => entry.kind === 'SIGNATURE');
      check(approvals.length === 1, 'PADES_APPROVAL_COUNT', 'UNSUPPORTED');
      const approval = approvals[0];
      check(
        equal(approval.cms, cms) && approval.signedRevisionLength === output.length,
        'PADES_PREPARED_SIGNATURE_BINDING',
      );
      const checked = inspectAdESSignature(approval.cms, {
        profile: 'PADES',
        content: signedContent(output, approval.byteRange, approval.signedRevisionLength),
      });
      failures.push(...checked.failures);
      const final = outcome(failures);
      if (final.overall !== 'VALID') throw failure(final.overall, final.reason);
      return Buffer.from(output);
    },
  });
}

/** Verify exactly covered PDF revisions under an external relying-party policy. */
export async function verifyPAdES(
  pdf,
  { minimumLevel = 'B', originalPDF, validationTime, knowledgeTime, policy } = {},
) {
  const failures = [],
    materials = [];
  let structure, linkage;
  try {
    pdf = bytes(pdf, 'PADES_PDF_REQUIRED');
    originalPDF =
      originalPDF === undefined ? undefined : bytes(originalPDF, 'PADES_ORIGINAL_PDF_REQUIRED');
    policy = copy(policy ?? {});
    check(LEVELS.includes(minimumLevel), 'PADES_LEVEL_UNSUPPORTED', 'UNSUPPORTED');
    check(
      instant(validationTime) && instant(knowledgeTime) && validationTime <= knowledgeTime,
      'PADES_VALIDATION_TIME',
    );
    structure = await inspectPAdESContainer(pdf);
    structuralDecisions(structure, failures);
    check(
      Array.isArray(structure.signatures) &&
        Array.isArray(structure.revisions) &&
        structure.revisions.length > 0,
      'PADES_STRUCTURE_RESULT',
    );
    const entries = structure.signatures.map((entry) => {
      const local = [];
      const content = attempt(local, () =>
        signedContent(pdf, entry.byteRange, entry.signedRevisionLength),
      );
      const inspected =
        entry.kind === 'SIGNATURE'
          ? inspectAdESSignature(entry.cms, { content, profile: 'PADES' })
          : entry.kind === 'TIMESTAMP'
            ? inspectRFC3161Token(entry.cms)
            : undefined;
      if (!inspected) local.push(result('UNSUPPORTED', 'PADES_SIGNATURE_KIND_UNSUPPORTED'));
      else local.push(...inspected.failures);
      if (
        entry.kind === 'TIMESTAMP' &&
        inspected?.failures.some((decision) => decision.reason === 'CADES_MULTIPLE_SIGNERS')
      )
        local.push(result('INVALID', 'PADES_MULTIPLE_SIGNERS'));
      const item = { ...entry, ...inspected, failures: local, content };
      if (entry.kind === 'TIMESTAMP' && item.info) {
        attempt(local, () =>
          check(
            equal(item.info.imprint, digest(item.info.hashOID, content)),
            'PADES_TIMESTAMP_IMPRINT',
          ),
        );
        attempt(local, () => {
          check(
            Array.isArray(policy.timestampPolicies) && policy.timestampPolicies.length > 0,
            'PADES_TIMESTAMP_POLICIES_MISSING',
            'INDETERMINATE',
          );
          check(policy.timestampPolicies.includes(item.info.policy), 'PADES_TIMESTAMP_POLICY');
          check(
            item.info.poeUpperBound <= knowledgeTime,
            'PADES_TIMESTAMP_NOT_YET_KNOWN',
            'INDETERMINATE',
          );
        });
        for (const attribute of item.parsed?.unsigned ?? [])
          local.push(result('UNSUPPORTED', 'PADES_TSA_UNSIGNED_ATTRIBUTE', { oid: attribute.id }));
      }
      failures.push(...local);
      return item;
    });
    const approvals = entries.filter((entry) => entry.kind === 'SIGNATURE');
    check(approvals.length > 0, 'PADES_APPROVAL_MISSING', 'INDETERMINATE');
    check(approvals.length === 1, 'PADES_APPROVAL_COUNT', 'UNSUPPORTED');
    const approval = approvals[0];
    attempt(failures, () => policyCheck(policy));
    if (originalPDF !== undefined) {
      await (async () => {
        try {
          check(
            originalPDF.length <= pdf.length &&
              equal(originalPDF, pdf.subarray(0, originalPDF.length)),
            'PADES_ORIGINAL_PREFIX_MISMATCH',
          );
          check(
            structure.revisions.some((revision) => revision.length === originalPDF.length),
            'PADES_ORIGINAL_REVISION_MISMATCH',
          );
          const original = await inspectPAdESContainer(originalPDF),
            originalFailures = [];
          structuralDecisions(original, originalFailures);
          failures.push(...originalFailures);
          const originalApproval = original.signatures.filter(
            (entry) => entry.kind === 'SIGNATURE',
          );
          check(
            originalApproval.length === 1 &&
              equal(originalApproval[0].cms, approval.cms) &&
              originalApproval[0].signedRevisionLength === approval.signedRevisionLength,
            'PADES_ORIGINAL_SIGNATURE_MISMATCH',
          );
          linkage = 'MATCHED';
        } catch (error) {
          failures.push(record(error));
        }
      })();
    }
    const times = { validationTime, knowledgeTime };
    const current = materialsAt(structure, entries, structure.revisions.length - 1);
    const timestamps = entries
      .filter((entry) => entry.kind === 'TIMESTAMP')
      .sort((a, b) => a.revisionIndex - b.revisionIndex);
    for (let index = 0; index < timestamps.length; index++) {
      const item = timestamps[index],
        previous = timestamps[index - 1];
      attempt(failures, () =>
        check(
          item.revisionIndex > approval.revisionIndex &&
            item.byteRange[1] >= approval.signedRevisionLength,
          'PADES_TIMESTAMP_COVERAGE',
        ),
      );
      if (previous?.info && item.info)
        attempt(failures, () =>
          check(
            previous.info.poeUpperBound <= item.info.genTime - item.info.accuracy,
            'PADES_TIMESTAMP_TIME_ORDER',
          ),
        );
    }
    // A timestamp never authenticates its own TSU material. Establish current
    // trust for the newest proof, then follow byte-exact later coverage backwards.
    for (let index = timestamps.length - 1; index >= 0; index--) {
      const item = timestamps[index],
        local = [...item.failures];
      const successors = timestamps.slice(index + 1).filter((later) => covers(later, item));
      const successor = successors[0];
      const covered = successors.map((proof) => ({
        ...materialsAt(structure, entries, proof.revisionIndex, proof),
        time: proof.info.poeUpperBound,
      }));
      if (item.info && item.signature) {
        const low = materialFor(
          item.signature,
          'TSA',
          item.info.genTime - item.info.accuracy,
          current,
          policy,
          times,
          local,
          covered,
        );
        const high = materialFor(
          item.signature,
          'TSA',
          item.info.poeUpperBound,
          current,
          policy,
          times,
          local,
          covered,
        );
        item.material = high;
        item.materials = [low, high];
        materials.push(low, high);
        const deadline = protection(item.signature, policy, local, item.info.hashOID);
        const horizons = [deadline, high?.overall === 'VALID' ? high.validUntil : undefined].filter(
          instant,
        );
        // A missing current status does not erase an already known protection
        // cutoff. Only an authenticated successor may move this endpoint back.
        if (horizons.length)
          attempt(local, () =>
            check(
              (successor?.info.poeUpperBound ?? knowledgeTime) < Math.min(...horizons),
              'PADES_PROTECTION_GAP',
            ),
          );
      }
      item.authenticated =
        !!item.info && item.material?.overall === 'VALID' && outcome(local).overall === 'VALID';
      item.failures = local;
      // All material/protection failures participate in the final aggregate.
      for (const decision of local) if (!failures.includes(decision)) failures.push(decision);
    }
    const trusted = timestamps.find(
      (item) => item.authenticated && item.info.poeUpperBound <= validationTime,
    );
    const stateTime = trusted?.info.poeUpperBound ?? validationTime;
    const signerCoverage = trusted
      ? timestamps
          .filter((proof) => covers(proof, approval))
          .map((proof) => ({
            ...materialsAt(structure, entries, proof.revisionIndex, proof),
            time: proof.info.poeUpperBound,
          }))
      : [];
    const signerMaterial = materialFor(
      approval.signature,
      'SIGNER',
      stateTime,
      current,
      policy,
      times,
      failures,
      signerCoverage,
      !trusted,
    );
    materials.push(signerMaterial);
    const signerDeadline = protection(approval.signature, policy, failures);
    const signerHorizons = [
      signerDeadline,
      signerMaterial?.overall === 'VALID' ? signerMaterial.validUntil : undefined,
    ].filter(instant);
    if (signerHorizons.length)
      attempt(failures, () =>
        check(
          (trusted ? stateTime : knowledgeTime) < Math.min(...signerHorizons),
          'PADES_SIGNER_PROTECTION_GAP',
        ),
      );
    if (signerMaterial?.overall === 'VALID')
      attempt(failures, () =>
        check(
          signerMaterial.usedCertificates.every((value) =>
            includes(approval.parsed.certificates, value),
          ),
          'PADES_BASELINE_CERTIFICATE_MISSING',
          'INDETERMINATE',
        ),
      );
    const completeMaterial =
      current.dssPresent &&
      materials.filter(Boolean).every((material) => materialClosure(material, current));
    const latest = timestamps.at(-1);
    const latestCovered = latest?.authenticated
      ? materialsAt(structure, entries, latest.revisionIndex, latest)
      : undefined;
    const preexisting = [
      signerMaterial,
      ...timestamps.slice(0, -1).flatMap((item) => item.materials ?? [item.material]),
    ];
    const latestRevision = latest && structure.revisions[latest.revisionIndex];
    const finalRevision = structure.revisions.at(-1);
    const completeProtection =
      latest?.authenticated &&
      latestCovered?.dssPresent &&
      preexisting.every((material) => materialClosure(material, latestCovered)) &&
      finalRevision.certificates.every((value) => includes(latestRevision.certificates, value)) &&
      finalRevision.crls.every((value) => includes(latestRevision.crls, value));
    let verifiedLevel;
    if (outcome(failures).overall === 'VALID')
      verifiedLevel = trusted
        ? completeMaterial
          ? completeProtection
            ? 'LTA'
            : 'LT'
          : 'T'
        : 'B';
    if (LEVELS.indexOf(minimumLevel) >= 1 && !trusted)
      failures.push(result('INDETERMINATE', 'PADES_SIGNATURE_POE_MISSING'));
    if (LEVELS.indexOf(minimumLevel) >= 2 && !completeMaterial)
      failures.push(result('INDETERMINATE', 'PADES_LT_MATERIAL_MISSING'));
    if (minimumLevel === 'LTA' && !completeProtection)
      failures.push(result('INDETERMINATE', 'PADES_LTA_COVERAGE_MISSING'));
    const final = outcome(failures);
    return result(final.overall, final.reason, {
      requestedLevel: minimumLevel,
      ...(verifiedLevel ? { verifiedLevel } : {}),
      ...(linkage ? { originalPDFLinkage: linkage } : {}),
      ...(trusted ? { stateTime, poeUpperBound: stateTime } : {}),
      ...(latest?.authenticated ? { preservationTime: latest.info.poeUpperBound } : {}),
      modificationPolicy: copy(structure.modificationPolicy),
      failures: Object.freeze(failures.map((item) => result(item.overall, item.reason))),
    });
  } catch (error) {
    failures.push(record(error));
    const final = outcome(failures);
    return result(final.overall, final.reason, {
      requestedLevel: minimumLevel,
      failures: Object.freeze(failures.map((item) => result(item.overall, item.reason))),
    });
  }
}

/** Prepare a byte-preserving DSS and/or document-timestamp incremental update. */
export async function preparePAdESAugmentation(
  pdf,
  {
    targetLevel,
    validationMaterial = {},
    timestampRequestOptions = {},
    policy,
    signatureBytes = 32768,
    fieldName,
  } = {},
) {
  pdf = bytes(pdf, 'PADES_PDF_REQUIRED');
  validationMaterial = copy(validationMaterial);
  timestampRequestOptions = copy(timestampRequestOptions);
  policy = copy(policy ?? {});
  check(['T', 'LT', 'LTA'].includes(targetLevel), 'PADES_LEVEL_UNSUPPORTED', 'UNSUPPORTED');
  const inspected = await inspectPAdESContainer(pdf),
    initialFailures = [];
  structuralDecisions(inspected, initialFailures);
  const approvals = inspected.signatures.filter((entry) => entry.kind === 'SIGNATURE');
  check(approvals.length === 1, 'PADES_APPROVAL_COUNT', 'UNSUPPORTED');
  for (const approval of approvals) {
    const checked = inspectAdESSignature(approval.cms, {
      profile: 'PADES',
      content: signedContent(pdf, approval.byteRange, approval.signedRevisionLength),
    });
    initialFailures.push(...checked.failures);
  }
  const initial = outcome(initialFailures);
  if (initial.overall !== 'VALID') throw failure(initial.overall, initial.reason);
  const certificates = validationMaterial.certificates ?? [],
    crls = validationMaterial.crls ?? [];
  check(Array.isArray(certificates) && Array.isArray(crls), 'PADES_VALIDATION_MATERIAL');
  let candidate = Buffer.from(pdf);
  if (targetLevel !== 'T' || certificates.length || crls.length)
    candidate = await appendPAdESDSS(candidate, { certificates, crls });
  let prepared, request;
  const hashOID = timestampRequestOptions.hashOID ?? OID.sha256;
  if (targetLevel !== 'LT') {
    prepared = preparedContainer(
      await preparePAdESContainer(candidate, { kind: 'TIMESTAMP', signatureBytes, fieldName }),
    );
    request = timestampRequest(digest(hashOID, prepared.content), {
      ...timestampRequestOptions,
      hashOID,
    });
  }
  return Object.freeze({
    ...(request
      ? { requestDER: Buffer.from(request.der), imprint: Buffer.from(request.imprint), hashOID }
      : {}),
    async finish(token, { validationTime, knowledgeTime, policy: updatedPolicy } = {}) {
      token = token === undefined ? undefined : bytes(token, 'PADES_TIMESTAMP_REQUIRED');
      const currentPolicy = copy(updatedPolicy === undefined ? policy : updatedPolicy);
      let output = Buffer.from(candidate);
      if (request) {
        check(token, 'PADES_TIMESTAMP_MISSING', 'INDETERMINATE');
        const checked = inspectRFC3161Token(token, { request });
        if (checked.overall !== 'VALID') throw failure(checked.overall, checked.reason);
        output = fill(prepared, token);
      } else check(token === undefined, 'PADES_UNEXPECTED_TIMESTAMP');
      const checked = await verifyPAdES(output, {
        minimumLevel: targetLevel,
        originalPDF: pdf,
        validationTime,
        knowledgeTime,
        policy: currentPolicy,
      });
      if (checked.overall !== 'VALID') throw failure(checked.overall, checked.reason);
      return Buffer.from(output);
    },
  });
}

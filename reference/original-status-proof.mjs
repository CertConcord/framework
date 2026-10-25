import { decodeCBOR, dcbor, equal } from './core.mjs';
import { parseCertificate, OID } from './pki.mjs';
import { readControl } from './state.mjs';
import { verifyStatusPreservation } from './status-preservation.mjs';
import { requireStatusDecision } from './status-result.mjs';
import { VerificationError } from './verification-result.mjs';

const need = (ok, reason, overall = 'INVALID') => {
  if (!ok) throw new VerificationError(reason, overall, 'status');
};

/** Select the original typed status and derive every authority-query identity from it. */
export function originalStatusContext(format, originalBytes, trust) {
  need(format === 'CMS', 'ORIGINAL_STATUS_CMS_ONLY', 'UNSUPPORTED');
  const original = decodeCBOR(originalBytes);
  const one = (type) => {
    const objects = original.objects.filter((object) => object.type === type);
    need(objects.length > 0, 'ORIGINAL_STATUS_MISSING_' + type, 'INDETERMINATE');
    need(objects.length === 1, 'ORIGINAL_STATUS_SINGLE_' + type);
    return objects[0].payload;
  };
  need(
    !original.objects.some((object) =>
      ['OrganizationAuthorizationStatus', 'CredentialStatusList'].includes(object.type),
    ),
    'ORIGINAL_STATUS_SINGLE_STATUS_ONLY',
    'UNSUPPORTED',
  );
  const cms = one('CertificateStatus'),
    certificate = parseCertificate(one('Certificate')),
    sim = decodeCBOR(one('SIM'));
  const body = readControl(cms, 'CertificateStatus', trust.statusCertificate);
  need(body.schemaVersion === 1 && body.scope === 'CERTIFICATE', 'ORIGINAL_STATUS_TYPE');
  need(
    equal(body.certificateID, certificate.certificateID) &&
      equal(body.trustDomainID, trust.trustDomainID),
    'ORIGINAL_STATUS_TARGET',
  );
  const scope = {
    trustDomainID: trust.trustDomainID,
    issuerID: trust.issuanceScope.issuerID,
    representation: certificate.algorithm === OID.mtc ? 'MTC' : 'X509',
    profileID: sim.profileID,
  };
  return {
    overall: 'VALID',
    cms,
    body,
    scope,
    certificate: trust.statusCertificate,
    matches(query, H) {
      return (
        query.role === 'STATUS_AUTHORITY' &&
        query.stateTime === body.publishedAt &&
        query.knowledgeTime === H &&
        equal(query.certificate, trust.statusCertificate) &&
        equal(dcbor(query.scope), dcbor(scope))
      );
    },
  };
}

/** Admit the selected exact CMS proof under H knowledge and preserve its chain through K. */
export function verifyOriginalStatusProof(context, selection, H, K) {
  need(
    selection &&
      typeof selection === 'object' &&
      !Array.isArray(selection) &&
      Object.keys(selection).every((key) =>
        ['evidenceRecord', 'preservationPolicy', 'protectionTrust'].includes(key),
      ),
    'ORIGINAL_STATUS_SELECTION',
  );
  if (context.overall !== 'VALID')
    throw new VerificationError(context.reason, context.overall, 'status');
  need(selection.evidenceRecord != null, 'ORIGINAL_STATUS_EVIDENCE_UNAVAILABLE', 'INDETERMINATE');
  let initialStatus;
  const preservation = selection.preservationPolicy;
  const policy =
    typeof preservation?.resolveTimestamp === 'function'
      ? {
          ...preservation,
          resolveTimestamp(token) {
            const selected = preservation.resolveTimestamp(token);
            if (typeof selected?.status !== 'function') return selected;
            return {
              ...selected,
              status(query) {
                // The shared helper verifies the initial proof before its renewal chain.
                initialStatus ??= {
                  evaluate: selected.status,
                  query: { ...query, certificate: Buffer.from(query.certificate) },
                };
                return selected.status(query);
              },
            };
          },
        }
      : preservation;
  const proofTime = verifyStatusPreservation(
    {
      cms: context.cms,
      issuerCertificate: context.certificate,
      evidenceRecord: selection.evidenceRecord,
    },
    context.body.publishedAt,
    selection.protectionTrust ?? {},
    K,
    policy,
    'ORIGINAL_STATUS',
  );
  need(proofTime <= H, 'ORIGINAL_STATUS_PROOF_NOT_YET_VISIBLE', 'INDETERMINATE');
  need(
    initialStatus?.query.stateTime === proofTime && initialStatus.query.knowledgeTime === proofTime,
    'ORIGINAL_STATUS_INITIAL_QUERY',
  );
  requireStatusDecision(
    initialStatus.evaluate,
    { ...initialStatus.query, knowledgeTime: H },
    'ORIGINAL_STATUS_TSA',
  );
  return {
    overall: 'VALID',
    reason: 'ORIGINAL_STATUS_PROOF_BOUND',
    proofOfExistenceUpperBound: proofTime,
  };
}

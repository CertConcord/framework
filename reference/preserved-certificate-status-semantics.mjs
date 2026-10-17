import assert from 'node:assert/strict';

// Authoring/test oracle only. No verifier or replay runner imports this module.
const define = (id, reason, overall = 'INVALID', overrides = {}) =>
  Object.freeze({
    id,
    overall,
    historical: 'VALID',
    current: overall,
    preservation: 'VALID',
    reason,
    currentReason: overall === 'VALID' ? 'ORG_HISTORY_AUTHORIZED' : reason,
    ...overrides,
  });
const valid = (id) => define(id, 'ORG_HISTORY_VALID', 'VALID');
export const preservedCertificateStatusSemantics = Object.freeze([
  valid('preserved-good'),
  valid('ordinary-revocation-after-document-proof'),
  define('revocation-at-document-proof', 'STATUS_REVOKED'),
  define('compromise-before-document-proof', 'STATUS_REVOKED'),
  define('retired-without-proof', 'AUTHORITY_EXPIRED'),
  define('proof-before-publication', 'ORG_CERTIFICATE_STATUS_PROOF_TIME'),
  valid('proof-at-publication'),
  valid('proof-before-protection-deadline'),
  define('proof-at-protection-deadline', 'ERS_INITIAL_PROOF_LATE'),
  define('proof-after-protection-deadline', 'ERS_INITIAL_PROOF_LATE'),
  valid('renewal-before-expiry'),
  define('renewal-at-expiry', 'ERS_RENEWAL_LATE'),
  define('renewal-after-expiry', 'ERS_RENEWAL_LATE'),
  define('proof-signature-tampered', 'CMS_SIGNATURE'),
  define('proof-covers-different-cms', 'TSA_REQUEST_BINDING'),
  define('cms-signer-certificate-substituted', 'CERTIFICATE_REPRESENTATION'),
  define('status-cross-domain', 'ORG_CERTIFICATE_STATUS_BINDING'),
  define('status-other-certificate', 'ORG_CERTIFICATE_STATUS_BINDING'),
  define('status-wrong-scope', 'STATUS_SCOPE_OR_KNOWLEDGE'),
  define('signer-not-appointed-at-publication', 'AUTHORITY_NOT_YET_VALID'),
  define('signer-retired-at-proof', 'AUTHORITY_EXPIRED'),
  define('signer-wrong-role', 'AUTHORITY_ROLE'),
  define('signer-wrong-scope', 'AUTHORITY_SCOPE'),
  define('signer-revoked-at-publication', 'AUTHORITY_REVOKED'),
  define('signer-compromised-at-proof', 'AUTHORITY_REVOKED'),
  valid('signer-compromised-after-proof'),
  define('missing-current-authority-coverage', 'HISTORY_KNOWLEDGE_COVERAGE', 'INDETERMINATE', {
    preservation: 'INDETERMINATE',
  }),
  define('stale-preserved-good', 'STATUS_STALE', 'INDETERMINATE'),
  define('stale-retrospective-compromise', 'STATUS_REVOKED'),
  define('same-publication-conflict', 'ORG_CERTIFICATE_STATUS_CONFLICT'),
  define('compromise-followed-by-current-good', 'STATUS_REVOKED'),
  valid('unpreserved-current-successor'),
  valid('current-successor-valid-proof'),
  define('current-successor-invalid-proof', 'CMS_SIGNATURE'),
  // The first proof's TSA query exceeds the resolver's selected K before the
  // credential-specific time guard is reached.
  define('current-successor-proof-after-knowledge', 'HISTORY_TIME'),
  valid('proof-at-selected-knowledge'),
  define('preserved-status-critical-unknown', 'STATUS_UNSUPPORTED', 'UNSUPPORTED'),
  define('missing-current-certificate-status', 'STATUS_STALE', 'INDETERMINATE'),
  define('missing-status-tsa-selection', 'ERS_TSA_TRUST_UNAVAILABLE', 'INDETERMINATE', {
    historical: 'INDETERMINATE',
    preservation: 'INDETERMINATE',
  }),
  define('malformed-status-proof', 'DER_TRUNCATED'),
  define('missing-status-key-deadline', 'ORG_PROTECTION_DEADLINE_MISSING', 'INDETERMINATE'),
]);

export function assertPreservedCertificateStatusOutcome(input, actual) {
  const spec = preservedCertificateStatusSemantics.find((entry) => entry.id === input.id);
  assert(spec, input.id);
  assert.equal(actual.overall, spec.overall, input.id + ': overall');
  assert.equal(actual.reason, spec.reason, input.id + ': reason');
  assert.equal(actual.historicalAuthorization.overall, spec.historical, input.id + ': historical');
  assert.equal(actual.currentAdmissibility.overall, spec.current, input.id + ': current');
  assert.equal(
    actual.currentAdmissibility.reason,
    spec.currentReason,
    input.id + ': current reason',
  );
  assert.equal(actual.preservation.overall, spec.preservation, input.id + ': preservation');
  const documentProof = input.id === 'missing-status-tsa-selection' ? null : 1_800_000_001;
  assert.equal(actual.proofOfExistenceUpperBound, documentProof);
  assert.equal(actual.historicalAuthorization.stateTime, documentProof);
  assert.equal(actual.currentAdmissibility.stateTime, documentProof);
  assert.equal(actual.currentAdmissibility.knowledgeTime, 1_800_007_200);
}

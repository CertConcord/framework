import assert from 'node:assert/strict';

// Authoring/test oracle only. Verification and replay never import this module.
const define = (id, reason, overall = 'INVALID', overrides = {}) =>
  Object.freeze({
    id,
    overall,
    historical: 'VALID',
    current: overall,
    preservation: 'VALID',
    proof: 1_800_000_001,
    reason,
    currentReason: overall === 'VALID' ? 'ORG_HISTORY_AUTHORIZED' : reason,
    ...overrides,
  });
const valid = (id) => define(id, 'ORG_HISTORY_VALID', 'VALID');
export const preservedDelegationStatusSemantics = Object.freeze([
  valid('preserved-grant'),
  valid('preserved-approver-registration'),
  valid('preserved-final-authorization'),
  define('retired-without-proof', 'AUTHORITY_EXPIRED'),
  define('proof-before-publication', 'ORG_STATUS_PROOF_TIME'),
  valid('proof-at-publication'),
  valid('proof-before-key-deadline'),
  define('proof-at-key-deadline', 'ERS_INITIAL_PROOF_LATE'),
  define('proof-at-signature-algorithm-deadline', 'ERS_INITIAL_PROOF_LATE'),
  define('proof-at-hash-deadline', 'ERS_INITIAL_PROOF_LATE'),
  define('proof-at-certificate-expiry', 'ERS_INITIAL_PROOF_LATE'),
  valid('renewal-before-expiry'),
  define('renewal-at-expiry', 'ERS_RENEWAL_LATE'),
  define('renewal-after-expiry', 'ERS_RENEWAL_LATE'),
  define('proof-signature-tampered', 'CMS_SIGNATURE'),
  define('proof-covers-different-cms', 'TSA_REQUEST_BINDING'),
  define('malformed-status-proof', 'DER_TRUNCATED'),
  define('cms-signer-certificate-substituted', 'CERTIFICATE_REPRESENTATION'),
  define('status-cross-domain', 'ORG_SCOPE'),
  define('status-cross-organization', 'ORG_SCOPE'),
  define('status-wrong-scope', 'ORG_STATUS_SCHEMA'),
  define('status-target-unavailable', 'ORG_STATUS_TARGET_UNAVAILABLE', 'INDETERMINATE'),
  define('status-wrong-object-hash', 'ORG_STATUS_TARGET_BINDING'),
  define('status-wrong-subject-key', 'ORG_STATUS_TARGET_BINDING'),
  define('signer-not-appointed-at-publication', 'AUTHORITY_NOT_YET_VALID'),
  define('signer-retired-at-proof', 'AUTHORITY_EXPIRED'),
  define('signer-wrong-role', 'AUTHORITY_ROLE'),
  define('signer-wrong-scope', 'AUTHORITY_SCOPE'),
  define('signer-object-type-not-mapped', 'ORG_AUTHORITY_MAPPING', 'INDETERMINATE'),
  define('signer-revoked-at-publication', 'AUTHORITY_REVOKED'),
  define('signer-compromised-at-proof', 'AUTHORITY_REVOKED'),
  valid('signer-compromised-after-proof'),
  define('missing-current-authority-coverage', 'HISTORY_KNOWLEDGE_COVERAGE', 'INDETERMINATE', {
    preservation: 'INDETERMINATE',
  }),
  define('stale-preserved-good', 'STATUS_STALE', 'INDETERMINATE'),
  define('stale-retrospective-compromise', 'ORG_STATUS_REVOKED'),
  valid('ordinary-revocation-after-document-proof'),
  define('revocation-at-document-proof', 'ORG_STATUS_REVOKED'),
  define('compromise-followed-by-current-good', 'ORG_STATUS_REVOKED'),
  define('same-epoch-conflict', 'ORG_STATUS_CONFLICT'),
  define('duplicate-invalid-proof', 'CMS_SIGNATURE'),
  valid('original-copy-valid-proof'),
  define('original-copy-invalid-proof', 'CMS_SIGNATURE'),
  define('original-copy-role-retired-at-package-proof', 'AUTHORITY_EXPIRED', 'INVALID', {
    historical: 'INVALID',
    proof: 1_800_000_020,
  }),
  valid('unpreserved-current-successor'),
  valid('current-successor-valid-proof'),
  define('current-successor-invalid-proof', 'CMS_SIGNATURE'),
  valid('proof-at-selected-knowledge'),
  define('current-successor-proof-after-knowledge', 'HISTORY_TIME'),
  define('preserved-status-critical-unknown', 'STATUS_UNSUPPORTED', 'UNSUPPORTED'),
  define('missing-status-key-deadline', 'ORG_KEY_MISSING', 'INDETERMINATE'),
]);

export function assertPreservedDelegationStatusOutcome(input, actual) {
  const spec = preservedDelegationStatusSemantics.find((entry) => entry.id === input.id);
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
  assert.equal(actual.proofOfExistenceUpperBound, spec.proof, input.id + ': package proof');
  assert.equal(actual.historicalAuthorization.stateTime, spec.proof);
  assert.equal(actual.currentAdmissibility.stateTime, spec.proof);
  assert.equal(actual.currentAdmissibility.knowledgeTime, 1_800_000_200);
}

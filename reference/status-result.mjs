import { requireThat } from './core.mjs';

/** Shared decision boundary for authenticated status evidence. */
export function statusResult(status, reason, details = {}) {
  const outcomes = {
    GOOD: 'VALID', REVOKED: 'INVALID', INVALID: 'INVALID',
    STALE: 'INDETERMINATE', UNKNOWN: 'INDETERMINATE',
    NOT_YET_KNOWN: 'INDETERMINATE', UNAVAILABLE: 'INDETERMINATE',
    UNSUPPORTED: 'UNSUPPORTED',
  };
  requireThat(Object.hasOwn(outcomes, status), 'STATUS_RESULT');
  const selected = ['NOT_YET_KNOWN', 'UNAVAILABLE'].includes(status) ? 'UNKNOWN' : status;
  return Object.freeze({ ...details, status: selected, overall: outcomes[status], ...(reason ? { reason } : {}) });
}

export function evaluateStatusEvidence(verify, prefix) {
  try { return verify(); }
  catch (error) {
    const reason = error.code ?? prefix + '_MALFORMED';
    return statusResult(['STATUS_CRITICAL_EXTENSION', 'DELTA_CRL_UNSUPPORTED'].includes(reason)
      ? 'UNSUPPORTED' : 'INVALID', reason);
  }
}

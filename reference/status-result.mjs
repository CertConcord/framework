import { requireThat } from './core.mjs';
import { VerificationError } from './verification-result.mjs';
import { isPromise } from 'node:util/types';

/** Admit a synchronous, explicit decision from an external status evaluator. */
export function requireStatusDecision(evaluate, query, code, dimension = 'time') {
  let decision;
  try {
    decision = evaluate(query);
  } catch {
    // Exceptions describe an unavailable evaluator, not an authenticated verdict.
    throw new VerificationError(code + '_UNAVAILABLE', 'INDETERMINATE', dimension);
  }
  // Legacy booleans cannot distinguish missing information from a rejection.
  if (decision === true) return;
  if (decision === false) throw new VerificationError(code, 'INVALID', dimension);
  if (isPromise(decision)) {
    // Observe native rejections without invoking an untrusted thenable method.
    Promise.prototype.then.call(decision, undefined, () => {});
    throw new VerificationError(code + '_DECISION', 'INVALID', dimension);
  }
  let overall, reason;
  try {
    const prototype = decision && Object.getPrototypeOf(decision);
    const selected = decision && Object.getOwnPropertyDescriptor(decision, 'overall');
    const explanation = decision && Object.getOwnPropertyDescriptor(decision, 'reason');
    if (
      decision === null ||
      typeof decision !== 'object' ||
      (prototype !== Object.prototype && prototype !== null) ||
      Object.hasOwn(decision, 'then') ||
      !selected ||
      !Object.hasOwn(selected, 'value') ||
      !explanation ||
      !Object.hasOwn(explanation, 'value') ||
      !['VALID', 'INVALID', 'INDETERMINATE', 'UNSUPPORTED'].includes(selected.value) ||
      typeof explanation.value !== 'string' ||
      explanation.value.trim().length === 0
    )
      throw new Error('Invalid status decision');
    overall = selected.value;
    reason = explanation.value;
  } catch {
    throw new VerificationError(code + '_DECISION', 'INVALID', dimension);
  }
  if (overall !== 'VALID') throw new VerificationError(reason, overall, dimension);
}

/** Shared decision boundary for authenticated status evidence. */
export function statusResult(status, reason, details = {}) {
  const outcomes = {
    GOOD: 'VALID',
    REVOKED: 'INVALID',
    INVALID: 'INVALID',
    STALE: 'INDETERMINATE',
    UNKNOWN: 'INDETERMINATE',
    NOT_YET_KNOWN: 'INDETERMINATE',
    UNAVAILABLE: 'INDETERMINATE',
    UNSUPPORTED: 'UNSUPPORTED',
  };
  requireThat(Object.hasOwn(outcomes, status), 'STATUS_RESULT');
  const selected = ['NOT_YET_KNOWN', 'UNAVAILABLE'].includes(status) ? 'UNKNOWN' : status;
  return Object.freeze({
    ...details,
    status: selected,
    overall: outcomes[status],
    ...(reason ? { reason } : {}),
  });
}

export function evaluateStatusEvidence(verify, prefix) {
  try {
    return verify();
  } catch (error) {
    const reason = error.code ?? prefix + '_MALFORMED';
    return statusResult(
      ['STATUS_CRITICAL_EXTENSION', 'DELTA_CRL_UNSUPPORTED'].includes(reason)
        ? 'UNSUPPORTED'
        : 'INVALID',
      reason,
    );
  }
}

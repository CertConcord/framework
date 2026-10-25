import { ProtocolError } from './core.mjs';
import { AuthorityError, requireAuthority } from './authority-history.mjs';
import { MdocValidationError } from './vendor/mdoc-signing/errors.mjs';

export const verificationDimensions = Object.freeze([
  'integrity',
  'issuerTrust',
  'qualification',
  'keyBinding',
  'authorization',
  'status',
  'time',
  'transparency',
]);
const outcomes = ['VALID', 'INDETERMINATE', 'UNSUPPORTED', 'INVALID'];
export const coreRevision = 'draft-03';

/** Fixed result identity shared by independently selected verification operations. */
export function verificationResult({
  overall,
  reason,
  profile = null,
  dimensions = {},
  ...details
}) {
  if (
    !outcomes.includes(overall) ||
    typeof reason !== 'string' ||
    !reason.length ||
    !(profile === null || (typeof profile === 'string' && profile.length > 0))
  )
    throw new ProtocolError('VERIFICATION_RESULT_SHAPE');
  const evaluated = {};
  for (const [name, value] of Object.entries(dimensions)) {
    if (
      !verificationDimensions.includes(name) ||
      !outcomes.includes(value?.overall) ||
      typeof value.reason !== 'string' ||
      !value.reason.length
    )
      throw new ProtocolError('VERIFICATION_RESULT_DIMENSION');
    evaluated[name] = Object.freeze({ overall: value.overall, reason: value.reason });
  }
  return Object.freeze({
    ...details,
    overall,
    reason,
    coreRevision,
    profile,
    dimensions: Object.freeze(evaluated),
  });
}
const unavailable = new Set([
  'ECP_MISSING_OBJECT',
  'ECP_STATUS_STALE',
  'ECP_STATUS_UNKNOWN',
  'STATUS_LIST_STALE',
  'STATUS_LIST_MISSING',
  'STATUS_LIST_NOT_YET_KNOWN',
  'DOCUMENT_ORGANIZATION_STATUS_STALE',
  'DOCUMENT_ORGANIZATION_STATUS_UNKNOWN',
  'DOCUMENT_TIMESTAMP_ACCURACY_REQUIRED',
  'DETACHED_CONTENT_MISSING',
]);
const unsupported = new Set(['SDK_UNSUPPORTED_PROFILE', 'ECP_UNSUPPORTED_SCHEMA']);

/** A capability outcome chosen by a verification boundary, never by evidence text. */
export class VerificationError extends ProtocolError {
  constructor(code, overall, dimension) {
    super(code);
    this.overall = outcomes.includes(overall) ? overall : 'INVALID';
    if (verificationDimensions.includes(dimension)) this.dimension = dimension;
  }
}

export function verificationOutcome(error) {
  // Only these implementation-owned classes carry a typed outcome. Arbitrary
  // objects, callback exceptions and reason substrings cannot supply a verdict.
  const typed =
    error instanceof VerificationError ||
    error instanceof AuthorityError ||
    error instanceof MdocValidationError;
  const code =
    error instanceof ProtocolError || error instanceof MdocValidationError
      ? error.code
      : 'MALFORMED_EVIDENCE';
  const reason = typeof code === 'string' && code.length > 0 ? code : 'VERIFICATION_FAILURE';
  return Object.freeze({
    overall:
      typed && outcomes.includes(error.overall) && error.overall !== 'VALID'
        ? error.overall
        : unavailable.has(reason)
          ? 'INDETERMINATE'
          : unsupported.has(reason)
            ? 'UNSUPPORTED'
            : 'INVALID',
    reason,
  });
}

const authorityDimension = Object.freeze({
  ISSUER: 'issuerTrust',
  DOCUMENT_SEAL: 'issuerTrust',
  REGISTRATION_AUTHORITY: 'qualification',
  KEY_BINDING_AUTHORITY: 'keyBinding',
  PERMIT_AUTHORITY: 'authorization',
  RECEIPT_AUTHORITY: 'authorization',
  EXECUTION_BINDING_AUTHORITY: 'authorization',
  ORGANIZATION_AUTHORITY: 'authorization',
  STATUS_AUTHORITY: 'status',
  TIMESTAMP_AUTHORITY: 'time',
  TRANSPARENCY_LOG: 'transparency',
});
const missingDimension = Object.freeze({
  DocumentTimestamp: 'time',
  RegistrationAuthorization: 'qualification',
  CertificateStatus: 'status',
  CredentialStatusList: 'status',
  OrganizationAuthorizationStatus: 'status',
  OperationPermit: 'authorization',
  ExecutionReceipt: 'authorization',
});
// A fixed eight-slot record for this verifier. It is not an evidence graph and
// cannot schedule checks or turn partial facts into an acceptance decision.
export class VerificationEvaluation {
  #dimensions = new Map();
  #observedErrors = new WeakSet();
  #phase;
  phase(dimension) {
    this.#phase = dimension;
  }
  missing(types) {
    for (const type of types)
      this.observe(missingDimension[type], 'INDETERMINATE', 'ECP_MISSING_OBJECT');
    if (types.length) this.#phase = undefined;
  }
  observe(dimension, overall, reason) {
    if (
      !verificationDimensions.includes(dimension) ||
      !outcomes.includes(overall) ||
      typeof reason !== 'string' ||
      !reason.length
    )
      return;
    const previous = this.#dimensions.get(dimension);
    if (!previous || outcomes.indexOf(overall) > outcomes.indexOf(previous.overall))
      this.#dimensions.set(dimension, Object.freeze({ overall, reason }));
  }
  failure(error, dimension = this.#phase) {
    // Only propagation of the same Error can be redundant. Two checks may have
    // the same code and outcome in different dimensions and both must survive.
    const object = error !== null && (typeof error === 'object' || typeof error === 'function');
    if (object && arguments.length < 2 && this.#observedErrors.has(error)) return;
    if (object) this.#observedErrors.add(error);
    const outcome = verificationOutcome(error);
    this.observe(
      error instanceof VerificationError ? (error.dimension ?? dimension) : dimension,
      outcome.overall,
      outcome.reason,
    );
  }
  authority(resolver) {
    if (typeof resolver !== 'function') return resolver;
    return (query) => {
      const role = query.role;
      let input;
      try {
        input = resolver(query);
      } catch (error) {
        this.failure(error, authorityDimension[role]);
        throw error;
      }
      let decision;
      try {
        const admitted = requireAuthority(() => input, query);
        const reason = Object.getOwnPropertyDescriptor(admitted, 'reason');
        decision =
          reason &&
          Object.hasOwn(reason, 'value') &&
          typeof reason.value === 'string' &&
          reason.value.length
            ? admitted
            : { overall: 'INDETERMINATE', reason: 'AUTHORITY_DECISION_MISSING' };
      } catch (error) {
        if (!(error instanceof AuthorityError)) throw error;
        decision = {
          overall: error.overall,
          reason:
            typeof error.code === 'string' && error.code.length
              ? error.code
              : 'AUTHORITY_DECISION_MISSING',
        };
      }
      // Quorum members are assessed as a set: an unused rejected vote must not
      // poison a sufficient set of independently admitted operators.
      if (decision && decision.overall !== 'VALID')
        this.observe(authorityDimension[role], decision.overall, decision.reason);
      return decision;
    };
  }
  result() {
    return Object.freeze(Object.fromEntries(this.#dimensions));
  }
}

export function evaluationPhase(evaluation, dimension) {
  if (evaluation instanceof VerificationEvaluation) evaluation.phase(dimension);
}
export function evaluationMissing(evaluation, types) {
  if (evaluation instanceof VerificationEvaluation) evaluation.missing(types);
}
export function evaluated(evaluation, dimension, overall, reason) {
  if (evaluation instanceof VerificationEvaluation) evaluation.observe(dimension, overall, reason);
}
export function evaluatedCheck(evaluation, dimension, callback) {
  try {
    return callback();
  } catch (error) {
    if (evaluation instanceof VerificationEvaluation) evaluation.failure(error, dimension);
    throw error;
  }
}

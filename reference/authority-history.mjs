import {
  ProtocolError, requireThat, fields, dcbor, decodeCBOR, equal, keyID, publicFromDER,
} from './core.mjs';
import { parseCertificate } from './pki.mjs';

export const authorityRoles = Object.freeze([
  'REGISTRATION_AUTHORITY', 'ISSUER', 'PERMIT_AUTHORITY', 'RECEIPT_AUTHORITY',
  'STATUS_AUTHORITY', 'TIMESTAMP_AUTHORITY', 'ORGANIZATION_AUTHORITY',
  'EXECUTION_BINDING_AUTHORITY', 'KEY_BINDING_AUTHORITY', 'RECOVERY_AUTHORITY',
  'DOCUMENT_SEAL', 'TRANSPARENCY_LOG', 'COSIGNER', 'MIRROR', 'ARCHIVE_CUSTODIAN',
]);
const copy = (value) => decodeCBOR(dcbor(value));
const time = (value) => Number.isSafeInteger(value) && value >= 0;
const instant = (value) => Number.isFinite(value) && value >= 0 && value <= Number.MAX_SAFE_INTEGER;
const result = (overall, reason, extra = {}) => Object.freeze({ overall, reason, ...extra });
const same = (a, b) => equal(dcbor(a), dcbor(b));
const scopeKeys = new Set(['trustDomainID', 'profileID', 'issuerID', 'representation', 'purpose']);

function validScope(scope) {
  return scope && !Array.isArray(scope) &&
    Buffer.isBuffer(scope.trustDomainID) && scope.trustDomainID.length === 32 &&
    Object.entries(scope).every(([key, value]) => scopeKeys.has(key) &&
      (key === 'trustDomainID' || (typeof value === 'string' && value.length > 0)));
}

/** Evaluate an already authenticated status statement; this function does not authenticate it. */
export function authorityStatus(statement, { authorityID, trustDomainID, stateTime, knowledgeTime }) {
  if (!statement) return result('INDETERMINATE', 'AUTHORITY_STATUS_MISSING');
  if (!equal(statement.authorityID, authorityID) || !equal(statement.trustDomainID, trustDomainID))
    return result('INVALID', 'AUTHORITY_STATUS_BINDING');
  if (!instant(stateTime) || !instant(knowledgeTime) || stateTime > knowledgeTime ||
      statement.scope !== 'AUTHORITY' || !time(statement.publishedAt) ||
      !time(statement.nextUpdate) || statement.nextUpdate <= statement.publishedAt)
    return result('INVALID', 'AUTHORITY_STATUS_SCHEMA');
  if (statement.publishedAt > knowledgeTime)
    return result('INDETERMINATE', 'AUTHORITY_STATUS_NOT_YET_KNOWN');
  if (statement.status === 'REVOKED') {
    if (!time(statement.effectiveTime) ||
        (statement.compromiseStart !== undefined && !time(statement.compromiseStart)))
      return result('INVALID', 'AUTHORITY_STATUS_SCHEMA');
    if (Math.min(statement.effectiveTime, statement.compromiseStart ?? Infinity) <= stateTime)
      return result('INVALID', 'AUTHORITY_REVOKED', { status: 'REVOKED' });
  }
  if (statement.nextUpdate <= knowledgeTime)
    return result('INDETERMINATE', 'AUTHORITY_STATUS_STALE', { status: 'STALE' });
  if (!['GOOD', 'REVOKED'].includes(statement.status))
    return result('INDETERMINATE', 'AUTHORITY_STATUS_UNKNOWN', { status: 'UNKNOWN' });
  return result('VALID', 'AUTHORITY_STATUS_GOOD', { status: 'GOOD', coverageUntil: statement.nextUpdate });
}

/**
 * Build an immutable relying-party authority selection. Records and status callbacks
 * are authenticated external policy inputs, never inferred from evidence or pins.
 * A scope containing only trustDomainID explicitly grants the role throughout that domain.
 */
export function createAuthorityResolver({ trustDomainID, authorities }) {
  requireThat(Buffer.isBuffer(trustDomainID) && trustDomainID.length === 32 &&
    Array.isArray(authorities), 'AUTHORITY_CONFIGURATION');
  const domain = Buffer.from(trustDomainID);
  const records = authorities.map((input) => {
    const { status, ...fields } = input;
    const record = copy(fields);
    validateRecordFields(record);
    requireThat(['CERTIFICATE', 'RAW_KEY'].includes(record.mode) &&
      time(record.knownAt) &&
      time(record.validFrom) && time(record.validUntil) && record.validUntil > record.validFrom &&
      Array.isArray(record.roles) && record.roles.length > 0 &&
      new Set(record.roles).size === record.roles.length &&
      record.roles.every((role) => authorityRoles.includes(role)) &&
      Array.isArray(record.scopes) && record.scopes.length > 0 &&
      record.scopes.every((scope) => validScope(scope) && equal(scope.trustDomainID, domain)),
    'AUTHORITY_CONFIGURATION');
    let certificate, publicKey;
    if (record.mode === 'CERTIFICATE') {
      requireThat(Buffer.isBuffer(record.certificate) && !record.publicKeyDER, 'AUTHORITY_CERTIFICATE');
      certificate = parseCertificate(record.certificate);
      publicKey = certificate.publicKey;
    } else {
      requireThat(Buffer.isBuffer(record.publicKeyDER) && !record.certificate, 'AUTHORITY_RAW_KEY');
      publicKey = publicFromDER(record.publicKeyDER);
    }
    if (record.algorithmValidUntil !== undefined)
      requireThat(time(record.algorithmValidUntil), 'AUTHORITY_ALGORITHM_DEADLINE');
    return { ...record, parsed: certificate, keyID: keyID(publicKey),
      status: typeof status === 'function' ? status : status === undefined ? undefined : copy(status) };
  });
  return Object.freeze((query) => {
    const { certificate, publicKeyDER, role, scope, stateTime, knowledgeTime } = query ?? {};
    if (!instant(stateTime) || !instant(knowledgeTime) || stateTime > knowledgeTime)
      return result('INVALID', 'AUTHORITY_TIME');
    if (!validScope(scope) || !equal(scope.trustDomainID, domain))
      return result('INVALID', 'AUTHORITY_SCOPE');
    if (!authorityRoles.includes(role)) return result('UNSUPPORTED', 'AUTHORITY_ROLE_UNSUPPORTED');
    let requestedKeyID;
    try {
      requestedKeyID = keyID(certificate ? parseCertificate(certificate).publicKey : publicFromDER(publicKeyDER));
    } catch { return result('INVALID', 'AUTHORITY_IDENTITY'); }
    const identities = records.filter((r) => equal(r.keyID, requestedKeyID) &&
      (r.mode === 'RAW_KEY' || equal(r.certificate, certificate)));
    if (!identities.length) return result('INDETERMINATE', 'AUTHORITY_MISSING');
    const known = identities.filter((r) => r.knownAt <= knowledgeTime);
    if (!known.length) return result('INDETERMINATE', 'AUTHORITY_NOT_YET_KNOWN');
    const roles = known.filter((r) => r.roles.includes(role));
    if (!roles.length) return result('INVALID', 'AUTHORITY_ROLE');
    const scoped = roles.filter((r) => r.scopes.some((grant) =>
      Object.entries(grant).every(([key, value]) => Object.hasOwn(scope, key) && same(value, scope[key]))));
    if (!scoped.length) return result('INVALID', 'AUTHORITY_SCOPE');
    const active = scoped.filter((r) => stateTime >= r.validFrom && stateTime < r.validUntil &&
      (!r.parsed || (stateTime >= r.parsed.notBefore && stateTime < r.parsed.notAfter)));
    if (!active.length && scoped.every((r) => stateTime < Math.max(r.validFrom, r.parsed?.notBefore ?? 0)))
      return result('INVALID', 'AUTHORITY_NOT_YET_VALID');
    if (!active.length) return result('INVALID', 'AUTHORITY_EXPIRED');
    const outcomes = active.map((record) => {
      if (record.algorithmValidUntil !== undefined && stateTime >= record.algorithmValidUntil)
        return result('INVALID', 'AUTHORITY_ALGORITHM_EXPIRED');
      let status;
      try {
        status = typeof record.status === 'function'
          ? record.status(copy({ authorityID: requestedKeyID, role, scope, stateTime, knowledgeTime }))
          : record.status;
      } catch { return result('INDETERMINATE', 'AUTHORITY_STATUS_UNAVAILABLE'); }
      if (status?.then) return result('INDETERMINATE', 'AUTHORITY_STATUS_UNAVAILABLE');
      // Typed adapters may report failure, but only a bound statement can establish GOOD.
      if (status?.overall && status.overall !== 'VALID') {
        if (!['INVALID', 'INDETERMINATE', 'UNSUPPORTED'].includes(status.overall))
          return result('INVALID', 'AUTHORITY_STATUS_SCHEMA');
        return result(status.overall, status.reason ?? 'AUTHORITY_STATUS_UNAVAILABLE');
      }
      const outcome = authorityStatus(status, { authorityID: requestedKeyID, trustDomainID: domain, stateTime, knowledgeTime });
      return outcome.overall === 'VALID'
        ? result('VALID', 'AUTHORITY_ADMITTED', { role, mode: record.mode, coverageUntil: outcome.coverageUntil })
        : outcome;
    });
    return outcomes.find((outcome) => outcome.overall === 'INVALID') ??
      (active.length > 1 ? result('INDETERMINATE', 'AUTHORITY_CONFLICT') : outcomes[0]);
  });
}

function validateRecordFields(record) {
  fields(record, ['mode', 'knownAt', 'validFrom', 'validUntil', 'roles', 'scopes'],
    ['certificate', 'publicKeyDER', 'algorithmValidUntil']);
}

export class AuthorityError extends ProtocolError {
  constructor(outcome) {
    super(outcome.reason);
    this.overall = outcome.overall;
  }
}

export function requireAuthority(resolver, query) {
  const outcome = typeof resolver === 'function'
    ? resolver(query)
    : result('INDETERMINATE', 'AUTHORITY_RESOLVER_REQUIRED');
  if (!outcome || !['VALID', 'INVALID', 'INDETERMINATE', 'UNSUPPORTED'].includes(outcome.overall))
    throw new AuthorityError(result('INDETERMINATE', 'AUTHORITY_DECISION_MISSING'));
  if (outcome.overall !== 'VALID') throw new AuthorityError(outcome);
  return outcome;
}

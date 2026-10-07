import { requireAuthority, AuthorityError } from './authority-history.mjs';
import { requireThat } from './core.mjs';

export function collectAuthorityFailure(check, failures) {
  try {
    return check();
  } catch (error) {
    if (!(error instanceof AuthorityError)) throw error;
    failures.push(error);
    return undefined;
  }
}

// Only verified participants supplied by the cryptographic primitive may contribute a vote.
// A rejected extra participant cannot veto a quorum of independently admitted operators.
export function requireAuthorityQuorum(
  resolver,
  { members, threshold, role, scope, stateTime, stateTimes = [stateTime], knowledgeTime },
) {
  requireThat(
    Array.isArray(members) &&
      Number.isSafeInteger(threshold) &&
      threshold > 0 &&
      Array.isArray(stateTimes) &&
      stateTimes.length > 0,
    'AUTHORITY_QUORUM_CONFIGURATION',
  );
  const operators = new Map(),
    keys = new Set();
  for (const member of members) {
    requireThat(
      typeof member.operatorID === 'string' &&
        member.operatorID.length > 0 &&
        Buffer.isBuffer(member.publicKeyDER),
      'AUTHORITY_QUORUM_MEMBER',
    );
    const key = member.publicKeyDER.toString('base64');
    requireThat(!keys.has(key), 'AUTHORITY_QUORUM_DUPLICATE_KEY');
    keys.add(key);
    const failures = [];
    for (const time of stateTimes)
      collectAuthorityFailure(
        () =>
          requireAuthority(resolver, {
            publicKeyDER: member.publicKeyDER,
            role,
            scope,
            stateTime: time,
            knowledgeTime,
          }),
        failures,
      );
    const overall = failures.some((error) => error.overall === 'INVALID')
      ? 'INVALID'
      : failures.some((error) => error.overall === 'UNSUPPORTED')
        ? 'UNSUPPORTED'
        : failures.length
          ? 'INDETERMINATE'
          : 'VALID';
    const votes = operators.get(member.operatorID) ?? new Set();
    votes.add(overall);
    operators.set(member.operatorID, votes);
  }
  const counts = { VALID: 0, INDETERMINATE: 0, UNSUPPORTED: 0, INVALID: 0 };
  for (const votes of operators.values()) {
    const best = ['VALID', 'INDETERMINATE', 'UNSUPPORTED', 'INVALID'].find((value) =>
      votes.has(value),
    );
    counts[best]++;
  }
  if (counts.VALID >= threshold) return { admittedOperatorCount: counts.VALID };
  const possible = counts.VALID + counts.INDETERMINATE + counts.UNSUPPORTED;
  const overall =
    possible < threshold
      ? 'INVALID'
      : counts.VALID + counts.INDETERMINATE < threshold
        ? 'UNSUPPORTED'
        : 'INDETERMINATE';
  throw new AuthorityError({
    overall,
    reason:
      role +
      '_AUTHORITY_QUORUM_' +
      { INVALID: 'REJECTED', UNSUPPORTED: 'UNSUPPORTED', INDETERMINATE: 'UNAVAILABLE' }[overall],
  });
}

export function requireAuthorities(
  resolver,
  queries,
  unavailable = [],
  priorFailures = [],
  quorums = [],
) {
  const failures = [...priorFailures];
  for (const query of queries) {
    try {
      requireAuthority(resolver, query);
    } catch (error) {
      if (!(error instanceof AuthorityError)) throw error;
      failures.push(error);
    }
  }
  for (const quorum of quorums)
    collectAuthorityFailure(() => requireAuthorityQuorum(resolver, quorum), failures);
  const failure =
    failures.find((error) => error.overall === 'INVALID') ??
    failures.find((error) => error.overall === 'UNSUPPORTED') ??
    failures[0];
  if (failure?.overall === 'INVALID' || failure?.overall === 'UNSUPPORTED') throw failure;
  if (unavailable.length)
    throw new AuthorityError({ overall: 'INDETERMINATE', reason: unavailable[0] });
  if (failure) throw failure;
}

export function operationAuthorityQueries(trust, scope, stateTime, knowledgeTime = stateTime) {
  return [
    ['PERMIT_AUTHORITY', trust.permitCertificate],
    ['RECEIPT_AUTHORITY', trust.receiptCertificate],
  ]
    .filter(([, certificate]) => certificate)
    .map(([role, certificate]) => ({
      certificate,
      role,
      scope,
      stateTime,
      knowledgeTime,
    }));
}

export function requireOperationAuthorities(trust, scope, stateTime, knowledgeTime = stateTime) {
  requireAuthorities(
    trust.authorityResolver,
    operationAuthorityQueries(trust, scope, stateTime, knowledgeTime),
  );
}

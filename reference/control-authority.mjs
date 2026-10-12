import { requireAuthority, AuthorityError } from './authority-history.mjs';

export function collectAuthorityFailure(check, failures) {
  try {
    return check();
  } catch (error) {
    if (!(error instanceof AuthorityError)) throw error;
    failures.push(error);
    return undefined;
  }
}

export function requireAuthorities(resolver, queries, unavailable = [], priorFailures = []) {
  const failures = [...priorFailures];
  for (const query of queries) {
    try {
      requireAuthority(resolver, query);
    } catch (error) {
      if (!(error instanceof AuthorityError)) throw error;
      failures.push(error);
    }
  }
  const failure =
    failures.find((error) => error.overall === 'INVALID') ??
    failures.find((error) => error.overall === 'UNSUPPORTED') ??
    failures[0];
  if (failure?.overall === 'INVALID') throw failure;
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

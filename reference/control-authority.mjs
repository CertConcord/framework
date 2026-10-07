import { requireAuthority, AuthorityError } from './authority-history.mjs';
import { requireThat } from './core.mjs';

export function requireAuthorities(resolver, queries, unavailable = []) {
  const failures = [];
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
  requireThat(unavailable.length === 0, unavailable[0]);
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

import { requireAuthority } from './authority-history.mjs';

export function operationAuthorityQueries(trust, scope, stateTime, knowledgeTime = stateTime) {
  return [
    ['PERMIT_AUTHORITY', trust.permitCertificate],
    ['RECEIPT_AUTHORITY', trust.receiptCertificate],
  ].filter(([, certificate]) => certificate).map(([role, certificate]) => ({
    certificate, role, scope, stateTime, knowledgeTime,
  }));
}

export function requireOperationAuthorities(trust, scope, stateTime, knowledgeTime = stateTime) {
  for (const query of operationAuthorityQueries(trust, scope, stateTime, knowledgeTime))
    requireAuthority(trust.authorityResolver, query);
}

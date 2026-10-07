import { createPublicKey } from 'node:crypto';
import {
  requireThat,
  fields,
  dcbor,
  decodeCBOR,
  equal,
  keyID,
  spki,
  H,
  b64u,
  now,
} from './core.mjs';
import { requireAuthority } from './authority-history.mjs';
import { parseCertificate } from './pki.mjs';

export function snapshotIssuanceScope(scope) {
  fields(scope, ['trustDomainID', 'issuerID', 'issuerKeyID', 'representation']);
  requireThat(
    Buffer.isBuffer(scope.trustDomainID) &&
      scope.trustDomainID.length === 32 &&
      typeof scope.issuerID === 'string' &&
      scope.issuerID.length > 0 &&
      Buffer.isBuffer(scope.issuerKeyID) &&
      scope.issuerKeyID.length === 64 &&
      ['X509', 'MTC', 'MDOC'].includes(scope.representation),
    'ISSUANCE_SCOPE',
  );
  return decodeCBOR(dcbor(scope));
}

export function issuanceAuthorityScope(request) {
  const { trustDomainID, issuerID, representation } = snapshotIssuanceScope(request.issuanceScope);
  return { trustDomainID, issuerID, representation, profileID: request.profileID };
}

export function issuanceRequestID(request) {
  return b64u(
    H('IssuanceRequest', {
      requestID: request.requestID,
      issuanceScope: snapshotIssuanceScope(request.issuanceScope),
    }),
  );
}

export function requireIssuanceAuthority(request, configuration, at = now()) {
  const { issuanceScope, privateKey, raCertificate, issuerCertificate, authorityResolver } =
    configuration;
  requireThat(
    equal(
      dcbor(snapshotIssuanceScope(request.issuanceScope)),
      dcbor(snapshotIssuanceScope(issuanceScope)),
    ),
    'ISSUANCE_SCOPE',
  );
  const publicKey = createPublicKey(privateKey);
  requireThat(equal(issuanceScope.issuerKeyID, keyID(publicKey)), 'ISSUANCE_SCOPE');
  if (issuerCertificate)
    requireThat(
      equal(keyID(parseCertificate(issuerCertificate).publicKey), keyID(publicKey)),
      'ISSUER_KEY_BINDING',
    );
  requireThat(
    request.schemaVersion === 1 &&
      Buffer.isBuffer(request.requestID) &&
      request.requestID.length === 32 &&
      Number.isSafeInteger(request.issuedAt) &&
      request.issuedAt >= 0 &&
      Number.isSafeInteger(request.expiresAt) &&
      request.issuedAt <= at &&
      request.expiresAt > at &&
      request.expiresAt > request.issuedAt &&
      request.expiresAt - request.issuedAt <= 300,
    'ISSUANCE_AUTHORIZATION',
  );
  const scope = issuanceAuthorityScope(request);
  requireAuthority(authorityResolver, {
    certificate: raCertificate,
    role: 'REGISTRATION_AUTHORITY',
    scope,
    stateTime: request.issuedAt,
    knowledgeTime: at,
  });
  requireAuthority(authorityResolver, {
    ...(issuerCertificate ? { certificate: issuerCertificate } : { publicKeyDER: spki(publicKey) }),
    role: 'ISSUER',
    scope,
    stateTime: at,
    knowledgeTime: at,
  });
}

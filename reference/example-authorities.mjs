import { now, keyID, publicFromDER, requireThat } from './core.mjs';
import { parseCertificate } from './pki.mjs';
import { createAuthorityResolver } from './authority-history.mjs';

// Synthetic external appointments for examples and tests, not operational status evidence.
export function exampleAuthorityResolver({ trustDomainID, authorities, at = now(), nextUpdate = at + 3600 }) {
  return createAuthorityResolver({ trustDomainID, authorities: authorities.map((authority) => {
    if (authority.mode === 'RAW_KEY') {
      requireThat(['knownAt', 'validFrom', 'validUntil'].every((field) => Number.isSafeInteger(authority[field])),
        'EXAMPLE_RAW_AUTHORITY_LIFETIME');
      return { scopes: [{ trustDomainID }], status: {
        authorityID: keyID(publicFromDER(authority.publicKeyDER)), trustDomainID,
        scope: 'AUTHORITY', status: 'GOOD', publishedAt: at, nextUpdate,
      }, ...authority };
    }
    const cert = parseCertificate(authority.certificate);
    return { mode: 'CERTIFICATE', scopes: [{ trustDomainID }],
      knownAt: at, validFrom: cert.notBefore, validUntil: cert.notAfter,
      status: { authorityID: keyID(cert.publicKey), trustDomainID,
        scope: 'AUTHORITY', status: 'GOOD', publishedAt: at, nextUpdate }, ...authority };
  }) });
}

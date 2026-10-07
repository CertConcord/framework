import { now, keyID } from './core.mjs';
import { parseCertificate } from './pki.mjs';
import { createAuthorityResolver } from './authority-history.mjs';

// Synthetic external appointments for examples and tests, not operational status evidence.
export function exampleAuthorityResolver({ trustDomainID, authorities, at = now(), nextUpdate = at + 3600 }) {
  return createAuthorityResolver({ trustDomainID, authorities: authorities.map((authority) => {
    const cert = parseCertificate(authority.certificate);
    return { mode: 'CERTIFICATE', scopes: [{ trustDomainID }],
      knownAt: at, validFrom: cert.notBefore, validUntil: cert.notAfter,
      status: { authorityID: keyID(cert.publicKey), trustDomainID,
        scope: 'AUTHORITY', status: 'GOOD', publishedAt: at, nextUpdate }, ...authority };
  }) });
}

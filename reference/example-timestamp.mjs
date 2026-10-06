import { generate, now } from './core.mjs';
import { issueCertificate, name } from './pki.mjs';
import { TimestampAuthority, timestampRequest, tokenFromResponse } from './timestamp.mjs';

// A deterministic software clock and a locally pinned authority model the protocol, not clock assurance.
export function exampleTimestamp(journal, { clock = now, accuracySeconds = 0 } = {}) {
  const ca = generate('ml-dsa-87'),
    key = generate('ml-dsa-87');
  const certificate = issueCertificate(
    {
      publicKey: key.publicKey,
      serial: 1,
      subject: name('Synthetic Document TSA'),
      issuer: name('Synthetic TSA Issuer'),
      profileID: 'CERTCONCORD-TSA-v1',
    },
    ca.privateKey,
  );
  const policy = '1.3.6.1.4.1.32473.90.1';
  const authority = new TimestampAuthority({
    certificate,
    privateKey: key.privateKey,
    policy,
    journal,
    clock,
    accuracySeconds,
  });
  return {
    issue: (imprint) =>
      tokenFromResponse(authority.issue(timestampRequest(imprint, { policy }).der)),
    trust: { certificate, issuerKey: ca.publicKey, policy, status: () => true },
  };
}

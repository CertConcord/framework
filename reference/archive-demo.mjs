import { pathToFileURL } from 'node:url';
import { runDemo } from './demo.mjs';
import { dcbor, generate, equal } from './core.mjs';
import { issueCertificate, name, OID, parseCertificate, verifyCMS } from './pki.mjs';
import { Journal } from './state.mjs';
import { TimestampAuthority, timestampRequest, tokenFromResponse } from './timestamp.mjs';
import { createERS, renewERS, verifyERSPreservation } from './archive.mjs';
import { createVerifier } from './sdk/index.mjs';

// Synthetic lifetimes exercise ordering; they are not algorithm retirement forecasts.
export async function runArchiveDemo() {
  const document = await runDemo({ trustedTime: true, activationMode: 'HUMAN_WEBAUTHN' }),
    bytes = dcbor(document.bundle),
    start = document.verification.proofOfExistenceUpperBound + 2,
    journal = new Journal(),
    root = generate('ml-dsa-87');
  let clock = start;
  const authority = (serial, notAfter) => {
    const key = generate('ml-dsa-87'),
      certificate = issueCertificate(
        {
          publicKey: key.publicKey,
          serial,
          issuer: name('Synthetic Archive Root'),
          subject: name('Synthetic Archive TSA ' + serial),
          profileID: 'CERTCONCORD-TSA-v1',
          notBefore: start - 60,
          notAfter,
        },
        root.privateKey,
      ),
      policy = '1.3.6.1.4.1.32473.90.2',
      tsa = new TimestampAuthority({
        certificate,
        privateKey: key.privateKey,
        policy,
        journal,
        clock: () => clock,
        accuracySeconds: 0,
      });
    return {
      certificate,
      issuerKey: root.publicKey,
      policy,
      validUntil: notAfter,
      status: () => true,
      issue: async (imprint, hashOID) =>
        tokenFromResponse(tsa.issue(timestampRequest(imprint, { hashOID, policy }).der)),
    };
  };
  const initial = authority(1, start + 3600),
    successor = authority(2, start + 7 * 86400);
  try {
    const first = await createERS(bytes, { tsa: initial.issue, hashOID: OID.sha256 });
    clock = start + 1000;
    const renewed = await renewERS(first, bytes, { tsa: successor.issue });
    clock = start + 2000;
    const record = await renewERS(renewed, bytes, {
      tsa: successor.issue,
      hashRenewal: true,
      hashOID: OID.sha512,
    });
    const preservationTrust = {
      at: start + 2 * 86400,
      dataValidUntil: start + 86400,
      hashValidUntil: { [OID.sha256]: start + 3000, [OID.sha512]: start + 10 * 86400 },
      resolveTimestamp: (token) => {
        const { certificate } = verifyCMS(token, { expectedContentType: OID.tstInfo });
        return [initial, successor].find((a) => equal(a.certificate, certificate));
      },
    };
    const preservation = verifyERSPreservation(record, bytes, preservationTrust),
      historical = createVerifier({
        format: 'CMS',
        trust: { ...document.trust, knowledgeTime: preservation.proofOfExistenceUpperBound },
      }).verify(bytes),
      current = createVerifier({
        format: 'CMS',
        trust: { ...document.trust, knowledgeTime: preservationTrust.at },
      }).verify(bytes),
      certificate = parseCertificate(
        document.bundle.objects.find((o) => o.type === 'Certificate').payload,
      );
    return {
      document,
      bytes,
      record,
      first,
      renewed,
      preservationTrust,
      summary: {
        clock: 'SYNTHETIC',
        issuerOnline: false,
        certificateExpiredAtEvaluation: certificate.notAfter <= preservationTrust.at,
        preservation,
        historical,
        current,
      },
    };
  } finally {
    journal.close();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  console.log(JSON.stringify((await runArchiveDemo()).summary, null, 2));

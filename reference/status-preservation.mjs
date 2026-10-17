import { ALG, keyID } from './core.mjs';
import { parseCertificate } from './pki.mjs';
import { verifyERSOriginalProof, verifyERSPreservation } from './archive.mjs';
import { VerificationError } from './verification-result.mjs';

const SHA256 = '2.16.840.1.101.3.4.2.1',
  SHA512 = '2.16.840.1.101.3.4.2.3';
const integer = (value) => Number.isSafeInteger(value) && value >= 0;
const need = (ok, reason, overall = 'INVALID') => {
  if (!ok) throw new VerificationError(reason, overall);
};

// The caller authenticates the typed CMS and its exact embedded signer first.
// This proof protects the complete CMS independently of the original package.
export function verifyStatusPreservation(member, publishedAt, trust, K, preservation, prefix) {
  need(
    Buffer.isBuffer(member.evidenceRecord) &&
      member.evidenceRecord.length > 0 &&
      member.evidenceRecord.length <= 16 * 1024 * 1024,
    prefix + '_PROOF',
  );
  need(
    preservation && typeof preservation.resolveTimestamp === 'function',
    prefix + '_PROOF_POLICY',
    'INDETERMINATE',
  );
  const signer = parseCertificate(member.issuerCertificate),
    algorithm = ALG[signer.publicKey.asymmetricKeyType],
    bounds = [signer.notAfter];
  for (const [map, id] of [
    [trust.keyDeadlines, keyID(signer.publicKey).toString('hex')],
    [trust.algorithmDeadlines, algorithm?.oid],
    [trust.algorithmDeadlines, signer.algorithm],
    [trust.hashDeadlines, signer.publicKey.asymmetricKeyType === 'ec' ? SHA256 : SHA512],
  ]) {
    need(integer(map?.[id]), 'ORG_PROTECTION_DEADLINE_MISSING', 'INDETERMINATE');
    bounds.push(map[id]);
  }
  const policy = { ...preservation, dataValidUntil: Math.min(...bounds) },
    first = verifyERSOriginalProof(member.evidenceRecord, member.cms, policy),
    proofTime = first.proofOfExistenceUpperBound;
  need(integer(publishedAt) && publishedAt <= proofTime && proofTime <= K, prefix + '_PROOF_TIME');
  verifyERSPreservation(member.evidenceRecord, member.cms, { ...policy, at: K });
  return proofTime;
}

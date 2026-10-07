import { decodeCBOR, equal, requireThat } from './core.mjs';
import { verifyERSPreservation } from './archive.mjs';
import { createVerifier } from './sdk/index.mjs';
import { documentTimestampImprint } from './document-evidence.mjs';

function failure(error) {
  const reason = error.code ?? 'HISTORICAL_VALIDATION_ERROR';
  return { overall: error.overall ?? (/REQUIRED|MISSING|STALE|COVERAGE/.test(reason) ? 'INDETERMINATE' : 'INVALID'), reason };
}
function evaluate(action) {
  try { return action(); } catch (error) { return failure(error); }
}

/** Preserve original bytes; evaluate refreshed retained evidence without changing the operation. */
export function verifyPreservedDocument({
  format, originalBytes, currentBytes = originalBytes, evidenceRecord, preservationPolicy,
  historicalTrust, currentTrust, authorityResolver, historicalKnowledgeTime, currentKnowledgeTime,
}) {
  requireThat(Number.isFinite(historicalKnowledgeTime) && Number.isFinite(currentKnowledgeTime) &&
    historicalKnowledgeTime <= currentKnowledgeTime &&
    typeof authorityResolver === 'function', 'HISTORICAL_POLICY');
  const preservation = evaluate(() => ({ overall: 'VALID', ...verifyERSPreservation(evidenceRecord,
    originalBytes, { ...preservationPolicy, at: currentKnowledgeTime }) }));
  const binding = evaluate(() => {
    const original = decodeCBOR(originalBytes), current = decodeCBOR(currentBytes);
    requireThat(equal(documentTimestampImprint(format, original.objects),
      documentTimestampImprint(format, current.objects)), 'HISTORICAL_OPERATION_CHANGED');
    requireThat(equal(historicalTrust.trustDomainID, currentTrust.trustDomainID), 'HISTORICAL_DOMAIN_CHANGED');
    return { overall: 'VALID' };
  });
  const historicalAuthorization = evaluate(() => createVerifier({ format,
    trust: { ...historicalTrust, authorityResolver, knowledgeTime: historicalKnowledgeTime } }).verify(originalBytes));
  const currentAdmissibility = binding.overall === 'VALID'
    ? evaluate(() => createVerifier({ format,
      trust: { ...currentTrust, authorityResolver, knowledgeTime: currentKnowledgeTime } }).verify(currentBytes))
    : binding;
  const decisions = [preservation, historicalAuthorization, currentAdmissibility];
  const overall = ['INVALID', 'UNSUPPORTED', 'INDETERMINATE'].find((value) =>
    decisions.some((decision) => decision.overall === value)) ?? 'VALID';
  return Object.freeze({ overall, preservation, historicalAuthorization, currentAdmissibility,
    historicalKnowledgeTime, currentKnowledgeTime });
}

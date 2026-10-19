import { decodeCBOR, equal, requireThat } from './core.mjs';
import { verifyERSOriginalProof, verifyERSPreservation } from './archive.mjs';
import { createVerifier } from './sdk/index.mjs';
import { documentTimestampImprint } from './document-evidence.mjs';
import { requireAuthorities } from './control-authority.mjs';
import { requireStatusDecision } from './status-result.mjs';
import {
  VerificationError,
  verificationOutcome,
  verificationResult,
} from './verification-result.mjs';

function failure(error) {
  return verificationOutcome(error);
}
function evaluate(action) {
  try {
    return action();
  } catch (error) {
    return failure(error);
  }
}

/** Preserve original bytes; evaluate refreshed retained evidence without changing the operation. */
export function verifyPreservedDocument({
  format,
  originalBytes,
  currentBytes = originalBytes,
  evidenceRecord,
  preservationPolicy,
  historicalTrust,
  currentTrust,
  authorityResolver,
  historicalKnowledgeTime,
  currentKnowledgeTime,
}) {
  requireThat(
    Number.isFinite(historicalKnowledgeTime) &&
      Number.isFinite(currentKnowledgeTime) &&
      historicalKnowledgeTime <= currentKnowledgeTime &&
      typeof authorityResolver === 'function',
    'HISTORICAL_POLICY',
  );
  const preservation = evaluate(() => ({
    overall: 'VALID',
    ...verifyERSPreservation(evidenceRecord, originalBytes, {
      ...preservationPolicy,
      at: currentKnowledgeTime,
    }),
  }));
  const timestampStatuses = [];
  const originalProof = evaluate(() => ({
    overall: 'VALID',
    ...verifyERSOriginalProof(evidenceRecord, originalBytes, {
      ...preservationPolicy,
      resolveTimestamp(token) {
        const selected = preservationPolicy.resolveTimestamp(token);
        if (typeof selected?.status !== 'function') return selected;
        return {
          ...selected,
          status(query) {
            timestampStatuses.push({
              evaluate: selected.status,
              query: { ...query, certificate: Buffer.from(query.certificate) },
            });
            return selected.status(query);
          },
        };
      },
    }),
  }));
  const P = originalProof.proofOfExistenceUpperBound;
  const historicalBytesVisibility = evaluate(() => {
    if (originalProof.overall !== 'VALID')
      throw new VerificationError('HISTORICAL_BYTES_UNPROVEN', 'INDETERMINATE', 'time');
    if (P > historicalKnowledgeTime)
      throw new VerificationError('HISTORICAL_BYTES_NOT_YET_PROVEN', 'INDETERMINATE', 'time');
    // Initial mathematics and its P-based admission remain independent of later
    // renewal. Historical knowledge must also retain TSA incidents known by H.
    for (const status of timestampStatuses)
      requireStatusDecision(
        status.evaluate,
        { ...status.query, knowledgeTime: historicalKnowledgeTime },
        'ERS_TSA_STATUS',
      );
    return { overall: 'VALID', reason: 'HISTORICAL_BYTES_PROVEN' };
  });
  const binding = evaluate(() => {
    const original = decodeCBOR(originalBytes),
      current = decodeCBOR(currentBytes);
    requireThat(
      equal(
        documentTimestampImprint(format, original.objects),
        documentTimestampImprint(format, current.objects),
      ),
      'HISTORICAL_OPERATION_CHANGED',
    );
    requireThat(
      equal(historicalTrust.trustDomainID, currentTrust.trustDomainID),
      'HISTORICAL_DOMAIN_CHANGED',
    );
    return { overall: 'VALID' };
  });
  const historical = evaluate(() =>
    createVerifier({
      format,
      trust: {
        ...historicalTrust,
        knowledgeTime: historicalKnowledgeTime,
        authorityResolver(query) {
          if (
            query.role !== 'STATUS_AUTHORITY' ||
            originalProof.overall !== 'VALID' ||
            P > historicalKnowledgeTime
          )
            return authorityResolver(query);
          if (query.stateTime > P)
            throw new VerificationError('HISTORICAL_STATUS_PROOF_TIME', 'INVALID', 'status');
          // A claimed publication time is not an authenticated signing instant.
          // Original status authority must still be admissible at the byte bound.
          let claimed;
          requireAuthorities(
            (selected) => {
              const result = authorityResolver(selected);
              if (selected === query) claimed = result;
              return result;
            },
            [query, { ...query, stateTime: P }],
          );
          return claimed;
        },
      },
    }).verify(originalBytes),
  );
  const order = ['VALID', 'INDETERMINATE', 'UNSUPPORTED', 'INVALID'];
  const stronger = (a, b) => order.indexOf(a.overall) > order.indexOf(b?.overall ?? 'VALID');
  const historicalAuthorization =
    historicalBytesVisibility.overall === 'VALID'
      ? historical
      : verificationResult({
          ...historical,
          ...(stronger(historicalBytesVisibility, historical) ? historicalBytesVisibility : {}),
          dimensions: {
            ...historical.dimensions,
            ...(stronger(historicalBytesVisibility, historical.dimensions?.time)
              ? { time: historicalBytesVisibility }
              : {}),
          },
        });
  const currentAdmissibility =
    binding.overall === 'VALID'
      ? evaluate(() =>
          createVerifier({
            format,
            trust: { ...currentTrust, authorityResolver, knowledgeTime: currentKnowledgeTime },
          }).verify(currentBytes),
        )
      : binding;
  const decisions = [preservation, historicalAuthorization, currentAdmissibility];
  const overall =
    ['INVALID', 'UNSUPPORTED', 'INDETERMINATE'].find((value) =>
      decisions.some((decision) => decision.overall === value),
    ) ?? 'VALID';
  return Object.freeze({
    overall,
    preservation,
    originalProof,
    historicalBytesVisibility,
    historicalAuthorization,
    currentAdmissibility,
    historicalKnowledgeTime,
    currentKnowledgeTime,
  });
}

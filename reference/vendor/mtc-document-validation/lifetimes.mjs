const reject = (code) => { const error = new Error(code); error.code = code; throw error; };
export function assertPreservationLifetimes(records, {at, dataValidUntil, hashValidUntil}, fail = reject) {
  const positive = n => Number.isSafeInteger(n) && n > 0;
  const need = (condition, code) => { if (!condition) fail(code); };
  need(Number.isSafeInteger(at) && at >= 0 && positive(dataValidUntil) &&
    hashValidUntil && Array.isArray(records) && records.length > 0, 'ERS_PRESERVATION_POLICY');
  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    need(Number.isSafeInteger(r.chain) && r.chain >= 0 &&
      Number.isFinite(r.genTime) && Number.isFinite(r.accuracy) && r.accuracy >= 0 &&
      r.poeUpperBound === r.genTime + r.accuracy && positive(r.validUntil) &&
      r.poeUpperBound <= at && r.poeUpperBound < r.validUntil &&
      (i === 0 ? r.chain === 0 : r.chain >= records[i-1].chain && r.chain <= records[i-1].chain+1),
      'ERS_RECORD_FACTS');
  }
  need(records[0].poeUpperBound < dataValidUntil, 'ERS_INITIAL_PROTECTION_LATE');
  for (let i = 0; i < records.length; i++) {
    const r = records[i], next = records[i+1];
    if (next) {
      need(r.poeUpperBound <= next.genTime-next.accuracy, 'ERS_INTERVAL_ORDER');
      need(next.poeUpperBound < r.validUntil, 'ERS_RENEWAL_LATE');
    } else need(at < r.validUntil, 'ERS_FINAL_PROTECTION_EXPIRED');
    const nextChain = records.find(n => n.chain > r.chain);
    need(positive(hashValidUntil[r.hashOID]), 'ERS_HASH_LIFETIME_REQUIRED');
    need((nextChain?.poeUpperBound ?? at) < hashValidUntil[r.hashOID], 'ERS_HASH_RENEWAL_LATE');
  }
  return true;
}

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, createPublicKey } from 'node:crypto';
import { verifyMTC } from './mtc.mjs';

const raw = readFileSync(new URL('./vectors/mtc-versions.json', import.meta.url));
const corpus = JSON.parse(raw);
const hash = (value) => createHash('sha256').update(value).digest('hex');
const publicKey = (value) =>
  createPublicKey({ key: Buffer.from(value, 'base64'), format: 'der', type: 'spki' });
const trust = {
  caID: corpus.caID,
  caPublicKey: publicKey(corpus.publicKeys[0].spki),
  members: corpus.publicKeys.slice(1).map((p) => ({ ...p, publicKey: publicKey(p.spki) })),
  threshold: 2,
  at: corpus.at,
  profileID: 'CERTCONCORD-PERSON-SIGN-v1',
  policyHash: Buffer.alloc(64, 1),
  rtmHash: Buffer.alloc(64, 2),
  membershipEpoch: 1,
  mode: 'HISTORICAL',
};
for (const row of corpus.cases)
  test(`MTC wire profiles: ${row.name}`, () => {
    const vector = corpus.certificates[row.certificate];
    const certificate = Buffer.from(vector.der, 'base64');
    assert.equal(hash(certificate), vector.sha256);
    const options = { ...trust, at: trust.at + (row.atOffset ?? 0) };
    if (row.revoked) options.revokedRanges = [{ logNumber: 1, start: 0, end: 1 }];
    if (row.cacheRoot)
      options.trustedSubtrees = [
        {
          ...trust,
          logNumber: 1,
          start: 0,
          end: 1,
          validFrom: corpus.at - 1,
          expiresAt: corpus.at + 1,
          root: Buffer.from(corpus.certificates[row.cacheRoot].root, 'hex'),
        },
      ];
    if (['STANDALONE', 'LANDMARK'].includes(row.expected)) {
      const result = verifyMTC(certificate, options);
      assert.equal(result.mode, row.expected);
      assert.equal(result.certificate.algorithm, '1.3.6.1.5.5.7.6.67');
      assert.equal(result.root.toString('hex'), vector.root);
      assert.deepEqual(result.certificate.raw, certificate);
      if (row.expected === 'STANDALONE')
        assert.deepEqual(
          result.verifiedCosigners.map((m) => m.id),
          ['32473.10', '32473.11'],
        );
    } else assert.throws(() => verifyMTC(certificate, options), { code: row.expected });
    assert.equal(hash(certificate), vector.sha256);
  });

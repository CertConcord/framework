import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { parseDER } from './core.mjs';
import { TimestampAuthority, parseTimestampRequest } from './timestamp.mjs';

const vectors = JSON.parse(readFileSync(new URL('./vectors/timestamp-request-structure.json', import.meta.url)));
const bytes = (row) => {
  const der = Buffer.from(row.base64, 'base64');
  assert.equal(der.length, row.bytes);
  assert.equal(createHash('sha256').update(der).digest('hex'), row.sha256);
  return der;
};

test('RFC 3161 request structure vectors preserve the fixed positive control', () => {
  assert.equal(vectors.schemaVersion, 1);
  assert.equal(vectors.standard, 'RFC 3161 section 2.4.1');
  const first = bytes(vectors.positive);
  const request = parseTimestampRequest(first);
  assert.equal(request.hashOID, vectors.hashOID);
  assert.equal(request.imprint.toString('hex'), vectors.imprintHex);
  assert.equal(request.policy, vectors.policy);
  assert.equal(request.nonce, BigInt(vectors.nonce));
  assert.equal(request.certReq, true);
});

for (const row of vectors.negative) {
  test(`RFC 3161 request rejects ${row.id} before TSA issuance`, () => {
    const positive = bytes(vectors.positive);
    const invalid = bytes(row);
    if (row.id === 'outer-context-tag') {
      assert.equal(invalid.length, positive.length);
      assert.equal(invalid[0], 0xa0);
      assert.deepEqual(invalid.subarray(1), positive.subarray(1));
    } else {
      const goodImprint = parseDER(positive).children[1].children;
      const badImprint = parseDER(invalid).children[1].children;
      assert.equal(badImprint.length, 3);
      assert.deepEqual(badImprint.slice(0, 2).map((field) => field.raw),
        goodImprint.map((field) => field.raw));
      assert.equal(badImprint[2].raw.toString('hex'), '0500');
    }
    assert.throws(() => parseTimestampRequest(invalid), { code: row.error });
    let journalWrites = 0;
    const tsa = new TimestampAuthority({
      policy: vectors.policy,
      journal: { put() { journalWrites++; } },
    });
    assert.throws(() => tsa.issue(invalid), { code: row.error });
    assert.equal(journalWrites, 0);
  });
}

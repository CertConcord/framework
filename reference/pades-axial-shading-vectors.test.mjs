import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { inspectAdESSignature } from './ades-cms.mjs';
import { pdfSignatures } from './pades-fixtures.mjs';
import { inspectPAdESContainer } from './pades-structure.mjs';

const raw = readFileSync(new URL('./vectors/pades-axial-shading-admission.json', import.meta.url));
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
assert.equal(sha256(raw), '95facb69b9db62b6c6f2261c9ca271855ea088b1ee5a4f8bc6dd1506c7dde44b');
const vectors = JSON.parse(raw);
assert.equal(vectors.schema, 'certconcord.pades-axial-shading-admission.v1');
assert.equal(vectors.baseMain, 'edfc3354869e273b4cee4278efdf263904d05adb');
assert.equal(vectors.officialIso32000_1Sha256,
  '9de0ca9e8570d6209e8bd48a355be8eb6ec376acfc3fc3ae97cd8730351417ff');

for (const pair of vectors.signedPDF) {
  test(`frozen signed axial shading dictionary: ${pair.id}`, () => {
    for (const label of ['positive', 'negative']) {
      const entry = pair[label];
      const pdf = Buffer.from(entry.base64, 'base64');
      assert.equal(pdf.length, entry.bytes);
      assert.equal(sha256(pdf), entry.sha256);
      const signatures = pdfSignatures(pdf);
      assert.equal(signatures.length, 1);
      const [{ cms, byteRange }] = signatures;
      assert.deepEqual(byteRange, entry.byteRange);
      assert.equal(sha256(cms), entry.cmsSha256);
      const [s1, n1, s2, n2] = byteRange;
      const content = Buffer.concat([pdf.subarray(s1, s1 + n1), pdf.subarray(s2, s2 + n2)]);
      assert.equal(inspectAdESSignature(cms, { content, profile: 'PADES' }).overall, 'VALID');
      if (label === 'positive') {
        const result = inspectPAdESContainer(pdf);
        assert.equal(result.signatures.length, 1);
        assert.equal(result.revisions.length, 2);
      } else {
        assert.throws(() => inspectPAdESContainer(pdf),
          error => error.overall === 'INVALID' && error.code === pair.negativeReason);
      }
    }
  });
}

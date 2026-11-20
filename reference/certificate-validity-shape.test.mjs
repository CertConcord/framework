import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import * as core from './core.mjs';
import * as pki from './pki.mjs';

const vectors = JSON.parse(readFileSync(new URL('./vectors/certificate-validity-shape.json', import.meta.url)));
const issuerPublicKey = createPublicKey({
  key: Buffer.from(vectors.issuerPublicKeySPKI, 'base64'), format: 'der', type: 'spki',
});
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');

for (const row of vectors.cases)
  test(`signed RFC 5280 Validity shape: ${row.id}`, () => {
    const raw = Buffer.from(row.certificate, 'base64');
    assert.equal(raw.toString('base64'), row.certificate);
    assert.equal(raw.length, row.bytes);
    assert.equal(digest(raw), row.sha256);
    const [tbs, , signature] = core.parseDER(raw).children;
    assert.equal(digest(tbs.raw), row.tbsSHA256);
    assert.equal(tbs.children[4].tag, row.validityTag);
    assert.equal(tbs.children[4].children?.length ?? null, row.validityMembers);
    assert.equal(signature.value[0], 0);
    assert(verify(null, tbs.raw, issuerPublicKey, signature.value.subarray(1)));
    const parse = () => pki.parseCertificate(raw);
    const validate = () => pki.validateCertificate(raw, issuerPublicKey, { at: vectors.fixedAt });
    if (row.expectedParseError) {
      assert.throws(parse, { code: row.expectedParseError });
      assert.throws(validate, { code: row.expectedParseError });
    } else {
      assert.equal(parse().serial, 528020n);
      assert.equal(validate().serial, 528020n);
    }
  });

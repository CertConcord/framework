import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, X509Certificate, verify } from 'node:crypto';
import { parseDER, der, oidText, seq } from './core.mjs';
import { inspectAdESSignature } from './ades-cms.mjs';

const document = JSON.parse(
  readFileSync(new URL('./vectors/cms-algorithm-protection.json', import.meta.url)),
);
assert.equal(document.schema, 'cms-algorithm-protection-v1');
assert.equal(document.registeredOID, '1.2.840.113549.1.9.16.2.52');
assert.equal(document.legacyOID, '1.2.840.113549.1.9.52');
assert.equal(document.vectors.length, 36);
assert.equal(new Set(document.vectors.map((v) => v.id)).size, 36);
for (const v of document.vectors)
  test('retained CMS algorithm-protection vector: ' + v.id, () => {
    const cms = Buffer.from(v.cmsHex, 'hex');
    const before = Buffer.from(cms);
    assert.equal(createHash('sha256').update(cms).digest('hex'), v.cmsSHA256);
    const signedData = parseDER(cms).children[1].children[0];
    const signer = signedData.children.at(-1).children[0].children;
    assert(['signed', 'unsigned'].includes(v.placement));
    assert([document.registeredOID, document.legacyOID].includes(v.attributeOID));
    const attributes = signer[v.placement === 'signed' ? 3 : 6].children;
    assert.equal(attributes.filter((a) => oidText(a.children[0]) === v.attributeOID).length, 1);
    const tbs = Buffer.from(v.signedAttributesHex, 'hex');
    const signature = Buffer.from(v.signatureHex, 'hex');
    const certificate = Buffer.from(v.signerCertificateHex, 'hex');
    const certFields = parseDER(certificate).children[0].children;
    const offset = certFields[0].tag === 0xa0 ? 1 : 0;
    assert.deepEqual(signer[1].raw, seq(certFields[offset + 2].raw, certFields[offset].raw));
    assert.deepEqual(der(0x31, signer[3].value), tbs);
    assert.deepEqual(signer[5].value, signature);
    assert(
      signedData.children
        .find((n) => n.tag === 0xa0)
        .children.some((n) => n.raw.equals(certificate)),
    );
    assert.equal(
      verify('sha256', tbs, new X509Certificate(certificate).publicKey, signature),
      true,
    );
    const invalidSignature = Buffer.from(signature);
    invalidSignature[invalidSignature.length - 1] ^= 1;
    assert.equal(
      verify('sha256', tbs, new X509Certificate(certificate).publicKey, invalidSignature),
      false,
    );
    const result = inspectAdESSignature(cms, {
      profile: v.profile,
      ...(v.contentHex !== undefined ? { content: Buffer.from(v.contentHex, 'hex') } : {}),
    });
    assert.deepEqual(
      { overall: result.overall, reason: result.reason, failures: result.failures },
      v.expected,
    );
    assert(Object.isFrozen(result));
    assert(Object.isFrozen(result.failures));
    assert.deepEqual(cms, before);
  });

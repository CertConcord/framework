import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, verify as verifySignature, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { der, equal, intValue, oidText, parseDER, sha256 } from './core.mjs';
import { verifyExternalCMS } from './external-cms.mjs';
import { OID, parseCertificate } from './pki.mjs';
import { verifyExternalTimestampToken } from './timestamp.mjs';

const vectors = JSON.parse(
  readFileSync(new URL('./vectors/external-cms-attribute-types.json', import.meta.url)),
);
assert.equal(vectors.profile, 'RFC5652-EXTERNAL-CMS-ATTRIBUTE-TYPES');
const original = (ref) => {
  const raw = Buffer.from(ref.derBase64, 'base64');
  assert.equal(createHash('sha256').update(raw).digest('hex'), ref.sha256);
  return raw;
};
const timestampOptions = (item, tsa, root) => ({
  imprint: sha256(original(item.content)),
  hashOID: OID.sha256,
  nonce: 9156438538392878302n,
  policy: '1.3.6.1.4.1.55555.91.1',
  certificate: tsa,
  issuerKey: new X509Certificate(root).publicKey,
  trustedIssuerName: parseCertificate(root).subject,
  at: 1800000040,
  maxFutureSkew: 0,
  revokedAt: Infinity,
});
const signedAttribute = (token) => {
  const signer = parseDER(token).children[1].children[0].children.at(-1).children[0];
  const attribute = signer.children[3].children.find(
    (a) => oidText(a.children[0]) === OID.messageDigest,
  );
  assert(attribute);
  return {
    signer,
    attribute,
    attrValues: attribute.children[1],
    value: attribute.children[1].children[0],
  };
};

for (const [name, item] of Object.entries(vectors.cases)) {
  const root = original(item.root),
    tsa = original(item.tsa);
  const positive = original(item.positiveToken),
    negative = original(item.negativeToken);
  const content = original(item.tstInfo);
  const options = timestampOptions(item, tsa, root);
  for (const [label, token, expected] of [
    ['positive', positive, item.positive],
    ['negative', negative, item.negative],
  ]) {
    test(`${name} ${label} retains its frozen signed attribute and digest`, () => {
      const signedData = parseDER(token).children[1].children[0];
      assert.equal(intValue(signedData.children[0]), BigInt(expected.signedDataVersion));
      assert.equal(signedData.children[1].tag, expected.digestAlgorithmsTag);
      const { signer, attrValues, value } = signedAttribute(token);
      assert.equal(attrValues.tag, expected.attrValuesTag);
      assert.equal(value.tag, expected.messageDigestValueTag);
      assert(equal(value.value, sha256(content)));
      const signedAttrs = der(0x31, signer.children[3].value);
      assert(
        verifySignature(
          'sha256',
          signedAttrs,
          new X509Certificate(tsa).publicKey,
          signer.children[5].value,
        ),
      );
    });
  }
  test(`${name} accepts the frozen canonical token in external CMS and full timestamp verification`, () => {
    const cms = verifyExternalCMS(positive, { certificate: tsa, expectedContentType: OID.tstInfo });
    assert(equal(cms.content, content));
    const info = verifyExternalTimestampToken(positive, options);
    assert.equal(info.nonce, options.nonce);
  });
  test(`${name} rejects the signed malformed token in external CMS`, () => {
    assert.throws(
      () => verifyExternalCMS(negative, { certificate: tsa, expectedContentType: OID.tstInfo }),
      { code: item.expectedError },
    );
  });
  test(`${name} rejects the signed malformed token in full timestamp verification`, () => {
    assert.throws(() => verifyExternalTimestampToken(negative, options), {
      code: item.expectedError,
    });
  });
}

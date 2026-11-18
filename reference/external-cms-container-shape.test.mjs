import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, verify as verifySignature, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { der, equal, parseDER, sha256 } from './core.mjs';
import { verifyExternalCMS } from './external-cms.mjs';
import { OID } from './pki.mjs';
import { verifyExternalTimestampToken } from './timestamp.mjs';

const vectors = JSON.parse(
  readFileSync(new URL('./vectors/external-cms-container-shape.json', import.meta.url)),
);
assert.equal(vectors.profile, 'RFC5652-EXTERNAL-CMS-CONTAINER-SHAPE');
const original = (ref) => {
  const raw = Buffer.from(ref.derBase64, 'base64');
  assert.equal(createHash('sha256').update(raw).digest('hex'), ref.sha256);
  return raw;
};
const root = original(vectors.root),
  tsa = original(vectors.tsa),
  content = original(vectors.content),
  tstInfo = original(vectors.tstInfo),
  positive = original(vectors.positiveToken);
const options = {
  imprint: sha256(content),
  hashOID: OID.sha256,
  nonce: 9156438538392878302n,
  policy: '1.3.6.1.4.1.55555.91.1',
  certificate: tsa,
  issuerKey: new X509Certificate(root).publicKey,
  at: 1800000040,
  maxFutureSkew: 0,
  revokedAt: Infinity,
};
const signedData = (token) => parseDER(token).children[1].children[0];
const embedded = (sd) => sd.children[2].children[1].children[0].value;
const signer = (sd) => sd.children.at(-1).children[0];

test('canonical container retains the signed TSTInfo and accepts both external paths', () => {
  const sd = signedData(positive);
  assert(equal(embedded(sd), tstInfo));
  const si = signer(sd);
  assert(
    verifySignature(
      'sha256',
      der(0x31, si.children[3].value),
      new X509Certificate(tsa).publicKey,
      si.children[5].value,
    ),
  );
  assert(
    equal(
      verifyExternalCMS(positive, { certificate: tsa, expectedContentType: OID.tstInfo }).content,
      tstInfo,
    ),
  );
  assert.equal(verifyExternalTimestampToken(positive, options).nonce, options.nonce);
});

for (const [name, item] of Object.entries(vectors.cases)) {
  const negative = original(item.negativeToken);
  test(`${name} changes only one container shape and retains the original signature`, () => {
    const outerPositive = parseDER(positive),
      outerNegative = parseDER(negative),
      sdPositive = signedData(positive),
      sdNegative = signedData(negative);
    assert.equal(negative.length, positive.length + 2);
    assert(equal(embedded(sdPositive), embedded(sdNegative)));
    assert(equal(embedded(sdNegative), tstInfo));
    assert(equal(signer(sdPositive).raw, signer(sdNegative).raw));
    assert(
      equal(
        sdPositive.children.find((n) => n.tag === 0xa0).raw,
        sdNegative.children.find((n) => n.tag === 0xa0).raw,
      ),
    );
    let before, after;
    if (name === 'contentInfoExtraMember') {
      before = outerPositive.children;
      after = outerNegative.children;
    } else if (name === 'encapContentInfoExtraMember') {
      before = sdPositive.children[2].children;
      after = sdNegative.children[2].children;
    } else {
      before = sdPositive.children;
      after = sdNegative.children;
    }
    assert.equal(after.length, before.length + 1);
    const extra = name === 'signedDataExtraMember' ? 3 : before.length;
    assert(equal(after[extra].raw, Buffer.from('0500', 'hex')));
    for (let i = 0; i < before.length; i++) {
      assert(equal(before[i].raw, after[i < extra ? i : i + 1].raw));
    }
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

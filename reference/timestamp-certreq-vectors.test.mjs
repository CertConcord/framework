import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { der, oidText, parseDER } from './core.mjs';
import { OID } from './pki.mjs';
import { parseTimestampRequest, tokenFromResponse, verifyTimestampToken } from './timestamp.mjs';

const vectors = JSON.parse(
  readFileSync(new URL('./vectors/timestamp-certreq-contract.json', import.meta.url), 'utf8'),
);
const hash = (raw) => createHash('sha256').update(raw).digest('hex');
function bytes(row) {
  const raw = Buffer.from(row.base64, 'base64');
  assert.equal(raw.length, row.bytes);
  assert.equal(hash(raw), row.sha256);
  return raw;
}

test('fixed RFC 3161 certReq tokens bind exact request, CMS certificate presence and signature', () => {
  assert.equal(vectors.schemaVersion, 1);
  assert.equal(vectors.profile, 'rfc3161-certreq-certificate-delivery');
  assert.deepEqual(
    vectors.cases.map((row) => row.id),
    ['certreq-true', 'certreq-absent'],
  );
  const certificate = bytes(vectors.certificate);
  const root = createPublicKey({ key: bytes(vectors.rootSPKI), type: 'spki', format: 'der' });
  const x509 = new X509Certificate(certificate);
  assert(x509.verify(root));
  const imprint = bytes(vectors.imprint);
  const query = {
    certificate,
    issuerKey: root,
    imprint,
    policy: vectors.policy,
    hashOID: vectors.hashOID,
    nonce: BigInt(vectors.nonce),
    at: vectors.epoch,
  };
  for (const row of vectors.cases) {
    const request = bytes(row.request);
    const response = bytes(row.response);
    const token = bytes(row.token);
    assert.equal(parseTimestampRequest(request).certReq, row.certReq, row.id);
    assert.deepEqual(tokenFromResponse(response), token, row.id);
    const sd = parseDER(token).children[1].children[0].children;
    assert.equal(sd[3].tag, row.certReq ? 0xa0 : 0x31, row.id);
    const signer = sd.at(-1).children[0].children;
    const tbs = der(0x31, signer[3].value);
    assert(verify(null, tbs, x509.publicKey, signer[5].value), row.id);
    const attributes = new Map(
      signer[3].children.map((attribute) => [
        oidText(attribute.children[0]),
        attribute.children[1].children[0],
      ]),
    );
    const content = sd[2].children[1].children[0].value;
    assert.deepEqual(
      attributes.get(OID.messageDigest).value,
      createHash('sha512').update(content).digest(),
      row.id,
    );
    const result = verifyTimestampToken(token, { ...query, certReq: row.certReq });
    assert.equal(result.nonce, query.nonce, row.id);
    assert.equal(result.genTime, vectors.epoch, row.id);
    assert.throws(
      () => verifyTimestampToken(token, { ...query, certReq: !row.certReq }),
      /TSA_CERT_REQ_RESPONSE/,
      row.id,
    );
  }
  const tampered = bytes(vectors.negative.token);
  assert.throws(
    () => verifyTimestampToken(tampered, { ...query, certReq: false }),
    /CMS_SIGNATURE/,
  );
});

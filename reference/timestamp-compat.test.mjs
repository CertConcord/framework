import test from 'node:test';
import assert from 'node:assert/strict';
import { generate, now, parseDER, seq, sha512 } from './core.mjs';
import { issueCertificate, name, OID, verifyCMS } from './pki.mjs';
import {
  TimestampAuthority,
  parseTimestampRequest,
  requestTimestamp,
  timestampRequest,
  tokenFromResponse,
  verifyTimestampToken,
} from './timestamp.mjs';
import { Journal } from './state.mjs';

function fixture() {
  const time = now();
  const root = generate('ml-dsa-87');
  const signer = generate('ml-dsa-65');
  const policy = '2.25.1234567890';
  const certificate = issueCertificate(
    {
      publicKey: signer.publicKey,
      issuer: name('Timestamp test root'),
      subject: name('Timestamp test signer'),
      serial: 2,
      profileID: 'CERTCONCORD-TSA-v1',
      notBefore: time - 60,
      notAfter: time + 86400,
    },
    root.privateKey,
  );
  const otherSigner = generate('ml-dsa-65');
  const wrongCertificate = issueCertificate(
    {
      publicKey: otherSigner.publicKey,
      issuer: name('Timestamp test root'),
      subject: name('Different timestamp signer'),
      serial: 3,
      profileID: 'CERTCONCORD-TSA-v1',
      notBefore: time - 60,
      notAfter: time + 86400,
    },
    root.privateKey,
  );
  const journal = new Journal();
  return {
    authority: new TimestampAuthority({
      certificate,
      privateKey: signer.privateKey,
      policy,
      journal,
      clock: () => time,
    }),
    certificate,
    wrongCertificate,
    policy,
    time,
    trust: { certificate, issuerKey: root.publicKey, policy, at: time },
    close: () => journal.close(),
  };
}

function certificateField(token) {
  return parseDER(token).children[1].children[0].children[3];
}

test('RFC 3161 certReq absent omits certificates but still verifies against external TSA certificate', () => {
  const f = fixture();
  try {
    const imprint = sha512(Buffer.from('timestamped document'));
    const trueRequest = timestampRequest(imprint, { policy: f.policy, nonce: 7n });
    const fields = parseDER(trueRequest.der).children;
    const absentRequest = seq(...fields.slice(0, -1).map((field) => field.raw));
    assert.equal(parseTimestampRequest(absentRequest).certReq, false);
    assert.deepEqual(
      timestampRequest(imprint, { policy: f.policy, nonce: 7n, certReq: false }).der,
      absentRequest,
    );
    const trueToken = tokenFromResponse(f.authority.issue(trueRequest.der));
    const absentToken = tokenFromResponse(f.authority.issue(absentRequest));
    assert.equal(certificateField(trueToken).tag, 0xa0);
    assert.equal(certificateField(absentToken).tag, 0x31);
    assert.equal(verifyTimestampToken(trueToken, { ...f.trust, imprint, nonce: 7n }).nonce, 7n);
    assert.equal(verifyTimestampToken(absentToken, { ...f.trust, imprint, nonce: 7n }).nonce, 7n);
    assert.throws(
      () =>
        verifyCMS(absentToken, {
          expectedCertificate: f.certificate,
          expectedContentType: OID.tstInfo,
        }),
      /CMS_SIGNERS/,
    );
    assert.throws(
      () => verifyTimestampToken(absentToken, { ...f.trust, imprint, nonce: 7n, certReq: true }),
      /TSA_CERT_REQ_RESPONSE/,
    );
    assert.throws(
      () => verifyTimestampToken(trueToken, { ...f.trust, imprint, nonce: 7n, certReq: false }),
      /TSA_CERT_REQ_RESPONSE/,
    );
    assert.throws(
      () =>
        verifyTimestampToken(absentToken, {
          ...f.trust,
          certificate: f.wrongCertificate,
          imprint,
          nonce: 7n,
        }),
      /CMS_SIGNER_ID_OR_ALGORITHM|ESS_CERTIFICATE_BINDING/,
    );
    const tampered = Buffer.from(absentToken);
    tampered[tampered.length - 1] ^= 1;
    assert.throws(
      () => verifyTimestampToken(tampered, { ...f.trust, imprint, nonce: 7n }),
      /CMS_SIGNATURE/,
    );
  } finally {
    f.close();
  }
});

test('RFC 3161 HTTP client accepts case-equivalent timestamp-reply and rejects a different type', async () => {
  const f = fixture();
  try {
    const imprint = sha512(Buffer.from('timestamped document'));
    const nonce = 11n;
    const trueRequest = timestampRequest(imprint, { policy: f.policy, nonce });
    const trueResponse = f.authority.issue(trueRequest.der);
    const falseRequest = timestampRequest(imprint, { policy: f.policy, nonce, certReq: false });
    const falseResponse = f.authority.issue(falseRequest.der);
    const fetchWithType = (contentType, expectedRequest, responseBody) => async (_url, options) => {
      assert.deepEqual(options.body, expectedRequest);
      return new Response(responseBody, {
        status: 200,
        headers: { 'content-type': contentType },
      });
    };
    for (const contentType of [
      'application/timestamp-reply',
      'Application/TIMESTAMP-REPLY; name="stamp.tsr"',
    ]) {
      const token = await requestTimestamp(imprint, {
        endpoint: 'https://tsa.example.test/',
        policy: f.policy,
        hashOID: OID.sha512,
        nonce,
        fetchImpl: fetchWithType(contentType, trueRequest.der, trueResponse),
        ...f.trust,
      });
      assert.equal(certificateField(token).tag, 0xa0);
    }
    const noCertificateToken = await requestTimestamp(imprint, {
      endpoint: 'https://tsa.example.test/',
      policy: f.policy,
      hashOID: OID.sha512,
      nonce,
      certReq: false,
      fetchImpl: fetchWithType('application/timestamp-reply', falseRequest.der, falseResponse),
      ...f.trust,
    });
    assert.equal(certificateField(noCertificateToken).tag, 0x31);
    await assert.rejects(
      requestTimestamp(imprint, {
        endpoint: 'https://tsa.example.test/',
        policy: f.policy,
        hashOID: OID.sha512,
        nonce,
        certReq: false,
        fetchImpl: fetchWithType('application/timestamp-reply', falseRequest.der, trueResponse),
        ...f.trust,
      }),
      /TSA_CERT_REQ_RESPONSE/,
    );
    await assert.rejects(
      requestTimestamp(imprint, {
        endpoint: 'https://tsa.example.test/',
        policy: f.policy,
        hashOID: OID.sha512,
        nonce,
        fetchImpl: fetchWithType('text/plain', trueRequest.der, trueResponse),
        ...f.trust,
      }),
      /TSA_HTTP/,
    );
  } finally {
    f.close();
  }
});

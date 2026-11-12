// Synthetic public fixtures. Private keys exist only while generating this corpus.
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import * as c from '../reference/core.mjs';
import * as p from '../reference/pki.mjs';
import { Journal } from '../reference/state.mjs';
import {
  TimestampAuthority,
  timestampRequest,
  tokenFromResponse,
} from '../reference/timestamp.mjs';

const epoch = 1770000000;
const policy = '2.25.316120261111';
const root = c.generate('ml-dsa-87');
const signer = c.generate('ml-dsa-65');
const certificate = p.issueCertificate(
  {
    publicKey: signer.publicKey,
    issuer: p.name('Synthetic certReq root'),
    subject: p.name('Synthetic certReq TSA'),
    serial: 14,
    profileID: 'CERTCONCORD-TSA-v1',
    notBefore: epoch - 60,
    notAfter: epoch + 86400,
  },
  root.privateKey,
);
const journal = new Journal();
const authority = new TimestampAuthority({
  certificate,
  privateKey: signer.privateKey,
  policy,
  journal,
  clock: () => epoch,
});
const imprint = c.sha512(Buffer.from('Fixed synthetic RFC 3161 certReq document input'));
const hash = (raw) => createHash('sha256').update(raw).digest('hex');
const encode = (raw) => ({ base64: raw.toString('base64'), sha256: hash(raw), bytes: raw.length });
const cases = [];
for (const certReq of [true, false]) {
  const request = timestampRequest(imprint, { policy, nonce: 19n, certReq });
  const response = authority.issue(request.der);
  const token = tokenFromResponse(response);
  cases.push({
    id: certReq ? 'certreq-true' : 'certreq-absent',
    certReq,
    request: encode(request.der),
    response: encode(response),
    token: encode(token),
  });
}
journal.close();
const tampered = Buffer.from(cases[1].token.base64, 'base64');
tampered[tampered.length - 1] ^= 1;
const vectors = {
  schemaVersion: 1,
  profile: 'rfc3161-certreq-certificate-delivery',
  epoch,
  policy,
  hashOID: p.OID.sha512,
  nonce: '19',
  imprint: encode(imprint),
  certificate: encode(certificate),
  rootSPKI: encode(c.spki(root.publicKey)),
  cases,
  negative: { id: 'certreq-absent-signature-tampered', token: encode(tampered) },
};
writeFileSync(
  new URL('../reference/vectors/timestamp-certreq-contract.json', import.meta.url),
  `${JSON.stringify(vectors, null, 2)}\n`,
);

import assert from 'node:assert/strict';
import { generate, sha512 } from '../core.mjs';
import { name, issueCertificate, signCMS } from '../pki.mjs';
import {
  TimestampAuthority,
  timestampRequest,
  tokenFromResponse,
  createERS,
  createXMLERS,
  verifyERS,
  verifyXMLERS,
} from '../archive.mjs';
import { examplePDF, preparePDF, verifyPDF } from '../pdf.mjs';
import { Journal } from '../state.mjs';

const root = generate('ml-dsa-87'),
  key = generate(),
  journal = new Journal(),
  policy = '2.25.9876543210';
const certificate = issueCertificate(
  {
    publicKey: key.publicKey,
    issuer: name('Synthetic root'),
    subject: name('Synthetic TSA'),
    serial: 1,
    profileID: 'CERTCONCORD-TSA-v1',
  },
  root.privateKey,
);
const authority = new TimestampAuthority({
  certificate,
  privateKey: key.privateKey,
  policy,
  journal,
});
const trust = { certificate, issuerKey: root.publicKey, policy };
const tsa = async (imprint, hashOID) =>
  tokenFromResponse(authority.issue(timestampRequest(imprint, { hashOID, policy }).der));
const document = Buffer.from('Synthetic archive content.'),
  ers = await createERS(document, { tsa }),
  xml = await createXMLERS(document, { tsa });
const signer = issueCertificate(
  {
    publicKey: key.publicKey,
    issuer: name('Synthetic root'),
    subject: name('Synthetic document signer'),
    serial: 2,
  },
  root.privateKey,
);
const prepared = await preparePDF(await examplePDF());
const pdf = prepared.finish(
  signCMS({ content: prepared.content, certificate: signer, detached: true }, key.privateKey),
);
verifyERS(ers, document, trust);
verifyXMLERS(xml, document, trust);
await verifyPDF(pdf, { issuerKey: root.publicKey });
journal.close();

export async function fuzz(data) {
  if (data.length < 4) return;
  const changed = Buffer.from(document),
    offset = data.readUInt16BE(1),
    mask = data[3] || 1;
  changed[offset % changed.length] ^= mask;
  switch (data[0] % 4) {
    case 0:
      assert.throws(() => verifyERS(ers, changed, trust));
      break;
    case 1:
      assert.throws(() => verifyXMLERS(xml, changed, trust));
      break;
    case 2: {
      // Change a byte covered by ByteRange, including PDF structure and content.
      const modified = Buffer.from(pdf),
        range = prepared.byteRange,
        total = range[1] + range[3],
        n = offset % total;
      modified[n < range[1] ? n : range[2] + n - range[1]] ^= mask;
      await assert.rejects(verifyPDF(modified, { issuerKey: root.publicKey }));
      break;
    }
    case 3: {
      // DTD/entity declarations must be rejected before any external resource is resolved.
      const name = 'entity' + sha512(data).subarray(0, 4).toString('hex');
      assert.throws(
        () =>
          verifyXMLERS(
            `<!DOCTYPE EvidenceRecord [<!ENTITY ${name} SYSTEM "https://example.invalid/">]>` + xml,
            document,
            trust,
          ),
        /XML_EXTERNAL_ENTITY_OR_SIZE/,
      );
      break;
    }
  }
}

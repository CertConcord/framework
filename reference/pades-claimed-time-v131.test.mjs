import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as core from './core.mjs';
import { inspectAdESSignature } from './ades-cms.mjs';
import { verifyPAdES, preparePAdESSignature, preparePAdESAugmentation } from './pades.mjs';
import {
  O, attr, epoch, independentApproval, padesFixture, pdfSignatures, plainPDF,
  appendRevision,
} from './pades-fixtures.mjs';

let f;
before(() => { f = padesFixture(); });
after(() => f?.close());

const claimed = epoch + 10;
const utc = (at) => new Date(at * 1000).toISOString()
  .replace(/[-:T]/g, '').replace('.000Z', 'Z');
const cmsTime = (at) =>
  attr(O.signingTime, core.der(23, Buffer.from(utc(at).slice(2), 'ascii')));
const verify = (pdf) => verifyPAdES(pdf, {
  minimumLevel: 'B',
  validationTime: epoch + 40,
  knowledgeTime: epoch + 40,
  policy: f.policy(),
});

test('the PDF 1.7 generator still emits M without CMS signing-time', async () => {
  const prepared = await preparePAdESSignature(f.pdf, {
    certificate: f.signer.der, certificates: [f.root.der], signingTime: claimed,
    signatureBytes: 8192,
  });
  const pdf = await prepared.finish(core.sign(prepared.tbs, f.signer.privateKey));
  assert.match(pdf.toString('binary'), /\/M \(D:\d{14}Z\)/);
  const entry = pdfSignatures(pdf)[0];
  const [a,b,c,d] = entry.byteRange;
  const content = Buffer.concat([pdf.subarray(a,a+b), pdf.subarray(c,c+d)]);
  const inspected = inspectAdESSignature(entry.cms, { profile: 'PADES', content });
  assert.equal(inspected.parsed.signed.some((a) => a.id === O.signingTime), false);
  assert.equal((await verify(pdf)).verifiedLevel, 'B');
});

test('PDF 1.7 accepts M-only, CMS-only, and equal dual claimed times', async () => {
  for (const [name, options] of [
    ['M only', {}],
    ['CMS only', { omitM: true, cmsOptions: { additionalSigned: [cmsTime(claimed)] } }],
    ['equal dual', { cmsOptions: { additionalSigned: [cmsTime(claimed)] } }],
  ]) {
    const { pdf, cms, content } = independentApproval(f, options);
    const inspected = inspectAdESSignature(cms, { profile: 'PADES', content });
    assert.equal(inspected.overall, 'VALID', name);
    const result = await verify(pdf);
    assert.equal(result.overall, 'VALID', name);
    assert.equal(result.reason, 'PADES_VALID', name);
    assert.equal(result.verifiedLevel, 'B', name);
  }
});

test('PDF 1.7 compares parsed instants across M and CMS time', async () => {
  const local = new Date((claimed + 3600) * 1000).toISOString()
    .slice(0, 19).replace(/[-:T]/g, '');
  const { pdf } = independentApproval(f, {
    dictionary: (body) => body.replace(/\/M \(D:[^)]+\)/, `/M (D:${local}+01'00')`),
    cmsOptions: { additionalSigned: [cmsTime(claimed)] },
  });
  const result = await verify(pdf);
  assert.equal(result.overall, 'VALID');
  assert.equal(result.verifiedLevel, 'B');
});

test('PDF 1.7 rejects unequal dual time and leaves neither time indeterminate', async () => {
  const unequal = independentApproval(f, {
    cmsOptions: { additionalSigned: [cmsTime(claimed + 60)] },
  }).pdf;
  const mismatch = await verify(unequal);
  assert.equal(mismatch.overall, 'INVALID');
  assert.equal(mismatch.reason, 'PADES_SIGNING_TIME_MISMATCH');
  const neither = independentApproval(f, { omitM: true }).pdf;
  const missing = await verify(neither);
  assert.equal(missing.overall, 'INDETERMINATE');
  assert.equal(missing.reason, 'PADES_SIGNING_TIME_REQUIRED');
});

test('malformed or misplaced CMS signing-time cannot satisfy the PDF 1.7 time gate', async () => {
  const malformed = independentApproval(f, {
    omitM: true,
    cmsOptions: { additionalSigned: [attr(O.signingTime, core.der(23, Buffer.from('271399080010Z')))] },
  }).pdf;
  const badTime = await verify(malformed);
  assert.equal(badTime.overall, 'INVALID');
  assert.equal(badTime.reason, 'CADES_SIGNING_TIME_ENCODING');
  const misplaced = independentApproval(f, {
    omitM: true,
    cmsOptions: { unsigned: [cmsTime(claimed)] },
  }).pdf;
  const badLocation = await verify(misplaced);
  assert.equal(badLocation.overall, 'INVALID');
  assert.equal(badLocation.reason, 'CADES_ATTRIBUTE_LOCATION');
});

test('CMS-only approval can enter the selected document-timestamp route', async () => {
  const b = independentApproval(f, {
    omitM: true,
    cmsOptions: { additionalSigned: [cmsTime(claimed)] },
  }).pdf;
  const t = (await f.augment({ preparePAdESAugmentation }, b, 'T')).pdf;
  const result = await verifyPAdES(t, {
    minimumLevel: 'T', validationTime: epoch + 40,
    knowledgeTime: epoch + 40, policy: f.policy(),
  });
  assert.equal(result.overall, 'VALID');
  assert.equal(result.verifiedLevel, 'T');
});

test('PDF 2.0 stays outside the selected parser profile', async () => {
  const pdf2 = Buffer.from(plainPDF());
  pdf2.write('%PDF-2.0', 0, 'ascii');
  const upgraded = appendRevision(plainPDF(), [
    { number: 1, body: '<< /Type /Catalog /Pages 2 0 R /Version /2.0 >>' },
  ]);
  for (const source of [pdf2, upgraded]) {
    const signed = independentApproval(f, {
      pdf: source,
      cmsOptions: { additionalSigned: [cmsTime(claimed)] },
    }).pdf;
    const result = await verify(signed);
    assert.equal(result.overall, 'UNSUPPORTED');
    assert.equal(result.reason, 'PADES_VERSION_UNSUPPORTED');
  }
});

import test, {before, after} from 'node:test';
import assert from 'node:assert/strict';
import {deflateSync} from 'node:zlib';
import {
  padesFixture,
  independentApproval,
  plainPDF,
  appendRevision,
  decision,
  loadPAdES,
} from './pades-fixtures.mjs';

const api = await loadPAdES();
let fixture;
before(() => { fixture = padesFixture(); });
after(() => fixture?.close());

const page = contents => `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] /Resources << /Font << /F1 4 0 R >> >> /Contents ${contents} >>`;
const rawStream = text => {
  const payload = Buffer.from(text, 'latin1');
  return Buffer.concat([
    Buffer.from(`<< /Length ${payload.length} >>\nstream\n`),
    payload,
    Buffer.from('endstream'),
  ]);
};
const flateStream = (text, arrayFilter = false) => {
  const payload = deflateSync(Buffer.from(text, 'latin1'));
  const filter = arrayFilter ? '[/FlateDecode]' : '/FlateDecode';
  return Buffer.concat([
    Buffer.from(`<< /Length ${payload.length} /Filter ${filter} >>\nstream\n`),
    payload,
    Buffer.from('\nendstream'),
  ]);
};
const checkSigned = async (pdf, overall, reason) => {
  const signed = independentApproval(fixture, {pdf}).pdf;
  const result = await decision(api, fixture, signed);
  assert.equal(result.overall, overall, JSON.stringify(result));
  if (reason) assert.equal(result.reason, reason);
};

test('signed page content array concatenates split string tokens before text admission', async () => {
  const valid = appendRevision(plainPDF(), [
    {number: 3, body: page('[5 0 R 6 0 R]')},
    {number: 5, body: rawStream('BT /F1 12 Tf 40 120 Td (A')},
    {number: 6, body: rawStream('B) Tj ET\n')},
  ]);
  await checkSigned(valid, 'VALID', 'PADES_VALID');
  const invalid = appendRevision(plainPDF(), [
    {number: 3, body: page('[5 0 R 6 0 R]')},
    {number: 5, body: rawStream('BT /F1 12 Tf 40 120 Td [(A) true')},
    {number: 6, body: rawStream(' (B)] TJ ET\n')},
  ]);
  await checkSigned(invalid, 'INVALID', 'PADES_TEXT_OPERAND');
});

test('signed Flate content stream is decoded before text admission', async () => {
  const valid = appendRevision(plainPDF(), [
    {number: 5, body: flateStream('BT /F1 12 Tf 40 120 Td (AB) Tj ET\n')},
  ]);
  await checkSigned(valid, 'VALID', 'PADES_VALID');
  const invalid = appendRevision(plainPDF(), [
    {number: 5, body: flateStream('BT /F1 [12] Tf 40 120 Td (AB) Tj ET\n')},
  ]);
  await checkSigned(invalid, 'INVALID', 'PADES_TEXT_OPERAND');
});

test('single-element Flate filter array preserves signed valid text', async () => {
  const pdf = appendRevision(plainPDF(), [
    {number: 5, body: flateStream('BT /F1 12 Tf 40 120 Td (AB) Tj ET\n', true)},
  ]);
  await checkSigned(pdf, 'VALID', 'PADES_VALID');
});

test('signed Flate content exceeding the admission budget stays unsupported', async () => {
  const oversized = 'BT /F1 12 Tf 40 120 Td (AB) Tj ET\n' +
    '%'.padEnd(17 * 1024 * 1024, 'A') + '\n';
  const pdf = appendRevision(plainPDF(), [
    {number: 5, body: flateStream(oversized)},
  ]);
  await checkSigned(pdf, 'UNSUPPORTED', 'PADES_PAGE_CONTENT_LIMIT');
});

test('operator-looking bytes in signed strings and comments are not executed', async () => {
  const stream = 'BT /F1 12 Tf 40 120 Td (true Tj [12] Tf) Tj % [true] TJ\nET\n';
  await checkSigned(plainPDF({stream}), 'VALID', 'PADES_VALID');
});

test('invalid signed page contents reference does not bypass text admission', async () => {
  const pdf = appendRevision(plainPDF(), [
    {number: 3, body: page('4 0 R')},
  ]);
  await checkSigned(pdf, 'INVALID', 'PADES_PAGE_CONTENT_STREAM');
});

test('signed Tf font name resolves against the active page Font resources', async () => {
  await checkSigned(plainPDF({stream: 'BT /F1 12 Tf 40 120 Td (AB) Tj ET\n'}),
    'VALID', 'PADES_VALID');
  await checkSigned(plainPDF({stream: 'BT /F0 12 Tf 40 120 Td (AB) Tj ET\n'}),
    'INVALID', 'PADES_TEXT_FONT_RESOURCE');
});

test('signed text font lookup uses inherited resources and a Page override', async () => {
  const inherited = appendRevision(plainPDF(), [
    {number: 2, body: '<< /Type /Pages /Kids [3 0 R] /Count 1 /Resources << /Font << /F1 4 0 R >> >> >>'},
    {number: 3, body: '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] /Contents 5 0 R >>'},
  ]);
  await checkSigned(inherited, 'VALID', 'PADES_VALID');
  const overridden = appendRevision(inherited, [
    {number: 3, body: '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] /Resources << /Font << /F0 4 0 R >> >> /Contents 5 0 R >>'},
  ]);
  await checkSigned(overridden, 'INVALID', 'PADES_TEXT_FONT_RESOURCE');
});

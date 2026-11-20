import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { inspectAdESSignature } from './ades-cms.mjs';
import {
  padesFixture,
  independentApproval,
  loadPAdES,
  decision,
  pdfSignatures,
  absentCapability,
} from './pades-fixtures.mjs';

const api = await loadPAdES();
const selected = { skip: !api && absentCapability };
let fixture;
before(() => { if (api) fixture = padesFixture(); });
after(() => fixture?.close());

const cases = [
  ['ordinary approval', {}, 'VALID', 'PADES_VALID'],
  ['qualified parent and child field name', { parentFieldName: 'Section', fieldName: 'Approval' }, 'VALID', 'PADES_VALID'],
  ['SigFlags zero', { sigFlags: '0' }, 'VALID', 'PADES_VALID'],
  ['SigFlags one', { sigFlags: '1' }, 'VALID', 'PADES_VALID'],
  ['SigFlags two', { sigFlags: '2' }, 'VALID', 'PADES_VALID'],
  ['SigFlags omitted', { sigFlags: null }, 'VALID', 'PADES_VALID'],
  ['approval Type omitted', { dictionary: (body) => body.replace('/Type /Sig ', '') }, 'VALID', 'PADES_VALID'],
  ['period inside partial field name', { fieldName: 'Approv.l' }, 'INVALID', 'PADES_FIELD_NAME'],
  ['period inside parent partial name', { parentFieldName: 'Sec.tion', fieldName: 'Approval' }, 'INVALID', 'PADES_FIELD_NAME'],
  ['SigFlags reserved bit', { sigFlags: '7' }, 'INVALID', 'PADES_SIG_FLAGS'],
  ['SigFlags real number', { sigFlags: '3.0' }, 'INVALID', 'PADES_SIG_FLAGS'],
  ['SigFlags long real token', { sigFlags: `${'0'.repeat(64)}.0` }, 'INVALID', 'PADES_SIG_FLAGS'],
  ['ByteRange real token', { transformByteRange: ([a, b, c, d]) => [a, `${b}.0`, c, d] }, 'INVALID', 'PADES_BYTE_RANGE'],
  ['wrong present approval Type', { type: 'Bogus' }, 'INVALID', 'PADES_SIGNATURE_TYPE'],
];

for (const [description, options, overall, reason] of cases)
  test(`independently signed ${description}`, selected, async () => {
    const signed = independentApproval(fixture, options);
    const extracted = pdfSignatures(signed.pdf);
    assert.equal(extracted.length, 1);
    assert.deepEqual(extracted[0].cms, signed.cms);
    const cms = inspectAdESSignature(signed.cms, { content: signed.content, profile: 'PADES' });
    assert.equal(cms.overall, 'VALID', `${description}: detached CMS must remain valid`);
    const result = await decision(api, fixture, signed.pdf);
    assert.equal(result.overall, overall, description);
    assert.equal(result.reason, reason, description);
    assert.equal(result.verifiedLevel ?? null, overall === 'VALID' ? 'B' : null);
  });

import assert from 'node:assert/strict';
import test, { before, after } from 'node:test';
import { inspectAdESSignature } from './ades-cms.mjs';
import {
  padesFixture,
  independentApproval,
  independentTimestamp,
  loadPAdES,
  decision,
  pdfSignatures,
  absentCapability,
} from './pades-fixtures.mjs';

const api = await loadPAdES();
const selected = { skip: !api && absentCapability };
let fixture, approval;
before(() => {
  if (api) {
    fixture = padesFixture();
    approval = independentApproval(fixture).pdf;
  }
});
after(() => fixture?.close());

const approvalVersion = (body, token) => {
  assert(body.includes(' /ByteRange [') && !body.includes(' /V '));
  return body.replace(' /ByteRange [', ` /V ${token} /ByteRange [`);
};
for (const [name, token, overall, reason] of [
  ['omitted approval version defaults to zero', undefined, 'VALID', 'PADES_VALID'],
  ['integer approval version zero', '0', 'VALID', 'PADES_VALID'],
  ['real approval version zero', '0.', 'INVALID', 'PADES_SIGNATURE_VERSION'],
])
  test(`independently signed ${name}`, selected, async () => {
    const signed = independentApproval(fixture, {
      dictionary: token === undefined ? undefined : body => approvalVersion(body, token),
    });
    const signatures = pdfSignatures(signed.pdf);
    assert.equal(signatures.length, 1);
    assert(signatures[0].cms.equals(signed.cms));
    assert.equal(inspectAdESSignature(signed.cms, {
      content: signed.content,
      profile: 'PADES',
    }).overall, 'VALID');
    const result = await decision(api, fixture, signed.pdf);
    assert.equal(result.overall, overall, name);
    assert.equal(result.reason, reason, name);
    assert.equal(result.verifiedLevel ?? null, overall === 'VALID' ? 'B' : null);
  });

const timestampVersion = (body, token) => {
  assert(body.includes(' /V 0 /ByteRange ['));
  return token === undefined
    ? body.replace(' /V 0 /ByteRange [', ' /ByteRange [')
    : body.replace(' /V 0 /ByteRange [', ` /V ${token} /ByteRange [`);
};
for (const [name, token, overall, reason] of [
  ['omitted document timestamp version', undefined, 'VALID', 'PADES_VALID'],
  ['integer document timestamp version zero', '0', 'VALID', 'PADES_VALID'],
  ['real document timestamp version zero', '0.', 'INVALID', 'PADES_TIMESTAMP_VERSION'],
  ['nonzero document timestamp version', '1', 'INVALID', 'PADES_TIMESTAMP_VERSION'],
])
  test(`independently signed ${name}`, selected, async () => {
    const signed = independentTimestamp(fixture, approval, {
      dictionary: body => timestampVersion(body, token),
    });
    assert.equal(pdfSignatures(signed.pdf).length, 2);
    const result = await decision(api, fixture, signed.pdf, 'T');
    assert.equal(result.overall, overall, name);
    assert.equal(result.reason, reason, name);
    assert.equal(result.verifiedLevel ?? null, overall === 'VALID' ? 'T' : null);
  });

import assert from 'node:assert/strict';
import test, { before, after } from 'node:test';
import { inspectAdESSignature } from './ades-cms.mjs';
import {
  padesFixture,
  plainPDF,
  appendRevision,
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

const parentDictionary = body => {
  assert(body.includes(' /Kids ['));
  return body.replace(' /Kids [', ' /FT /Sig /Kids [');
};
const fieldDictionary = (token, parentMode = 'valid') => body => {
  assert(body.includes(' /FT /Sig /T (Approval)'));
  let updated = body.replace(' /FT /Sig /T (Approval)',
    `${token === undefined ? '' : ` /FT ${token}`} /T (Approval)`);
  if (parentMode === 'missing') {
    assert.match(updated, / \/Parent \d+ 0 R/);
    updated = updated.replace(/ \/Parent \d+ 0 R/, '');
  } else if (parentMode === 'wrong') {
    assert.match(updated, / \/Parent \d+ 0 R/);
    updated = updated.replace(/ \/Parent \d+ 0 R/, ' /Parent 1 0 R');
  }
  return updated;
};

for (const [label, token, parentMode, overall, reason] of [
  ['omitted local FT inherits parent Sig', undefined, 'valid', 'VALID', 'PADES_VALID'],
  ['local name FT Sig remains explicit', '/Sig', 'valid', 'VALID', 'PADES_VALID'],
  ['local PDF null FT inherits parent Sig', 'null', 'valid', 'VALID', 'PADES_VALID'],
  ['local integer FT cannot inherit parent Sig', '0', 'valid', 'INVALID', 'PADES_FIELD_TYPE'],
  ['local string FT cannot inherit parent Sig', '(Sig)', 'valid', 'INVALID', 'PADES_FIELD_TYPE'],
  ['child without Parent cannot inherit Sig', undefined, 'missing', 'INVALID', 'PADES_FIELD_PARENT'],
  ['child pointing at another Parent cannot inherit Sig', undefined, 'wrong', 'INVALID', 'PADES_FIELD_PARENT'],
])
  test(`independently signed ${label}`, selected, async () => {
    const signed = independentApproval(fixture, {
      parentFieldName: 'Group',
      parentDictionary,
      fieldDictionary: fieldDictionary(token, parentMode),
    });
    const signatures = pdfSignatures(signed.pdf);
    assert.equal(signatures.length, 1);
    assert(signatures[0].cms.equals(signed.cms));
    assert.equal(inspectAdESSignature(signed.cms, {
      content: signed.content, profile: 'PADES',
    }).overall, 'VALID');
    const result = await decision(api, fixture, signed.pdf);
    assert.equal(result.overall, overall, label);
    assert.equal(result.reason, reason, label);
    assert.equal(result.verifiedLevel ?? null, overall === 'VALID' ? 'B' : null);
  });

for (const [label, objectBody, overall, reason] of [
  ['indirect local name FT Sig', '/Sig', 'VALID', 'PADES_VALID'],
  ['indirect local integer FT cannot inherit Sig', '0', 'INVALID', 'PADES_FIELD_TYPE'],
  ['indirect PDF null FT inherits parent Sig', 'null', 'VALID', 'PADES_VALID'],
])
  test(`independently signed ${label}`, selected, async () => {
    const unsigned = appendRevision(plainPDF(), [{ number: 6, body: objectBody }]);
    const signed = independentApproval(fixture, {
      pdf: unsigned,
      parentFieldName: 'Group',
      parentDictionary,
      fieldDictionary: fieldDictionary('6 0 R'),
    });
    const signatures = pdfSignatures(signed.pdf);
    assert.equal(signatures.length, 1);
    assert(signatures[0].cms.equals(signed.cms));
    assert.equal(inspectAdESSignature(signed.cms, {
      content: signed.content, profile: 'PADES',
    }).overall, 'VALID');
    const result = await decision(api, fixture, signed.pdf);
    assert.equal(result.overall, overall, label);
    assert.equal(result.reason, reason, label);
    assert.equal(result.verifiedLevel ?? null, overall === 'VALID' ? 'B' : null);
  });

import assert from 'node:assert/strict';
import test, { before, after } from 'node:test';
import { inspectAdESSignature } from './ades-cms.mjs';
import { inspectPAdESContainer } from './pades-structure.mjs';
import {
  plainPDF, padesFixture, independentApproval, loadPAdES, decision,
  pdfSignatures, absentCapability,
} from './pades-fixtures.mjs';

const api = await loadPAdES();
const selected = { skip: !api && absentCapability };
let fixture;
before(() => { if (api) fixture = padesFixture(); });
after(() => fixture?.close());

function signedInheritedVisual(variant) {
  return independentApproval(fixture, {
    pdf: plainPDF(), parentFieldName: 'Group',
    fieldDictionary: body => {
      assert(body.includes(' /FT /Sig /T (Approval)'));
      let result = body.replace(' /FT /Sig /T (Approval)',
        ' /Subtype /Widget /Rect [20 20 120 50] /P 3 0 R');
      if (variant !== 'sharedLocalAndInherited')
        result = result.replace(' /V 6 0 R', '');
      return result;
    },
    parentDictionary: body => {
      assert(body.includes(' /Kids [7 0 R]'));
      return body.replace(' /Kids [', ' /FT /Sig /V 6 0 R /Kids [')
        .replace('] >>', ' 10 0 R] >>');
    },
    additionalObjects: ({ state, sig, field, parent, form }) => {
      assert.deepEqual([sig, field, parent, form], [6, 7, 8, 9]);
      const extra = form + 1;
      const page = { number: 3, body: state.objects.get(3).body.replace(/>>$/,
        ` /Annots [${field} 0 R ${extra} 0 R] >>`) };
      const isNonWidget = variant === 'nonWidgetDuplicate';
      const secondV = variant === 'differentLocalValue' ? ' /V 11 0 R' : '';
      const secondFT = variant === 'differentLocalType' ? ' /FT /Btn' : '';
      const second = { number: extra,
        body: `<< ${isNonWidget ? '' : '/Subtype /Widget '}/Rect [160 20 260 50] /P 3 0 R /Parent ${parent} 0 R${secondFT}${secondV} >>` };
      return variant === 'differentLocalValue'
        ? [page, second, { number: 11, body: '<< /Type /Sig >>' }]
        : [page, second];
    },
  });
}

for (const [variant, overall, reason] of [
  ['sharedLocalAndInherited', 'VALID', 'PADES_VALID'],
  ['sharedInheritedOnly', 'VALID', 'PADES_VALID'],
  ['differentLocalValue', 'INVALID', 'PADES_DUPLICATE_FIELD_NAME'],
  ['differentLocalType', 'INVALID', 'PADES_DUPLICATE_FIELD_NAME'],
  ['nonWidgetDuplicate', 'INVALID', 'PADES_DUPLICATE_FIELD_NAME'],
])
  test(`signed inherited-value visual fields: ${variant}`, selected, async () => {
    const signed = signedInheritedVisual(variant);
    const signatures = pdfSignatures(signed.pdf);
    assert.equal(signatures.length, 1);
    assert(signatures[0].cms.equals(signed.cms));
    assert.equal(inspectAdESSignature(signed.cms, {
      content: signed.content, profile: 'PADES',
    }).overall, 'VALID');
    const result = await decision(api, fixture, signed.pdf);
    assert.equal(result.overall, overall, variant);
    assert.equal(result.reason, reason, variant);
    assert.equal(result.verifiedLevel ?? null, overall === 'VALID' ? 'B' : null);
    if (overall === 'VALID')
      assert.equal(inspectPAdESContainer(signed.pdf).signatures.length, 1);
    else
      assert.throws(() => inspectPAdESContainer(signed.pdf), {
        code: 'PADES_DUPLICATE_FIELD_NAME',
      });
  });

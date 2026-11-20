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

function signedVisualField(variant) {
  const duplicate = variant !== 'single';
  return independentApproval(fixture, {
    pdf: plainPDF(), parentFieldName: 'Group',
    fieldDictionary: body => {
      assert(body.includes(' /FT /Sig /T (Approval)'));
      return variant === 'namedDuplicate' ? body
        : body.replace(' /FT /Sig /T (Approval)',
          ' /Subtype /Widget /Rect [20 20 120 50] /P 3 0 R');
    },
    parentDictionary: body => {
      assert(body.includes(' /Kids ['));
      let result = body.replace(' /Kids [', ' /FT /Sig /Kids [');
      if (duplicate) result = result.replace('] >>', ' 10 0 R] >>');
      return result;
    },
    additionalObjects: ({ state, sig, field, parent, form }) => {
      assert.equal(sig, 6);
      assert.equal(field, 7);
      assert.equal(parent, 8);
      assert.equal(form, 9);
      const extra = form + 1;
      const pageBody = state.objects.get(3).body;
      assert(pageBody.endsWith('>>'));
      const page = { number: 3, body: pageBody.replace(/>>$/, 
        ` /Annots [${field} 0 R${duplicate ? ` ${extra} 0 R` : ''}] >>`) };
      if (!duplicate) return [page];
      const secondSig = form + 2;
      const widget = {
        number: extra,
        body: `<< /Subtype /Widget /Rect [160 20 260 50] /P 3 0 R /Parent ${parent} 0 R${variant === 'namedDuplicate' ? ' /T (Approval)' : ''}${variant === 'differentType' ? ' /FT /Btn' : ''} /V ${variant === 'differentSignature' ? secondSig : sig} 0 R${variant === 'differentDefault' ? ' /DV (other)' : ''} >>`,
      };
      return variant === 'differentSignature'
        ? [page, widget, { number: secondSig, body: '<< /Type /Sig >>' }]
        : [page, widget];
    },
  });
}

for (const [variant, overall, reason] of [
  ['single', 'VALID', 'PADES_VALID'],
  ['sharedVisualRepresentations', 'VALID', 'PADES_VALID'],
  ['differentSignature', 'INVALID', 'PADES_DUPLICATE_FIELD_NAME'],
  ['differentDefault', 'INVALID', 'PADES_DUPLICATE_FIELD_NAME'],
  ['differentType', 'INVALID', 'PADES_DUPLICATE_FIELD_NAME'],
  ['namedDuplicate', 'INVALID', 'PADES_DUPLICATE_FIELD_NAME'],
])
  test(`independently signed ${variant} field`, selected, async () => {
    const signed = signedVisualField(variant);
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
    if (overall === 'VALID') {
      const parsed = inspectPAdESContainer(signed.pdf);
      assert.equal(parsed.signatures.length, 1, 'one underlying signature is counted once');
    }
  });

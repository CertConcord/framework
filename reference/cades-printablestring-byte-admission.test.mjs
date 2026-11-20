import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import test from 'node:test';
import { bit, der, parseDER, seq, set, sign } from './core.mjs';
import { sameDistinguishedName } from './x509-name.mjs';
import { cmsView, decision, epoch, fixture, rewriteCMS } from './cades-fixtures.mjs';
import { prepareCAdESSignature, verifyCAdES } from './cades.mjs';
import { validateCAdESMaterial } from './cades-validation.mjs';

const originalValid = Buffer.from('3016311430120603550403130b4c616273205369676e6572', 'hex');
const originalMalformed = Buffer.from('3016311430120603550403130bcc616273205369676e6572', 'hex');

function printableName(name, { text, highBit = false } = {}) {
  const parsed = parseDER(name);
  assert.equal(parsed.children.length, 1);
  assert.equal(parsed.children[0].children.length, 1);
  const attr = parsed.children[0].children[0];
  assert.equal(attr.children.length, 2);
  const value = Buffer.from(text ?? attr.children[1].value);
  if (highBit) value[0] |= 0x80;
  return seq(set(seq(attr.children[0].raw, der(0x13, value))));
}

test('PrintableString checks original octets before DN case and space normalization', () => {
  assert.equal(sameDistinguishedName(originalValid, originalValid), true);
  assert.throws(() => sameDistinguishedName(originalValid, originalMalformed),
    { code: 'CADES_ISSUER_NAME_ENCODING' });
  assert.throws(() => sameDistinguishedName(originalMalformed, originalValid),
    { code: 'CADES_ISSUER_NAME_ENCODING' });
  assert.throws(() => sameDistinguishedName(originalMalformed, originalMalformed),
    { code: 'CADES_ISSUER_NAME_ENCODING' });
  const spaced = printableName(originalValid, { text: ' labs  signer ' });
  assert.equal(sameDistinguishedName(originalValid, spaced), true);
});

test('signed CMS signer identity and direct-root candidate selection reject high-bit PrintableString', () => {
  const f = fixture();
  try {
    const cms = f.baseCMS({ prepareCAdESSignature });
    const view = cmsView(cms);
    const signerID = view.fields[1];
    const originalName = signerID.children[0].raw;
    const printable = printableName(originalName);
    const malformed = printableName(originalName, { highBit: true });
    const caseAndSpace = printableName(originalName, { text: ' cades  root ' });
    const cmsWithName = (name) => {
      const fields = view.fields.map((node) => node.raw);
      fields[1] = seq(name, signerID.children[1].raw);
      return rewriteCMS(cms, { signers: [seq(...fields)] });
    };
    const cmsValid = cmsWithName(printable);
    const cmsMalformed = cmsWithName(malformed);
    const cmsEquivalent = cmsWithName(caseAndSpace);
    assert.deepEqual(cmsView(cmsValid).fields.slice(3, 6).map((node) => node.raw),
      cmsView(cmsMalformed).fields.slice(3, 6).map((node) => node.raw));
    const validCMS = decision({ verifyCAdES }, f, cmsValid);
    const malformedCMS = decision({ verifyCAdES }, f, cmsMalformed);
    const equivalentCMS = decision({ verifyCAdES }, f, cmsEquivalent);
    assert.deepEqual([validCMS.overall, validCMS.reason], ['VALID', 'CADES_VALID']);
    assert.deepEqual([equivalentCMS.overall, equivalentCMS.reason], ['VALID', 'CADES_VALID']);
    assert.deepEqual([malformedCMS.overall, malformedCMS.reason],
      ['INVALID', 'CADES_SIGNING_CERTIFICATE_BINDING']);

    const leaf = parseDER(f.signer.der);
    const tbs = leaf.children[0];
    const issuerIndex = tbs.children[0].tag === 0xa0 ? 3 : 2;
    const issuer = tbs.children[issuerIndex].raw;
    const leafWithIssuer = (name) => {
      const changedTbs = seq(...tbs.children.map((node, index) =>
        index === issuerIndex ? name : node.raw));
      return seq(changedTbs, leaf.children[1].raw, bit(sign(changedTbs, f.root.privateKey)));
    };
    const directValid = leafWithIssuer(printableName(issuer));
    const directMalformed = leafWithIssuer(printableName(issuer, { highBit: true }));
    const directEquivalent = leafWithIssuer(printableName(issuer, { text: ' cades  root ' }));
    const rootKey = new X509Certificate(f.root.der).publicKey;
    for (const certificate of [directValid, directMalformed, directEquivalent])
      assert.equal(new X509Certificate(certificate).verify(rootKey), true);
    const alternateRoot = f.certificate('CAdES Root');
    assert.equal(new X509Certificate(alternateRoot.der).verify(alternateRoot.publicKey), true);
    const status = f.material().crls[0];
    const material = (certificate, trustedRoots = [f.root.der]) =>
      validateCAdESMaterial({
        certificate,
        certificates: [f.root.der],
        crls: [status],
        purpose: 'SIGNER',
        stateTime: epoch + 40,
        knowledgeTime: epoch + 40,
        policy: f.policy({ trustedRoots }),
      });
    const directValidResult = material(directValid);
    const directMalformedResult = material(directMalformed);
    const directEquivalentResult = material(directEquivalent);
    const ambiguous = material(directValid, [f.root.der, alternateRoot.der]);
    const wrongKey = material(directValid, [alternateRoot.der]);
    assert.deepEqual([directValidResult.overall, directValidResult.reason],
      ['VALID', 'CADES_MATERIAL_VALID']);
    assert.deepEqual([directEquivalentResult.overall, directEquivalentResult.reason],
      ['VALID', 'CADES_MATERIAL_VALID']);
    assert.deepEqual([directMalformedResult.overall, directMalformedResult.reason],
      ['INVALID', 'CADES_ISSUER_NAME_ENCODING']);
    assert.deepEqual([ambiguous.overall, ambiguous.reason],
      ['INDETERMINATE', 'CADES_ROOT_CONFLICT']);
    assert.deepEqual([wrongKey.overall, wrongKey.reason],
      ['INVALID', 'CADES_CERTIFICATE_SIGNATURE']);
  } finally {
    f.close();
  }
});

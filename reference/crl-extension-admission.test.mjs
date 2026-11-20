import assert from 'node:assert/strict';
import test, { after, before } from 'node:test';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { fixture, decision, loadCAdES } from './cades-fixtures.mjs';
import { issueCRL, verifyCRL } from './revocation.mjs';
import { identityCRLValidator } from './identity.mjs';
import { Journal } from './state.mjs';

const freshestOID = '2.5.29.46';
const nonceOID = '1.3.6.1.5.5.7.48.1.2';
const caIssuersOID = '1.3.6.1.5.5.7.48.2';
const ocspOID = '1.3.6.1.5.5.7.48.1';
const uri = c.der(0x86, Buffer.from('https://example.invalid/delta.crl', 'ascii'));
const pointName = c.der(0xa0, c.der(0xa0, uri));
const point = c.seq(pointName);
const freshest = (points, critical = false) =>
  p.extension(freshestOID, c.seq(...points), critical);
const aia = (method) => p.extension('1.3.6.1.5.5.7.1.1',
  c.seq(c.seq(c.oid(method), uri)));
const issuerAltName = (names) => p.extension('2.5.29.18', c.seq(...names));

const api = await loadCAdES();
assert(api, 'CAdES is required for complete direct CRL extension admission');
let cades, cms;
before(() => {
  cades = fixture();
  cms = cades.baseCMS(api);
});
after(() => cades?.close());

function signedCAdESResult(extensions = []) {
  const crl = cades.crl({ extensions });
  const result = decision(api, cades, cms, 'B', {
    policy: cades.policy({ currentMaterial: cades.material(crl) }),
  });
  return { crl, result };
}

for (const [name, extensions, overall, reason] of [
  ['no optional extension', [], 'VALID', 'CADES_VALID'],
  ['noncritical Freshest locator', [freshest([point])], 'VALID', 'CADES_VALID'],
  ['two Freshest locations', [freshest([point, point])], 'VALID', 'CADES_VALID'],
  ['critical Freshest locator', [freshest([point], true)], 'UNSUPPORTED', 'CADES_CRL_EXTENSION_UNSUPPORTED'],
  ['empty Freshest point list', [freshest([])], 'INVALID', 'CADES_CRL_FRESHEST'],
  ['Freshest point without a name', [freshest([c.seq()])], 'INVALID', 'CADES_CRL_FRESHEST'],
  ['Freshest reasons field', [freshest([c.seq(pointName, c.der(0x81, Buffer.from([7, 0x80])))])], 'INVALID', 'CADES_CRL_FRESHEST'],
  ['Freshest cRLIssuer field', [freshest([c.seq(pointName, c.der(0xa2, uri))])], 'INVALID', 'CADES_CRL_FRESHEST'],
  ['delta indicator with Freshest', [freshest([point]), p.extension('2.5.29.27', c.integer(1), true)], 'UNSUPPORTED', 'CADES_CRL_PROFILE_UNSUPPORTED'],
  ['valid caIssuers AIA', [aia(caIssuersOID)], 'VALID', 'CADES_VALID'],
  ['OCSP-only CRL AIA', [aia(ocspOID)], 'INVALID', 'CADES_CRL_AIA'],
  ['empty CRL issuerAltName', [issuerAltName([])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
  ['valid CRL issuerAltName', [issuerAltName([uri])], 'VALID', 'CADES_VALID'],
]) {
  test(`issuer-signed complete direct CRL ${name}`, () => {
    const { crl, result } = signedCAdESResult(extensions);
    const parsed = c.parseDER(crl);
    assert(c.verify(parsed.children[0].raw, parsed.children[2].value.subarray(1),
      cades.root.publicKey), 'CRL signature covers the extension bytes');
    assert.equal(result.overall, overall, `${name}: ${JSON.stringify(result.checks)}`);
    assert.equal(result.reason, reason, `${name}: ${JSON.stringify(result.checks)}`);
    if (overall === 'VALID') assert.equal(result.verifiedLevel, 'B');
  });
}

const at = 1792530000;
function identityFixture() {
  const key = c.generate('ec');
  const issuerName = p.name('Synthetic CRL critical extension issuer');
  const fields = c.parseDER(p.tbsCertificate({
    publicKey: key.publicKey, issuer: issuerName, subject: issuerName,
    serial: 1, signatureAlgorithm: 'ec', ca: true,
    notBefore: at - 3600, notAfter: at + 3600,
  })).children;
  const certificateExtensions = fields.at(-1).children[0].children
    .filter((entry) => c.oidText(entry.children[0]) !== '2.5.29.15')
    .map((entry) => entry.raw);
  const tbs = c.seq(...fields.slice(0, -1).map((field) => field.raw),
    c.der(0xa3, c.seq(...certificateExtensions,
      p.extension('2.5.29.15', c.der(3, Buffer.from([1, 0x02])), true))));
  const issuerCertificate = p.certificateFromTBS(tbs, 'ec', c.sign(tbs, key.privateKey));
  const certificate = p.issueCertificate({
    publicKey: c.generate('ec').publicKey,
    issuer: issuerName, subject: p.name('Synthetic document signer'),
    serial: 2, notBefore: at - 3600, notAfter: at + 1800,
  }, key.privateKey);
  const raw = issueCRL({ issuer: issuerName, privateKey: key.privateKey,
    number: 7, thisUpdate: at - 60, nextUpdate: at + 600 });
  return { key, issuerName, issuerCertificate, certificate, raw };
}
function addSignedCRLExtension(raw, privateKey, extension) {
  const parsed = c.parseDER(raw);
  const fields = parsed.children[0].children;
  const members = fields.at(-1).children[0].children.map((entry) => entry.raw);
  const tbs = c.seq(...fields.slice(0, -1).map((field) => field.raw),
    c.der(0xa0, c.seq(...members, extension)));
  return c.seq(tbs, parsed.children[1].raw, c.bit(c.sign(tbs, privateKey)));
}

test('identity CRL rejects signed unprocessed critical OCSP nonce without advancing watermark', async () => {
  const value = identityFixture();
  const positive = value.raw;
  const negative = addSignedCRLExtension(positive, value.key.privateKey,
    p.extension(nonceOID, c.octet(Buffer.alloc(16, 0xa5)), true));
  const options = { issuer: value.issuerName, publicKey: value.key.publicKey,
    serial: 2, at };
  assert.equal(verifyCRL(positive, options).status, 'GOOD');
  const parsed = c.parseDER(negative);
  assert(c.verify(parsed.children[0].raw, parsed.children[2].value.subarray(1),
    value.key.publicKey), 'negative CRL retains a valid issuer signature');
  assert.equal(verifyCRL(negative, options).reason, 'STATUS_CRITICAL_EXTENSION');
  const journal = new Journal();
  const watermarkID = c.b64u(c.sha512(value.issuerCertificate));
  let current = negative;
  try {
    const admit = identityCRLValidator({
      issuerCertificate: value.issuerCertificate,
      journal,
      fetchCRL: async () => current,
    });
    await assert.rejects(admit({ certificate: value.certificate, at }),
      { code: 'STATUS_CRITICAL_EXTENSION' });
    assert.equal(journal.get('identity-crl-watermark', watermarkID), undefined);
    current = positive;
    assert.equal((await admit({ certificate: value.certificate, at })).status, 'GOOD');
    const accepted = journal.get('identity-crl-watermark', watermarkID);
    assert.deepEqual(accepted.value.digest, c.sha512(positive));
    current = negative;
    await assert.rejects(admit({ certificate: value.certificate, at }),
      { code: 'STATUS_CRITICAL_EXTENSION' });
    assert.deepEqual(journal.get('identity-crl-watermark', watermarkID), accepted);
  } finally {
    journal.close();
  }
});

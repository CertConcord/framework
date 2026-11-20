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
const pointFor = name => c.seq(c.der(0xa0, c.der(0xa0, name)));
const malformedIP = c.der(0x87, Buffer.from([0x7f]));
const validIP = c.der(0x87, Buffer.from([127, 0, 0, 1]));
const malformedDirectory = c.der(0xa4, c.der(0x05, Buffer.alloc(0)));
const validDirectory = c.der(0xa4, p.name('Synthetic CRL locator'));
const relativeURI = c.der(0x86, Buffer.from('delta.crl', 'ascii'));
const malformedDNS = c.der(0x82, Buffer.from('bad!.example', 'ascii'));
const validDNS = c.der(0x82, Buffer.from('issuer.example', 'ascii'));
const malformedMail = c.der(0x81, Buffer.from('issuer.example', 'ascii'));
const validMail = c.der(0x81, Buffer.from('ca@issuer.example', 'ascii'));
const highBitMail = c.der(0x81, Buffer.concat([Buffer.from([0xe3]),
  Buffer.from('a@issuer.example', 'ascii')]));
const hostlessURI = c.der(0x86, Buffer.from('https://', 'ascii'));
const malformedEDI = c.der(0xa5, c.der(0xa1, c.der(0x13, Buffer.from([0xff]))));
const validEDI = c.der(0xa5, c.der(0xa1, c.der(0x13, Buffer.from('Issuer', 'ascii'))));
const malformedUTF8EDI = c.der(0xa5, c.der(0xa1, c.der(0x0c, Buffer.from([0xc0, 0xaf]))));
const validUTF8EDI = c.der(0xa5, c.der(0xa1, c.der(0x0c, Buffer.from('Issuer', 'utf8'))));
const teletexEDI = c.der(0xa5, c.der(0xa1, c.der(0x14, Buffer.from('Issuer', 'ascii'))));
const malformedNamePrintable = c.der(0xa4, c.seq(c.der(0x31,
  c.seq(c.oid('2.5.4.3'), c.der(0x13, Buffer.from([0xff]))))));
const ipv6URI = c.der(0x86, Buffer.from('https://[::1]/delta.crl', 'ascii'));
const hostlessQueryURI = c.der(0x86, Buffer.from('https://?q=1', 'ascii'));
const x400Tag = c.der(0xa3, c.seq());
const numericURI = c.der(0x86, Buffer.from('https://2130706433', 'ascii'));
const dottedIPv4URI = c.der(0x86, Buffer.from('https://127.0.0.1/delta.crl', 'ascii'));
const nameFor = (id, value) => c.der(0xa4,
  c.seq(c.der(0x31, c.seq(c.oid(id), value))));
const cnBoolean = nameFor('2.5.4.3', c.der(0x01, Buffer.from([0xff])));
const unknownBoolean = nameFor('1.2.3.4.5', c.der(0x01, Buffer.from([0xff])));
const businessBoolean = nameFor('2.5.4.15', c.der(0x01, Buffer.from([0xff])));
const countryUTF8 = nameFor('2.5.4.6', c.der(0x0c, Buffer.from('US', 'utf8')));
const countryPrintable = nameFor('2.5.4.6', c.der(0x13, Buffer.from('US', 'ascii')));
const freshest = (points, critical = false) =>
  p.extension(freshestOID, c.seq(...points), critical);
const aia = (method, location = uri) => p.extension('1.3.6.1.5.5.7.1.1',
  c.seq(c.seq(c.oid(method), location)));
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
  ['valid Freshest IP locator', [freshest([pointFor(validIP)])], 'VALID', 'CADES_VALID'],
  ['one-octet Freshest IP locator', [freshest([pointFor(malformedIP)])], 'INVALID', 'CADES_CRL_FRESHEST'],
  ['valid Freshest directoryName locator', [freshest([pointFor(validDirectory)])], 'VALID', 'CADES_VALID'],
  ['NULL Freshest directoryName locator', [freshest([pointFor(malformedDirectory)])], 'INVALID', 'CADES_CRL_FRESHEST'],
  ['hostless Freshest URI locator', [freshest([pointFor(hostlessURI)])], 'INVALID', 'CADES_CRL_FRESHEST'],
  ['numeric original Freshest URI host', [freshest([pointFor(numericURI)])], 'INVALID', 'CADES_CRL_FRESHEST'],
  ['dotted IPv4 Freshest URI host', [freshest([pointFor(dottedIPv4URI)])], 'VALID', 'CADES_VALID'],
  ['CN BOOLEAN Freshest directoryName', [freshest([pointFor(cnBoolean)])], 'INVALID', 'CADES_CRL_FRESHEST'],
  ['valid Freshest EDI partyName', [freshest([pointFor(validEDI)])], 'VALID', 'CADES_VALID'],
  ['invalid Freshest EDI PrintableString', [freshest([pointFor(malformedEDI)])], 'INVALID', 'CADES_CRL_FRESHEST'],
  ['valid Freshest IPv6 URI locator', [freshest([pointFor(ipv6URI)])], 'VALID', 'CADES_VALID'],
  ['invalid Freshest EDI UTF8String', [freshest([pointFor(malformedUTF8EDI)])], 'INVALID', 'CADES_CRL_FRESHEST'],
  ['valid Freshest EDI UTF8String', [freshest([pointFor(validUTF8EDI)])], 'VALID', 'CADES_VALID'],
  ['relative Freshest URI locator', [freshest([pointFor(relativeURI)])], 'INVALID', 'CADES_CRL_FRESHEST'],
  ['critical Freshest locator', [freshest([point], true)], 'UNSUPPORTED', 'CADES_CRL_EXTENSION_UNSUPPORTED'],
  ['empty Freshest point list', [freshest([])], 'INVALID', 'CADES_CRL_FRESHEST'],
  ['Freshest point without a name', [freshest([c.seq()])], 'INVALID', 'CADES_CRL_FRESHEST'],
  ['Freshest reasons field', [freshest([c.seq(pointName, c.der(0x81, Buffer.from([7, 0x80])))])], 'INVALID', 'CADES_CRL_FRESHEST'],
  ['Freshest cRLIssuer field', [freshest([c.seq(pointName, c.der(0xa2, uri))])], 'INVALID', 'CADES_CRL_FRESHEST'],
  ['delta indicator with Freshest', [freshest([point]), p.extension('2.5.29.27', c.integer(1), true)], 'UNSUPPORTED', 'CADES_CRL_PROFILE_UNSUPPORTED'],
  ['valid caIssuers AIA', [aia(caIssuersOID)], 'VALID', 'CADES_VALID'],
  ['valid caIssuers directoryName', [aia(caIssuersOID, validDirectory)], 'VALID', 'CADES_VALID'],
  ['one-octet caIssuers IP', [aia(caIssuersOID, malformedIP)], 'INVALID', 'CADES_CRL_AIA'],
  ['NULL caIssuers directoryName', [aia(caIssuersOID, malformedDirectory)], 'INVALID', 'CADES_CRL_AIA'],
  ['hostless caIssuers URI', [aia(caIssuersOID, hostlessURI)], 'INVALID', 'CADES_CRL_AIA'],
  ['numeric original caIssuers URI host', [aia(caIssuersOID, numericURI)], 'INVALID', 'CADES_CRL_AIA'],
  ['dotted IPv4 caIssuers URI host', [aia(caIssuersOID, dottedIPv4URI)], 'VALID', 'CADES_VALID'],
  ['CN BOOLEAN caIssuers directoryName', [aia(caIssuersOID, cnBoolean)], 'INVALID', 'CADES_CRL_AIA'],
  ['valid caIssuers EDI partyName', [aia(caIssuersOID, validEDI)], 'VALID', 'CADES_VALID'],
  ['invalid caIssuers EDI PrintableString', [aia(caIssuersOID, malformedEDI)], 'INVALID', 'CADES_CRL_AIA'],
  ['malformed caIssuers directoryName PrintableString', [aia(caIssuersOID, malformedNamePrintable)], 'INVALID', 'CADES_CRL_AIA'],
  ['OCSP-only CRL AIA', [aia(ocspOID)], 'INVALID', 'CADES_CRL_AIA'],
  ['empty CRL issuerAltName', [issuerAltName([])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
  ['valid CRL issuerAltName', [issuerAltName([uri])], 'VALID', 'CADES_VALID'],
  ['valid CRL issuerAltName IP', [issuerAltName([validIP])], 'VALID', 'CADES_VALID'],
  ['valid CRL issuerAltName DNS', [issuerAltName([validDNS])], 'VALID', 'CADES_VALID'],
  ['invalid CRL issuerAltName DNS character', [issuerAltName([malformedDNS])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
  ['valid CRL issuerAltName mailbox', [issuerAltName([validMail])], 'VALID', 'CADES_VALID'],
  ['CRL issuerAltName mailbox without at-sign', [issuerAltName([malformedMail])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
  ['CRL issuerAltName mailbox with high-bit IA5 byte', [issuerAltName([highBitMail])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
  ['one-octet CRL issuerAltName IP', [issuerAltName([malformedIP])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
  ['hostless CRL issuerAltName URI', [issuerAltName([hostlessURI])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
  ['numeric original CRL issuerAltName URI host', [issuerAltName([numericURI])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
  ['dotted IPv4 CRL issuerAltName URI host', [issuerAltName([dottedIPv4URI])], 'VALID', 'CADES_VALID'],
  ['CN BOOLEAN CRL issuerAltName directoryName', [issuerAltName([cnBoolean])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
  ['businessCategory BOOLEAN CRL issuerAltName directoryName', [issuerAltName([businessBoolean])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
  ['countryName UTF8 CRL issuerAltName directoryName', [issuerAltName([countryUTF8])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
  ['countryName Printable CRL issuerAltName directoryName', [issuerAltName([countryPrintable])], 'VALID', 'CADES_VALID'],
  ['unknown OID BOOLEAN CRL issuerAltName directoryName', [issuerAltName([unknownBoolean])], 'VALID', 'CADES_VALID'],
  ['valid CRL issuerAltName EDI partyName', [issuerAltName([validEDI])], 'VALID', 'CADES_VALID'],
  ['invalid CRL issuerAltName EDI PrintableString', [issuerAltName([malformedEDI])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
  ['hostless query CRL issuerAltName URI', [issuerAltName([hostlessQueryURI])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
  ['unselected CRL issuerAltName x400Address tag', [issuerAltName([x400Tag])], 'UNSUPPORTED', 'CADES_CRL_GENERAL_NAME_UNSUPPORTED'],
  ['unselected CRL issuerAltName Teletex EDI', [issuerAltName([teletexEDI])], 'UNSUPPORTED', 'CADES_CRL_GENERAL_NAME_UNSUPPORTED'],
  ['NULL CRL issuerAltName directoryName', [issuerAltName([malformedDirectory])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
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

test('identity CRL rejects signed unprocessed critical OCSP nonce in a revoked entry', () => {
  const value = identityFixture();
  const positive = issueCRL({ issuer: value.issuerName, privateKey: value.key.privateKey,
    number: 8, thisUpdate: at - 60, nextUpdate: at + 600,
    entries: [{ serial: 2, revokedAt: at - 30, reason: 1 }] });
  const parsed = c.parseDER(positive);
  const fields = parsed.children[0].children;
  const entries = fields[5].children;
  assert.equal(entries.length, 1);
  const revoked = entries[0].children;
  const extensionMembers = revoked[2].children.map((extension) => extension.raw);
  const modifiedEntry = c.seq(revoked[0].raw, revoked[1].raw,
    c.seq(...extensionMembers, p.extension(nonceOID, c.octet(Buffer.alloc(16, 0xa5)), true)));
  const tbs = c.seq(...fields.slice(0, 5).map((field) => field.raw),
    c.seq(modifiedEntry), ...fields.slice(6).map((field) => field.raw));
  const negative = c.seq(tbs, parsed.children[1].raw,
    c.bit(c.sign(tbs, value.key.privateKey)));
  const options = { issuer: value.issuerName, publicKey: value.key.publicKey,
    serial: 2, at };
  assert.equal(verifyCRL(positive, options).status, 'REVOKED');
  assert(c.verify(tbs, c.parseDER(negative).children[2].value.subarray(1),
    value.key.publicKey), 'negative CRL retains a valid issuer signature');
  const result = verifyCRL(negative, options);
  assert.equal(result.status, 'UNSUPPORTED');
  assert.equal(result.reason, 'STATUS_CRITICAL_EXTENSION');
});

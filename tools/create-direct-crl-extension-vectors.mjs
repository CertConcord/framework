import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import * as c from '../reference/core.mjs';
import * as p from '../reference/pki.mjs';
import { epoch, fixture, loadCAdES } from '../reference/cades-fixtures.mjs';
import { issueCRL } from '../reference/revocation.mjs';

const output = process.argv[2];
assert(output && process.argv.length === 3, 'Provide one new output JSON path');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const artifact = bytes => ({ bytes: bytes.length, sha256: hash(bytes), derBase64: bytes.toString('base64') });
const uri = c.der(0x86, Buffer.from('https://example.invalid/delta.crl', 'ascii'));
const pointName = c.der(0xa0, c.der(0xa0, uri));
const point = c.seq(pointName);
const pointFor = name => c.seq(c.der(0xa0, c.der(0xa0, name)));
const malformedIP = c.der(0x87, Buffer.from([0x7f]));
const validIP = c.der(0x87, Buffer.from([127, 0, 0, 1]));
const malformedDirectory = c.der(0xa4, c.der(0x05, Buffer.alloc(0)));
const validDirectory = c.der(0xa4, p.name('Synthetic frozen CRL locator'));
const relativeURI = c.der(0x86, Buffer.from('delta.crl', 'ascii'));
const malformedDNS = c.der(0x82, Buffer.from('bad!.example', 'ascii'));
const malformedMail = c.der(0x81, Buffer.from('issuer.example', 'ascii'));
const highBitMail = c.der(0x81, Buffer.concat([Buffer.from([0xe3]),
  Buffer.from('a@issuer.example', 'ascii')]));
const hostlessURI = c.der(0x86, Buffer.from('https://', 'ascii'));
const malformedEDI = c.der(0xa5, c.der(0xa1, c.der(0x13, Buffer.from([0xff]))));
const validEDI = c.der(0xa5, c.der(0xa1, c.der(0x13, Buffer.from('Issuer', 'ascii'))));
const numericURI = c.der(0x86, Buffer.from('https://2130706433', 'ascii'));
const dottedIPv4URI = c.der(0x86, Buffer.from('https://127.0.0.1/delta.crl', 'ascii'));
const rawPathBracketURI = c.der(0x86, Buffer.from('https://example.com/[', 'ascii'));
const rawQueryBracketURI = c.der(0x86, Buffer.from('https://example.com/?q=[', 'ascii'));
const repeatedFragmentURI = c.der(0x86, Buffer.from('https://example.com/#a#b', 'ascii'));
const encodedPathBracketURI = c.der(0x86, Buffer.from('https://example.com/%5B', 'ascii'));
const otherNameFor = (id, value) => c.der(0xa0, Buffer.concat([c.oid(id), c.der(0xa0, value)]));
const smtpBoolean = otherNameFor('1.3.6.1.5.5.7.8.9', c.der(0x01, Buffer.from([0xff])));
const smtpEmptyUTF8 = otherNameFor('1.3.6.1.5.5.7.8.9', c.der(0x0c, Buffer.alloc(0)));
const smtpInvalidUTF8 = otherNameFor('1.3.6.1.5.5.7.8.9', c.der(0x0c, Buffer.from([0xc0, 0xaf])));
const smtpValidUTF8 = otherNameFor('1.3.6.1.5.5.7.8.9', c.der(0x0c, Buffer.from('ü@example.com', 'utf8')));
const smtpUnicodeDomain = otherNameFor('1.3.6.1.5.5.7.8.9', c.der(0x0c, Buffer.from('ü@álpha.example', 'utf8')));
const unknownOtherBoolean = otherNameFor('1.2.3.4.6', c.der(0x01, Buffer.from([0xff])));
const smtpReservedLabel = otherNameFor('1.3.6.1.5.5.7.8.9', c.der(0x0c, Buffer.from('ü@ab--cd.example.com', 'utf8')));
const smtpValidALabel = otherNameFor('1.3.6.1.5.5.7.8.9', c.der(0x0c, Buffer.from('ü@xn--bcher-kva.example', 'utf8')));
const smtpEmojiALabel = otherNameFor('1.3.6.1.5.5.7.8.9', c.der(0x0c, Buffer.from('ü@xn--e28h.example', 'utf8')));
const unknownOtherNoncanonicalTrue = otherNameFor('1.2.3.4.6', c.der(0x01, Buffer.from([0x01])));
const unknownOtherNoncanonicalNull = otherNameFor('1.2.3.4.6', c.der(0x05, Buffer.from([0x00])));
const unknownOtherNoncanonicalBit = otherNameFor('1.2.3.4.6', c.der(0x03, Buffer.from([0x01, 0x01])));
const unknownOtherConstructedOctet = otherNameFor('1.2.3.4.6', c.der(0x24, c.der(0x04, Buffer.from([0x01]))));
const unknownOtherCanonicalBit = otherNameFor('1.2.3.4.6', c.der(0x03, Buffer.from([0x01, 0x00])));
const unknownOtherCanonicalFalse = otherNameFor('1.2.3.4.6', c.der(0x01, Buffer.from([0x00])));
const unknownOtherNestedNoncanonicalTrue = otherNameFor('1.2.3.4.6', c.seq(c.der(0x01, Buffer.from([0x01]))));
const unknownOtherNestedCanonical = otherNameFor('1.2.3.4.6', c.seq(c.der(0x01, Buffer.from([0xff])), c.der(0x05, Buffer.alloc(0))));
const unknownOtherNoncanonicalEnum = otherNameFor('1.2.3.4.6', c.der(0x0a, Buffer.from([0x00, 0x01])));
const unknownOtherInvalidUTF8 = otherNameFor('1.2.3.4.6', c.der(0x0c, Buffer.from([0xc0, 0xaf])));
const unknownOtherNonminimalOID = otherNameFor('1.2.3.4.6', c.der(0x06, Buffer.from([0x2a, 0x80, 0x03])));
const unknownOtherPrivateValueTag = otherNameFor('1.2.3.4.6', c.der(0xc1, Buffer.from([0x00])));
const nameFor = (id, value) => c.der(0xa4,
  c.seq(c.der(0x31, c.seq(c.oid(id), value))));
const cnBoolean = nameFor('2.5.4.3', c.der(0x01, Buffer.from([0xff])));
const unknownBoolean = nameFor('1.2.3.4.5', c.der(0x01, Buffer.from([0xff])));
const descriptionBoolean = nameFor('2.5.4.13', c.der(0x01, Buffer.from([0xff])));
const descriptionUTF8 = nameFor('2.5.4.13', c.der(0x0c, Buffer.from('CRL locator', 'utf8')));
const destinationNumeric = nameFor('2.5.4.27', c.der(0x13, Buffer.from('1', 'ascii')));
const destinationAlphabetic = nameFor('2.5.4.27', c.der(0x13, Buffer.from('AASD', 'ascii')));
const telephoneBoolean = nameFor('2.5.4.20', c.der(0x01, Buffer.from([0xff])));
const telephonePrintable = nameFor('2.5.4.20', c.der(0x13, Buffer.from('+1 234 567 8901', 'ascii')));
const destinationBoolean = nameFor('2.5.4.27', c.der(0x01, Buffer.from([0xff])));
const houseBoolean = nameFor('2.5.4.51', c.der(0x01, Buffer.from([0xff])));
const memberBoolean = nameFor('2.5.4.31', c.der(0x01, Buffer.from([0xff])));
const cnRelative = c.seq(c.oid('2.5.4.3'), c.der(0x0c, Buffer.from('A', 'utf8')));
const ouRelative = c.seq(c.oid('2.5.4.11'), c.der(0x0c, Buffer.from('B', 'utf8')));
const relativePoint = values => c.seq(c.der(0xa0, c.der(0xa1, Buffer.concat(values))));
const orderedRelativePoint = relativePoint([cnRelative, ouRelative]);
const reversedRelativePoint = relativePoint([ouRelative, cnRelative]);
const freshest = (points, critical = false) =>
  p.extension('2.5.29.46', c.seq(...points), critical);
const aia = (method, location = uri) => p.extension('1.3.6.1.5.5.7.1.1',
  c.seq(c.seq(c.oid(method), location)));
const ian = names => p.extension('2.5.29.18', c.seq(...names));

const api = await loadCAdES();
assert(api, 'CAdES fixture producer required');
const f = fixture();
let document;
try {
  const cms = f.baseCMS(api);
  const cases = [];
  for (const [id, extensions, overall, reason] of [
    ['baseline', [], 'VALID', 'CADES_VALID'],
    ['freshest', [freshest([point])], 'VALID', 'CADES_VALID'],
    ['freshestTwoLocations', [freshest([point, point])], 'VALID', 'CADES_VALID'],
    ['freshestValidIP', [freshest([pointFor(validIP)])], 'VALID', 'CADES_VALID'],
    ['freshestMalformedIP', [freshest([pointFor(malformedIP)])], 'INVALID', 'CADES_CRL_FRESHEST'],
    ['freshestValidDirectory', [freshest([pointFor(validDirectory)])], 'VALID', 'CADES_VALID'],
    ['freshestMalformedDirectory', [freshest([pointFor(malformedDirectory)])], 'INVALID', 'CADES_CRL_FRESHEST'],
    ['freshestHostlessURI', [freshest([pointFor(hostlessURI)])], 'INVALID', 'CADES_CRL_FRESHEST'],
    ['freshestNumericURI', [freshest([pointFor(numericURI)])], 'INVALID', 'CADES_CRL_FRESHEST'],
    ['freshestDottedIPv4URI', [freshest([pointFor(dottedIPv4URI)])], 'VALID', 'CADES_VALID'],
    ['freshestRawPathBracket', [freshest([pointFor(rawPathBracketURI)])], 'INVALID', 'CADES_CRL_FRESHEST'],
    ['freshestRepeatedFragment', [freshest([pointFor(repeatedFragmentURI)])], 'INVALID', 'CADES_CRL_FRESHEST'],
    ['freshestEncodedPathBracket', [freshest([pointFor(encodedPathBracketURI)])], 'VALID', 'CADES_VALID'],
    ['freshestSMTPBoolean', [freshest([pointFor(smtpBoolean)])], 'INVALID', 'CADES_CRL_FRESHEST'],
    ['freshestSMTPMailbox', [freshest([pointFor(smtpValidUTF8)])], 'VALID', 'CADES_VALID'],
    ['freshestCNBoolean', [freshest([pointFor(cnBoolean)])], 'INVALID', 'CADES_CRL_FRESHEST'],
    ['freshestDescriptionBoolean', [freshest([pointFor(descriptionBoolean)])], 'INVALID', 'CADES_CRL_FRESHEST'],
    ['freshestTelephoneBoolean', [freshest([pointFor(telephoneBoolean)])], 'INVALID', 'CADES_CRL_FRESHEST'],
    ['freshestOrderedRelativeRDN', [freshest([orderedRelativePoint])], 'VALID', 'CADES_VALID'],
    ['freshestReverseRelativeRDN', [freshest([reversedRelativePoint])], 'INVALID', 'CADES_CRL_FRESHEST'],
    ['freshestValidEDI', [freshest([pointFor(validEDI)])], 'VALID', 'CADES_VALID'],
    ['freshestMalformedEDI', [freshest([pointFor(malformedEDI)])], 'INVALID', 'CADES_CRL_FRESHEST'],
    ['freshestRelativeURI', [freshest([pointFor(relativeURI)])], 'INVALID', 'CADES_CRL_FRESHEST'],
    ['freshestCritical', [freshest([point], true)], 'UNSUPPORTED', 'CADES_CRL_EXTENSION_UNSUPPORTED'],
    ['freshestEmpty', [freshest([])], 'INVALID', 'CADES_CRL_FRESHEST'],
    ['freshestReasons', [freshest([c.seq(pointName, c.der(0x81, Buffer.from([7, 0x80])))])],
      'INVALID', 'CADES_CRL_FRESHEST'],
    ['freshestCRLIssuer', [freshest([c.seq(pointName, c.der(0xa2, uri))])],
      'INVALID', 'CADES_CRL_FRESHEST'],
    ['freshestWithDelta', [freshest([point]), p.extension('2.5.29.27', c.integer(1), true)],
      'UNSUPPORTED', 'CADES_CRL_PROFILE_UNSUPPORTED'],
    ['aiaCaIssuers', [aia('1.3.6.1.5.5.7.48.2')], 'VALID', 'CADES_VALID'],
    ['aiaValidDirectory', [aia('1.3.6.1.5.5.7.48.2', validDirectory)], 'VALID', 'CADES_VALID'],
    ['aiaMalformedIP', [aia('1.3.6.1.5.5.7.48.2', malformedIP)], 'INVALID', 'CADES_CRL_AIA'],
    ['aiaMalformedDirectory', [aia('1.3.6.1.5.5.7.48.2', malformedDirectory)], 'INVALID', 'CADES_CRL_AIA'],
    ['aiaHostlessURI', [aia('1.3.6.1.5.5.7.48.2', hostlessURI)], 'INVALID', 'CADES_CRL_AIA'],
    ['aiaNumericURI', [aia('1.3.6.1.5.5.7.48.2', numericURI)], 'INVALID', 'CADES_CRL_AIA'],
    ['aiaDottedIPv4URI', [aia('1.3.6.1.5.5.7.48.2', dottedIPv4URI)], 'VALID', 'CADES_VALID'],
    ['aiaRawPathBracket', [aia('1.3.6.1.5.5.7.48.2', rawPathBracketURI)], 'INVALID', 'CADES_CRL_AIA'],
    ['aiaRepeatedFragment', [aia('1.3.6.1.5.5.7.48.2', repeatedFragmentURI)], 'INVALID', 'CADES_CRL_AIA'],
    ['aiaSMTPBoolean', [aia('1.3.6.1.5.5.7.48.2', smtpBoolean)], 'INVALID', 'CADES_CRL_AIA'],
    ['aiaSMTPMailbox', [aia('1.3.6.1.5.5.7.48.2', smtpValidUTF8)], 'VALID', 'CADES_VALID'],
    ['aiaCNBoolean', [aia('1.3.6.1.5.5.7.48.2', cnBoolean)], 'INVALID', 'CADES_CRL_AIA'],
    ['aiaDescriptionBoolean', [aia('1.3.6.1.5.5.7.48.2', descriptionBoolean)], 'INVALID', 'CADES_CRL_AIA'],
    ['aiaTelephoneBoolean', [aia('1.3.6.1.5.5.7.48.2', telephoneBoolean)], 'INVALID', 'CADES_CRL_AIA'],
    ['aiaValidEDI', [aia('1.3.6.1.5.5.7.48.2', validEDI)], 'VALID', 'CADES_VALID'],
    ['aiaMalformedEDI', [aia('1.3.6.1.5.5.7.48.2', malformedEDI)], 'INVALID', 'CADES_CRL_AIA'],
    ['aiaOCSPOnly', [aia('1.3.6.1.5.5.7.48.1')], 'INVALID', 'CADES_CRL_AIA'],
    ['issuerAltName', [ian([uri])], 'VALID', 'CADES_VALID'],
    ['issuerAltNameValidIP', [ian([validIP])], 'VALID', 'CADES_VALID'],
    ['issuerAltNameMalformedIP', [ian([malformedIP])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
    ['issuerAltNameMalformedDirectory', [ian([malformedDirectory])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
    ['issuerAltNameMalformedDNS', [ian([malformedDNS])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
    ['issuerAltNameMalformedMail', [ian([malformedMail])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
    ['issuerAltNameHighBitMail', [ian([highBitMail])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
    ['issuerAltNameHostlessURI', [ian([hostlessURI])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
    ['issuerAltNameNumericURI', [ian([numericURI])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
    ['issuerAltNameDottedIPv4URI', [ian([dottedIPv4URI])], 'VALID', 'CADES_VALID'],
    ['issuerAltNameRawQueryBracket', [ian([rawQueryBracketURI])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
    ['issuerAltNameRepeatedFragment', [ian([repeatedFragmentURI])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
    ['issuerAltNameSMTPBoolean', [ian([smtpBoolean])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
    ['issuerAltNameSMTPEmpty', [ian([smtpEmptyUTF8])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
    ['issuerAltNameSMTPInvalidUTF8', [ian([smtpInvalidUTF8])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
    ['issuerAltNameSMTPMailbox', [ian([smtpValidUTF8])], 'VALID', 'CADES_VALID'],
    ['issuerAltNameSMTPUnicodeDomain', [ian([smtpUnicodeDomain])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
    ['issuerAltNameUnknownOtherBoolean', [ian([unknownOtherBoolean])], 'VALID', 'CADES_VALID'],
    ['issuerAltNameSMTPReservedLabel', [ian([smtpReservedLabel])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
    ['issuerAltNameSMTPValidALabel', [ian([smtpValidALabel])], 'VALID', 'CADES_VALID'],
    ['issuerAltNameSMTPEmojiALabel', [ian([smtpEmojiALabel])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
    ['issuerAltNameUnknownOtherNoncanonicalTrue', [ian([unknownOtherNoncanonicalTrue])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
    ['issuerAltNameUnknownOtherNoncanonicalNull', [ian([unknownOtherNoncanonicalNull])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
    ['issuerAltNameUnknownOtherNoncanonicalBit', [ian([unknownOtherNoncanonicalBit])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
    ['issuerAltNameUnknownOtherConstructedOctet', [ian([unknownOtherConstructedOctet])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
    ['issuerAltNameUnknownOtherCanonicalBit', [ian([unknownOtherCanonicalBit])], 'VALID', 'CADES_VALID'],
    ['issuerAltNameUnknownOtherCanonicalFalse', [ian([unknownOtherCanonicalFalse])], 'VALID', 'CADES_VALID'],
    ['issuerAltNameUnknownOtherNestedNoncanonicalTrue', [ian([unknownOtherNestedNoncanonicalTrue])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
    ['issuerAltNameUnknownOtherNestedCanonical', [ian([unknownOtherNestedCanonical])], 'VALID', 'CADES_VALID'],
    ['issuerAltNameUnknownOtherNoncanonicalEnum', [ian([unknownOtherNoncanonicalEnum])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
    ['issuerAltNameUnknownOtherInvalidUTF8', [ian([unknownOtherInvalidUTF8])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
    ['issuerAltNameUnknownOtherNonminimalOID', [ian([unknownOtherNonminimalOID])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
    ['issuerAltNameUnknownOtherPrivateValueTag', [ian([unknownOtherPrivateValueTag])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
    ['freshestSMTPReservedLabel', [freshest([pointFor(smtpReservedLabel)])], 'INVALID', 'CADES_CRL_FRESHEST'],
    ['freshestSMTPValidALabel', [freshest([pointFor(smtpValidALabel)])], 'VALID', 'CADES_VALID'],
    ['aiaUnknownOtherNoncanonicalTrue', [aia('1.3.6.1.5.5.7.48.2', unknownOtherNoncanonicalTrue)], 'INVALID', 'CADES_CRL_AIA'],
    ['issuerAltNameCNBoolean', [ian([cnBoolean])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
    ['issuerAltNameDescriptionBoolean', [ian([descriptionBoolean])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
    ['issuerAltNameTelephoneBoolean', [ian([telephoneBoolean])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
    ['issuerAltNameDestinationBoolean', [ian([destinationBoolean])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
    ['issuerAltNameDestinationNumeric', [ian([destinationNumeric])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
    ['issuerAltNameDestinationAlphabetic', [ian([destinationAlphabetic])], 'VALID', 'CADES_VALID'],
    ['issuerAltNameHouseBoolean', [ian([houseBoolean])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
    ['issuerAltNameMemberBoolean', [ian([memberBoolean])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
    ['issuerAltNameDescriptionUTF8', [ian([descriptionUTF8])], 'VALID', 'CADES_VALID'],
    ['issuerAltNameTelephonePrintable', [ian([telephonePrintable])], 'VALID', 'CADES_VALID'],
    ['issuerAltNameUnknownBoolean', [ian([unknownBoolean])], 'VALID', 'CADES_VALID'],
    ['issuerAltNameValidEDI', [ian([validEDI])], 'VALID', 'CADES_VALID'],
    ['issuerAltNameMalformedEDI', [ian([malformedEDI])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
    ['issuerAltNameEmpty', [ian([])], 'INVALID', 'CADES_CRL_ISSUER_ALT_NAME'],
  ])
    cases.push({ id, crl: artifact(f.crl({ extensions })), expected: { overall, reason } });
  document = {
    at: epoch + 40,
    root: artifact(f.root.der),
    signer: artifact(f.signer.der),
    content: artifact(f.content),
    cms: artifact(cms),
    cases,
  };
} finally {
  f.close();
}

const at = 1792530000;
const key = c.generate('ec');
const issuerName = p.name('Synthetic frozen CRL critical issuer');
const fields = c.parseDER(p.tbsCertificate({
  publicKey: key.publicKey, issuer: issuerName, subject: issuerName,
  serial: 1, signatureAlgorithm: 'ec', ca: true,
  notBefore: at - 3600, notAfter: at + 3600,
})).children;
const certificateExtensions = fields.at(-1).children[0].children
  .filter(entry => c.oidText(entry.children[0]) !== '2.5.29.15')
  .map(entry => entry.raw);
const tbs = c.seq(...fields.slice(0, -1).map(field => field.raw),
  c.der(0xa3, c.seq(...certificateExtensions,
    p.extension('2.5.29.15', c.der(3, Buffer.from([1, 0x02])), true))));
const issuerCertificate = p.certificateFromTBS(tbs, 'ec', c.sign(tbs, key.privateKey));
const certificate = p.issueCertificate({
  publicKey: c.generate('ec').publicKey,
  issuer: issuerName, subject: p.name('Synthetic frozen document signer'),
  serial: 2, notBefore: at - 3600, notAfter: at + 1800,
}, key.privateKey);
const positive = issueCRL({ issuer: issuerName, privateKey: key.privateKey,
  number: 7, thisUpdate: at - 60, nextUpdate: at + 600 });
const parsed = c.parseDER(positive);
const crlFields = parsed.children[0].children;
const members = crlFields.at(-1).children[0].children.map(entry => entry.raw);
const negativeTBS = c.seq(...crlFields.slice(0, -1).map(field => field.raw),
  c.der(0xa0, c.seq(...members,
    p.extension('1.3.6.1.5.5.7.48.1.2', c.octet(Buffer.alloc(16, 0xa5)), true))));
const criticalNonce = c.seq(negativeTBS, parsed.children[1].raw,
  c.bit(c.sign(negativeTBS, key.privateKey)));
const identity = {
  at, serial: '2',
  issuerCertificate: artifact(issuerCertificate),
  certificate: artifact(certificate),
  positiveCRL: artifact(positive),
  criticalNonceCRL: artifact(criticalNonce),
  expected: { positive: 'GOOD', criticalNonce: 'STATUS_CRITICAL_EXTENSION' },
};

const vectors = {
  schema: 'certconcord.direct-crl-extension-admission.v1',
  baseMain: '723af0d3aa8912e6c2eb14e05ec53e12f61123d3',
  document, identity,
  limitations: 'Synthetic keys, fixed-time CAdES B and identity CRL adapter. URI is a locator and is never fetched. No delta merge, production trust, LT/LTA or VeriCommons lock claim.',
};
writeFileSync(output, JSON.stringify(vectors, null, 2) + '\n', { flag: 'wx' });
console.log(JSON.stringify({ output, sha256: hash(Buffer.from(JSON.stringify(vectors, null, 2) + '\n')),
  documentCases: document.cases.length, identityCases: 2 }));

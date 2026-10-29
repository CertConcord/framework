// Synthetic public fixtures. Keys exist only while generating this corpus.
import { writeFileSync } from 'node:fs';
import { createHash, verify } from 'node:crypto';
import * as c from '../reference/core.mjs';
import * as p from '../reference/pki.mjs';
import { cmsView, rewriteCMS } from '../reference/cades-fixtures.mjs';

const epoch = 1769990400,
  root = c.generate('ml-dsa-65'),
  signer = c.generate('ml-dsa-65'),
  otherRoot = c.generate('ml-dsa-65'),
  issuer = p.name('Synthetic timestamp name root'),
  subject = p.name('Synthetic timestamp name signer'),
  alias = p.name('Synthetic timestamp directory alias'),
  wrong = p.name('Synthetic other timestamp signer'),
  policy = '2.25.31615816',
  imprint = c.sha512(Buffer.from('Synthetic timestamp name contract input')),
  directory = (name) => c.der(0xa4, name),
  hint = (...names) => c.der(0xa0, Buffer.concat(names)),
  certificate = (serial, extraExtensions = [], profileID = 'CERTCONCORD-TSA-v1') =>
    p.issueCertificate(
      {
        publicKey: signer.publicKey,
        issuer,
        subject,
        serial,
        notBefore: epoch - 60,
        notAfter: epoch + 3600,
        profileID,
        extraExtensions,
      },
      root.privateKey,
    ),
  certificates = {
    subject: certificate(1),
    san: certificate(2, [
      p.extension('2.5.29.17', c.seq(c.der(0x82, Buffer.from('tsa.example')), directory(alias))),
    ]),
    wrongEKU: certificate(3, [], 'CERTCONCORD-EVIDENCE-SIGN-v1'),
    sanInvalidTag: certificate(4, [
      p.extension('2.5.29.17', c.seq(c.integer(1), directory(alias))),
    ]),
    sanPrimitiveDirectory: certificate(5, [
      p.extension('2.5.29.17', c.seq(c.der(0x84, alias), directory(alias))),
    ]),
  },
  info = (...optional) =>
    c.seq(
      c.integer(1),
      c.oid(policy),
      c.seq(p.algID(p.OID.sha512), c.octet(imprint)),
      c.integer(1001),
      p.generalizedTime(epoch),
      c.seq(c.integer(1)),
      c.integer(42),
      ...optional,
    ),
  encode = (content, cert = certificates.subject) =>
    p.signCMS({ content, contentType: p.OID.tstInfo, certificate: cert }, signer.privateKey),
  cases = [],
  sha256 = (raw) => createHash('sha256').update(raw).digest('hex');

function add(id, optional, expected, cert = 'subject', overrides = {}) {
  const raw = overrides.raw ?? encode(info(...optional), certificates[cert]),
    view = cmsView(raw),
    tbs = c.der(0x31, view.fields[3].value);
  cases.push({
    id,
    certificate: cert,
    raw: raw.toString('base64'),
    sha256: sha256(raw),
    tstInfo: view.embeddedContent.toString('base64'),
    signedAttributes: tbs.toString('base64'),
    signature: view.signature.toString('base64'),
    signatureValid: verify(null, tbs, signer.publicKey, view.signature),
    expected,
    ...(overrides.query && { query: overrides.query }),
  });
}
const valid = { overall: 'VALID' },
  invalid = (code) => ({ overall: 'INVALID', code }),
  unsupported = { overall: 'UNSUPPORTED', code: 'TSA_NAME_UNSUPPORTED' };
add('absent-name', [], valid);
add('subject-directory-name', [hint(directory(subject))], valid);
add('san-directory-name', [hint(directory(alias))], valid, 'san');
add('subject-with-mixed-san', [hint(directory(subject))], valid, 'san');
add('different-directory-name', [hint(directory(wrong))], invalid('TSA_NAME_BINDING'));
add('issuer-name-is-not-subject', [hint(directory(issuer))], invalid('TSA_NAME_BINDING'));
add(
  'directory-name-only-in-another-certificate',
  [],
  {
    'CERTCONCORD-PQ': invalid('CMS_SIGNERS'),
    'EXTERNAL-RFC3161': invalid('TSA_NAME_BINDING'),
  },
  'subject',
  {
    raw: rewriteCMS(encode(info(hint(directory(alias)))), {
      certificates: [certificates.subject, certificates.san],
    }),
  },
);
add(
  'mismatching-directory-name-with-san',
  [hint(directory(wrong))],
  invalid('TSA_NAME_BINDING'),
  'san',
);
add(
  'matching-subject-with-invalid-san-tag',
  [hint(directory(subject))],
  invalid('TSA_CERTIFICATE_NAME_ENCODING'),
  'sanInvalidTag',
);
add(
  'matching-san-with-primitive-directory-tag',
  [hint(directory(alias))],
  invalid('TSA_CERTIFICATE_NAME_ENCODING'),
  'sanPrimitiveDirectory',
);
for (const [id, value] of [
  ['dns-name-even-if-in-san', c.der(0x82, Buffer.from('tsa.example'))],
  ['rfc822-name', c.der(0x81, Buffer.from('tsa@example.test'))],
  ['uri-name', c.der(0x86, Buffer.from('https://tsa.example/'))],
  ['ip-address', c.der(0x87, Buffer.from([192, 0, 2, 1]))],
  ['registered-id', c.der(0x88, c.parseDER(c.oid('1.2.3.4')).value)],
  [
    'other-name',
    c.der(0xa0, Buffer.concat([c.oid('1.2.3.4'), c.der(0xa0, c.der(12, Buffer.from('test')))])),
  ],
  ['edi-party-name', c.der(0xa5, c.der(0xa1, c.der(12, Buffer.from('test'))))],
  ['x400-address', c.der(0xa3, c.seq())],
])
  add(id, [hint(value)], unsupported, 'san');
for (const [id, value] of [
  ['empty-tsa-wrapper', hint()],
  ['multiple-general-names', hint(directory(subject), directory(wrong))],
  ['directory-without-name', hint(c.der(0xa4, Buffer.alloc(0)))],
  ['directory-with-two-names', hint(c.der(0xa4, Buffer.concat([subject, wrong])))],
  ['directory-with-octet-string', hint(c.der(0xa4, c.octet(subject)))],
  ['empty-directory-name', hint(directory(c.seq()))],
  ['directory-rdn-not-a-set', hint(directory(c.seq(c.integer(1))))],
  ['directory-empty-rdn', hint(directory(c.seq(c.set())))],
  ['directory-attribute-without-value', hint(directory(c.seq(c.set(c.seq(c.oid('2.5.4.3'))))))],
  ['unknown-general-name-tag', hint(c.der(0x89, Buffer.from('test')))],
])
  add(id, [value], invalid('TSA_NAME_ENCODING'));
add(
  'duplicate-tsa-field',
  [hint(directory(subject)), hint(directory(subject))],
  invalid('TST_DUPLICATE_FIELD'),
);
const matching = encode(info(hint(directory(subject)))),
  view = cmsView(matching);
const changedContent = Buffer.from(view.embeddedContent);
changedContent[changedContent.length - 1] ^= 1;
const contentTamper = c.seq(
  view.root.children[0].raw,
  c.der(
    0xa0,
    c.seq(
      ...view.sd.children.map((node, index) =>
        index === 2 ? c.seq(view.contentType.raw, c.der(0xa0, c.octet(changedContent))) : node.raw,
      ),
    ),
  ),
);
add('content-tamper', [], invalid('CMS_CONTENT_DIGEST'), 'subject', { raw: contentTamper });
const changedSignature = Buffer.from(view.signature);
changedSignature[changedSignature.length - 1] ^= 1;
add('signature-tamper', [], invalid('CMS_SIGNATURE'), 'subject', {
  raw: rewriteCMS(matching, { signature: changedSignature }),
});
const attrs = c.set(
  ...view.fields[3].children.map((attribute) =>
    c.oidText(attribute.children[0]) === p.OID.ess
      ? p.attribute(
          p.OID.ess,
          c.seq(c.seq(c.seq(p.algID(p.OID.sha512), c.octet(c.sha512(certificates.san))))),
        )
      : attribute.raw,
  ),
);
add(
  'ess-other-certificate',
  [],
  {
    'CERTCONCORD-PQ': invalid('ESS_CERTIFICATE_BINDING'),
    'EXTERNAL-RFC3161': invalid('CMS_ESS_CERTIFICATE'),
  },
  'subject',
  {
    raw: rewriteCMS(matching, {
      signed: c.parseDER(attrs).children.map((node) => node.raw),
      signature: c.sign(attrs, signer.privateKey),
    }),
  },
);
add(
  'matching-name-wrong-eku',
  [hint(directory(subject))],
  {
    'CERTCONCORD-PQ': invalid('CERTIFICATE_EKU'),
    'EXTERNAL-RFC3161': invalid('TSA_TRUST_OR_EKU'),
  },
  'wrongEKU',
);
add(
  'matching-name-wrong-root',
  [hint(directory(subject))],
  {
    'CERTCONCORD-PQ': invalid('CERTIFICATE_SIGNATURE'),
    'EXTERNAL-RFC3161': invalid('TSA_TRUST_OR_EKU'),
  },
  'subject',
  { query: { issuer: 'other' } },
);

const mandatory = c
    .parseDER(info())
    .children.slice(0, 5)
    .map((node) => node.raw),
  optional = [
    c.seq(c.integer(1)),
    c.der(1, Buffer.from([255])),
    c.integer(42),
    hint(directory(subject)),
  ],
  ordered = encode(c.seq(...mandatory, ...optional));
add('ordered-optional-fields', [], valid, 'subject', { raw: ordered });
for (const [id, order] of [
  ['nonce-before-accuracy', [2, 0, 1, 3]],
  ['ordering-before-accuracy', [1, 0, 2, 3]],
  ['tsa-before-nonce', [0, 1, 3, 2]],
  ['nonce-before-ordering', [0, 2, 1, 3]],
  ['tsa-before-accuracy', [3, 0, 1, 2]],
])
  add(id, [], invalid('TST_FIELD_ORDER'), 'subject', {
    raw: encode(c.seq(...mandatory, ...order.map((index) => optional[index]))),
  });
const orderedView = cmsView(ordered),
  changedOrderedContent = Buffer.from(orderedView.embeddedContent);
changedOrderedContent[changedOrderedContent.length - 1] ^= 1;
add('ordered-content-tamper', [], invalid('CMS_CONTENT_DIGEST'), 'subject', {
  raw: c.seq(
    orderedView.root.children[0].raw,
    c.der(
      0xa0,
      c.seq(
        ...orderedView.sd.children.map((node, index) =>
          index === 2
            ? c.seq(orderedView.contentType.raw, c.der(0xa0, c.octet(changedOrderedContent)))
            : node.raw,
        ),
      ),
    ),
  ),
});
const changedOrderedSignature = Buffer.from(orderedView.signature);
changedOrderedSignature[changedOrderedSignature.length - 1] ^= 1;
add('ordered-signature-tamper', [], invalid('CMS_SIGNATURE'), 'subject', {
  raw: rewriteCMS(ordered, { signature: changedOrderedSignature }),
});

writeFileSync(
  new URL('../reference/vectors/timestamp-name-contract.json', import.meta.url),
  JSON.stringify(
    {
      schemaVersion: 1,
      profile: 'rfc3161-tstinfo-admission',
      description:
        'Fresh synthetic signed tokens for optional TSTInfo field order and TSA GeneralName binding. Exact directoryName DER is matched only to the CMS-selected signer subject or directoryName SAN. Other name forms are unselected. No private keys, authority history or deployment qualification are included.',
      query: {
        at: epoch + 2,
        nonce: '42',
        policy,
        hashOID: p.OID.sha512,
        imprint: imprint.toString('base64'),
      },
      roots: {
        issuer: c.spki(root.publicKey).toString('base64'),
        other: c.spki(otherRoot.publicKey).toString('base64'),
      },
      certificates: Object.fromEntries(
        Object.entries(certificates).map(([id, raw]) => [
          id,
          { raw: raw.toString('base64'), sha256: sha256(raw) },
        ]),
      ),
      cases,
    },
    null,
    2,
  ) + '\n',
);
console.log('Timestamp name contract: ' + cases.length + ' raw vectors');

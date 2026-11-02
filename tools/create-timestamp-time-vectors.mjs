// Synthetic signed bytes; private keys are never serialized.
import { writeFileSync } from 'node:fs';
import { createHash, verify } from 'node:crypto';
import * as c from '../reference/core.mjs';
import * as p from '../reference/pki.mjs';
import { cmsView, rewriteCMS } from '../reference/cades-fixtures.mjs';

const epoch = 1793275200,
  root = c.generate('ml-dsa-65'),
  other = c.generate('ml-dsa-65'),
  signer = c.generate('ml-dsa-65'),
  policy = '2.25.316120261102',
  imprint = c.sha512(Buffer.from('Synthetic RFC3161 time interval input')),
  hash = (raw) => createHash('sha256').update(raw).digest('hex'),
  certificates = Object.fromEntries(
    ['tsa', 'wrongEKU'].map((id, index) => [
      id,
      p.issueCertificate(
        {
          publicKey: signer.publicKey,
          issuer: p.name('Synthetic time boundary root'),
          subject: p.name('Synthetic time boundary TSA'),
          serial: index + 1,
          notBefore: epoch - 100,
          notAfter: epoch + 100,
          profileID: index ? 'CERTCONCORD-EVIDENCE-SIGN-v1' : 'CERTCONCORD-TSA-v1',
        },
        root.privateKey,
      ),
    ]),
  ),
  valid = { overall: 'VALID' },
  invalid = (code) => ({ overall: 'INVALID', code }),
  unsupported = { overall: 'UNSUPPORTED', code: 'TST_TIME_PRECISION_UNSUPPORTED' },
  unknown = { overall: 'INDETERMINATE', code: 'TSA_ACCURACY_REQUIRED' },
  accuracy = (seconds = 0, millis = 0, micros = 0) =>
    c.seq(
      c.integer(seconds),
      ...(millis ? [c.der(0x80, c.parseDER(c.integer(millis)).value)] : []),
      ...(micros ? [c.der(0x81, c.parseDER(c.integer(micros)).value)] : []),
    ),
  cases = [];

function add(id, time, accuracyDER, expected = valid, options = {}) {
  const certificate = options.certificate ?? 'tsa',
    info = c.seq(
      c.integer(1),
      c.oid(policy),
      c.seq(p.algID(p.OID.sha512), c.octet(imprint)),
      c.integer(1001),
      c.der(24, Buffer.from(time)),
      ...(accuracyDER ? [accuracyDER] : []),
    ),
    raw =
      options.raw ??
      p.signCMS(
        { content: info, contentType: p.OID.tstInfo, certificate: certificates[certificate] },
        signer.privateKey,
      ),
    view = cmsView(raw),
    attrs = c.der(0x31, view.fields[3].value);
  cases.push({
    id,
    certificate,
    time,
    raw: raw.toString('base64'),
    sha256: hash(raw),
    tstInfo: view.embeddedContent.toString('base64'),
    signedAttributes: attrs.toString('base64'),
    signature: view.signature.toString('base64'),
    signatureValid: verify(null, attrs, signer.publicKey, view.signature),
    expected,
    queries: options.queries ?? [],
    ...(options.units && { units: options.units }),
  });
  return raw;
}
for (const [id, fraction, micros] of [
  ['whole', '', 0],
  ['tenth', '.1', 100000],
  ['hundredth', '.12', 120000],
  ['millisecond', '.123', 123000],
  ['binary-fraction', '.125', 125000],
])
  add(id, `20261029120000${fraction}Z`, accuracy(), valid, {
    units: { timeMicros: String(BigInt(epoch) * 1000000n + BigInt(micros)), accuracyMicros: '0' },
  });
add('empty-accuracy', '20261029120000Z', c.seq(), valid, {
  units: { timeMicros: '1793275200000000', accuracyMicros: '0' },
});
add('compound-accuracy', '20261029120000.123Z', accuracy(1, 2, 3), valid, {
  units: { timeMicros: '1793275200123000', accuracyMicros: '1002003' },
});
add('microsecond-accuracy', '20261029120000.001Z', accuracy(0, 0, 1), valid, {
  units: { timeMicros: '1793275200001000', accuracyMicros: '1' },
  queries: [
    { id: 'before-upper', revokedAt: epoch + 0.001, expected: invalid('TSA_TIME_OR_REVOCATION') },
    { id: 'after-upper', revokedAt: epoch + 0.002, expected: valid },
  ],
});
add('rounded-equal-millisecond', '20261029120000.001Z', accuracy(0, 1), valid, {
  units: { timeMicros: '1793275200001000', accuracyMicros: '1000' },
  queries: [
    { id: 'inside', revokedAt: epoch + 0.0015, expected: invalid('TSA_TIME_OR_REVOCATION') },
    { id: 'equal', revokedAt: epoch + 0.002, expected: invalid('TSA_TIME_OR_REVOCATION') },
    { id: 'after', revokedAt: epoch + 0.003, expected: valid },
  ],
});
add('two-second-interval', '20261029120000Z', accuracy(2), valid, {
  units: { timeMicros: '1793275200000000', accuracyMicros: '2000000' },
  queries: [0, 1, 2, 3].map((offset) => ({
    id: 'cutoff-' + offset,
    revokedAt: epoch + offset,
    expected: offset === 3 ? valid : invalid('TSA_TIME_OR_REVOCATION'),
  })),
});
add('missing-accuracy', '20261029120000Z', undefined, valid, {
  queries: [
    { id: 'finite-cutoff', revokedAt: epoch + 10, expected: unknown },
    { id: 'nominal-revoked', revokedAt: epoch, expected: invalid('TSA_TIME_OR_REVOCATION') },
    {
      id: 'nominal-future',
      at: epoch - 1,
      revokedAt: epoch + 10,
      expected: invalid('TSA_TIME_OR_REVOCATION'),
    },
    {
      id: 'wrong-issuer',
      revokedAt: epoch + 10,
      issuer: 'other',
      expected: {
        'CERTCONCORD-PQ': invalid('CERTIFICATE_SIGNATURE'),
        'EXTERNAL-RFC3161': invalid('TSA_TRUST_OR_EKU'),
      },
    },
  ],
});
add(
  'missing-accuracy-wrong-eku',
  '20261029120000Z',
  undefined,
  {
    'CERTCONCORD-PQ': invalid('CERTIFICATE_EKU'),
    'EXTERNAL-RFC3161': invalid('TSA_TRUST_OR_EKU'),
  },
  {
    certificate: 'wrongEKU',
    queries: [
      {
        id: 'finite-cutoff',
        revokedAt: epoch + 10,
        expected: {
          'CERTCONCORD-PQ': invalid('CERTIFICATE_EKU'),
          'EXTERNAL-RFC3161': invalid('TSA_TRUST_OR_EKU'),
        },
      },
    ],
  },
);
for (const [id, fraction] of [
  ['four-digits', '.1234'],
  ['six-digits', '.123456'],
  ['one-microsecond', '.000001'],
  ['long-fraction', '.123456789123456789'],
])
  add(id, `20261029120000${fraction}Z`, accuracy(), unsupported);
for (const [id, time] of [
  ['zero-fraction', '20261029120000.0Z'],
  ['trailing-zero', '20261029120000.1230Z'],
  ['fine-trailing-zero', '20261029120000.123450Z'],
  ['empty-fraction', '20261029120000.Z'],
  ['nonleap-day', '20260229000000Z'],
  ['normalized-day', '20260230000000Z'],
  ['normalized-hour', '20261029240000Z'],
  ['second-60', '20261029120060Z'],
])
  add(id, time, accuracy(), invalid('TST_TIME'));
add('future-time', '20261029120011Z', accuracy(), invalid('TSA_TIME_OR_REVOCATION'));
const control = add('signature-control', '20261029120000.001Z', accuracy(0, 1)),
  view = cmsView(control),
  signature = Buffer.from(view.signature);
signature[0] ^= 1;
add('signature-tamper', '20261029120000.001Z', accuracy(0, 1), invalid('CMS_SIGNATURE'), {
  raw: rewriteCMS(control, { signature }),
});
const content = Buffer.from(view.embeddedContent);
content[content.length - 1] ^= 1;
add('content-tamper', '20261029120000.001Z', accuracy(0, 1), invalid('CMS_CONTENT_DIGEST'), {
  raw: c.seq(
    view.root.children[0].raw,
    c.der(
      0xa0,
      c.seq(
        ...view.sd.children.map((n, i) =>
          i === 2 ? c.seq(view.contentType.raw, c.der(0xa0, c.octet(content))) : n.raw,
        ),
      ),
    ),
  ),
});
writeFileSync(
  new URL('../reference/vectors/timestamp-time-contract.json', import.meta.url),
  JSON.stringify(
    {
      schemaVersion: 1,
      profile: 'rfc3161-helper-time-interval',
      description:
        'Synthetic signed canonical time, selected precision, accuracy and finite revocation controls. Number bounds conservatively enclose exact integer-microsecond endpoints. No private keys or production clock/status assurance.',
      query: { at: epoch + 10, maxFutureSkew: 0, policy, imprint: imprint.toString('base64') },
      roots: {
        issuer: c.spki(root.publicKey).toString('base64'),
        other: c.spki(other.publicKey).toString('base64'),
      },
      certificates: Object.fromEntries(
        Object.entries(certificates).map(([id, raw]) => [
          id,
          { raw: raw.toString('base64'), sha256: hash(raw) },
        ]),
      ),
      cases,
    },
    null,
    2,
  ) + '\n',
);
console.log('Timestamp time contract: ' + cases.length + ' raw vectors');

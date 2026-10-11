import { readFileSync, writeFileSync } from 'node:fs';
import * as c from './core.mjs';

export const binaryAttachment = Buffer.from([0, 1, 2, 10, 13, 127, 128, 254, 255]);
export const textMessage = Buffer.from(
  'From: Alice <alice@example.test>\r\nTo: Routing <unselected@example.test>\r\n' +
    'Subject: Ordinary complete message\r\nDate: Tue, 15 Jan 2027 12:00:00 +0000\r\n' +
    'Message-ID: <fixed-fixture@example.test>\r\nMIME-Version: 1.0\r\n' +
    'Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n' +
    'Hello =C3=A9.\r\n',
);

export const multipartMessage = Buffer.from(
  'From: Alice <alice@example.test>\r\nTo: Different routing <unselected@example.test>\r\n' +
    'Cc: Copy <copy@example.test>\r\nSubject: Complete MIME tree\r\n' +
    'MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="outer-fixture"\r\n\r\n' +
    '--outer-fixture\r\nContent-Type: multipart/alternative; boundary="inner-fixture"\r\n\r\n' +
    '--inner-fixture\r\nContent-Type: text/plain; charset=utf-8\r\n' +
    'Content-Transfer-Encoding: quoted-printable\r\n\r\nHello =C3=A9.\r\n' +
    '--inner-fixture\r\nContent-Type: text/html; charset=utf-8\r\n' +
    'Content-Transfer-Encoding: base64\r\n\r\nPHA+SGVsbG8gw6kuPC9wPg==\r\n' +
    '--inner-fixture--\r\n' +
    '--outer-fixture\r\nContent-Type: application/octet-stream\r\n' +
    'Content-Disposition: attachment; filename="../untrusted-label.bin"\r\n' +
    'Content-ID: <binary-fixture@example.test>\r\nContent-Transfer-Encoding: base64\r\n\r\n' +
    binaryAttachment.toString('base64') +
    '\r\n--outer-fixture--\r\n',
);

export function simpleMessage(headers = [], body = 'Ordinary text.\r\n') {
  return Buffer.from(['From: alice@example.test', ...headers, '', body].join('\r\n'));
}
export function opaqueCarrier(cms, { kind = 'signed-data', extraHeaders = [], outer = true } = {}) {
  return Buffer.from(
    [
      ...(outer ? ['From: alice@example.test', 'MIME-Version: 1.0'] : []),
      `Content-Type: application/pkcs7-mime; smime-type=${kind}; name=smime.p7m`,
      'Content-Transfer-Encoding: base64',
      ...extraHeaders,
      '',
      cms
        .toString('base64')
        .match(/.{1,64}/g)
        .join('\r\n') + '\r\n',
    ].join('\r\n'),
  );
}

// The comparison producer uses the normal public OpenSSL CMS command. It is an
// independent invocation and byte source, not a second trust implementation.
export function ordinaryCMS(f, { content, leaf = f.signer, ess = true } = {}) {
  const input = f.file('ordinary-cms-content.bin');
  const output = f.file('ordinary-cms.der');
  writeFileSync(
    input,
    content ?? Buffer.from('Content-Type: text/plain\r\n\r\nOrdinary body.\r\n'),
  );
  f.run(
    'cms',
    '-sign',
    '-binary',
    '-nodetach',
    '-nosmimecap',
    '-md',
    'sha256',
    ...(ess ? ['-cades'] : []),
    '-in',
    input,
    '-signer',
    leaf.pemFile,
    '-inkey',
    leaf.keyFile,
    '-certfile',
    f.root.pemFile,
    '-outform',
    'DER',
    '-out',
    output,
  );
  return readFileSync(output);
}

export function replaceSignature(cms) {
  const ci = c.parseDER(cms);
  const ciParts = ci.children;
  const sd = ciParts[1].children[0];
  const fields = sd.children;
  const signerSet = fields.at(-1).children;
  const signer = signerSet[0].children;
  const signatureIndex = signer.findIndex((node, index) => index > 3 && node.tag === 4);
  if (signatureIndex < 0) throw new Error('Fixture signature OCTET STRING not found');
  const signature = Buffer.from(signer[signatureIndex].value);
  signature[signature.length - 1] ^= 1;
  signer[signatureIndex] = { raw: c.octet(signature) };
  const changedSigner = c.seq(...signer.map((node) => node.raw));
  const changedSet = c.der(
    0x31,
    Buffer.concat([changedSigner, ...signerSet.slice(1).map((node) => node.raw)]),
  );
  fields[fields.length - 1] = { raw: changedSet };
  return c.seq(ciParts[0].raw, c.der(0xa0, c.seq(...fields.map((node) => node.raw))));
}

export function replaceEnvelopeTag(cms) {
  const ci = c.parseDER(cms).children;
  const envelope = ci[1].children[0].children;
  const macIndex = envelope.findLastIndex((node) => node.tag === 4);
  if (macIndex < 0) throw new Error('Fixture GCM tag not found');
  const tag = Buffer.from(envelope[macIndex].value);
  tag[0] ^= 1;
  envelope[macIndex] = { raw: c.octet(tag) };
  return c.seq(ci[0].raw, c.der(0xa0, c.seq(...envelope.map((node) => node.raw))));
}

export function flatPartsMessage(leafCount) {
  const parts = Array.from(
    { length: leafCount },
    (_, index) => `--parts-fixture\r\nContent-Type: text/plain\r\n\r\nPart ${index}.\r\n`,
  ).join('');
  return simpleMessage(
    ['Content-Type: multipart/mixed; boundary=parts-fixture'],
    parts + '--parts-fixture--\r\n',
  );
}
export function nestedMessage(containerCount) {
  let value = 'Content-Type: text/plain\r\n\r\nLeaf.\r\n';
  for (let i = containerCount - 1; i >= 0; i--)
    value = `Content-Type: multipart/mixed; boundary=nest-${i}\r\n\r\n--nest-${i}\r\n${value}--nest-${i}--\r\n`;
  return Buffer.from('From: alice@example.test\r\n' + value);
}

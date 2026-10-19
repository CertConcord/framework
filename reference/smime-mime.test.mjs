import test from 'node:test';
import assert from 'node:assert/strict';
import { prepareMimeMessage, inspectVerifiedMime } from './smime-mime.mjs';
import { normalizeMailbox, headerMailbox } from './smime-address.mjs';

const attachment = Buffer.from([0, 1, 2, 10, 13, 255]);
const entity = (type, disposition) =>
  Buffer.from(
    `Content-Type: ${type}\r\n` +
      (disposition ? `Content-Disposition: ${disposition}\r\n` : '') +
      `Content-Transfer-Encoding: base64\r\n\r\n${attachment.toString('base64')}\r\n`,
    'ascii',
  );
const message = (mime) => Buffer.concat([Buffer.from('From: alice@example.test\r\n'), mime]);
const extended = (value) => `utf-8''${encodeURIComponent(value)}`;

test('S/MIME consumes the selected mailbox without changing local-part identity', () => {
  assert.deepEqual(normalizeMailbox({ mailbox: 'Alice+tag@EXAMPLE.TEST' }), {
    mailbox: 'Alice+tag@example.test',
  });
  assert.equal(headerMailbox('"Display name" <Alice+tag@EXAMPLE.TEST>'), 'Alice+tag@example.test');
});

test('S/MIME does not admit mailbox identities recovered from unselected header grammar', () => {
  for (const [value, overall] of [
    ['user @ example.test', 'INVALID'],
    ['Alice <user@example.test(x)evil.test>', 'INVALID'],
    ['"Display Name" <(alice@example.test)>', 'INVALID'],
    ['Alice <"user@evil.test"@good.test>', 'UNSUPPORTED'],
    ['Alice <a@[x@evil.test]>', 'UNSUPPORTED'],
    ['Alice <a@example.test> <b@evil.test>', 'INVALID'],
    ['Alice <a@example.test trailing>', 'INVALID'],
    ['(a@evil.test)', 'INVALID'],
    ['Group: a@example.test;', 'INVALID'],
    ['a@good.test (x) b@evil.test', 'INVALID'],
  ]) {
    assert.throws(
      () => headerMailbox(value),
      (error) => {
        assert.equal(error.overall, overall, value);
        return true;
      },
    );
  }
});

for (const [label, filename, type, disposition] of [
  ['ordinary filename', 'safe.txt', 'application/octet-stream', 'attachment; filename=safe.txt'],
  [
    'partial encoded-word literal',
    'a=?b',
    'application/octet-stream',
    'attachment; filename="a=?b"',
  ],
  [
    'quoted encoded-word literal',
    '=?utf-8?Q?evil?=.txt',
    'application/octet-stream',
    'attachment; filename="=?utf-8?Q?evil?=.txt"',
  ],
  [
    'extended encoded-word literal',
    '=?utf-8?Q?evil?=.txt',
    'application/octet-stream',
    `attachment; filename*=${extended('=?utf-8?Q?evil?=.txt')}`,
  ],
  [
    'single encoded zero segment',
    'a=?b',
    'application/octet-stream',
    `attachment; filename*0*=${extended('a=?b')}`,
  ],
  [
    'single encoded name segment',
    'a=?b',
    `application/octet-stream; name*0*=${extended('a=?b')}`,
    null,
  ],
  [
    'UTF-8 filename',
    '\u00e9.txt',
    'application/octet-stream',
    `attachment; filename*=${extended('\u00e9.txt')}`,
  ],
]) {
  test(`S/MIME preserves ${label} and attachment bytes through preparation`, async () => {
    const mime = entity(type, disposition);
    const incoming = await inspectVerifiedMime({ mime });
    assert.equal(incoming.parts.length, 1);
    assert.equal(incoming.parts[0].filename, filename);
    assert.deepEqual(incoming.parts[0].bytes, attachment);
    const prepared = await prepareMimeMessage({ message: message(mime) });
    assert.deepEqual(prepared.headerClaims, {
      fromMailbox: 'alice@example.test',
      senderMailbox: null,
    });
    const outgoing = await inspectVerifiedMime({ mime: prepared.mime });
    assert.equal(outgoing.parts.length, 1);
    assert.equal(outgoing.parts[0].filename, filename);
    assert.equal(outgoing.parts[0].mediaType, 'application/octet-stream');
    assert.deepEqual(outgoing.parts[0].bytes, attachment);
  });
}

test('S/MIME does not recursively decode nested encoded-word filename literals', async () => {
  const filename = '=?utf-8?Q?=3D=3Futf-8=3FQ=3Fevil=3F=3D.txt?=';
  const inspected = await inspectVerifiedMime({
    mime: entity('application/octet-stream', `attachment; filename*=${extended(filename)}`),
  });
  assert.equal(inspected.parts[0].filename, filename);
  assert.deepEqual(inspected.parts[0].bytes, attachment);
});

for (const [label, parameters, code, overall] of [
  [
    'missing extended delimiters',
    'filename*="=?utf-8?Q?evil?=.txt"',
    'SMIME_PARAMETER_SYNTAX',
    'INVALID',
  ],
  [
    'missing zero-segment delimiters',
    'filename*0*="=?utf-8?Q?evil?=.txt"',
    'SMIME_PARAMETER_SYNTAX',
    'INVALID',
  ],
  ['malformed percent escape', "filename*=utf-8''bad%2", 'SMIME_PARAMETER_SYNTAX', 'INVALID'],
  ['unencoded extended special', "filename*=utf-8''bad?word", 'SMIME_PARAMETER_SYNTAX', 'INVALID'],
  [
    'multiple segments',
    "filename*0*=utf-8''first; filename*1*=second",
    'SMIME_PARAMETER_CONTINUATION_UNSUPPORTED',
    'UNSUPPORTED',
  ],
  [
    'nonzero initial segment',
    "filename*1*=utf-8''first",
    'SMIME_PARAMETER_CONTINUATION_UNSUPPORTED',
    'UNSUPPORTED',
  ],
  [
    'leading-zero segment',
    "filename*00*=utf-8''first",
    'SMIME_PARAMETER_CONTINUATION_UNSUPPORTED',
    'UNSUPPORTED',
  ],
  [
    'unencoded zero segment',
    'filename*0=first',
    'SMIME_PARAMETER_CONTINUATION_UNSUPPORTED',
    'UNSUPPORTED',
  ],
  [
    'duplicate encoded zero segment',
    "filename*0*=utf-8''first; FILENAME*0*=utf-8''second",
    'SMIME_DUPLICATE_PARAMETER',
    'INVALID',
  ],
  [
    'plain and zero segment alias',
    "filename=first; filename*0*=utf-8''second",
    'SMIME_DUPLICATE_PARAMETER',
    'INVALID',
  ],
  [
    'extended and zero segment alias',
    "filename*=utf-8''first; filename*0*=utf-8''second",
    'SMIME_DUPLICATE_PARAMETER',
    'INVALID',
  ],
  ['encoded filename control', "filename*=utf-8''first%00second", 'SMIME_FILENAME', 'INVALID'],
]) {
  test(`S/MIME rejects ${label} before returning MIME content`, async () => {
    const mime = entity('application/octet-stream', `attachment; ${parameters}`);
    for (const action of [
      () => inspectVerifiedMime({ mime }),
      () => prepareMimeMessage({ message: message(mime) }),
    ]) {
      await assert.rejects(action, (error) => {
        assert.equal(error.code, code);
        assert.equal(error.overall, overall);
        assert.equal(Object.hasOwn(error, 'mime'), false);
        assert.equal(Object.hasOwn(error, 'parts'), false);
        return true;
      });
    }
  });
}

test('S/MIME preparation refuses writer output needing multiple filename segments', async () => {
  const filename = 'a'.repeat(90);
  const mime = entity('application/octet-stream', `attachment; filename=${filename}`);
  const input = await inspectVerifiedMime({ mime });
  assert.equal(input.parts[0].filename, filename);
  await assert.rejects(() => prepareMimeMessage({ message: message(mime) }), {
    code: 'SMIME_PARAMETER_CONTINUATION_UNSUPPORTED',
    overall: 'UNSUPPORTED',
  });
});

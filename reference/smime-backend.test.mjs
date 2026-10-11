import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { createSmimeBackend } from './smime-backend.mjs';
import * as c from './core.mjs';
import { smimeMaterialFixture, ENCRYPTION, O } from './smime-material-fixtures.mjs';
import { SMIME_OID, entity } from './smime-application-fixtures.mjs';
import {
  textMessage,
  multipartMessage,
  binaryAttachment,
  simpleMessage,
  opaqueCarrier,
  ordinaryCMS,
  replaceSignature,
  replaceEnvelopeTag,
  flatPartsMessage,
  nestedMessage,
} from './smime-message-fixtures.mjs';

let f;
let backend;
let otherRecipient;
const config = (keyMap) => ({
  opensslPath: process.env.OPENSSL_BIN,
  opensslConfig: process.env.OPENSSL_CONF,
  ...(process.env.OPENSSL_MODULES ? { opensslModulePath: process.env.OPENSSL_MODULES } : {}),
  keyMap,
});
before(() => {
  f = smimeMaterialFixture();
  otherRecipient = f.certificate('Second mail recipient', {
    purpose: ENCRYPTION,
    key: f.key('rsa'),
    emails: ['carol@example.test'],
  });
  backend = createSmimeBackend(
    config({
      signer: f.signer.privateKey,
      recipient: f.recipient.privateKey,
      other: otherRecipient.privateKey,
    }),
  );
});
after(() => f?.close());

async function fails(action, expected) {
  await assert.rejects(action, (error) => {
    assert.equal(error.overall, expected, `${error.code}: ${error.message}`);
    assert.equal(typeof error.code, 'string');
    assert.equal(Object.hasOwn(error, 'content'), false);
    assert.equal(Object.hasOwn(error, 'messageBytes'), false);
    assert.equal(Object.hasOwn(error, 'privateKey'), false);
    return true;
  });
}
const sign = (content = entity, changes = {}) =>
  backend.sign({
    content,
    certificate: f.signer.der,
    certificates: [f.root.der],
    keyRef: 'signer',
    expectedPublicKeyDER: c.spki(f.signer.publicKey),
    ...changes,
  });
const decrypt = (cms, changes = {}) =>
  backend.decrypt({
    cms,
    certificate: f.recipient.der,
    keyRef: 'recipient',
    expectedPublicKeyDER: c.spki(f.recipient.publicKey),
    ...changes,
  });

test('S/MIME mailbox normalization lowercases only the domain and consumes the full address', () => {
  assert.deepEqual(backend.normalizeMailbox({ mailbox: 'Alice@EXAMPLE.TEST' }), {
    mailbox: 'Alice@example.test',
  });
  assert.deepEqual(backend.normalizeMailbox({ mailbox: 'alice+tag@example.test' }), {
    mailbox: 'alice+tag@example.test',
  });
  assert.notDeepEqual(
    backend.normalizeMailbox({ mailbox: 'Alice@example.test' }),
    backend.normalizeMailbox({ mailbox: 'alice@example.test' }),
  );
});
for (const [label, mailbox, overall] of [
  ['display name', 'Alice <alice@example.test>', 'UNSUPPORTED'],
  ['group', 'Group: alice@example.test;', 'UNSUPPORTED'],
  ['multiple mailboxes', 'alice@example.test,bob@example.test', 'UNSUPPORTED'],
  ['EAI', '\u00e9@example.test', 'UNSUPPORTED'],
  ['ignored suffix', 'alice@example.test trailing garbage', 'INVALID'],
  ['missing domain', 'alice@', 'INVALID'],
  ['header injection', 'alice@example.test\r\nBcc: bob@example.test', 'INVALID'],
]) {
  test(`S/MIME mailbox parser rejects ${label}`, () => {
    assert.throws(
      () => backend.normalizeMailbox({ mailbox }),
      (error) => {
        assert.equal(error.overall, overall);
        assert.equal(typeof error.code, 'string');
        return true;
      },
    );
  });
}

test('S/MIME MIME preparation separates unprotected headers and preserves selected text', async () => {
  const result = await backend.prepareMimeMessage({ message: textMessage });
  assert.deepEqual(result.headerClaims, { fromMailbox: 'alice@example.test', senderMailbox: null });
  assert.deepEqual(result.normalization.originalMessageHash, c.sha256(textMessage));
  assert.equal(result.normalization.textParts, 1);
  const headerBlock = result.mime.subarray(0, result.mime.indexOf('\r\n\r\n')).toString('ascii');
  assert.match(headerBlock, /Content-Type:\s*text\/plain/i);
  assert.doesNotMatch(headerBlock, /^(From|To|Cc|Subject|Date|Message-ID|MIME-Version):/im);
  assert(
    result.outerHeaders.some(
      (header) => header.name === 'subject' && header.value === 'Ordinary complete message',
    ),
  );
  assert(result.outerHeaders.every((header) => Buffer.isBuffer(header.raw)));
  const inspected = await backend.inspectVerifiedMime({ mime: result.mime });
  assert.equal(inspected.parts.length, 1);
  assert.equal(inspected.parts[0].mediaType, 'text/plain');
  assert.equal(inspected.parts[0].charset, 'utf-8');
  assert.deepEqual(inspected.parts[0].bytes, Buffer.from('Hello \u00e9.\r\n'));
});

test('S/MIME MIME preparation preserves nested alternatives and inert binary attachment bytes', async () => {
  const result = await backend.prepareMimeMessage({ message: multipartMessage });
  const inspected = await backend.inspectVerifiedMime({ mime: result.mime });
  assert.equal(inspected.tree.length, 5);
  assert.deepEqual(
    inspected.parts.map((part) => part.mediaType),
    ['text/plain', 'text/html', 'application/octet-stream'],
  );
  const attachment = inspected.parts[2];
  assert.deepEqual(attachment.bytes, binaryAttachment);
  assert.equal(attachment.filename, '../untrusted-label.bin');
  assert.equal(attachment.disposition, 'attachment');
  assert.equal(attachment.contentID, '<binary-fixture@example.test>');
  assert.equal(inspected.tree[0].children, 2);
  assert.equal(inspected.tree[1].children, 2);
  assert(inspected.parts[1].bytes.toString('utf8').includes('<p>Hello \u00e9.</p>'));
});

test('S/MIME absent Content-Type retains the RFC2045 text default despite a filename', async () => {
  const input = simpleMessage(
    ['Content-Disposition: attachment; filename="guess.html"'],
    'Plain text.\r\n',
  );
  const result = await backend.prepareMimeMessage({ message: input });
  const inspected = await backend.inspectVerifiedMime({ mime: result.mime });
  assert.equal(inspected.parts[0].mediaType, 'text/plain');
  assert.deepEqual(inspected.parts[0].bytes, Buffer.from('Plain text.\r\n'));
  assert.equal(inspected.parts[0].filename, 'guess.html');
});

test('S/MIME legal field case and folding preserve the single author', async () => {
  const input = Buffer.from(
    'fRoM: Alice\r\n <alice@example.test>\r\nsEnDeR: alice@example.test\r\n' +
      'cOnTeNt-TyPe: text/plain;\r\n charset=us-ascii\r\n\r\nFolded control.\r\n',
  );
  const prepared = await backend.prepareMimeMessage({ message: input });
  assert.deepEqual(prepared.headerClaims, {
    fromMailbox: 'alice@example.test',
    senderMailbox: 'alice@example.test',
  });
  const inspected = await backend.inspectVerifiedMime({ mime: prepared.mime });
  assert.deepEqual(inspected.parts[0].bytes, Buffer.from('Folded control.\r\n'));
});

for (const [label, headers] of [
  ['From', ['From: alice@example.test']],
  ['Sender', ['Sender: alice@example.test', 'sENDER: alice@example.test']],
  ['Content-Type', ['Content-Type: text/plain', 'content-type: text/plain']],
  [
    'Content-Transfer-Encoding',
    ['Content-Transfer-Encoding: 7bit', 'CONTENT-TRANSFER-ENCODING: 7bit'],
  ],
  ['Content-Disposition', ['Content-Disposition: inline', 'content-disposition: inline']],
  ['charset parameter', ['Content-Type: text/plain; charset=utf-8; CHARSET=us-ascii']],
  ['filename parameter', ['Content-Disposition: attachment; filename=a.txt; FILENAME=b.txt']],
  ['boundary parameter', ['Content-Type: multipart/mixed; boundary=a; boundary=b']],
]) {
  test(`S/MIME MIME parser rejects duplicate ${label} before convenience access`, async () => {
    await fails(() => backend.prepareMimeMessage({ message: simpleMessage(headers) }), 'INVALID');
  });
}

for (const [label, input, overall] of [
  [
    'mbox preamble',
    Buffer.concat([Buffer.from('From sender@example.test Tue Jan 15\r\n'), textMessage]),
    'INVALID',
  ],
  ['HTTP preamble', Buffer.concat([Buffer.from('HTTP/1.1 200 OK\r\n'), textMessage]), 'INVALID'],
  ['malformed header name', simpleMessage(['Bad field: value']), 'INVALID'],
  [
    'multiple From authors',
    Buffer.from('From: alice@example.test,bob@example.test\r\n\r\nBody.\r\n'),
    'UNSUPPORTED',
  ],
  ['nonempty Bcc', simpleMessage(['Bcc: hidden@example.test']), 'INVALID'],
  ['protected header extension', simpleMessage(['HP-Outer: value']), 'UNSUPPORTED'],
  [
    'unselected charset',
    simpleMessage(['Content-Type: text/plain; charset=iso-8859-1']),
    'UNSUPPORTED',
  ],
  [
    'attached message interpretation',
    simpleMessage(['Content-Type: message/rfc822']),
    'UNSUPPORTED',
  ],
  [
    'multipart signed root',
    simpleMessage([
      'Content-Type: multipart/signed; boundary=a; protocol="application/pkcs7-signature"',
    ]),
    'UNSUPPORTED',
  ],
  ['invalid base64', simpleMessage(['Content-Transfer-Encoding: base64'], 'AA@=\r\n'), 'INVALID'],
  [
    'invalid quoted printable',
    simpleMessage(['Content-Transfer-Encoding: quoted-printable'], 'broken=GG\r\n'),
    'INVALID',
  ],
  [
    '8bit octets declared 7bit',
    Buffer.concat([simpleMessage(['Content-Transfer-Encoding: 7bit'], ''), Buffer.from([0x80])]),
    'INVALID',
  ],
]) {
  test(`S/MIME MIME parser rejects ${label}`, async () => {
    await fails(() => backend.prepareMimeMessage({ message: input }), overall);
  });
}

test('S/MIME empty Bcc is not a hidden-recipient claim', async () => {
  const value = await backend.prepareMimeMessage({ message: simpleMessage(['Bcc:']) });
  assert.deepEqual(value.headerClaims, { fromMailbox: 'alice@example.test', senderMailbox: null });
  assert(Buffer.isBuffer(value.mime));
});

test('S/MIME carrier serialization preserves exact CMS and keeps ENTITY free of outer fields', async () => {
  const { cms } = await sign();
  const prepared = await backend.prepareMimeMessage({ message: textMessage });
  const { message: complete } = await backend.packageCMS({
    cms,
    kind: 'SIGNED_DATA',
    format: 'MESSAGE',
    outerHeaders: prepared.outerHeaders,
  });
  const parsed = await backend.parseProtectedMessage({ message: complete, format: 'MESSAGE' });
  assert.deepEqual(parsed.cms, cms);
  assert.equal(parsed.kind, 'SIGNED_DATA');
  assert.equal(parsed.headerClaims.fromMailbox, 'alice@example.test');
  const { message: inner } = await backend.packageCMS({
    cms,
    kind: 'SIGNED_DATA',
    format: 'ENTITY',
  });
  assert.doesNotMatch(
    inner.subarray(0, inner.indexOf('\r\n\r\n')).toString('ascii'),
    /^(From|Date|Message-ID|MIME-Version):/im,
  );
  const innerParsed = await backend.parseProtectedMessage({ message: inner, format: 'ENTITY' });
  assert.deepEqual(innerParsed.cms, cms);
  assert.deepEqual(innerParsed.outerHeaders, []);
  assert.deepEqual(innerParsed.headerClaims, { fromMailbox: null, senderMailbox: null });
  await fails(
    () =>
      backend.packageCMS({
        cms,
        kind: 'SIGNED_DATA',
        format: 'ENTITY',
        outerHeaders: prepared.outerHeaders,
      }),
    'INVALID',
  );
  await fails(
    () => backend.parseProtectedMessage({ message: complete, format: 'ENTITY' }),
    'INVALID',
  );
});

test('S/MIME carrier parsing exposes a MIME hint without treating it as cryptographic truth', async () => {
  const { cms } = await sign();
  const message = opaqueCarrier(cms, { kind: 'authEnveloped-data' });
  const carrier = await backend.parseProtectedMessage({ message, format: 'MESSAGE' });
  assert.equal(carrier.kind, 'AUTH_ENVELOPED_DATA');
  const inspected = await backend.inspectCMS({ cms: carrier.cms });
  assert.equal(inspected.overall, 'VALID');
  assert.equal(inspected.kind, 'SIGNED_DATA');
  assert.equal(inspected.contentTypeOID, SMIME_OID.signed);
});

for (const [label, extraHeaders] of [
  ['duplicate transfer encoding', ['Content-Transfer-Encoding: base64']],
  ['duplicate smime-type', []],
]) {
  test(`S/MIME protected carrier rejects ${label}`, async () => {
    const { cms } = await sign();
    let message = opaqueCarrier(cms, { extraHeaders });
    if (label === 'duplicate smime-type')
      message = Buffer.from(
        message
          .toString('ascii')
          .replace(
            'smime-type=signed-data;',
            'smime-type=signed-data; SMIME-TYPE=authEnveloped-data;',
          ),
      );
    await fails(() => backend.parseProtectedMessage({ message, format: 'MESSAGE' }), 'INVALID');
  });
}

test('S/MIME a signed attachment beside unsigned text is not a protected root message', async () => {
  const { cms } = await sign();
  const signedAttachment = opaqueCarrier(cms, { outer: false });
  const mixed = Buffer.concat([
    Buffer.from(
      'From: alice@example.test\r\nContent-Type: multipart/mixed; boundary=unsigned-root\r\n\r\n' +
        '--unsigned-root\r\nContent-Type: text/plain\r\n\r\nUnsigned text.\r\n--unsigned-root\r\n',
    ),
    signedAttachment,
    Buffer.from('--unsigned-root--\r\n'),
  ]);
  await fails(
    () => backend.parseProtectedMessage({ message: mixed, format: 'MESSAGE' }),
    'UNSUPPORTED',
  );
});

test('S/MIME actual signer binds the private key and exact bytes with selected CMS facts', async () => {
  const described = await backend.describeKey({ keyRef: 'signer' });
  assert.deepEqual(described.publicKeyDER, c.spki(f.signer.publicKey));
  const content = Buffer.concat([entity, Buffer.from('An additional exact line.\r\n')]);
  const { cms } = await sign(content);
  const inspected = await backend.inspectCMS({ cms });
  assert.equal(inspected.overall, 'VALID', JSON.stringify(inspected.checks));
  assert.equal(inspected.kind, 'SIGNED_DATA');
  assert.equal(inspected.contentTypeOID, SMIME_OID.signed);
  assert.deepEqual(inspected.content, content);
  assert.deepEqual(inspected.certificate, f.signer.der);
  assert.deepEqual(inspected.signer.certificateHash, c.sha256(f.signer.der));
  assert.deepEqual(inspected.signer.publicKeyDER, c.spki(f.signer.publicKey));
  assert.equal(inspected.signer.hashOID, O.sha256);
  assert.equal(inspected.signer.signatureOID, O.es256);
  assert(inspected.signer.signedAttributeOIDs.includes('1.2.840.113549.1.9.16.2.47'));
  assert.equal(inspected.certificates.length, 1);
  assert.deepEqual(inspected.certificates[0], f.signer.der);
  writeFileSync(f.file('backend-sign.der'), cms);
  f.run(
    'cms',
    '-verify',
    '-binary',
    '-inform',
    'DER',
    '-in',
    f.file('backend-sign.der'),
    '-noverify',
    '-out',
    f.file('backend-sign-content.bin'),
  );
  assert.deepEqual(readFileSync(f.file('backend-sign-content.bin')), content);
});

test('S/MIME ordinary OpenSSL output lacking ESSv2 is explicitly UNSUPPORTED', async () => {
  const cms = ordinaryCMS(f, { content: entity, ess: false });
  const result = await backend.inspectCMS({ cms });
  assert.equal(result.overall, 'UNSUPPORTED', JSON.stringify(result.checks));
  assert.deepEqual(result.content, entity);
});
test('S/MIME bad signature dominates ordinary OpenSSL output lacking ESSv2', async () => {
  const cms = replaceSignature(ordinaryCMS(f, { content: entity, ess: false }));
  const result = await backend.inspectCMS({ cms });
  assert.equal(result.overall, 'INVALID', JSON.stringify(result.checks));
  assert(result.checks.some((check) => check.overall === 'INVALID'));
});
test('S/MIME sign rejects a mismatched actual key instead of trying another key', async () => {
  await fails(
    () => sign(entity, { expectedPublicKeyDER: c.spki(f.recipient.publicKey) }),
    'INVALID',
  );
});
test('S/MIME key references are opaque map keys and cannot select a filesystem path', async () => {
  await fails(() => backend.describeKey({ keyRef: f.signer.keyFile }), 'INDETERMINATE');
});
test('S/MIME backend copies constructor key maps and mutable PEM input', async () => {
  const originalPEM = Buffer.from(f.signer.privateKey.export({ type: 'pkcs8', format: 'pem' }));
  const keyMap = { fixed: originalPEM };
  const fixed = createSmimeBackend(config(keyMap));
  originalPEM.fill(0);
  keyMap.fixed = f.recipient.privateKey;
  const described = await fixed.describeKey({ keyRef: 'fixed' });
  assert.deepEqual(described.publicKeyDER, c.spki(f.signer.publicKey));
  const { cms } = await fixed.sign({
    content: entity,
    certificate: f.signer.der,
    certificates: [],
    keyRef: 'fixed',
    expectedPublicKeyDER: c.spki(f.signer.publicKey),
  });
  const result = await backend.inspectCMS({ cms });
  assert.equal(result.overall, 'VALID');
  assert.deepEqual(result.content, entity);
});

test('S/MIME real AuthEnvelopedData includes every explicit recipient and selected algorithms', async () => {
  const { cms: signed } = await sign();
  const { message: inner } = await backend.packageCMS({
    cms: signed,
    kind: 'SIGNED_DATA',
    format: 'ENTITY',
  });
  const certificates = [f.recipient.der, otherRecipient.der];
  const { cms } = await backend.encrypt({ content: inner, certificates });
  const facts = await backend.inspectCMS({ cms, recipientCertificates: certificates });
  assert.equal(facts.overall, 'VALID', JSON.stringify(facts.checks));
  assert.equal(facts.kind, 'AUTH_ENVELOPED_DATA');
  assert.equal(facts.contentTypeOID, SMIME_OID.authenticatedEnvelope);
  assert.equal(facts.recipients.length, 2);
  assert.equal(facts.recipientMatches.length, 2);
  assert.deepEqual(
    facts.recipientMatches.map((match) => match.certificateHash.toString('hex')).sort(),
    certificates.map((raw) => c.sha256(raw).toString('hex')).sort(),
  );
  assert.equal(facts.encryption.contentTypeOID, SMIME_OID.data);
  assert.equal(facts.encryption.algorithmOID, SMIME_OID.aes256GCM);
  assert.equal(facts.encryption.nonce.length, 12);
  assert.equal(facts.encryption.tagLength, 16);
  assert.equal(facts.encryption.authenticatedAttributesPresent, false);
  for (const recipient of facts.recipients) {
    assert.equal(recipient.keyEncryptionOID, SMIME_OID.oaep);
    const parameters = c.parseDER(recipient.keyEncryptionParametersDER).children;
    assert.equal(c.oidText(parameters[0].children[0].children[0]), O.sha256);
    const mgf = parameters[1].children[0].children;
    assert.equal(c.oidText(mgf[0]), SMIME_OID.mgf1);
    assert.equal(c.oidText(mgf[1].children[0]), O.sha256);
    if (parameters[2]) {
      const label = parameters[2].children[0].children;
      assert.equal(c.oidText(label[0]), SMIME_OID.pSpecified);
      assert.deepEqual(label[1].value, Buffer.alloc(0));
    }
  }
  const first = await decrypt(cms);
  assert.deepEqual(first.content, inner);
  assert.deepEqual(first.recipient.certificateHash, c.sha256(f.recipient.der));
  const second = await decrypt(cms, {
    certificate: otherRecipient.der,
    keyRef: 'other',
    expectedPublicKeyDER: c.spki(otherRecipient.publicKey),
  });
  assert.deepEqual(second.content, inner);
});

test('S/MIME bad GCM authentication releases no partial plaintext', async () => {
  const { cms } = await backend.encrypt({
    content: Buffer.from('Private candidate bytes.'),
    certificates: [f.recipient.der],
  });
  await fails(() => decrypt(replaceEnvelopeTag(cms)), 'INVALID');
});
test('S/MIME decrypt rejects the wrong selected private key without fallback', async () => {
  const { cms } = await backend.encrypt({
    content: Buffer.from('Private candidate bytes.'),
    certificates: [f.recipient.der],
  });
  await fails(() => decrypt(cms, { keyRef: 'other' }), 'INVALID');
});

for (const [nodes, expected] of [
  [128, 'VALID'],
  [129, 'UNSUPPORTED'],
]) {
  test(`S/MIME MIME tree enforces ${nodes} total nodes including the root`, async () => {
    const operation = () => backend.prepareMimeMessage({ message: flatPartsMessage(nodes - 1) });
    if (expected !== 'VALID') return fails(operation, expected);
    const prepared = await operation();
    const inspected = await backend.inspectVerifiedMime({ mime: prepared.mime });
    assert.equal(inspected.tree.length, nodes);
    assert.equal(inspected.parts.length, nodes - 1);
  });
}
for (const [depth, expected] of [
  [16, 'VALID'],
  [17, 'UNSUPPORTED'],
]) {
  test(`S/MIME MIME tree enforces depth ${depth} with the root at one`, async () => {
    const operation = () => backend.prepareMimeMessage({ message: nestedMessage(depth - 1) });
    if (expected !== 'VALID') return fails(operation, expected);
    const prepared = await operation();
    const inspected = await backend.inspectVerifiedMime({ mime: prepared.mime });
    assert.equal(inspected.parts[0].path.length, depth - 1);
  });
}
for (const [headers, expected] of [
  [128, 'VALID'],
  [129, 'UNSUPPORTED'],
]) {
  test(`S/MIME MIME parser enforces ${headers} fields per entity`, async () => {
    const extra = Array.from({ length: headers - 2 }, (_, index) => `X-Fixture-${index}: value`);
    const operation = () =>
      backend.prepareMimeMessage({
        message: simpleMessage(['Content-Type: text/plain', ...extra]),
      });
    if (expected !== 'VALID') return fails(operation, expected);
    const prepared = await operation();
    const parsed = await backend.inspectVerifiedMime({ mime: prepared.mime });
    assert.equal(parsed.parts.length, 1);
  });
}
test('S/MIME MIME input cannot exceed the fixed 32 MiB bound', async () => {
  await fails(
    () => backend.prepareMimeMessage({ message: Buffer.alloc(33554433, 0x41) }),
    'UNSUPPORTED',
  );
});
test('S/MIME opaque carrier input cannot exceed the fixed 32 MiB bound', async () => {
  await fails(
    () =>
      backend.parseProtectedMessage({ message: Buffer.alloc(33554433, 0x41), format: 'MESSAGE' }),
    'UNSUPPORTED',
  );
});
test('S/MIME decoded MIME cannot exceed the fixed 16 MiB bound', async () => {
  const mime = Buffer.concat([
    Buffer.from(
      'Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n',
    ),
    Buffer.from(Buffer.alloc(16777217, 0x31).toString('base64')),
  ]);
  await fails(() => backend.inspectVerifiedMime({ mime }), 'UNSUPPORTED');
});

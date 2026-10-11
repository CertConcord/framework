import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { SmimeApplication } from './smime.mjs';
import { createSmimeBackend } from './smime-backend.mjs';
import * as c from './core.mjs';
import { smimeMaterialFixture, ENCRYPTION } from './smime-material-fixtures.mjs';
import {
  applicationFixture,
  expectOverall,
  identity,
  noOutput,
} from './smime-application-fixtures.mjs';
import {
  textMessage,
  multipartMessage,
  binaryAttachment,
  replaceEnvelopeTag,
  replaceSignature,
  ordinarySignedEntity,
} from './smime-message-fixtures.mjs';

let material;
let backend;
let otherRecipient;
before(() => {
  material = smimeMaterialFixture();
  otherRecipient = material.certificate('Other actual recipient', {
    purpose: ENCRYPTION,
    key: material.key('rsa'),
    emails: ['carol@example.test'],
  });
  backend = createSmimeBackend({
    opensslPath: process.env.OPENSSL_BIN,
    opensslConfig: process.env.OPENSSL_CONF,
    ...(process.env.OPENSSL_MODULES ? { opensslModulePath: process.env.OPENSSL_MODULES } : {}),
    keyMap: {
      signer: material.signer.privateKey,
      recipient: material.recipient.privateKey,
      other: otherRecipient.privateKey,
    },
  });
});
after(() => material?.close());

function fixture(customBackend = backend) {
  const f = applicationFixture(material);
  f.app = new SmimeApplication({ readContext: f.readContext, backend: customBackend });
  f.protect = (mode = 'SIGNED', message = multipartMessage) => ({
    ...f.protectInput(mode),
    message: Buffer.from(message),
  });
  f.process = (message, requiredProtection = 'SIGNED') => ({
    message,
    requiredProtection,
    expectedSenderMailbox: 'alice@example.test',
    ...(requiredProtection === 'SIGNED_AND_ENCRYPTED'
      ? {
          recipient: {
            mailbox: 'bob@example.test',
            certificate: material.recipient.der,
            keyRef: 'recipient',
          },
        }
      : {}),
  });
  return f;
}
const methodNames = [
  'normalizeMailbox',
  'prepareMimeMessage',
  'parseProtectedMessage',
  'packageCMS',
  'inspectVerifiedMime',
  'describeKey',
  'sign',
  'inspectCMS',
  'encrypt',
  'decrypt',
];
function instrument(after = {}) {
  const counts = {};
  const wrapper = Object.fromEntries(
    methodNames.map((name) => [
      name,
      name === 'normalizeMailbox'
        ? (input) => backend[name](input)
        : async (input) => {
            counts[name] = (counts[name] ?? 0) + 1;
            const result = await backend[name](input);
            if (after[name]) await after[name](result, input);
            return result;
          },
    ]),
  );
  return { wrapper, counts };
}

for (const mode of ['SIGNED', 'SIGNED_AND_ENCRYPTED']) {
  test(`S/MIME actual ${mode} complete message preserves original CMS MIME and binary content`, async () => {
    const f = fixture();
    const protectedResult = expectOverall(
      await f.app.protectSmimeMessage(f.protect(mode)),
      'VALID',
    );
    const parsed = await backend.parseProtectedMessage({
      message: protectedResult.message,
      format: 'MESSAGE',
    });
    let signedCMS = parsed.cms;
    if (mode === 'SIGNED_AND_ENCRYPTED') {
      const decrypted = await backend.decrypt({
        cms: parsed.cms,
        certificate: material.recipient.der,
        keyRef: 'recipient',
        expectedPublicKeyDER: c.spki(material.recipient.publicKey),
      });
      signedCMS = (
        await backend.parseProtectedMessage({ message: decrypted.content, format: 'ENTITY' })
      ).cms;
    }
    const crypto = await backend.inspectCMS({ cms: signedCMS });
    assert.equal(crypto.overall, 'VALID');
    const received = expectOverall(
      await f.app.processSmimeMessage(f.process(protectedResult.message, mode)),
      'VALID',
    );
    assert.deepEqual(received.content.mime, crypto.content);
    assert.deepEqual(received.canonicalMimeHash, c.sha256(crypto.content));
    assert.deepEqual(protectedResult.canonicalMimeHash, received.canonicalMimeHash);
    assert.deepEqual(received.authenticatedAuthor, identity(material.signer, 'alice@example.test'));
    assert.deepEqual(received.protection, { content: mode, outerHeaders: 'UNPROTECTED' });
    assert.deepEqual(
      received.content.parts.find((part) => part.mediaType === 'application/octet-stream').bytes,
      binaryAttachment,
    );
    assert.equal(
      received.content.parts.find((part) => part.mediaType === 'application/octet-stream').filename,
      '../untrusted-label.bin',
    );
  });
}

test('S/MIME actual encryption admits two explicit keys without inferring a To recipient', async () => {
  const f = fixture();
  const input = f.protect('SIGNED_AND_ENCRYPTED', textMessage);
  input.recipients.push({ mailbox: 'carol@example.test', certificate: otherRecipient.der });
  const sent = expectOverall(await f.app.protectSmimeMessage(input), 'VALID');
  assert.deepEqual(sent.admittedRecipients, [
    identity(material.recipient, 'bob@example.test'),
    identity(otherRecipient, 'carol@example.test'),
  ]);
  const outer = await backend.parseProtectedMessage({ message: sent.message, format: 'MESSAGE' });
  const facts = await backend.inspectCMS({
    cms: outer.cms,
    recipientCertificates: [material.recipient.der, otherRecipient.der],
  });
  assert.equal(facts.recipients.length, 2);
  assert.equal(facts.recipientMatches.length, 2);
  const received = expectOverall(
    await f.app.processSmimeMessage({
      ...f.process(sent.message, 'SIGNED_AND_ENCRYPTED'),
      recipient: {
        mailbox: 'carol@example.test',
        certificate: otherRecipient.der,
        keyRef: 'other',
      },
    }),
    'VALID',
  );
  assert.deepEqual(received.matchedRecipient, identity(otherRecipient, 'carol@example.test'));
  assert(f.queries.every((query) => query.mailbox !== 'unselected@example.test'));
});

test('S/MIME valid signature does not authenticate a changed outer Subject', async () => {
  const f = fixture();
  const sent = expectOverall(
    await f.app.protectSmimeMessage(f.protect('SIGNED', textMessage)),
    'VALID',
  );
  const changed = Buffer.from(
    sent.message
      .toString('ascii')
      .replace(/^Subject:[^\r\n]*/im, 'Subject: Unprotected replacement'),
  );
  assert.notDeepEqual(changed, sent.message);
  const received = expectOverall(await f.app.processSmimeMessage(f.process(changed)), 'VALID');
  assert.equal(received.protection.outerHeaders, 'UNPROTECTED');
  assert.equal(
    received.outerHeaders.find((header) => header.name === 'subject').value,
    'Unprotected replacement',
  );
  assert.deepEqual(received.canonicalMimeHash, sent.canonicalMimeHash);
});

test('S/MIME valid CMS cannot authorize a different outer From author', async () => {
  const f = fixture();
  const sent = expectOverall(
    await f.app.protectSmimeMessage(f.protect('SIGNED', textMessage)),
    'VALID',
  );
  const changed = Buffer.from(
    sent.message.toString('ascii').replace(/^From:[^\r\n]*/im, 'From: mallory@example.test'),
  );
  const originalCMS = (
    await backend.parseProtectedMessage({ message: sent.message, format: 'MESSAGE' })
  ).cms;
  const changedCMS = (await backend.parseProtectedMessage({ message: changed, format: 'MESSAGE' }))
    .cms;
  assert.deepEqual(changedCMS, originalCMS);
  assert.equal((await backend.inspectCMS({ cms: changedCMS })).overall, 'VALID');
  expectOverall(await f.app.processSmimeMessage(f.process(changed)), 'INVALID');
});

test('S/MIME real MIME smime-type substitution cannot switch the selected CMS mode', async () => {
  const f = fixture();
  const sent = expectOverall(
    await f.app.protectSmimeMessage(f.protect('SIGNED', textMessage)),
    'VALID',
  );
  const changed = Buffer.from(
    sent.message
      .toString('ascii')
      .replace(/smime-type="?signed-data"?/i, 'smime-type=authEnveloped-data'),
  );
  assert.notDeepEqual(changed, sent.message);
  const received = expectOverall(
    await f.app.processSmimeMessage(f.process(changed, 'SIGNED_AND_ENCRYPTED')),
    'INVALID',
  );
  assert.equal(received.effectMayHaveOccurred, false);
});

test('S/MIME actual GCM failure releases no MIME or attachments', async () => {
  const f = fixture();
  const sent = expectOverall(
    await f.app.protectSmimeMessage(f.protect('SIGNED_AND_ENCRYPTED')),
    'VALID',
  );
  const outer = await backend.parseProtectedMessage({ message: sent.message, format: 'MESSAGE' });
  const { message } = await backend.packageCMS({
    cms: replaceEnvelopeTag(outer.cms),
    kind: 'AUTH_ENVELOPED_DATA',
    format: 'MESSAGE',
    outerHeaders: outer.outerHeaders,
  });
  const result = expectOverall(
    await f.app.processSmimeMessage(f.process(message, 'SIGNED_AND_ENCRYPTED')),
    'INVALID',
  );
  assert.equal(result.effectMayHaveOccurred, true);
  noOutput(result);
});

test('S/MIME real bad signature dominates unavailable current configuration', async () => {
  const f = fixture();
  const sent = expectOverall(
    await f.app.protectSmimeMessage(f.protect('SIGNED', textMessage)),
    'VALID',
  );
  const outer = await backend.parseProtectedMessage({ message: sent.message, format: 'MESSAGE' });
  const { message } = await backend.packageCMS({
    cms: replaceSignature(outer.cms),
    kind: 'SIGNED_DATA',
    format: 'MESSAGE',
    outerHeaders: outer.outerHeaders,
  });
  f.state.contextOverride = () => {
    throw new Error('configuration unavailable');
  };
  expectOverall(await f.app.processSmimeMessage(f.process(message)), 'INVALID');
});

test('S/MIME real completed signature is not encrypted or released after current withdrawal', async () => {
  let f;
  const observed = instrument({
    sign() {
      f.state.knowledgeTime += 1;
      f.state.mailboxDecision = () => ({ overall: 'INVALID', reason: 'FIXTURE_BINDING_WITHDRAWN' });
    },
  });
  f = fixture(observed.wrapper);
  const result = expectOverall(
    await f.app.protectSmimeMessage(f.protect('SIGNED_AND_ENCRYPTED', textMessage)),
    'INVALID',
  );
  assert.equal(result.effectMayHaveOccurred, true);
  assert.equal(observed.counts.sign, 1);
  assert.equal(observed.counts.encrypt ?? 0, 0);
  noOutput(result);
});

test('S/MIME actual receiver decrypts an unchanged ordinary OpenSSL signed MIME entity', async () => {
  const f = fixture();
  const content = Buffer.from(
    'Content-Type: text/plain; charset=us-ascii\r\n\r\nOrdinary CLI body.\r\n',
  );
  const inner = ordinarySignedEntity(material, { content });
  assert.match(inner.toString('ascii'), /^MIME-Version:\s*1\.0\r?$/m);
  const encrypted = await backend.encrypt({
    content: inner,
    certificates: [material.recipient.der],
  });
  const decrypted = await backend.decrypt({
    cms: encrypted.cms,
    certificate: material.recipient.der,
    keyRef: 'recipient',
    expectedPublicKeyDER: c.spki(material.recipient.publicKey),
  });
  assert.deepEqual(decrypted.content, inner);
  const outerHeaders = [
    { name: 'from', value: 'alice@example.test', raw: Buffer.from('From: alice@example.test\r\n') },
  ];
  const { message } = await backend.packageCMS({
    cms: encrypted.cms,
    kind: 'AUTH_ENVELOPED_DATA',
    format: 'MESSAGE',
    outerHeaders,
  });
  const result = expectOverall(
    await f.app.processSmimeMessage(f.process(message, 'SIGNED_AND_ENCRYPTED')),
    'VALID',
  );
  assert.deepEqual(result.content.mime, content);
  assert.deepEqual(result.canonicalMimeHash, c.sha256(content));
  assert.deepEqual(result.authenticatedAuthor, identity(material.signer, 'alice@example.test'));
  assert.deepEqual(result.matchedRecipient, identity(material.recipient, 'bob@example.test'));
});

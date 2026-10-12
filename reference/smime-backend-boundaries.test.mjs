import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createSmimeBackend } from './smime-backend.mjs';
import { smimeMaterialFixture } from './smime-material-fixtures.mjs';
import * as c from './core.mjs';
import { entity } from './smime-application-fixtures.mjs';
import { ordinaryCMS, ordinarySignedEntity, replaceSignature } from './smime-message-fixtures.mjs';

let f;
let backend;
let rsaSigner;
before(() => {
  f = smimeMaterialFixture();
  rsaSigner = f.certificate('Ordinary RSA mail signer', { key: f.recipient });
  backend = createSmimeBackend({
    opensslPath: process.env.OPENSSL_BIN,
    opensslConfig: process.env.OPENSSL_CONF,
    ...(process.env.OPENSSL_MODULES ? { opensslModulePath: process.env.OPENSSL_MODULES } : {}),
    keyMap: { signer: f.signer.privateKey },
  });
});
after(() => f?.close());

for (const [method, input] of [
  ['prepareMimeMessage', { message: 'not bytes' }],
  ['parseProtectedMessage', { message: 'not bytes', format: 'MESSAGE' }],
  ['packageCMS', { cms: 'not bytes', kind: 'SIGNED_DATA', format: 'ENTITY' }],
  ['inspectVerifiedMime', { mime: 'not bytes' }],
]) {
  test(`S/MIME ${method} preserves the asynchronous error contract for invalid input`, async () => {
    let operation;
    assert.doesNotThrow(() => {
      operation = backend[method](input);
    });
    assert(operation instanceof Promise, 'The frozen adapter API returns a Promise');
    await assert.rejects(operation, (error) => {
      assert.equal(error.overall, 'INVALID');
      assert.equal(typeof error.code, 'string');
      return true;
    });
  });
}

const sign = (certificates) =>
  backend.sign({
    content: entity,
    certificate: f.signer.der,
    certificates,
    keyRef: 'signer',
    expectedPublicKeyDER: c.spki(f.signer.publicKey),
  });

test('S/MIME signer rejects sparse auxiliary certificate arrays as invalid input', async () => {
  const certificates = new Array(2);
  certificates[1] = f.root.der;
  await assert.rejects(
    () => sign(certificates),
    (error) => {
      assert.equal(error.overall, 'INVALID');
      return true;
    },
  );
});
test('S/MIME encryptor rejects sparse explicit recipient arrays without dropping a recipient', async () => {
  const certificates = new Array(2);
  certificates[1] = f.recipient.der;
  await assert.rejects(
    () => backend.encrypt({ content: entity, certificates }),
    (error) => {
      assert.equal(error.overall, 'INVALID');
      return true;
    },
  );
});
for (const count of [32, 33]) {
  test(`S/MIME signer enforces the ${count} raw auxiliary certificate boundary before deduplication`, async () => {
    const operation = () => sign(Array.from({ length: count }, () => Buffer.from(f.root.der)));
    if (count === 33) {
      await assert.rejects(operation, (error) => {
        assert.equal(error.overall, 'UNSUPPORTED');
        return true;
      });
      return;
    }
    const { cms } = await operation();
    const result = await backend.inspectCMS({ cms });
    assert.equal(result.overall, 'VALID');
    assert.deepEqual(result.content, entity);
    assert.deepEqual(result.certificates, [f.signer.der]);
  });
}

test('S/MIME complete legal multiple-author From is an unsupported identity grammar', async () => {
  const message = Buffer.from(
    'From: alice@example.test, bob@example.test\r\nSender: alice@example.test\r\n' +
      'Content-Type: text/plain\r\n\r\nMultiple authors.\r\n',
  );
  await assert.rejects(
    () => backend.prepareMimeMessage({ message }),
    (error) => {
      assert.equal(error.overall, 'UNSUPPORTED');
      return true;
    },
  );
});

test('S/MIME carrier preserves legal repeated custom fields and RFC field-name characters', async () => {
  const outerHeaders = [
    { name: 'from', value: 'alice@example.test', raw: Buffer.from('From: alice@example.test\r\n') },
    { name: 'x_trace', value: 'first', raw: Buffer.from('X_Trace: first\r\n') },
    { name: 'x_trace', value: 'second', raw: Buffer.from('X_Trace: second\r\n') },
  ];
  const cms = c.seq(c.integer(1));
  const { message } = await backend.packageCMS({
    cms,
    kind: 'SIGNED_DATA',
    format: 'MESSAGE',
    outerHeaders,
  });
  const parsed = await backend.parseProtectedMessage({ message, format: 'MESSAGE' });
  assert.deepEqual(parsed.cms, cms);
  assert.deepEqual(
    parsed.outerHeaders.filter((header) => header.name === 'x_trace').map((header) => header.value),
    ['first', 'second'],
  );
});

test('S/MIME carrier rejects an incomplete HeaderRecord with a typed error', async () => {
  const cms = c.seq(c.integer(1));
  await assert.rejects(
    () =>
      backend.packageCMS({
        cms,
        kind: 'SIGNED_DATA',
        format: 'MESSAGE',
        outerHeaders: [{ name: 'from', value: 'alice@example.test' }],
      }),
    (error) => {
      assert.equal(error.overall, 'INVALID');
      assert.equal(typeof error.code, 'string');
      return true;
    },
  );
});

test('S/MIME CMS exceeding 16 MiB is classified before parsing any content', async () => {
  let result;
  try {
    result = await backend.inspectCMS({ cms: Buffer.alloc(16777217) });
  } catch (error) {
    result = error;
  }
  assert.equal(result.overall, 'UNSUPPORTED');
  assert.equal(Object.hasOwn(result, 'content'), false);
});

for (const hash of ['sha256', 'sha512']) {
  test(`S/MIME ordinary mathematically valid RSA ${hash} remains an unsupported suite`, async () => {
    const cms = ordinaryCMS(f, { content: entity, leaf: rsaSigner, hash });
    const result = await backend.inspectCMS({ cms });
    assert.equal(result.overall, 'UNSUPPORTED', JSON.stringify(result.checks));
  });
  test(`S/MIME safely available bad RSA ${hash} math dominates the unselected suite`, async () => {
    const cms = replaceSignature(ordinaryCMS(f, { content: entity, leaf: rsaSigner, hash }));
    const result = await backend.inspectCMS({ cms });
    assert.equal(result.overall, 'INVALID', JSON.stringify(result.checks));
    assert(result.checks.some((check) => check.overall === 'INVALID'));
  });
}

test('S/MIME entity accepts the original OpenSSL MIME version without installing outer claims', async () => {
  const message = ordinarySignedEntity(f, { content: entity });
  assert.match(message.toString('ascii'), /^MIME-Version:\s*1\.0\r?$/m);
  const original = Buffer.from(message);
  const parsed = await backend.parseProtectedMessage({ message, format: 'ENTITY' });
  assert.deepEqual(message, original, 'The original OpenSSL bytes are not normalized in place');
  assert.deepEqual(parsed.outerHeaders, []);
  assert.deepEqual(parsed.headerClaims, { fromMailbox: null, senderMailbox: null });
  const facts = await backend.inspectCMS({ cms: parsed.cms });
  assert.equal(facts.overall, 'VALID');
  assert.deepEqual(facts.content, entity);
});

for (const variant of ['duplicate version', 'unsupported version', 'outer From', 'outer Subject']) {
  test(`S/MIME entity rejects ${variant} beside an otherwise valid OpenSSL signed carrier`, async () => {
    const original = ordinarySignedEntity(f, { content: entity });
    const text = original.toString('ascii');
    const version = text.match(/^MIME-Version:[^\r\n]*(\r?\n)/m);
    assert(version, 'The ordinary CLI emits its own MIME-Version field');
    const eol = version[1];
    const changed = Buffer.from(
      variant === 'duplicate version'
        ? version[0] + text
        : variant === 'unsupported version'
          ? text.replace(/^MIME-Version:[^\r\n]*/m, 'MIME-Version: 2.0')
          : `${variant === 'outer From' ? 'From: alice@example.test' : 'Subject: Unprotected'}${eol}${text}`,
    );
    await assert.rejects(
      () => backend.parseProtectedMessage({ message: changed, format: 'ENTITY' }),
      (error) => {
        assert.equal(error.overall, variant === 'unsupported version' ? 'UNSUPPORTED' : 'INVALID');
        return true;
      },
    );
  });
}

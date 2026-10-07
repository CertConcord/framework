import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, readFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import * as c from './core.mjs';
import { timestampRequest, parseTSTInfo } from './timestamp.mjs';
import { verifyExternalCMS } from './external-cms.mjs';
import {
  O,
  epoch,
  fixture,
  hash,
  cmsView,
  opensslAvailable,
  loadCAdES,
  absentCapability,
  unsignedValues,
  independentIndex,
  independentArchiveImprint,
  replaceUnsigned,
} from './cades-fixtures.mjs';
const api = await loadCAdES();
const available = { skip: !opensslAvailable && 'OpenSSL fixture producer is unavailable' };
let f;
before(() => {
  if (opensslAvailable) f = fixture();
});
after(() => f?.close());

test(
  'independent OpenSSL certificates and full CRLs cross-check with native X509 and strict DER parsers',
  available,
  () => {
    assert.match(f.run('version'), /^OpenSSL 3\./);
    for (const entry of [f.signer, f.tsa, f.successor]) {
      const cert = new X509Certificate(entry.der);
      assert(cert.verify(f.root.publicKey));
      assert.equal(cert.validFromDate.getTime() / 1000, epoch - 100);
      assert.deepEqual(cert.raw, entry.der);
    }
    const statuses = [f.opensslCRL(), f.crl(), f.crl({ utcTime: true })];
    for (const [index, crl] of statuses.entries()) {
      const path = f.file(`differential-${index}.crl.der`);
      writeFileSync(path, crl);
      f.run('crl', '-verify', '-inform', 'DER', '-in', path, '-CAfile', f.root.pemFile, '-noout');
      const [tbs, , signature] = c.parseDER(crl).children;
      assert(c.verify(tbs.raw, signature.value.subarray(1), f.root.publicKey));
    }
  },
);

test(
  'OpenSSL-generated RFC3161 token independently authenticates the selected imprint and critical TSA chain',
  available,
  () => {
    const request = timestampRequest(hash(f.content), {
      hashOID: O.sha256,
      policy: O.policy,
      nonce: 5678n,
    });
    const token = f.token(request, { genTime: epoch + 20 });
    writeFileSync(f.file('timestamp.der'), token);
    writeFileSync(f.file('timestamp.tsq'), request.der);
    f.run(
      'ts',
      '-verify',
      '-token_in',
      '-in',
      f.file('timestamp.der'),
      '-queryfile',
      f.file('timestamp.tsq'),
      '-CAfile',
      f.root.pemFile,
      '-untrusted',
      f.tsa.pemFile,
      '-attime',
      String(epoch + 30),
    );
    const info = parseTSTInfo(cmsView(token).embeddedContent);
    assert.equal(info.genTime, epoch + 20);
    assert.deepEqual(info.imprint, request.imprint);
    const verified = verifyExternalCMS(token, {
      certificate: f.tsa.der,
      expectedContentType: O.tstInfo,
    });
    assert.deepEqual(verified.content, cmsView(token).embeddedContent);
  },
);

test(
  'OpenSSL CMS verification proves original signature remains valid after independently encoded unsigned ATS augmentation',
  available,
  () => {
    writeFileSync(f.file('document.bin'), f.content);
    f.run(
      'cms',
      '-sign',
      '-cades',
      '-binary',
      '-in',
      f.file('document.bin'),
      '-signer',
      f.signer.pemFile,
      '-inkey',
      f.signer.keyFile,
      '-certfile',
      f.root.pemFile,
      '-md',
      'sha256',
      '-outform',
      'DER',
      '-out',
      f.file('base.der'),
    );
    const original = readFileSync(f.file('base.der')),
      index = independentIndex(original);
    const imprint = independentArchiveImprint(original, f.content, index);
    const token = replaceUnsigned(
      f.token({ hashOID: O.sha256, imprint, policy: O.policy, nonce: 5679n }),
      O.index,
      [index],
    );
    const augmented = replaceUnsigned(original, O.archiveTimestamp, [token]);
    writeFileSync(f.file('augmented.der'), augmented);
    f.run(
      'cms',
      '-verify',
      '-noverify',
      '-binary',
      '-inform',
      'DER',
      '-in',
      f.file('augmented.der'),
      '-content',
      f.file('document.bin'),
      '-out',
      f.file('verified.bin'),
    );
    assert.deepEqual(readFileSync(f.file('verified.bin')), f.content);
    assert.deepEqual(
      cmsView(augmented)
        .fields.slice(0, 6)
        .map((n) => n.raw),
      cmsView(original)
        .fields.slice(0, 6)
        .map((n) => n.raw),
    );
    // -noverify checks CMS cryptography only; this fixture is not asserted to meet a Baseline level.
  },
);

test(
  'OpenSSL independently parses and verifies every selected runtime-produced CAdES lifecycle stage',
  {
    skip: !api ? absentCapability : !opensslAvailable && 'OpenSSL fixture producer is unavailable',
  },
  () => {
    writeFileSync(f.file('document.bin'), f.content);
    for (const [level, cms] of Object.entries(f.lifecycle(api))) {
      writeFileSync(f.file(`${level}.der`), cms);
      f.run('cms', '-cmsout', '-print', '-inform', 'DER', '-in', f.file(`${level}.der`));
      f.run(
        'cms',
        '-verify',
        '-cades',
        '-binary',
        '-inform',
        'DER',
        '-in',
        f.file(`${level}.der`),
        '-content',
        f.file('document.bin'),
        '-CAfile',
        f.root.pemFile,
        '-purpose',
        'any',
        '-attime',
        String(epoch + 40),
        '-out',
        f.file('verified.bin'),
      );
      assert.deepEqual(readFileSync(f.file('verified.bin')), f.content);
      for (const token of [
        ...unsignedValues(cms, O.signatureTimestamp),
        ...unsignedValues(cms, O.archiveTimestamp),
      ]) {
        const info = parseTSTInfo(cmsView(token).embeddedContent);
        writeFileSync(f.file('retained-token.der'), token);
        f.run(
          'ts',
          '-verify',
          '-token_in',
          '-in',
          f.file('retained-token.der'),
          '-digest',
          info.imprint.toString('hex'),
          '-CAfile',
          f.root.pemFile,
          '-untrusted',
          f.tsa.pemFile,
          '-attime',
          String(epoch + 40),
        );
      }
    }
  },
);

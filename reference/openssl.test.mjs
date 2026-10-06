import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { resolve, join, sep } from 'node:path';
import { X509Certificate } from 'node:crypto';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { verifyExternalTimestampToken } from './archive.mjs';
import { createCSR } from './enrollment.mjs';
import { issueCRL } from './revocation.mjs';
import { runPasskeyDemo } from './passkey-demo.mjs';
import { encryptCMS, decryptCMS } from './protection.mjs';
const executable = process.env.OPENSSL_BIN ?? 'openssl';
const available = spawnSync(executable, ['version'], { encoding: 'utf8' }).status === 0;
const help = available ? spawnSync(executable, ['cms', '-help'], { encoding: 'utf8' }) : {};
const kemCMSAvailable = available && (help.stdout + help.stderr).includes('-recip_kdf');
if (!available && process.env.CERTCONCORD_REQUIRE_OPENSSL === '1')
  throw Error('OpenSSL is required by this test environment');
if (!kemCMSAvailable && process.env.CERTCONCORD_REQUIRE_CMS_KEM === '1')
  throw Error('OpenSSL CMS KEM support is required by this test environment');
const pem = (label, b) =>
  `-----BEGIN ${label}-----\n${b
    .toString('base64')
    .match(/.{1,64}/g)
    .join('\n')}\n-----END ${label}-----\n`;
test(
  'independent OpenSSL and reference exchange ML-KEM AuthEnvelopedData in both directions',
  { skip: !kemCMSAvailable && 'OpenSSL 3.6 or later with CMS KEM support is required' },
  () => {
    const runtime = resolve('.runtime');
    mkdirSync(runtime, { recursive: true });
    const dir = mkdtempSync(join(runtime, 'openssl-kem-'));
    const file = (name) => join(dir, name);
    const run = (...args) => execFileSync(executable, args, { stdio: 'pipe' });
    try {
      for (const algorithm of ['ml-kem-768', 'ml-kem-1024']) {
        const ca = c.generate('ml-dsa-87'),
          recipient = c.generate(algorithm);
        const certificate = p.issueCertificate(
          {
            publicKey: recipient.publicKey,
            subject: p.name('Synthetic KEM Recipient'),
            issuer: p.name('Synthetic Issuer'),
            serial: 1,
            profileID: 'CERTCONCORD-DOC-ENC-v1',
          },
          ca.privateKey,
        );
        const subjectKeyIdentifier = c.parseDER(
          p.parseCertificate(certificate).extensions.get('2.5.29.14').value,
        ).value;
        const plaintext = Buffer.from('Independent CMS KEM encryption: ' + algorithm);
        writeFileSync(file('recipient.pem'), pem('CERTIFICATE', certificate));
        writeFileSync(
          file('key.pem'),
          recipient.privateKey.export({ type: 'pkcs8', format: 'pem' }),
        );
        writeFileSync(file('plaintext.bin'), plaintext);
        writeFileSync(
          file('reference.der'),
          encryptCMS(plaintext, [{ publicKey: recipient.publicKey, subjectKeyIdentifier }]),
        );
        run(
          'cms',
          '-decrypt',
          '-debug_decrypt',
          '-binary',
          '-inform',
          'DER',
          '-in',
          file('reference.der'),
          '-recip',
          file('recipient.pem'),
          '-inkey',
          file('key.pem'),
          '-out',
          file('decoded.bin'),
        );
        assert.deepEqual(readFileSync(file('decoded.bin')), plaintext);
        for (const ukm of [undefined, '00'.repeat(32)]) {
          run(
            'cms',
            '-encrypt',
            '-binary',
            '-in',
            file('plaintext.bin'),
            '-outform',
            'DER',
            '-out',
            file('openssl.der'),
            '-aes-256-gcm',
            '-aes256-wrap',
            '-keyid',
            '-recip',
            file('recipient.pem'),
            '-recip_kdf',
            'HKDF-SHA256',
            ...(ukm === undefined ? [] : ['-recip_ukm', ukm]),
          );
          assert.deepEqual(
            decryptCMS(readFileSync(file('openssl.der')), {
              privateKey: recipient.privateKey,
              subjectKeyIdentifier,
            }),
            plaintext,
          );
        }
      }
    } finally {
      assert(resolve(dir).startsWith(runtime + sep));
      rmSync(dir, { recursive: true, force: true });
    }
  },
);
test(
  'independent OpenSSL verifies the Passkey document-key PKCS10 and ECDSA CMS bytes',
  { skip: !available },
  async () => {
    const result = await runPasskeyDemo({ algorithm: -300, version: 'previewSign-4' });
    const runtime = resolve('.runtime');
    mkdirSync(runtime, { recursive: true });
    const dir = mkdtempSync(join(runtime, 'openssl-passkey-'));
    try {
      writeFileSync(join(dir, 'request.der'), result.csr);
      writeFileSync(join(dir, 'signature.der'), result.cms);
      writeFileSync(join(dir, 'document.bin'), result.document);
      execFileSync(
        executable,
        ['req', '-verify', '-inform', 'DER', '-in', join(dir, 'request.der'), '-noout'],
        { stdio: 'pipe' },
      );
      execFileSync(
        executable,
        [
          'cms',
          '-verify',
          '-noverify',
          '-binary',
          '-inform',
          'DER',
          '-in',
          join(dir, 'signature.der'),
          '-content',
          join(dir, 'document.bin'),
          '-out',
          join(dir, 'verified.bin'),
        ],
        { stdio: 'pipe' },
      );
      assert.deepEqual(readFileSync(join(dir, 'verified.bin')), result.document);
    } finally {
      assert(resolve(dir).startsWith(runtime + sep));
      rmSync(dir, { recursive: true, force: true });
    }
  },
);
test(
  'independent OpenSSL validates RRA ML-DSA CSR/CMS/CRL; RRA validates OpenSSL RSA TSA CMS',
  { skip: !available },
  () => {
    const runtime = resolve('.runtime');
    mkdirSync(runtime, { recursive: true });
    const dir = mkdtempSync(join(runtime, 'openssl-')),
      file = (n) => join(dir, n),
      run = (...args) => execFileSync(executable, args, { stdio: 'pipe' });
    try {
      const key = c.generate(),
        ca = c.generate('ml-dsa-87'),
        subject = p.name('Synthetic Subject'),
        issuer = p.name('Synthetic Issuer'),
        cert = p.issueCertificate(
          { publicKey: key.publicKey, subject, issuer, serial: 1 },
          ca.privateKey,
        ),
        caCert = p.issueCertificate(
          { publicKey: ca.publicKey, subject: issuer, issuer, serial: 2, ca: true },
          ca.privateKey,
        ),
        csr = createCSR({ subject, publicKey: key.publicKey, privateKey: key.privateKey }),
        cms = p.signCMS(
          { content: Buffer.from('independent interop'), certificate: cert },
          key.privateKey,
        ),
        crl = issueCRL({ issuer, privateKey: ca.privateKey, number: 1, entries: [] });
      for (const [n, b] of [
        ['csr.der', csr],
        ['cms.der', cms],
        ['crl.der', crl],
        ['ca.pem', pem('CERTIFICATE', caCert)],
      ])
        writeFileSync(file(n), b);
      run('req', '-inform', 'DER', '-in', file('csr.der'), '-verify', '-noout');
      run(
        'cms',
        '-verify',
        '-binary',
        '-inform',
        'DER',
        '-in',
        file('cms.der'),
        '-noverify',
        '-out',
        file('verified.bin'),
      );
      assert.equal(readFileSync(file('verified.bin'), 'utf8'), 'independent interop');
      run(
        'crl',
        '-inform',
        'DER',
        '-in',
        file('crl.der'),
        '-CAfile',
        file('ca.pem'),
        '-verify',
        '-noout',
      );
      run(
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-keyout',
        file('rsa.key'),
        '-out',
        file('rsa.pem'),
        '-days',
        '1',
        '-subj',
        '/CN=Synthetic OpenSSL TSA',
        '-addext',
        'basicConstraints=critical,CA:false',
        '-addext',
        'keyUsage=critical,digitalSignature',
        '-addext',
        'extendedKeyUsage=critical,timeStamping',
      );
      const imprint = c.sha512(Buffer.from('frozen evidence')),
        nonce = 37n,
        policy = '1.2.3.4',
        info = c.seq(
          c.integer(1),
          c.oid(policy),
          c.seq(p.algID(p.OID.sha512), c.octet(imprint)),
          c.integer(1),
          p.generalizedTime(c.now()),
          c.integer(nonce),
        );
      writeFileSync(file('tstinfo.der'), info);
      run(
        'cms',
        '-sign',
        '-cades',
        '-nodetach',
        '-binary',
        '-in',
        file('tstinfo.der'),
        '-signer',
        file('rsa.pem'),
        '-inkey',
        file('rsa.key'),
        '-outform',
        'DER',
        '-out',
        file('tsa.der'),
        '-md',
        'sha256',
        '-econtent_type',
        p.OID.tstInfo,
      );
      const x509 = new X509Certificate(readFileSync(file('rsa.pem'))),
        token = readFileSync(file('tsa.der'));
      assert.equal(
        verifyExternalTimestampToken(token, {
          imprint,
          nonce,
          policy,
          certificate: x509.raw,
          issuerKey: x509.publicKey,
        }).nonce,
        nonce,
      );
      assert.throws(
        () =>
          verifyExternalTimestampToken(token, {
            imprint: c.random(64),
            nonce,
            policy,
            certificate: x509.raw,
            issuerKey: x509.publicKey,
          }),
        /BINDING/,
      );
    } finally {
      const target = resolve(dir);
      assert(target.startsWith(runtime + sep));
      rmSync(target, { recursive: true, force: true });
    }
  },
);

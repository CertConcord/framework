import { spawn } from 'node:child_process';
import { createPrivateKey, createPublicKey, KeyObject, X509Certificate } from 'node:crypto';
import { mkdtemp, writeFile, rm, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join } from 'node:path';
import {
  bytes,
  check,
  failure,
  hash,
  LIMITS,
  outcome,
  workerCall,
} from './smime-adapter-common.mjs';

const structureWorker = new URL('./smime-cms-worker.mjs', import.meta.url);
const equal = (a, b) =>
  a instanceof Uint8Array && b instanceof Uint8Array && Buffer.from(a).equals(Buffer.from(b));
const pem = (der) =>
  `-----BEGIN CERTIFICATE-----\n${der
    .toString('base64')
    .match(/.{1,64}/g)
    .join('\n')}\n-----END CERTIFICATE-----\n`;
function certificateList(values = []) {
  check(
    Array.isArray(values) && values.length <= LIMITS.certificates,
    'SMIME_CERTIFICATE_LIMIT',
    'UNSUPPORTED',
  );
  let total = 0;
  return Array.from(values, (value) => {
    const raw = bytes(value, LIMITS.content);
    total += raw.length;
    check(total <= LIMITS.input, 'SMIME_SIZE_LIMIT', 'UNSUPPORTED');
    try {
      new X509Certificate(raw);
    } catch {
      throw failure('SMIME_CERTIFICATE_ENCODING');
    }
    return raw;
  });
}
const inspectStructure = (cms, recipientCertificates = []) =>
  workerCall(structureWorker, 'inspect', {
    cms: bytes(cms),
    recipientCertificates: certificateList(recipientCertificates),
  });

export function createSmimeCMS({
  opensslPath,
  opensslConfig,
  opensslModulePath,
  keyMap = {},
} = {}) {
  check(
    typeof opensslPath === 'string' &&
      isAbsolute(opensslPath) &&
      typeof opensslConfig === 'string' &&
      isAbsolute(opensslConfig),
    'SMIME_OPENSSL_CONFIGURATION',
  );
  check(
    opensslModulePath === undefined ||
      (typeof opensslModulePath === 'string' && isAbsolute(opensslModulePath)),
    'SMIME_OPENSSL_CONFIGURATION',
  );
  check(
    keyMap &&
      typeof keyMap === 'object' &&
      !Array.isArray(keyMap) &&
      [Object.prototype, null].includes(Object.getPrototypeOf(keyMap)),
    'SMIME_KEY_MAP',
  );
  const keys = new Map();
  const names = Object.keys(keyMap);
  check(names.length <= 128, 'SMIME_KEY_MAP_LIMIT', 'UNSUPPORTED');
  for (const name of names) {
    check(name.length > 0 && name.length <= 256, 'SMIME_KEY_REFERENCE');
    const entry = Object.getOwnPropertyDescriptor(keyMap, name);
    check(entry && Object.hasOwn(entry, 'value'), 'SMIME_KEY_MAP');
    const input = entry.value;
    let encoded;
    try {
      if (input instanceof KeyObject) {
        check(input.type === 'private', 'SMIME_PRIVATE_KEY_REQUIRED');
        encoded = input.export({ format: 'der', type: 'pkcs8' });
        keys.set(name, createPrivateKey({ key: encoded, format: 'der', type: 'pkcs8' }));
      } else {
        encoded = bytes(input, 65536);
        check(
          /^-{5}BEGIN PRIVATE KEY-{5}(?:\r?\n)/.test(encoded.toString('latin1')),
          'SMIME_PKCS8_KEY_REQUIRED',
        );
        keys.set(name, createPrivateKey({ key: encoded, format: 'pem', type: 'pkcs8' }));
      }
    } catch (error) {
      throw error.overall ? error : failure('SMIME_PRIVATE_KEY_ENCODING');
    } finally {
      encoded?.fill(0);
    }
  }
  const environment = { ...process.env, OPENSSL_CONF: opensslConfig };
  for (const name of [
    'SSL_CERT_FILE',
    'SSL_CERT_DIR',
    'OPENSSL_CONF_INCLUDE',
    'OPENSSL_ENGINES',
    'OPENSSL_MODULES',
  ])
    delete environment[name];
  if (opensslModulePath) environment.OPENSSL_MODULES = opensslModulePath;

  function run(args, { secret, maximum = LIMITS.input } = {}) {
    return new Promise((resolve, reject) => {
      let child;
      try {
        child = spawn(opensslPath, args, {
          env: environment,
          shell: false,
          windowsHide: true,
          stdio: ['pipe', 'pipe', 'pipe'],
        });
      } catch {
        reject(failure('SMIME_OPENSSL_UNAVAILABLE', 'INDETERMINATE'));
        return;
      }
      let outputLength = 0,
        diagnosticLength = 0,
        stopped,
        done = false;
      const chunks = [];
      const stop = (code) => {
        stopped ??= failure(code, 'INDETERMINATE');
        child.kill('SIGKILL');
      };
      const timer = setTimeout(() => stop('SMIME_OPENSSL_TIMEOUT'), LIMITS.timeout);
      child.stdout.on('data', (chunk) => {
        outputLength += chunk.length;
        if (outputLength > maximum) stop('SMIME_OPENSSL_OUTPUT_LIMIT');
        else if (!stopped) chunks.push(Buffer.from(chunk));
      });
      child.stderr.on('data', (chunk) => {
        diagnosticLength += chunk.length;
        if (diagnosticLength > LIMITS.diagnostics) stop('SMIME_OPENSSL_DIAGNOSTIC_LIMIT');
      });
      child.stdin.on('error', () => {}); // Early CLI failure may close its input pipe.
      child.once('error', () => {
        stopped ??= failure('SMIME_OPENSSL_UNAVAILABLE', 'INDETERMINATE');
      });
      child.once('close', (status) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        if (stopped) {
          for (const chunk of chunks) chunk.fill(0);
          reject(stopped);
        } else resolve({ status, output: Buffer.concat(chunks, outputLength) });
      });
      child.stdin.end(secret);
    });
  }
  let ready;
  function available() {
    // Cache only executable capability, never a trust or permission decision.
    ready ??= run(['version'], { maximum: LIMITS.diagnostics }).then(({ status, output }) => {
      check(status === 0, 'SMIME_OPENSSL_UNAVAILABLE', 'INDETERMINATE');
      check(
        /^OpenSSL 3\.6\.5(?:\s|$)/.test(output.toString('ascii')),
        'SMIME_OPENSSL_VERSION_UNSUPPORTED',
        'UNSUPPORTED',
      );
    });
    return ready;
  }
  async function temporary(action) {
    let directory;
    try {
      directory = await mkdtemp(join(tmpdir(), 'certconcord-smime-'));
      await chmod(directory, 0o700);
      const put = async (name, content) => {
        const path = join(directory, name);
        await writeFile(path, content, { mode: 0o600, flag: 'wx' });
        return path;
      };
      return await action(put);
    } finally {
      if (directory) await rm(directory, { recursive: true, force: true });
    }
  }
  function key(keyRef, expectedPublicKeyDER, certificate, use) {
    check(typeof keyRef === 'string' && keys.has(keyRef), 'SMIME_KEY_UNAVAILABLE', 'INDETERMINATE');
    const actual = keys.get(keyRef),
      publicKeyDER = createPublicKey(actual).export({ type: 'spki', format: 'der' });
    if (expectedPublicKeyDER !== undefined) {
      check(equal(publicKeyDER, bytes(expectedPublicKeyDER, 65536)), 'SMIME_PRIVATE_KEY_BINDING');
      check(
        equal(
          publicKeyDER,
          new X509Certificate(certificate).publicKey.export({ type: 'spki', format: 'der' }),
        ),
        'SMIME_CERTIFICATE_KEY_BINDING',
      );
    }
    if (use === 'sign')
      check(
        actual.asymmetricKeyType === 'ec' &&
          actual.asymmetricKeyDetails?.namedCurve === 'prime256v1',
        'SMIME_SIGNER_KEY_UNSUPPORTED',
        'UNSUPPORTED',
      );
    if (use === 'decrypt')
      check(
        actual.asymmetricKeyType === 'rsa' &&
          [3072, 4096].includes(actual.asymmetricKeyDetails?.modulusLength),
        'SMIME_RECIPIENT_KEY_UNSUPPORTED',
        'UNSUPPORTED',
      );
    return { actual, publicKeyDER };
  }
  async function describeKey({ keyRef } = {}) {
    const snapshot = key(keyRef);
    await available();
    return { publicKeyDER: Buffer.from(snapshot.publicKeyDER) };
  }
  async function sign({
    content,
    certificate,
    certificates = [],
    keyRef,
    expectedPublicKeyDER,
    ...extra
  } = {}) {
    check(Object.keys(extra).length === 0, 'SMIME_SIGN_OPTIONS');
    content = bytes(content, LIMITS.content);
    [certificate] = certificateList([certificate]);
    certificateList(certificates); // Auxiliary public input is bounded; only the signer is embedded.
    const snapshot = key(keyRef, expectedPublicKeyDER, certificate, 'sign');
    check(expectedPublicKeyDER !== undefined, 'SMIME_PRIVATE_KEY_BINDING');
    // POSIX mode bits provide the selected private-file isolation. Native
    // Windows needs a dedicated ACL implementation before private operations.
    check(process.platform !== 'win32', 'SMIME_PRIVATE_FILE_ISOLATION_UNSUPPORTED', 'UNSUPPORTED');
    await available();
    const secret = Buffer.from(snapshot.actual.export({ type: 'pkcs8', format: 'pem' }));
    try {
      return await temporary(async (put) => {
        const source = await put('content.bin', content),
          cert = await put('signer.pem', pem(certificate)),
          privateFile = await put('key.pem', secret);
        const { status, output } = await run([
          'cms',
          '-sign',
          '-binary',
          '-nodetach',
          '-outform',
          'DER',
          '-md',
          'sha256',
          '-cades',
          '-nosmimecap',
          '-provider',
          'default',
          '-in',
          source,
          '-signer',
          cert,
          '-inkey',
          privateFile,
        ]);
        check(status === 0, 'SMIME_SIGN_FAILED', 'INDETERMINATE');
        const inspected = await inspectStructure(output);
        check(inspected.overall === 'VALID', inspected.reason, inspected.overall);
        check(
          equal(inspected.content, content) && equal(inspected.certificate, certificate),
          'SMIME_SIGN_OUTPUT_BINDING',
        );
        return { cms: output };
      });
    } finally {
      secret.fill(0);
    }
  }
  async function inspectCMS({ cms, recipientCertificates = [] } = {}) {
    cms = bytes(cms);
    recipientCertificates = certificateList(recipientCertificates);
    const inspected = await inspectStructure(cms, recipientCertificates);
    const mathSuite =
      (inspected.signer?.hashOID === '2.16.840.1.101.3.4.2.1' &&
        inspected.signer?.signatureOID === '1.2.840.10045.4.3.2') ||
      (['2.16.840.1.101.3.4.2.1', '2.16.840.1.101.3.4.2.3'].includes(inspected.signer?.hashOID) &&
        [
          '1.2.840.113549.1.1.1', // rsaEncryption with the declared CMS digest
          '1.2.840.113549.1.1.11', // sha256WithRSAEncryption
          '1.2.840.113549.1.1.13', // sha512WithRSAEncryption
        ].includes(inspected.signer?.signatureOID));
    if (
      inspected.kind === 'SIGNED_DATA' &&
      inspected.certificate &&
      inspected.content !== undefined &&
      mathSuite
    ) {
      try {
        await available();
        await temporary(async (put) => {
          const input = await put('message.der', cms),
            cert = await put('signer.pem', pem(inspected.certificate));
          const { status, output } = await run([
            'cms',
            '-verify',
            '-binary',
            '-inform',
            'DER',
            '-in',
            input,
            '-noverify',
            '-nointern',
            '-certfile',
            cert,
            '-no-CAfile',
            '-no-CApath',
            '-no-CAstore',
            '-provider',
            'default',
          ]);
          if (status === 0) {
            inspected.checks.push({
              overall: equal(output, inspected.content) ? 'VALID' : 'INVALID',
              reason: equal(output, inspected.content)
                ? 'SMIME_OPENSSL_SIGNATURE_VALID'
                : 'SMIME_OPENSSL_CONTENT_BINDING',
            });
          } else
            inspected.checks.push({
              overall: status === 4 ? 'INVALID' : 'INDETERMINATE',
              reason:
                status === 4 ? 'SMIME_OPENSSL_SIGNATURE_INVALID' : 'SMIME_OPENSSL_VERIFY_FAILED',
            });
          output.fill(0);
        });
      } catch (error) {
        inspected.checks.push({
          overall: error.overall ?? 'INDETERMINATE',
          reason: error.code ?? 'SMIME_OPENSSL_UNAVAILABLE',
        });
      }
    }
    return { ...inspected, ...outcome(inspected.checks) };
  }
  async function encrypt({ content, certificates } = {}) {
    content = bytes(content);
    certificates = certificateList(certificates);
    check(certificates.length > 0, 'SMIME_RECIPIENT_REQUIRED');
    const identities = new Set();
    for (const certificate of certificates) {
      const publicKey = new X509Certificate(certificate).publicKey;
      check(
        publicKey.asymmetricKeyType === 'rsa' &&
          [3072, 4096].includes(publicKey.asymmetricKeyDetails?.modulusLength),
        'SMIME_RECIPIENT_KEY_UNSUPPORTED',
        'UNSUPPORTED',
      );
      const id = publicKey.export({ type: 'spki', format: 'der' }).toString('hex');
      check(!identities.has(id), 'SMIME_DUPLICATE_RECIPIENT_KEY');
      identities.add(id);
    }
    await available();
    return temporary(async (put) => {
      const source = await put('content.bin', content);
      const args = [
        'cms',
        '-encrypt',
        '-binary',
        '-outform',
        'DER',
        '-aes-256-gcm',
        '-provider',
        'default',
        '-in',
        source,
      ];
      for (const [i, certificate] of certificates.entries()) {
        const path = await put(`recipient-${i}.pem`, pem(certificate));
        args.push(
          '-recip',
          path,
          '-keyopt',
          'rsa_padding_mode:oaep',
          '-keyopt',
          'rsa_oaep_md:sha256',
          '-keyopt',
          'rsa_mgf1_md:sha256',
        );
      }
      const { status, output } = await run(args);
      check(status === 0, 'SMIME_ENCRYPT_FAILED', 'INDETERMINATE');
      const inspected = await inspectStructure(output, certificates);
      check(inspected.overall === 'VALID', inspected.reason, inspected.overall);
      check(
        inspected.recipients.length === certificates.length &&
          inspected.recipientMatches.length === certificates.length &&
          certificates.every((cert) =>
            inspected.recipientMatches.some((match) => equal(match.certificateHash, hash(cert))),
          ),
        'SMIME_ENCRYPT_RECIPIENT_BINDING',
      );
      return { cms: output };
    });
  }
  async function decrypt({ cms, certificate, keyRef, expectedPublicKeyDER } = {}) {
    cms = bytes(cms);
    [certificate] = certificateList([certificate]);
    const snapshot = key(keyRef, expectedPublicKeyDER, certificate, 'decrypt');
    check(expectedPublicKeyDER !== undefined, 'SMIME_PRIVATE_KEY_BINDING');
    check(process.platform !== 'win32', 'SMIME_PRIVATE_FILE_ISOLATION_UNSUPPORTED', 'UNSUPPORTED');
    const inspected = await inspectStructure(cms, [certificate]);
    check(
      inspected.kind === 'AUTH_ENVELOPED_DATA',
      'SMIME_DECRYPT_TYPE_UNSUPPORTED',
      'UNSUPPORTED',
    );
    check(inspected.overall === 'VALID', inspected.reason, inspected.overall);
    check(inspected.recipientMatches.length === 1, 'SMIME_RECIPIENT_BINDING');
    await available();
    const secret = Buffer.from(snapshot.actual.export({ type: 'pkcs8', format: 'pem' }));
    try {
      return await temporary(async (put) => {
        const input = await put('message.der', cms),
          cert = await put('recipient.pem', pem(certificate)),
          privateFile = await put('key.pem', secret);
        const { status, output } = await run([
          'cms',
          '-decrypt',
          '-binary',
          '-inform',
          'DER',
          '-in',
          input,
          '-recip',
          cert,
          '-inkey',
          privateFile,
        ]);
        if (status !== 0) {
          output.fill(0);
          throw failure(
            'SMIME_AUTHENTICATED_DECRYPTION_FAILED',
            status === 4 ? 'INVALID' : 'INDETERMINATE',
          );
        }
        return { content: output, recipient: inspected.recipientMatches[0] };
      });
    } finally {
      secret.fill(0);
    }
  }
  return Object.freeze({ describeKey, sign, inspectCMS, encrypt, decrypt });
}

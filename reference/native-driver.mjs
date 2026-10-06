import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { createPublicKey } from 'node:crypto';
import { requireThat, b64u, unb64u, sha256, spki, equal, verify } from './core.mjs';
import { parseJSON } from './json.mjs';
import { p1363ToDER, derToP1363 } from './providers.mjs';

export class AppleNativeProvider {
  constructor({ executable, executableSHA256, keys = new Map(), reason }) {
    requireThat(
      process.platform === 'darwin' &&
        isAbsolute(executable) &&
        typeof reason === 'string' &&
        reason.length > 0,
      'APPLE_PLATFORM_OR_CONTEXT',
    );
    requireThat(
      sha256(readFileSync(executable)).toString('hex') === executableSHA256,
      'NATIVE_EXECUTABLE_PIN',
    );
    Object.assign(this, { executable, keys, reason });
    this.id = 'apple-secure-enclave-v1';
  }
  async call(request) {
    return new Promise((resolve, reject) => {
      const child = spawn(this.executable, [], {
          stdio: ['pipe', 'pipe', 'pipe'],
          windowsHide: true,
        }),
        chunks = [];
      let size = 0,
        done = false;
      const timer = setTimeout(() => {
        child.kill();
        reject(Error('NATIVE_TIMEOUT'));
      }, 120000);
      child.stdout.on('data', (b) => {
        size += b.length;
        if (size > 65536) {
          child.kill();
          reject(Error('NATIVE_RESPONSE_LIMIT'));
        } else chunks.push(b);
      });
      child.stderr.resume();
      child.on('error', (e) => {
        clearTimeout(timer);
        reject(e);
      });
      child.on('close', (code) => {
        clearTimeout(timer);
        try {
          requireThat(code === 0, 'NATIVE_OPERATION_FAILED');
          resolve(parseJSON(Buffer.concat(chunks).toString('utf8')));
        } catch (e) {
          reject(e);
        }
      });
      child.stdin.end(JSON.stringify(request));
    });
  }
  async generate({ keyRef }) {
    requireThat(!this.keys.has(keyRef), 'NATIVE_DUPLICATE_KEY');
    const r = await this.call({ action: 'generate', alias: keyRef }),
      publicKey = createPublicKey({ key: r.jwk, format: 'jwk' });
    this.keys.set(keyRef, publicKey);
    return publicKey;
  }
  async capabilities(keyRef) {
    const pin = this.keys.get(keyRef);
    requireThat(pin, 'NATIVE_KEY_PIN');
    const r = await this.call({ action: 'public', alias: keyRef }),
      publicKey = createPublicKey({ key: r.jwk, format: 'jwk' });
    requireThat(equal(spki(pin), spki(publicKey)), 'NATIVE_KEY_REPLACED');
    return {
      publicKey,
      algorithm: 'ec',
      input: 'MESSAGE',
      custody: 'SECURE_ENCLAVE_UNATTESTED',
      localUV: !keyRef.startsWith('certconcord-managed-'),
      exportable: false,
    };
  }
  async sign({ keyRef, tbs }) {
    const c = await this.capabilities(keyRef),
      r = await this.call({ action: 'sign', alias: keyRef, tbs: b64u(tbs), reason: this.reason }),
      signature = p1363ToDER(unb64u(r.signature));
    requireThat(verify(tbs, signature, c.publicKey), 'NATIVE_SIGNATURE');
    return signature;
  }
}
export function holderSigner(provider, keyRef) {
  return async (tbs) => {
    const c = await provider.capabilities(keyRef);
    requireThat(c.algorithm === 'ec', 'HOLDER_ALGORITHM');
    return derToP1363(await provider.sign({ keyRef, tbs }));
  };
}

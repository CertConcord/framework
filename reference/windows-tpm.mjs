import koffi from 'koffi';
import { createPublicKey } from 'node:crypto';
import { requireThat, b64u, sha256, equal, spki, verify } from './core.mjs';
import { p1363ToDER } from './providers.mjs';
import {
  readPublicCommand,
  readPublicResponse,
  certifyCommand,
  certifyResponse,
} from './tpm-wire.mjs';

export class WindowsTPMProvider {
  constructor({ keys = new Map() } = {}) {
    requireThat(process.platform === 'win32', 'WINDOWS_REQUIRED');
    this.keys = keys;
    this.id = 'windows-tpm-cng-v1';
    this.lib = koffi.load('ncrypt.dll');
    this.api = {};
    for (const [n, signature] of Object.entries({
      OpenStorageProvider: '_Out_ uintptr_t * phProvider, str16 name, uint32_t flags',
      CreatePersistedKey:
        'uintptr_t provider, _Out_ uintptr_t * phKey, str16 algorithm, str16 name, uint32_t legacy, uint32_t flags',
      OpenKey:
        'uintptr_t provider, _Out_ uintptr_t * phKey, str16 name, uint32_t legacy, uint32_t flags',
      FinalizeKey: 'uintptr_t key, uint32_t flags',
      GetProperty:
        'uintptr_t key, str16 property, _Out_ uint8_t * output, uint32_t length, _Out_ uint32_t * written, uint32_t flags',
      SetProperty:
        'uintptr_t key, str16 property, uint8_t * input, uint32_t length, uint32_t flags',
      ExportKey:
        'uintptr_t key, uintptr_t exportKey, str16 blobType, void * parameters, _Out_ uint8_t * output, uint32_t length, _Out_ uint32_t * written, uint32_t flags',
      SignHash:
        'uintptr_t key, void * padding, uint8_t * digest, uint32_t digestLength, _Out_ uint8_t * output, uint32_t length, _Out_ uint32_t * written, uint32_t flags',
      FreeObject: 'uintptr_t handle',
    }))
      this.api[n] = this.lib.func('int32_t __stdcall NCrypt' + n + '(' + signature + ')');
    const h = [0];
    this.check(this.api.OpenStorageProvider(h, 'Microsoft Platform Crypto Provider', 0));
    this.provider = h[0];
  }
  check(status) {
    requireThat(status === 0, 'CNG_' + (status >>> 0).toString(16));
  }
  close() {
    if (this.provider) {
      this.api.FreeObject(this.provider);
      this.provider = 0;
    }
  }
  open(name) {
    requireThat(
      typeof name === 'string' && /^certconcord-[a-zA-Z0-9_-]{8,100}$/.test(name),
      'TPM_KEY_NAME',
    );
    const h = [0];
    this.check(this.api.OpenKey(this.provider, h, name, 0, 0));
    return h[0];
  }
  generate(name, { requireLocalUV = false } = {}) {
    requireThat(!requireLocalUV, 'UNSUPPORTED_LOCAL_UV');
    requireThat(/^certconcord-[a-zA-Z0-9_-]{8,100}$/.test(name), 'TPM_KEY_NAME');
    const h = [0];
    this.check(this.api.CreatePersistedKey(this.provider, h, 'ECDSA_P256', name, 0, 0));
    try {
      this.check(this.api.SetProperty(h[0], 'Export Policy', Buffer.alloc(4), 4, 0));
      this.check(this.api.SetProperty(h[0], 'Key Usage', Buffer.from([2, 0, 0, 0]), 4, 0));
      this.check(this.api.FinalizeKey(h[0], 0));
      const publicKey = this.publicKey(h[0]);
      this.keys.set(name, publicKey);
      return publicKey;
    } finally {
      this.api.FreeObject(h[0]);
    }
  }
  publicKey(handle) {
    const size = [0];
    this.check(this.api.ExportKey(handle, 0, 'ECCPUBLICBLOB', null, null, 0, size, 0));
    requireThat(size[0] === 72, 'TPM_PUBLIC_BLOB');
    const b = Buffer.alloc(size[0]);
    this.check(this.api.ExportKey(handle, 0, 'ECCPUBLICBLOB', null, b, b.length, size, 0));
    requireThat(b.readUInt32LE(0) === 0x31534345 && b.readUInt32LE(4) === 32, 'TPM_CURVE');
    return createPublicKey({
      key: { kty: 'EC', crv: 'P-256', x: b64u(b.subarray(8, 40)), y: b64u(b.subarray(40, 72)) },
      format: 'jwk',
    });
  }
  property(handle, name) {
    const out = Buffer.alloc(64),
      size = [0];
    this.check(this.api.GetProperty(handle, name, out, out.length, size, 0));
    requireThat(size[0] > 0 && size[0] <= out.length, 'TPM_PROPERTY_SIZE');
    return out.subarray(0, size[0]);
  }
  platformHandle(handle, provider = false) {
    const value = this.property(handle, 'PCP_PLATFORMHANDLE');
    if (provider) {
      requireThat(value.length === koffi.sizeof('uintptr_t'), 'TPM_CONTEXT_SIZE');
      return value.length === 8 ? value.readBigUInt64LE() : value.readUInt32LE();
    }
    requireThat(value.length === 4, 'TPM_HANDLE_SIZE');
    return value.readUInt32LE();
  }
  submit(context, command) {
    this.tbsLibrary ??= koffi.load('tbs.dll');
    this.submitCommand ??= this.tbsLibrary.func(
      'uint32_t __stdcall Tbsip_Submit_Command(uintptr_t context, uint32_t locality, uint32_t priority, uint8_t * command, uint32_t length, _Out_ uint8_t * response, _Inout_ uint32_t * responseLength)',
    );
    const response = Buffer.alloc(65536),
      size = [response.length];
    const status = this.submitCommand(context, 0, 200, command, command.length, response, size);
    requireThat(status === 0, 'TBS_' + status.toString(16));
    requireThat(size[0] <= response.length, 'TPM_RESPONSE_SIZE');
    return response.subarray(0, size[0]);
  }
  async attest(keyRef, { akName, akID, akAlgorithm = 'ec', challenge }) {
    requireThat(
      typeof challenge === 'string' &&
        /^[A-Za-z0-9_-]{43}$/.test(challenge) &&
        typeof akID === 'string',
      'TPM_ATTESTATION_CHALLENGE',
    );
    await this.capabilities(keyRef);
    const object = this.open(keyRef);
    let ak;
    try {
      ak = this.open(akName);
      for (const handle of [object, ak])
        requireThat(
          this.property(handle, 'PCP_PASSWORD_REQUIRED').every((b) => b === 0),
          'UNSUPPORTED_TPM_AUTHORIZATION',
        );
      const context = this.platformHandle(this.provider, true),
        objectHandle = this.platformHandle(object),
        akHandle = this.platformHandle(ak);
      const pub = readPublicResponse(this.submit(context, readPublicCommand(objectHandle)));
      const result = certifyResponse(
        this.submit(
          context,
          certifyCommand({
            objectHandle,
            akHandle,
            qualifyingData: sha256(Buffer.from(challenge, 'utf8')),
            akAlgorithm,
          }),
        ),
      );
      return {
        format: 'tpm2-certify',
        akID,
        pubArea: pub.pubArea,
        certInfo: result.certInfo,
        signature: result.signature,
      };
    } finally {
      this.api.FreeObject(object);
      if (ak) this.api.FreeObject(ak);
    }
  }
  async capabilities(keyRef) {
    const pin = this.keys.get(keyRef);
    requireThat(pin, 'TPM_KEY_PIN_REQUIRED');
    const h = this.open(keyRef);
    try {
      const publicKey = this.publicKey(h);
      requireThat(equal(spki(pin), spki(publicKey)), 'TPM_KEY_REPLACED');
      return {
        publicKey,
        algorithm: 'ec',
        input: 'MESSAGE',
        custody: 'TPM_PROVIDER_UNATTESTED',
        localUV: false,
        exportable: false,
      };
    } finally {
      this.api.FreeObject(h);
    }
  }
  async sign({ keyRef, tbs }) {
    const capability = await this.capabilities(keyRef);
    const raw = await this.signP1363(keyRef, tbs);
    const signature = p1363ToDER(raw);
    requireThat(verify(tbs, signature, capability.publicKey), 'TPM_SIGNATURE');
    return signature;
  }
  async signP1363(keyRef, tbs) {
    const h = this.open(keyRef);
    try {
      const output = Buffer.alloc(64),
        size = [0],
        digest = sha256(tbs);
      this.check(this.api.SignHash(h, null, digest, digest.length, output, output.length, size, 0));
      requireThat(size[0] === 64, 'TPM_SIGNATURE_SIZE');
      return output;
    } finally {
      this.api.FreeObject(h);
    }
  }
}

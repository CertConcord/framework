import {
  X509Certificate,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';
import {
  b64u,
  unb64u,
  requireThat,
  sha256,
  sha512,
  sign,
  verify,
  spki,
  parseDER,
  integer,
  seq,
  equal,
  D,
  H,
  dcbor,
  decodeCBOR,
  now,
  keyID,
} from './core.mjs';
import { postJSON, requestJSON, requestBytes, endpoint } from './transport.mjs';
import { parseJSON } from './json.mjs';
import { readControl, validateActivation } from './state.mjs';

export class SoftwareProvider {
  constructor(keys) {
    this.id = 'certconcord-software-v1';
    this.keys = keys;
  }
  async capabilities(ref) {
    const k = this.keys.get(ref);
    requireThat(k, 'KEY_NOT_FOUND');
    return {
      publicKey: k.publicKey,
      algorithm: k.publicKey.asymmetricKeyType,
      input: 'MESSAGE',
      custody: 'SOFTWARE',
      localUV: false,
      exportable: true,
    };
  }
  async sign({ keyRef, tbs }) {
    const k = this.keys.get(keyRef);
    requireThat(k, 'KEY_NOT_FOUND');
    return sign(tbs, k.privateKey);
  }
}
export class RemoteCryptoKey {
  constructor({ url, token, allowLoopback = false }) {
    endpoint(url, { allowLoopback });
    Object.assign(this, { url, token, allowLoopback });
    this.id = 'certconcord-remote-cryptokey-v1';
  }
  async call(path, data) {
    return postJSON(this.url + '/rra/v1/' + path, data, {
      headers: { authorization: 'Bearer ' + this.token },
      allowLoopback: this.allowLoopback,
    });
  }
  async capabilities(keyRef) {
    const r = await this.call('capabilities', { keyRef });
    requireThat(r.version === 1 && r.input === 'MESSAGE', 'REMOTE_VERSION_OR_INPUT');
    return {
      ...r,
      publicKey: createPublicKey({ key: unb64u(r.spki), format: 'der', type: 'spki' }),
    };
  }
  async sign({ keyRef, tbs, operationID, permit }) {
    const r = await this.call('sign', {
      version: 1,
      keyRef,
      tbs: b64u(tbs),
      operationID,
      permit: b64u(permit),
    });
    requireThat(
      r.operationID === operationID && r.tbsHash === b64u(sha512(tbs)),
      'REMOTE_RESPONSE_BINDING',
    );
    return unb64u(r.signature);
  }
  async getOperationResult(operationID) {
    return this.call('result', { operationID });
  }
}
// The service runs behind authenticated transport. Every invocation still needs a signed permit.
export class RemoteCryptoKeyService {
  constructor({ provider, journal, permitCertificate, audience, authorize, clock = now }) {
    requireThat(typeof authorize === 'function', 'REMOTE_AUTHORIZATION_REQUIRED');
    Object.assign(this, { provider, journal, permitCertificate, audience, authorize, clock });
  }
  async handle(path, data) {
    data = decodeCBOR(dcbor(data));
    if (path === 'capabilities') {
      const c = await this.provider.capabilities(data.keyRef);
      return {
        version: 1,
        algorithm: c.algorithm,
        input: c.input,
        custody: c.custody,
        localUV: c.localUV,
        exportable: c.exportable,
        spki: b64u(spki(c.publicKey)),
      };
    }
    if (path === 'result') {
      const r = this.journal.result(data.operationID);
      return r
        ? {
            operationID: data.operationID,
            status: r.status,
            ...(r.result ? JSON.parse(r.result.toString('utf8')) : {}),
          }
        : { operationID: data.operationID, status: 'NOT_FOUND' };
    }
    requireThat(path === 'sign' && data.version === 1, 'REMOTE_REQUEST');
    const tbs = unb64u(data.tbs),
      permit = unb64u(data.permit),
      p = readControl(permit, 'OperationPermit', this.permitCertificate),
      caps = await this.provider.capabilities(data.keyRef);
    validateActivation(p.activation, {
      tbs,
      publicKey: caps.publicKey,
      audience: this.audience,
      at: this.clock(),
    });
    const checkTime = () => {
      const at = this.clock();
      requireThat(
        Number.isSafeInteger(at) &&
          at >= 0 &&
          Number.isSafeInteger(p.issuedAt) &&
          Number.isSafeInteger(p.expiresAt) &&
          p.issuedAt >= p.activation.issuedAt &&
          p.issuedAt <= at &&
          p.expiresAt > at &&
          p.expiresAt > p.issuedAt &&
          p.expiresAt - p.issuedAt <= 30 &&
          p.expiresAt <= p.activation.expiresAt &&
          b64u(p.activation.operationID) === data.operationID,
        'REMOTE_PERMIT',
      );
    };
    checkTime();
    const authorize = async () =>
      requireThat(
        (await this.authorize({
          permit: decodeCBOR(dcbor(p)),
          keyRef: data.keyRef,
          capabilities: { ...caps },
        })) === true,
        'REMOTE_AUTHORIZATION_DENIED',
      );
    await authorize();
    checkTime();
    const digest = H('RemoteDispatch', {
        keyRef: data.keyRef,
        permitHash: sha512(permit),
        tbsHash: sha512(tbs),
      }),
      old = this.journal.reserve(data.operationID, digest);
    if (old) {
      requireThat(old.status === 'COMPLETED', 'UNKNOWN_EXECUTION');
      return JSON.parse(Buffer.from(old.result).toString('utf8'));
    }
    try {
      const signature = Buffer.from(
        await this.provider.sign({
          keyRef: data.keyRef,
          tbs: Buffer.from(tbs),
          operationID: data.operationID,
          permit: Buffer.from(permit),
        }),
      );
      requireThat(verify(tbs, signature, caps.publicKey), 'PROVIDER_SIGNATURE');
      await authorize();
      checkTime();
      const result = {
        operationID: data.operationID,
        tbsHash: b64u(sha512(tbs)),
        signature: b64u(signature),
      };
      this.journal.complete(data.operationID, Buffer.from(JSON.stringify(result)));
      return result;
    } catch (e) {
      this.journal.uncertain(data.operationID);
      throw e;
    }
  }
}
export function derToP1363(signature) {
  const r = parseDER(signature);
  requireThat(r.tag === 48 && r.children.length === 2, 'ECDSA_DER');
  return Buffer.concat(
    r.children.map((n) => {
      requireThat(n.tag === 2 && !(n.value[0] & 128), 'ECDSA_INTEGER');
      let b = n.value;
      if (b[0] === 0) b = b.subarray(1);
      requireThat(b.length <= 32, 'ECDSA_INTEGER');
      return Buffer.concat([Buffer.alloc(32 - b.length), b]);
    }),
  );
}
export function p1363ToDER(signature) {
  requireThat(signature.length === 64, 'ECDSA_P1363');
  const n = (b) => integer(BigInt('0x' + b.toString('hex')));
  return seq(n(signature.subarray(0, 32)), n(signature.subarray(32)));
}
export class CSCProvider {
  constructor({ url, accessToken, credentials, authorize, allowLoopback = false }) {
    requireThat(typeof authorize === 'function', 'CSC_ACTIVATION_REQUIRED');
    endpoint(url, { allowLoopback });
    Object.assign(this, { url, accessToken, credentials, authorize, allowLoopback });
    this.id = 'csc-v2.2.0.0-es256';
  }
  async post(path, data) {
    const r = await requestBytes(this.url + '/csc/v2/' + path, {
      method: 'POST',
      headers: { authorization: 'Bearer ' + this.accessToken, 'content-type': 'application/json' },
      body: JSON.stringify(data),
      allowLoopback: this.allowLoopback,
    });
    requireThat(r.status === 200, 'CSC_HTTP_' + r.status);
    requireThat(
      (r.headers.get('content-type') ?? '').split(';')[0] === 'application/json',
      'CSC_MEDIA_TYPE',
    );
    const value = parseJSON(r.body.toString('utf8'));
    requireThat(value && typeof value === 'object' && !Array.isArray(value), 'CSC_RESPONSE');
    return value;
  }
  async capabilities(keyRef) {
    const pin = this.credentials.get(keyRef);
    requireThat(pin, 'CSC_KEY_PIN');
    const info = await this.post('info', {});
    requireThat(info.specs === '2.2.0.0', 'CSC_VERSION');
    requireThat(
      Array.isArray(info.methods) &&
        ['credentials/info', 'credentials/authorize', 'signatures/signHash'].every((m) =>
          info.methods.includes(m),
        ),
      'CSC_METHODS',
    );
    const r = await this.post('credentials/info', {
      credentialID: keyRef,
      certificates: 'chain',
      certInfo: true,
      authInfo: true,
    });
    requireThat(
      r.key?.status === 'enabled' &&
        Array.isArray(r.key.algo) &&
        r.key.algo.includes('1.2.840.10045.4.3.2') &&
        r.key.len === 256 &&
        r.key.curve === '1.2.840.10045.3.1.7',
      'CSC_UNSUPPORTED_CAPABILITY',
    );
    requireThat(
      Array.isArray(r.cert?.certificates) &&
        r.cert.certificates.length > 0 &&
        equal(cscBase64(r.cert.certificates[0]), pin.certificate),
      'CSC_CERTIFICATE_PIN',
    );
    const publicKey = new X509Certificate(pin.certificate).publicKey;
    requireThat(
      publicKey.asymmetricKeyType === 'ec' &&
        publicKey.asymmetricKeyDetails.namedCurve === 'prime256v1' &&
        equal(spki(publicKey), spki(pin.publicKey)),
      'CSC_PUBLIC_KEY_PIN',
    );
    requireThat(r.cert.status === undefined || r.cert.status === 'valid', 'CSC_CERTIFICATE_STATUS');
    requireThat(
      r.auth?.mode === 'explicit' &&
        Array.isArray(r.auth.objects) &&
        r.SCAL === '2' &&
        Number.isSafeInteger(r.multisign) &&
        r.multisign >= 1,
      'CSC_AUTHORIZATION_PROFILE',
    );
    return {
      publicKey,
      algorithm: 'ec',
      input: 'MESSAGE',
      custody: 'REMOTE',
      localUV: false,
      exportable: false,
      auth: r.auth,
    };
  }
  async sign({ keyRef, tbs, operationID, permit }) {
    const message = Buffer.from(tbs),
      c = await this.capabilities(keyRef),
      hash = sha256(message).toString('base64'),
      activation = await this.authorize({
        keyRef,
        tbs: Buffer.from(message),
        operationID,
        permit,
        hash,
        auth: c.auth,
      });
    requireThat(
      activation &&
        typeof activation.SAD === 'string' &&
        activation.SAD.length > 0 &&
        !Object.hasOwn(activation, 'handle') &&
        (activation.expiresIn === undefined ||
          (Number.isSafeInteger(activation.expiresIn) && activation.expiresIn > 0)),
      'CSC_SAD_REQUIRED',
    );
    const r = await this.post('signatures/signHash', {
      credentialID: keyRef,
      SAD: activation.SAD,
      hashes: [hash],
      hashAlgorithmOID: '2.16.840.1.101.3.4.2.1',
      signAlgo: '1.2.840.10045.4.3.2',
      operationMode: 'S',
      clientData: operationID,
    });
    requireThat(
      Array.isArray(r.signatures) && r.signatures.length === 1 && !Object.hasOwn(r, 'responseID'),
      'CSC_SIGNATURE_COUNT',
    );
    const signature = cscBase64(r.signatures[0]);
    requireThat(cryptoVerify('sha256', message, c.publicKey, signature), 'CSC_SIGNATURE');
    return signature;
  }
  async authorizeCredential({ credentialID, hash, authData = [], PIN, OTP }) {
    requireThat(this.credentials.has(credentialID), 'CSC_KEY_PIN');
    requireThat(cscBase64(hash).length === 32, 'CSC_HASH');
    requireThat(PIN === undefined && OTP === undefined, 'CSC_LEGACY_AUTH');
    requireThat(
      Array.isArray(authData) &&
        authData.every(
          (a) =>
            a &&
            typeof a.id === 'string' &&
            a.id.length > 0 &&
            (a.value === undefined || typeof a.value === 'string'),
        ) &&
        new Set(authData.map((a) => a.id)).size === authData.length,
      'CSC_AUTH_DATA',
    );
    return this.post('credentials/authorize', {
      credentialID,
      numSignatures: 1,
      hashes: [hash],
      hashAlgorithmOID: '2.16.840.1.101.3.4.2.1',
      authData,
    });
  }
}
function cscBase64(value) {
  requireThat(typeof value === 'string' && value.length > 0, 'CSC_BASE64');
  const bytes = Buffer.from(value, 'base64');
  requireThat(bytes.toString('base64') === value, 'CSC_BASE64');
  return bytes;
}
function crc32c(b) {
  let c = 0xffffffff;
  for (const x of b) {
    c ^= x;
    for (let i = 0; i < 8; i++) c = (c >>> 1) ^ (c & 1 ? 0x82f63b78 : 0);
  }
  return (c ^ 0xffffffff) >>> 0;
}
export class GoogleKMSProvider {
  constructor({ credentials, accessToken }) {
    Object.assign(this, { credentials, accessToken });
    this.id = 'google-kms-es256';
  }
  async capabilities(keyRef) {
    const pin = this.credentials.get(keyRef);
    requireThat(
      pin &&
        /^projects\/[^/]+\/locations\/[^/]+\/keyRings\/[^/]+\/cryptoKeys\/[^/]+\/cryptoKeyVersions\/\d+$/.test(
          keyRef,
        ),
      'KMS_KEY_VERSION',
    );
    const r = await requestJSON('https://cloudkms.googleapis.com/v1/' + keyRef + '/publicKey', {
      headers: { authorization: 'Bearer ' + (await this.accessToken()) },
    });
    requireThat(
      r.algorithm === 'EC_SIGN_P256_SHA256' && r.protectionLevel === 'HSM',
      'KMS_ALGORITHM_OR_CUSTODY',
    );
    const key = createPublicKey(r.pem);
    requireThat(
      equal(spki(key), spki(pin.publicKey)) && String(crc32c(Buffer.from(r.pem))) === r.pemCrc32c,
      'KMS_KEY_PIN_OR_CRC',
    );
    return {
      publicKey: key,
      algorithm: 'ec',
      input: 'MESSAGE',
      custody: 'REMOTE_HSM',
      localUV: false,
      exportable: false,
    };
  }
  async sign({ keyRef, tbs }) {
    const c = await this.capabilities(keyRef),
      digest = sha256(tbs),
      r = await postJSON(
        'https://cloudkms.googleapis.com/v1/' + keyRef + ':asymmetricSign',
        { digest: { sha256: digest.toString('base64') }, digestCrc32c: String(crc32c(digest)) },
        { headers: { authorization: 'Bearer ' + (await this.accessToken()) } },
      );
    const sig = Buffer.from(r.signature ?? '', 'base64');
    requireThat(
      r.name === keyRef &&
        r.verifiedDigestCrc32c === true &&
        String(crc32c(sig)) === r.signatureCrc32c &&
        cryptoVerify('sha256', tbs, c.publicKey, sig),
      'KMS_SIGNATURE',
    );
    return sig;
  }
}

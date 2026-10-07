// Browser-only drivers. PRF outputs and local vault secrets remain on the client.
const u8 = (v) =>
    ArrayBuffer.isView(v)
      ? new Uint8Array(v.buffer, v.byteOffset, v.byteLength)
      : new Uint8Array(v),
  concat = (...a) => {
    const r = new Uint8Array(a.reduce((n, v) => n + v.length, 0));
    let p = 0;
    for (const v of a) {
      r.set(v, p);
      p += v.length;
    }
    return r;
  };
export const base64url = (v) =>
  btoa(String.fromCharCode(...u8(v)))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/, '');
export const fromBase64url = (v) =>
  Uint8Array.from(atob(v.replaceAll('-', '+').replaceAll('_', '/')), (c) => c.charCodeAt(0));
function head(m, n) {
  n = BigInt(n);
  if (n < 24n) return Uint8Array.of(m * 32 + Number(n));
  const w = n <= 255n ? 1 : n <= 65535n ? 2 : n <= 4294967295n ? 4 : 8,
    r = new Uint8Array(w + 1);
  r[0] = m * 32 + { 1: 24, 2: 25, 4: 26, 8: 27 }[w];
  for (let i = w; i > 0; i--) {
    r[i] = Number(n & 255n);
    n >>= 8n;
  }
  return r;
}
export function encode(value) {
  if (value === null) return Uint8Array.of(246);
  if (typeof value === 'boolean') return Uint8Array.of(value ? 245 : 244);
  if (typeof value === 'number' || typeof value === 'bigint') {
    if (typeof value === 'number' && !Number.isSafeInteger(value)) throw Error('INTEGER_RANGE');
    return BigInt(value) >= 0 ? head(0, value) : head(1, -1n - BigInt(value));
  }
  if (value instanceof Uint8Array || value instanceof ArrayBuffer) {
    const b = u8(value);
    return concat(head(2, b.length), b);
  }
  if (typeof value === 'string') {
    if (value !== value.normalize('NFC')) throw Error('TEXT_NFC');
    const b = new TextEncoder().encode(value);
    return concat(head(3, b.length), b);
  }
  if (Array.isArray(value)) return concat(head(4, value.length), ...value.map(encode));
  const entries = Object.entries(value)
    .map(([k, v]) => [encode(k), encode(v)])
    .sort((a, b) => {
      for (let i = 0; i < Math.min(a[0].length, b[0].length); i++)
        if (a[0][i] !== b[0][i]) return a[0][i] - b[0][i];
      return a[0].length - b[0].length;
    });
  return concat(head(5, entries.length), ...entries.flat());
}
const domain = (label, value) => encode(['CertConcord', 3, label, value]);
function rejectCleartextPRF(credential) {
  const results = credential.getClientExtensionResults?.().prf?.results;
  if (!results) return;
  const secrets = [results.first, results.second]
    .filter((v) => v !== undefined)
    .map((v) => {
      if (!(v instanceof ArrayBuffer || ArrayBuffer.isView(v)) || v.byteLength !== 32)
        throw Error('PRF_OUTPUT_LENGTH');
      return u8(v);
    });
  for (const name of ['authenticatorData', 'attestationObject']) {
    const value = credential.response[name];
    if (value === undefined) continue;
    const bytes = u8(value);
    if (bytes.length > 65536) throw Error('WEBAUTHN_PUBLIC_DATA_LIMIT');
    for (const secret of secrets) {
      for (let i = 0; i <= bytes.length - secret.length; i++) {
        if (secret.every((b, j) => bytes[i + j] === b)) throw Error('PRF_CLEARTEXT_IN_SIGNED_DATA');
      }
    }
  }
}
export function publicAssertion(credential) {
  rejectCleartextPRF(credential);
  const r = credential.response;
  return {
    id: credential.id,
    rawId: base64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: base64url(r.clientDataJSON),
      authenticatorData: base64url(r.authenticatorData),
      signature: base64url(r.signature),
      userHandle: r.userHandle ? base64url(r.userHandle) : null,
    },
  };
}
export function publicRegistration(credential) {
  rejectCleartextPRF(credential);
  return {
    id: credential.id,
    rawId: base64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: base64url(credential.response.clientDataJSON),
      attestationObject: base64url(credential.response.attestationObject),
      transports: credential.response.getTransports?.() ?? [],
    },
  };
}
export function prfInput(header) {
  const names = [
    'schemaVersion',
    'trustDomainID',
    'subjectID',
    'credentialIDHash',
    'rpID',
    'purpose',
    'epoch',
    'contextID',
    'prfSalt',
  ];
  return domain('PRFInput', Object.fromEntries(names.map((k) => [k, header[k]])));
}
export async function evaluatePRF({
  credentialID,
  rpID,
  challenge,
  first,
  second,
  credentials = globalThis.navigator.credentials,
}) {
  const id = base64url(credentialID),
    input = { first };
  if (second) input.second = second;
  const c = await credentials.get({
    publicKey: {
      challenge,
      rpId: rpID,
      userVerification: 'required',
      allowCredentials: [{ id: credentialID, type: 'public-key' }],
      extensions: { prf: { evalByCredential: { [id]: input } } },
    },
  });
  if (!c || base64url(c.rawId) !== id) throw Error('CREDENTIAL_BINDING');
  const prf = c.getClientExtensionResults().prf?.results;
  if (!prf?.first || prf.first.byteLength !== 32 || (second && prf.second?.byteLength !== 32))
    throw Error('PRF_UNAVAILABLE');
  return {
    assertion: publicAssertion(c),
    first: u8(prf.first),
    ...(second ? { second: u8(prf.second) } : {}),
  };
}
export async function wrapRoot(prf, root, header, { subtle = globalThis.crypto.subtle } = {}) {
  if (prf.byteLength !== 32 || root.byteLength !== 32 || header.aead !== 'AES-256-GCM')
    throw Error('WRAPPER_PARAMETERS');
  const material = await subtle.importKey('raw', prf, 'HKDF', false, ['deriveKey']);
  const key = await subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: header.kdfSalt, info: domain('WrapperKDF', header) },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt'],
  );
  const nonce = crypto.getRandomValues(new Uint8Array(12)),
    out = u8(
      await subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: nonce,
          additionalData: domain('WrapperAAD', header),
          tagLength: 128,
        },
        key,
        root,
      ),
    );
  return { schemaVersion: 1, header, nonce, ciphertext: out.slice(0, -16), tag: out.slice(-16) };
}
export async function unwrapRoot(prf, wrapper, { subtle = globalThis.crypto.subtle } = {}) {
  const h = wrapper.header;
  if (h.aead !== 'AES-256-GCM' || prf.byteLength !== 32) throw Error('WRAPPER_PARAMETERS');
  const material = await subtle.importKey('raw', prf, 'HKDF', false, ['deriveKey']),
    key = await subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: h.kdfSalt, info: domain('WrapperKDF', h) },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt'],
    );
  return u8(
    await subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: wrapper.nonce,
        additionalData: domain('WrapperAAD', h),
        tagLength: 128,
      },
      key,
      concat(wrapper.ciphertext, wrapper.tag),
    ),
  );
}
export async function createRawSigningKey(
  publicKeyOptions,
  {
    algorithms = [-9],
    version = 'previewSign5-2026-09-09',
    credentials = globalThis.navigator?.credentials,
  } = {},
) {
  const extension = rawExtensionName(version);
  checkRawAlgorithms(algorithms);
  if (Object.hasOwn(publicKeyOptions.extensions ?? {}, 'remoteClientDataJSON'))
    throw Error('REMOTE_CLIENT_DATA_PROFILE_REQUIRED');
  if (typeof credentials?.create !== 'function') throw Error('RAW_SIGNING_UNAVAILABLE');
  const credential = await credentials.create({
    publicKey: {
      ...publicKeyOptions,
      authenticatorSelection: {
        ...publicKeyOptions.authenticatorSelection,
        residentKey: 'required',
        requireResidentKey: true,
        userVerification: 'required',
      },
      extensions: { ...publicKeyOptions.extensions, [extension]: { generateKey: { algorithms } } },
    },
  });
  const key = rawOutput(credential, extension).generatedKey;
  if (!key || !algorithms.includes(key.algorithm)) throw Error('RAW_SIGNING_UNAVAILABLE');
  return { credential, key, version, registration: publicRegistration(credential) };
}
const rawExtensionName = (version) => {
  const id = { 'previewSign-4': 'previewSign', 'previewSign5-2026-09-09': 'previewSign5' }[version];
  if (!id) throw Error('RAW_SIGNING_VERSION');
  return id;
};
function checkRawAlgorithms(algorithms) {
  if (
    !Array.isArray(algorithms) ||
    algorithms.length === 0 ||
    algorithms.length > 3 ||
    new Set(algorithms).size !== algorithms.length ||
    !algorithms.every((a) => [-9, -300, -65539].includes(a))
  )
    throw Error('RAW_SIGNING_ALGORITHM');
}
function rawOutput(credential, extension) {
  const result = credential?.getClientExtensionResults?.()?.[extension];
  if (!result) throw Error('RAW_SIGNING_UNAVAILABLE');
  if (Object.hasOwn(result, 'errorCode'))
    throw Error('RAW_SIGNING_EXTENSION_ERROR:' + result.errorCode);
  return result;
}
export async function generateRawSigningKey(
  publicKeyOptions,
  {
    algorithms = [-9],
    version = 'previewSign5-2026-09-09',
    credentials = globalThis.navigator?.credentials,
  } = {},
) {
  const extension = rawExtensionName(version);
  checkRawAlgorithms(algorithms);
  if (Object.hasOwn(publicKeyOptions.extensions ?? {}, 'remoteClientDataJSON'))
    throw Error('REMOTE_CLIENT_DATA_PROFILE_REQUIRED');
  if (version !== 'previewSign5-2026-09-09' || publicKeyOptions.allowCredentials?.length !== 1)
    throw Error('RAW_GENERATION_CEREMONY');
  if (typeof credentials?.get !== 'function') throw Error('RAW_SIGNING_UNAVAILABLE');
  const credential = await credentials.get({
    publicKey: {
      ...publicKeyOptions,
      userVerification: 'required',
      extensions: { ...publicKeyOptions.extensions, [extension]: { generateKey: { algorithms } } },
    },
  });
  if (
    !credential ||
    base64url(credential.rawId) !== base64url(publicKeyOptions.allowCredentials[0].id)
  )
    throw Error('CREDENTIAL_BINDING');
  const key = rawOutput(credential, extension).generatedKey;
  if (!key || !algorithms.includes(key.algorithm)) throw Error('RAW_SIGNING_UNAVAILABLE');
  return { credential, key, version, assertion: publicAssertion(credential) };
}
export async function rawSign({
  credentialID,
  rpID,
  challenge,
  keyHandle,
  tbs,
  algorithm = -9,
  version = 'previewSign5-2026-09-09',
  additionalArgs,
  credentials = globalThis.navigator?.credentials,
}) {
  const extension = rawExtensionName(version);
  checkRawAlgorithms([algorithm]);
  if (typeof credentials?.get !== 'function') throw Error('RAW_SIGNING_UNAVAILABLE');
  tbs = u8(tbs).slice();
  credentialID = u8(credentialID).slice();
  keyHandle = u8(keyHandle).slice();
  challenge = u8(challenge).slice();
  if (
    tbs.length === 0 ||
    tbs.length > 1024 * 1024 ||
    credentialID.length === 0 ||
    credentialID.length > 1024 ||
    keyHandle.length > 1024 ||
    challenge.length < 16 ||
    challenge.length > 1024
  )
    throw Error('RAW_SIGNING_INPUT');
  if (additionalArgs !== undefined) additionalArgs = u8(additionalArgs).slice();
  if (
    (algorithm === -65539) !== (additionalArgs !== undefined) ||
    (additionalArgs !== undefined &&
      (u8(additionalArgs).length === 0 || u8(additionalArgs).length > 512))
  )
    throw Error('RAW_SIGNING_ARGUMENTS');
  const input = algorithm !== -9 ? await crypto.subtle.digest('SHA-256', tbs) : tbs,
    id = base64url(credentialID);
  const c = await credentials.get({
    publicKey: {
      challenge,
      rpId: rpID,
      allowCredentials: [{ type: 'public-key', id: credentialID }],
      userVerification: 'required',
      extensions: {
        [extension]: {
          signByCredential: {
            [id]: {
              keyHandle,
              tbs: input,
              ...(additionalArgs === undefined ? {} : { additionalArgs }),
            },
          },
        },
      },
    },
  });
  if (!c || base64url(c.rawId) !== id) throw Error('CREDENTIAL_BINDING');
  const signature = rawOutput(c, extension).signature;
  if (!signature) throw Error('RAW_SIGNING_UNAVAILABLE');
  return { signature: u8(signature), assertion: publicAssertion(c) };
}

export async function getRemoteSigningKey(
  { userIdentifier, keyId, expiresAt },
  { subtle = globalThis.crypto?.subtle } = {},
) {
  if (typeof subtle?.getRemoteKey !== 'function') throw Error('REMOTE_CRYPTOKEY_UNAVAILABLE');
  if (
    typeof userIdentifier !== 'string' ||
    userIdentifier.length === 0 ||
    userIdentifier.length > 256 ||
    (keyId !== undefined && (typeof keyId !== 'string' || keyId.length > 1024)) ||
    (expiresAt !== undefined && (!Number.isFinite(expiresAt) || expiresAt < 0))
  )
    throw Error('REMOTE_CRYPTOKEY_PARAMETERS');
  const key = await subtle.getRemoteKey(
    {
      name: 'remote',
      userIdentifier,
      ...(keyId === undefined ? {} : { keyId }),
      ...(expiresAt === undefined ? {} : { expiresAt }),
    },
    ['sign'],
  );
  if (
    !key ||
    key.extractable !== false ||
    key.algorithm?.name !== 'remote' ||
    key.usages?.length !== 1 ||
    key.usages[0] !== 'sign' ||
    (keyId !== undefined && key.algorithm.keyId !== keyId)
  )
    throw Error('REMOTE_CRYPTOKEY_BINDING');
  return key;
}
export async function remoteCryptoSign(
  { key, tbs, publicKeySPKI },
  { subtle = globalThis.crypto?.subtle } = {},
) {
  if (
    typeof subtle?.sign !== 'function' ||
    typeof subtle?.verify !== 'function' ||
    typeof subtle?.importKey !== 'function'
  )
    throw Error('REMOTE_CRYPTOKEY_UNAVAILABLE');
  tbs = u8(tbs).slice();
  publicKeySPKI = u8(publicKeySPKI).slice();
  if (
    !key ||
    key.extractable !== false ||
    key.algorithm?.name !== 'remote' ||
    key.usages?.length !== 1 ||
    key.usages[0] !== 'sign' ||
    tbs.length === 0 ||
    tbs.length > 1024 * 1024 ||
    publicKeySPKI.length > 512
  )
    throw Error('REMOTE_CRYPTOKEY_BINDING');
  const publicKey = await subtle.importKey(
    'spki',
    publicKeySPKI,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  );
  const signature = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, tbs);
  if (!(await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, signature, tbs)))
    throw Error('REMOTE_CRYPTOKEY_SIGNATURE');
  return u8(signature);
}
export async function digitalCredentialRequest(
  request,
  { protocol = 'openid4vp-v1-signed', credentials = globalThis.navigator.credentials } = {},
) {
  const data =
    protocol === 'openid4vp-v1-signed' && typeof request === 'string' ? { request } : request;
  const credential = await credentials.get({ digital: { requests: [{ protocol, data }] } });
  if (!credential || credential.protocol !== protocol)
    throw Error('DIGITAL_CREDENTIAL_UNAVAILABLE_OR_PROTOCOL');
  return credential;
}

import { createECDH, hkdfSync, createHmac } from 'node:crypto';
import { p256 } from '@noble/curves/nist.js';
import { hash_to_field } from '@noble/curves/abstract/hash-to-curve.js';
import { sha256 as nobleSHA256 } from '@noble/hashes/sha2.js';
import {
  generate,
  random,
  b64u,
  unb64u,
  sha256,
  H,
  now,
  sign,
  equal,
  requireThat,
} from './core.mjs';
import { issueCertificate, name } from './pki.mjs';
import { encode, decode } from './cose.mjs';
import { p1363ToDER } from './ecdsa.mjs';
import { rawExtension } from './raw-signing.mjs';

// Software authenticator for protocol examples and negative tests. All keys are ephemeral test keys.
export function examplePasskey({
  rpID = 'website.example',
  origin = 'https://website.example',
  version = 'previewSign5-2026-09-09',
  algorithm = -9,
  handle = random(),
} = {}) {
  const parent = generate('ec'),
    document = generate('ec'),
    kem = generate('ec');
  const root = generate('ec'),
    attestor = generate('ec'),
    credentialID = random(),
    keyHandle = handle;
  const aaguid = random(16),
    extensionID = rawExtension(version);
  const rootName = name('Synthetic authenticator root');
  const rootCertificate = issueCertificate(
    { publicKey: root.publicKey, subject: rootName, issuer: rootName, serial: 1, ca: true },
    root.privateKey,
  );
  const attestationCertificate = issueCertificate(
    {
      publicKey: attestor.publicKey,
      subject: name('Synthetic authenticator attestation'),
      issuer: rootName,
      serial: 2,
      profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1',
    },
    root.privateKey,
  );
  const cose = (publicKey, alg = -9) => {
    const j = publicKey.export({ format: 'jwk' });
    return new Map([
      [1, 2],
      [3, alg],
      [-1, 1],
      [-2, unb64u(j.x)],
      [-3, unb64u(j.y)],
    ]);
  };
  const publicKeyBytes =
    algorithm === -65539
      ? encode(
          new Map([
            [1, -65537],
            [3, -65700],
            [-1, cose(document.publicKey)],
            [-2, cose(kem.publicKey)],
          ]),
        )
      : encode(cose(document.publicKey));
  let counter = 0,
    fixedFlags = 5;
  const client = (type, challenge) =>
    Buffer.from(JSON.stringify({ type, challenge: b64u(challenge), origin, crossOrigin: false }));
  function auth(flags, extensions, attested) {
    const count = Buffer.alloc(4);
    count.writeUInt32BE(attested?.child ? 0 : ++counter);
    let tail = Buffer.alloc(0);
    if (attested) {
      const id = attested.id,
        length = Buffer.alloc(2);
      length.writeUInt16BE(id.length);
      tail = Buffer.concat([aaguid, length, id, attested.key]);
    }
    return Buffer.concat([
      sha256(Buffer.from(rpID)),
      Buffer.from([flags]),
      count,
      tail,
      ...(extensions ? [encode(extensions)] : []),
    ]);
  }
  function packed(authData, clientDataJSON) {
    return encode(
      new Map([
        ['fmt', 'packed'],
        ['authData', authData],
        [
          'attStmt',
          new Map([
            ['alg', -7],
            ['x5c', [attestationCertificate]],
            ['sig', sign(Buffer.concat([authData, sha256(clientDataJSON)]), attestor.privateKey)],
          ]),
        ],
      ]),
    );
  }
  function generated(clientDataJSON, parentFlags) {
    return {
      algorithm,
      keyHandle,
      publicKey: publicKeyBytes,
      attestationObject: packed(
        auth(parentFlags | 192, new Map([[extensionID, new Map([[4, fixedFlags]])]]), {
          child: true,
          id: keyHandle,
          key: publicKeyBytes,
        }),
        clientDataJSON,
      ),
    };
  }
  function assertion(challenge, rawSignature, generation = false) {
    const data = client('webauthn.get', challenge);
    const extensionData = generation
      ? new Map([[3, algorithm]])
      : rawSignature
        ? new Map([[6, rawSignature]])
        : null;
    const authData = auth(
      extensionData ? 133 : 5,
      extensionData && new Map([[extensionID, extensionData]]),
    );
    return {
      type: 'public-key',
      id: b64u(credentialID),
      rawId: credentialID,
      response: {
        clientDataJSON: data,
        authenticatorData: authData,
        signature: sign(Buffer.concat([authData, sha256(data)]), parent.privateKey),
        userHandle: null,
      },
      getClientExtensionResults: () =>
        generation
          ? { [extensionID]: { generatedKey: generated(data, 133) } }
          : rawSignature
            ? { [extensionID]: { signature: rawSignature } }
            : {},
    };
  }
  // Decapsulation is confined to this software fixture; deployed authenticators retain seed secrets.
  function derivedPrivate(additionalArgs) {
    const args = decode(additionalArgs),
      ctx = args.get(-2),
      ticket = args.get(-1);
    requireThat(args.get(3) === -65539 && args.get(-3) === -65700, 'EXAMPLE_ARKG_ARGS');
    const ctxPrime = Buffer.concat([Buffer.from([ctx.length]), ctx]);
    const ctxKem = Buffer.concat([Buffer.from('ARKG-Derive-Key-KEM.'), ctxPrime]);
    const dst = Buffer.from('ARKG-ECDH.ARKG-P256');
    const ecdh = createECDH('prime256v1');
    ecdh.setPrivateKey(unb64u(kem.privateKey.export({ format: 'jwk' }).d));
    const shared = ecdh.computeSecret(ticket.subarray(16));
    const hkdf = (label) =>
      Buffer.from(
        hkdfSync(
          'sha256',
          shared,
          Buffer.alloc(32),
          Buffer.concat([Buffer.from(label), dst, ctxKem]),
          32,
        ),
      );
    requireThat(
      equal(
        createHmac('sha256', hkdf('ARKG-KEM-HMAC-mac.'))
          .update(ticket.subarray(16))
          .digest()
          .subarray(0, 16),
        ticket.subarray(0, 16),
      ),
      'EXAMPLE_ARKG_MAC',
    );
    const tau = hash_to_field(hkdf('ARKG-KEM-HMAC-shared.'), 1, {
      DST: Buffer.concat([Buffer.from('ARKG-BL-EC.ARKG-P256ARKG-Derive-Key-BL.'), ctxPrime]),
      p: p256.Point.Fn.ORDER,
      m: 1,
      k: 128,
      expand: 'xmd',
      hash: nobleSHA256,
    })[0][0];
    const d = BigInt(
      '0x' + unb64u(document.privateKey.export({ format: 'jwk' }).d).toString('hex'),
    );
    return Buffer.from(((d + tau) % p256.Point.Fn.ORDER).toString(16).padStart(64, '0'), 'hex');
  }
  const credentials = {
    async create({ publicKey: options }) {
      const data = client('webauthn.create', options.challenge);
      const parentAuth = auth(197, new Map([[extensionID, new Map([[3, algorithm]])]]), {
        id: credentialID,
        key: encode(cose(parent.publicKey, -7)),
      });
      return {
        type: 'public-key',
        id: b64u(credentialID),
        rawId: credentialID,
        response: {
          clientDataJSON: data,
          attestationObject: packed(parentAuth, data),
          getTransports: () => ['usb'],
        },
        getClientExtensionResults: () => ({
          [extensionID]: { generatedKey: generated(data, 197) },
        }),
      };
    },
    async get({ publicKey: options }) {
      const input = options.extensions?.[extensionID];
      if (input?.generateKey) return assertion(options.challenge, null, true);
      if (!input) return assertion(options.challenge);
      const raw = input.signByCredential[b64u(credentialID)];
      requireThat(equal(Buffer.from(raw.keyHandle), keyHandle), 'EXAMPLE_KEY_HANDLE');
      const privateBytes =
        algorithm === -65539
          ? derivedPrivate(Buffer.from(raw.additionalArgs))
          : unb64u(document.privateKey.export({ format: 'jwk' }).d);
      const signature = p1363ToDER(
        Buffer.from(
          p256.sign(new Uint8Array(raw.tbs), privateBytes, {
            prehash: algorithm === -9,
            lowS: false,
          }),
        ),
      );
      return assertion(options.challenge, signature);
    },
  };
  return {
    parent,
    document,
    kem,
    credentialID,
    keyHandle,
    aaguid,
    credentials,
    assertion,
    publicKeyBytes,
    attestationCertificate,
    rootCertificate,
    setFixedFlags: (value) => {
      fixedFlags = value;
    },
    attestationPolicy: {
      roots: [rootCertificate],
      models: [
        {
          aaguid,
          rootHash: sha256(rootCertificate),
          versions: [version],
          algorithms: [algorithm],
          custody: 'SECURE_ELEMENT',
          nonExportable: true,
          status: 'APPROVED',
          expiresAt: now() + 86400,
        },
      ],
      status: (_certificate, { at }) => ({
        status: 'GOOD',
        checkedAt: at,
        nextUpdate: at + 300,
        evidenceHash: H('SyntheticAttestationStatus', {}),
      }),
    },
  };
}

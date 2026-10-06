import {
  D,
  H,
  dcbor,
  decodeCBOR,
  fields,
  requireThat,
  random,
  hkdf,
  seal,
  open,
  wrapAES,
  unwrapAES,
  equal,
  sha256,
  sha512,
  mac,
  keyID,
  encapsulate,
  decapsulate,
  now,
  b64u,
  unb64u,
  seq,
  set,
  oid,
  octet,
  integer,
  der,
  parseDER,
  oidText,
  intValue,
  ALG,
} from './core.mjs';
import { algID, OID } from './pki.mjs';

const purposes = [
  'ACCOUNT_WRAP',
  'SIGNING_VAULT_WRAP',
  'ENCRYPTION_VAULT_WRAP',
  'RECEIPT_WRAP',
  'TRANSACTION_SECRET',
  'LOCAL_VAULT',
  'RECOVERY_STATE',
  'KEY_TRANSITION',
  'PRIVATE_EVIDENCE',
];
const headerFields = [
  'schemaVersion',
  'trustDomainID',
  'subjectID',
  'credentialIDHash',
  'rpID',
  'purpose',
  'epoch',
  'contextID',
  'prfSalt',
  'wrapperID',
  'kdfSalt',
  'kdf',
  'aead',
  'amkVersion',
];
export function wrapperHeader(options) {
  const h = {
    schemaVersion: 1,
    epoch: 0,
    amkVersion: 1,
    prfSalt: random(),
    wrapperID: random(),
    kdfSalt: random(),
    kdf: 'HKDF-SHA-256',
    aead: 'AES-256-GCM',
    ...options,
  };
  validateHeader(h);
  return h;
}
export function validateHeader(h) {
  fields(h, headerFields);
  requireThat(
    h.schemaVersion === 1 &&
      h.kdf === 'HKDF-SHA-256' &&
      ['AES-256-GCM', 'AES-256-KW', 'AES-256-KWP'].includes(h.aead),
    'WRAPPER_ALGORITHM',
  );
  requireThat(
    purposes.includes(h.purpose) &&
      typeof h.rpID === 'string' &&
      h.rpID.length > 0 &&
      Number.isSafeInteger(h.epoch) &&
      h.epoch >= 0 &&
      Number.isSafeInteger(h.amkVersion) &&
      h.amkVersion > 0,
    'WRAPPER_CONTEXT',
  );
  for (const k of [
    'trustDomainID',
    'subjectID',
    'credentialIDHash',
    'contextID',
    'prfSalt',
    'wrapperID',
    'kdfSalt',
  ])
    requireThat(Buffer.isBuffer(h[k]) && h[k].length === 32, 'WRAPPER_LENGTH');
  return h;
}
export function prfInput(h) {
  validateHeader(h);
  return D('PRFInput', Object.fromEntries(headerFields.slice(0, 9).map((k) => [k, h[k]])));
}
export function wrapRoot(prf, root, header) {
  validateHeader(header);
  requireThat(prf.length === 32 && root.length === 32, 'ROOT_LENGTH');
  const k = hkdf(prf, header.kdfSalt, D('WrapperKDF', header));
  try {
    if (header.aead === 'AES-256-GCM')
      return { schemaVersion: 1, header, ...seal(k, root, D('WrapperAAD', header)) };
    // Metadata-bound KDF is mandatory for KW/KWP. The independent MAC also authenticates the complete envelope.
    const ciphertext = wrapAES(k, root, header.aead === 'AES-256-KWP');
    const m = hkdf(prf, header.kdfSalt, D('WrapperMACKey', header));
    try {
      return {
        schemaVersion: 1,
        header,
        ciphertext,
        tag: mac(m, D('WrapperMAC', { header, ciphertext })),
      };
    } finally {
      m.fill(0);
    }
  } finally {
    k.fill(0);
  }
}
export function unwrapRoot(prf, wrapper) {
  fields(wrapper, ['schemaVersion', 'header', 'ciphertext', 'tag'], ['nonce']);
  requireThat(prf.length === 32 && wrapper.schemaVersion === 1, 'WRAPPER_VERSION');
  const h = validateHeader(wrapper.header),
    k = hkdf(prf, h.kdfSalt, D('WrapperKDF', h));
  try {
    if (h.aead === 'AES-256-GCM') {
      requireThat(Buffer.isBuffer(wrapper.nonce), 'WRAPPER_NONCE');
      return open(k, wrapper, D('WrapperAAD', h));
    }
    requireThat(!wrapper.nonce, 'KW_UNEXPECTED_NONCE');
    const m = hkdf(prf, h.kdfSalt, D('WrapperMACKey', h));
    try {
      requireThat(
        equal(mac(m, D('WrapperMAC', { header: h, ciphertext: wrapper.ciphertext })), wrapper.tag),
        'WRAPPER_MAC',
      );
      return unwrapAES(k, wrapper.ciphertext, h.aead === 'AES-256-KWP');
    } finally {
      m.fill(0);
    }
  } finally {
    k.fill(0);
  }
}

export class EpochTransition {
  constructor(journal) {
    this.journal = journal;
  }
  prepare(id, { oldWrapper, newWrapper, expectedRevision = -1 }) {
    for (const k of ['trustDomainID', 'subjectID', 'contextID'])
      requireThat(equal(oldWrapper.header[k], newWrapper.header[k]), 'EPOCH_BINDING');
    for (const k of ['purpose', 'rpID', 'amkVersion'])
      requireThat(oldWrapper.header[k] === newWrapper.header[k], 'EPOCH_BINDING');
    requireThat(
      newWrapper.header.epoch === oldWrapper.header.epoch + 1 &&
        !equal(oldWrapper.header.prfSalt, newWrapper.header.prfSalt) &&
        !equal(oldWrapper.header.kdfSalt, newWrapper.header.kdfSalt),
      'EPOCH_BINDING',
    );
    return this.journal.put(
      'epoch',
      id,
      { state: 'PREPARED', oldWrapper, newWrapper },
      expectedRevision,
    );
  }
  commit(id, newPRF, oldPRF) {
    return this.journal.transaction(() => {
      const r = this.journal.get('epoch', id);
      requireThat(r?.value.state === 'PREPARED' && Buffer.isBuffer(oldPRF), 'EPOCH_STATE');
      const oldRoot = unwrapRoot(oldPRF, r.value.oldWrapper);
      try {
        const newRoot = unwrapRoot(newPRF, r.value.newWrapper);
        try {
          requireThat(equal(oldRoot, newRoot), 'EPOCH_ROOT_CHANGED');
          return this.journal.put('epoch', id, { ...r.value, state: 'COMMITTED' }, r.revision);
        } finally {
          newRoot.fill(0);
        }
      } finally {
        oldRoot.fill(0);
      }
    });
  }
  retire(id, revision) {
    const r = this.journal.get('epoch', id);
    requireThat(r?.revision === revision && r.value.state === 'COMMITTED', 'EPOCH_STATE');
    return this.journal.put('epoch', id, { ...r.value, state: 'OLD_RETIRED' }, revision);
  }
}

export function encryptVault(
  root,
  plaintext,
  {
    objectID = random(),
    objectVersion = 1,
    rootID = random(),
    rootVersion = 1,
    purpose = 'LOCAL_VAULT',
    mediaType = 'application/octet-stream',
    chunkSize = 1024 * 1024,
  } = {},
) {
  requireThat(
    root.length === 32 &&
      chunkSize >= 1024 &&
      chunkSize <= 16 * 1024 * 1024 &&
      plaintext.length <= 1024 * 1024 * 1024,
    'VAULT_LIMIT',
  );
  const h = {
    schemaVersion: 1,
    objectID,
    objectVersion,
    rootID,
    rootVersion,
    purpose,
    mediaType,
    length: plaintext.length,
    chunkSize,
    chunkCount: Math.max(1, Math.ceil(plaintext.length / chunkSize)),
    salt: random(),
  };
  const dek = random(),
    k = hkdf(root, h.salt, D('VaultDEK', h));
  try {
    const wrapped = seal(k, dek, D('VaultHeader', h)),
      chunks = [];
    for (let i = 0; i < h.chunkCount; i++) {
      const a = { headerHash: H('VaultHeader', h), index: i, total: h.chunkCount };
      chunks.push(
        seal(dek, plaintext.subarray(i * chunkSize, (i + 1) * chunkSize), D('VaultChunk', a)),
      );
    }
    return { header: h, wrapped, chunks };
  } finally {
    dek.fill(0);
    k.fill(0);
  }
}
export function decryptVault(
  root,
  vault,
  { expectedObjectID, expectedRootID, maxBytes = 1024 * 1024 * 1024 } = {},
) {
  fields(vault, ['header', 'wrapped', 'chunks']);
  const h = vault.header;
  fields(h, [
    'schemaVersion',
    'objectID',
    'objectVersion',
    'rootID',
    'rootVersion',
    'purpose',
    'mediaType',
    'length',
    'chunkSize',
    'chunkCount',
    'salt',
  ]);
  requireThat(
    h.schemaVersion === 1 &&
      Number.isSafeInteger(h.length) &&
      h.length >= 0 &&
      h.length <= maxBytes &&
      Number.isSafeInteger(h.chunkSize) &&
      h.chunkSize >= 1024 &&
      h.chunkSize <= 16 * 1024 * 1024 &&
      h.chunkCount === Math.max(1, Math.ceil(h.length / h.chunkSize)) &&
      vault.chunks.length === h.chunkCount,
    'VAULT_LENGTH',
  );
  if (expectedObjectID) requireThat(equal(h.objectID, expectedObjectID), 'VAULT_OBJECT');
  if (expectedRootID) requireThat(equal(h.rootID, expectedRootID), 'VAULT_ROOT');
  const k = hkdf(root, h.salt, D('VaultDEK', h)),
    decoded = [];
  let dek;
  try {
    dek = open(k, vault.wrapped, D('VaultHeader', h));
    for (let i = 0; i < h.chunkCount; i++) {
      const p = open(
        dek,
        vault.chunks[i],
        D('VaultChunk', { headerHash: H('VaultHeader', h), index: i, total: h.chunkCount }),
      );
      decoded.push(p);
      requireThat(
        p.length === (i === h.chunkCount - 1 ? h.length - i * h.chunkSize : h.chunkSize),
        'VAULT_CHUNK_LENGTH',
      );
    }
    return Buffer.concat(decoded);
  } finally {
    k.fill(0);
    dek?.fill(0);
    decoded.forEach((b) => b.fill(0));
  }
}

export function kemChallenge(
  publicKey,
  { subjectID, audience, requestID = random(), nonce = random(), expiresAt = now() + 120 },
) {
  const e = encapsulate(publicKey);
  const context = {
    schemaVersion: 1,
    requestID,
    keyID: keyID(publicKey),
    subjectID,
    audience,
    nonce,
    expiresAt,
    ciphertextHash: sha512(e.ciphertext),
  };
  const k = hkdf(e.sharedKey, nonce, D('KEMPossessionKDF', context));
  try {
    return {
      challenge: { context, ciphertext: e.ciphertext },
      expected: mac(k, D('KEMPossession', context)),
    };
  } finally {
    k.fill(0);
    e.sharedKey.fill(0);
  }
}
export function answerKEMChallenge(privateKey, challenge, { audience, at = now() }) {
  const c = challenge.context;
  requireThat(
    c.audience === audience &&
      c.expiresAt > at &&
      equal(c.ciphertextHash, sha512(challenge.ciphertext)),
    'KEM_CHALLENGE_CONTEXT',
  );
  const shared = decapsulate(privateKey, challenge.ciphertext),
    k = hkdf(shared, c.nonce, D('KEMPossessionKDF', c));
  try {
    return mac(k, D('KEMPossession', c));
  } finally {
    shared.fill(0);
    k.fill(0);
  }
}

const kemORI = '1.2.840.113549.1.9.16.13.3',
  authEnvelope = '1.2.840.113549.1.9.16.1.23',
  hkdfOID = '1.2.840.113549.1.9.16.3.28',
  kwOID = '2.16.840.1.101.3.4.1.45',
  gcmOID = '2.16.840.1.101.3.4.1.46';
export function encryptCMS(plaintext, recipients) {
  requireThat(recipients.length > 0 && recipients.length <= 100, 'RECIPIENT_LIMIT');
  const cek = random();
  try {
    const seen = new Set(),
      infos = recipients.map(({ publicKey, subjectKeyIdentifier }) => {
        requireThat(
          ['ml-kem-768', 'ml-kem-1024'].includes(publicKey.asymmetricKeyType) &&
            subjectKeyIdentifier.length > 0,
          'KEM_RECIPIENT',
        );
        const id = b64u(subjectKeyIdentifier);
        requireThat(!seen.has(id), 'DUPLICATE_RECIPIENT');
        seen.add(id);
        const e = encapsulate(publicKey),
          ukm = random(),
          wrap = algID(kwOID),
          info = seq(wrap, integer(32), der(0xa0, octet(ukm))),
          k = hkdf(e.sharedKey, Buffer.alloc(0), info);
        try {
          const kri = seq(
            integer(0),
            der(0x80, subjectKeyIdentifier),
            algID(publicKey.asymmetricKeyType),
            octet(e.ciphertext),
            algID(hkdfOID),
            integer(32),
            der(0xa0, octet(ukm)),
            wrap,
            octet(wrapAES(k, cek)),
          );
          return der(0xa4, Buffer.concat([oid(kemORI), kri]));
        } finally {
          k.fill(0);
          e.sharedKey.fill(0);
        }
      });
    const e = seal(cek, plaintext);
    return seq(
      oid(authEnvelope),
      der(
        0xa0,
        seq(
          integer(0),
          set(...infos),
          seq(
            oid(OID.data),
            seq(oid(gcmOID), seq(octet(e.nonce), integer(16))),
            der(0x80, e.ciphertext),
          ),
          octet(e.tag),
        ),
      ),
    );
  } finally {
    cek.fill(0);
  }
}
export function decryptCMS(raw, { privateKey, subjectKeyIdentifier }) {
  const r = parseDER(raw);
  requireThat(
    r.tag === 48 &&
      r.children.length === 2 &&
      oidText(r.children[0]) === authEnvelope &&
      r.children[1].tag === 0xa0 &&
      r.children[1].children.length === 1 &&
      r.children[1].children[0].tag === 48,
    'CMS_ENVELOPE_TYPE',
  );
  const a = r.children[1].children[0].children;
  requireThat(
    a.length === 4 &&
      intValue(a[0]) === 0n &&
      a[1].tag === 49 &&
      a[1].children.length >= 1 &&
      a[1].children.length <= 100 &&
      a[2].tag === 48 &&
      a[3].tag === 4 &&
      a[3].value.length === 16,
    'CMS_ENVELOPE_STRUCTURE',
  );
  let selected;
  for (const ri of a[1].children) {
    requireThat(
      ri.tag === 0xa4 &&
        ri.children.length === 2 &&
        oidText(ri.children[0]) === kemORI &&
        ri.children[1].tag === 48,
      'CMS_RECIPIENT_TYPE',
    );
    const c = ri.children[1].children;
    requireThat([8, 9].includes(c.length) && c[1].tag === 0x80, 'KEM_PARAMETERS');
    if (equal(c[1].value, subjectKeyIdentifier)) {
      requireThat(!selected, 'DUPLICATE_RECIPIENT');
      selected = c;
    }
  }
  requireThat(selected, 'RECIPIENT_NOT_FOUND');
  const c = selected,
    ukm = c.length === 9 ? c[6] : undefined,
    wrap = c[ukm ? 7 : 6],
    encryptedKey = c[ukm ? 8 : 7];
  requireThat(
    intValue(c[0]) === 0n &&
      c[1].tag === 0x80 &&
      equal(c[2].raw, algID(privateKey.asymmetricKeyType)) &&
      c[3].tag === 4 &&
      equal(c[4].raw, algID(hkdfOID)) &&
      intValue(c[5]) === 32n &&
      (!ukm || (ukm.tag === 0xa0 && ukm.children.length === 1 && ukm.children[0].tag === 4)) &&
      equal(wrap.raw, algID(kwOID)) &&
      encryptedKey.tag === 4,
    'KEM_PARAMETERS',
  );
  const shared = decapsulate(privateKey, c[3].value),
    k = hkdf(shared, Buffer.alloc(0), seq(wrap.raw, c[5].raw, ...(ukm ? [ukm.raw] : [])));
  let cek;
  try {
    cek = unwrapAES(k, encryptedKey.value);
    const e = a[2].children;
    requireThat(
      e.length === 3 &&
        oidText(e[0]) === OID.data &&
        e[1].tag === 48 &&
        e[1].children.length === 2 &&
        oidText(e[1].children[0]) === gcmOID &&
        e[1].children[1].tag === 48 &&
        e[2].tag === 0x80,
      'ENCRYPTED_CONTENT',
    );
    const p = e[1].children[1].children;
    requireThat(
      p.length === 2 && p[0].tag === 4 && p[0].value.length === 12 && intValue(p[1]) === 16n,
      'GCM_PARAMETERS',
    );
    return open(cek, { nonce: p[0].value, ciphertext: e[2].value, tag: a[3].value });
  } finally {
    shared.fill(0);
    k.fill(0);
    cek?.fill(0);
  }
}

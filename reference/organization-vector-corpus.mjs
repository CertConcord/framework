import { createHash, createPublicKey } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { createVectorReader } from './vector-corpus.mjs';

export const defaultOrganizationHistoryVectorDirectory = fileURLToPath(
  new URL('./vectors/organization-history-rar2/', import.meta.url),
);
export const organizationVectorProfile = 'certconcord-organization-history-vectors-draft-03-rar2';
export const vectorHash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const need = (condition, code) => {
  if (!condition) throw Object.assign(new Error(code), { code });
};
const keys = (value, required, optional = []) => {
  need(
    object(value) &&
      required.every((name) => Object.hasOwn(value, name)) &&
      Object.keys(value).every((name) => required.includes(name) || optional.includes(name)),
    'ORG_VECTOR_SCHEMA',
  );
};
const forbidden = new Set(['__proto__', 'prototype', 'constructor', 'privateKey', 'privateKeyDER']);
const configurationOnlyForbidden = new Set([
  'overall',
  'reason',
  'authorityResolver',
  'resolveTimestamp',
  'readKnowledge',
  'operator',
  'executionCurrent',
  'stateTime',
  'databasePath',
  'expected',
]);
const fileLimit = 32 * 1024 * 1024;
const totalLimit = 128 * 1024 * 1024;
const jsonLimit = 4 * 1024 * 1024;

/** Fail rather than silently drop a result field during JSON serialization. */
export function assertLosslessVectorJSON(value) {
  const pending = [[value, 0]],
    seen = new Set();
  let count = 0;
  while (pending.length) {
    const [item, depth] = pending.pop();
    need(depth <= 64 && ++count <= 200000, 'ORG_VECTOR_JSON_DEPTH');
    if (item === null || ['string', 'boolean'].includes(typeof item)) continue;
    if (typeof item === 'number') {
      need(Number.isFinite(item) && !Object.is(item, -0), 'ORG_VECTOR_JSON_VALUE');
      continue;
    }
    need(item && typeof item === 'object' && !seen.has(item), 'ORG_VECTOR_JSON_VALUE');
    seen.add(item);
    const array = Array.isArray(item);
    need(
      Object.getPrototypeOf(item) === (array ? Array.prototype : Object.prototype),
      'ORG_VECTOR_JSON_VALUE',
    );
    need(Object.getOwnPropertySymbols(item).length === 0, 'ORG_VECTOR_JSON_VALUE');
    const names = Object.getOwnPropertyNames(item);
    if (array)
      need(
        names.length === item.length + 1 &&
          names.every((name, index) => name === (index < item.length ? String(index) : 'length')),
        'ORG_VECTOR_JSON_VALUE',
      );
    for (const name of names) {
      if (array && name === 'length') continue;
      need(!forbidden.has(name), 'ORG_VECTOR_CONFIG_FIELD');
      const descriptor = Object.getOwnPropertyDescriptor(item, name);
      need(Object.hasOwn(descriptor, 'value') && descriptor.enumerable, 'ORG_VECTOR_JSON_VALUE');
      pending.push([descriptor.value, depth + 1]);
    }
  }
}
export function canonicalVectorJSON(value) {
  assertLosslessVectorJSON(value);
  return Buffer.from(JSON.stringify(value, null, 2) + '\n');
}
function parseJSON(bytes) {
  need(bytes.length <= jsonLimit, 'ORG_VECTOR_JSON_SIZE');
  let text, value;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    value = JSON.parse(text);
  } catch {
    need(false, 'ORG_VECTOR_JSON');
  }
  need(canonicalVectorJSON(value).equals(bytes), 'ORG_VECTOR_JSON_CANONICAL');
  return value;
}
const freeze = (value) => {
  if (object(value) || Array.isArray(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
};

/** Load only inventoried public data. Hashes are integrity metadata, not authority. */
export function loadOrganizationHistoryVectorCorpus(
  directory = defaultOrganizationHistoryVectorDirectory,
) {
  const { root, readContained } = createVectorReader(directory);
  const manifest = parseJSON(readContained('manifest.json', jsonLimit, 'ORG_VECTOR_JSON_SIZE'));
  keys(manifest, ['schemaVersion', 'profile', 'description', 'provenance', 'files', 'cases']);
  need(
    manifest.schemaVersion === 1 && manifest.profile === organizationVectorProfile,
    'ORG_VECTOR_VERSION',
  );
  need(
    typeof manifest.description === 'string' && manifest.description.length > 0,
    'ORG_VECTOR_SCHEMA',
  );
  need(
    Array.isArray(manifest.files) && manifest.files.length > 0 && manifest.files.length <= 512,
    'ORG_VECTOR_FILE_LIMIT',
  );
  need(
    Array.isArray(manifest.cases) && manifest.cases.length > 0 && manifest.cases.length <= 128,
    'ORG_VECTOR_CASE_LIMIT',
  );
  const files = new Map(),
    descriptors = new Map(),
    folded = new Set();
  let storedTotal = 0,
    decodedTotal = 0;
  for (const descriptor of manifest.files) {
    keys(descriptor, [
      'path',
      'bytes',
      'sha256',
      'mediaType',
      'encoding',
      'decodedBytes',
      'decodedSHA256',
    ]);
    need(
      typeof descriptor.path === 'string' &&
        /^files\/[0-9a-f]{64}\.[a-z0-9.]+$/.test(descriptor.path) &&
        descriptor.path.length <= 240 &&
        !folded.has(descriptor.path.toLowerCase()),
      'ORG_VECTOR_PATH',
    );
    folded.add(descriptor.path.toLowerCase());
    for (const field of ['bytes', 'decodedBytes'])
      need(
        Number.isSafeInteger(descriptor[field]) &&
          descriptor[field] >= 0 &&
          descriptor[field] <= fileLimit,
        'ORG_VECTOR_FILE_DESCRIPTOR',
      );
    for (const field of ['sha256', 'decodedSHA256'])
      need(
        typeof descriptor[field] === 'string' && /^[0-9a-f]{64}$/.test(descriptor[field]),
        'ORG_VECTOR_FILE_DESCRIPTOR',
      );
    need(
      ['base64', 'utf8'].includes(descriptor.encoding) &&
        typeof descriptor.mediaType === 'string' &&
        descriptor.mediaType.length > 0,
      'ORG_VECTOR_FILE_DESCRIPTOR',
    );
    need(
      descriptor.path.split('/')[1].startsWith(descriptor.decodedSHA256 + '.'),
      'ORG_VECTOR_ADDRESS',
    );
    storedTotal += descriptor.bytes;
    decodedTotal += descriptor.decodedBytes;
    need(storedTotal <= totalLimit && decodedTotal <= totalLimit, 'ORG_VECTOR_TOTAL_SIZE');
  }
  for (const descriptor of manifest.files) {
    const stored = readContained(
      descriptor.path,
      fileLimit,
      'ORG_VECTOR_FILE_SIZE',
      descriptor.bytes,
    );
    need(vectorHash(stored) === descriptor.sha256, 'ORG_VECTOR_FILE_HASH');
    let decoded = stored;
    if (descriptor.encoding === 'base64') {
      need(stored.length <= Math.ceil(descriptor.decodedBytes / 3) * 4 + 1, 'ORG_VECTOR_BASE64');
      decoded = Buffer.from(stored.toString('ascii'), 'base64');
      need(Buffer.from(decoded.toString('base64') + '\n').equals(stored), 'ORG_VECTOR_BASE64');
    }
    need(
      decoded.length === descriptor.decodedBytes &&
        vectorHash(decoded) === descriptor.decodedSHA256,
      'ORG_VECTOR_DECODED_HASH',
    );
    if (descriptor.encoding === 'utf8') {
      need(
        descriptor.mediaType === 'application/json' && descriptor.path.endsWith('.json'),
        'ORG_VECTOR_MATERIAL_TYPE',
      );
      parseJSON(decoded);
    } else need(descriptor.path.endsWith('.b64'), 'ORG_VECTOR_MATERIAL_TYPE');
    files.set(descriptor.path, decoded);
    descriptors.set(descriptor.path, descriptor);
  }
  const read = (name) => {
    need(typeof name === 'string' && files.has(name), 'ORG_VECTOR_FILE_UNDECLARED');
    return Buffer.from(files.get(name));
  };
  const readJSON = (name) => {
    need(descriptors.get(name)?.encoding === 'utf8', 'ORG_VECTOR_JSON_REFERENCE');
    return parseJSON(read(name));
  };
  const materialize = (value, depth = 0) => {
    need(depth <= 64, 'ORG_VECTOR_CONFIG_DEPTH');
    if (Array.isArray(value)) return value.map((child) => materialize(child, depth + 1));
    if (!object(value)) return value;
    if (Object.hasOwn(value, '$hex')) {
      keys(value, ['$hex']);
      need(
        typeof value.$hex === 'string' &&
          /^(?:[0-9a-f]{2})*$/.test(value.$hex) &&
          value.$hex.length <= 8192,
        'ORG_VECTOR_HEX',
      );
      return Buffer.from(value.$hex, 'hex');
    }
    if (Object.hasOwn(value, '$file')) {
      keys(value, ['$file', 'type']);
      need(['bytes', 'spki'].includes(value.type), 'ORG_VECTOR_MATERIAL_TYPE');
      const bytes = read(value.$file);
      if (value.type === 'spki') {
        let key;
        try {
          key = createPublicKey({ key: bytes, type: 'spki', format: 'der' });
        } catch {
          need(false, 'ORG_VECTOR_PUBLIC_KEY');
        }
        need(
          key.type === 'public' && key.export({ type: 'spki', format: 'der' }).equals(bytes),
          'ORG_VECTOR_PUBLIC_KEY',
        );
      }
      return bytes;
    }
    need(
      Object.keys(value).every(
        (name) =>
          !name.startsWith('$') && !forbidden.has(name) && !configurationOnlyForbidden.has(name),
      ),
      'ORG_VECTOR_CONFIG_FIELD',
    );
    return Object.fromEntries(
      Object.entries(value).map(([name, child]) => [name, materialize(child, depth + 1)]),
    );
  };
  const config = (name) => materialize(readJSON(name));
  const ids = new Set();
  for (const entry of manifest.cases) {
    keys(entry, [
      'id',
      'description',
      'originalBytes',
      'evidenceRecord',
      'policy',
      'knowledge',
      'expected',
    ]);
    need(
      typeof entry.id === 'string' &&
        /^[a-z][a-z0-9-]{0,95}$/.test(entry.id) &&
        !ids.has(entry.id) &&
        typeof entry.description === 'string' &&
        entry.description.length > 0,
      'ORG_VECTOR_CASE_ID',
    );
    ids.add(entry.id);
    read(entry.originalBytes);
    read(entry.evidenceRecord);
    const policy = config(entry.policy),
      knowledge = config(entry.knowledge);
    keys(policy, ['schemaVersion', 'trust', 'retainedAuthorities', 'preservation']);
    need(policy.schemaVersion === 1, 'ORG_VECTOR_VERSION');
    keys(knowledge, [
      'knowledgeTime',
      'authorityHistory',
      'statusMaterial',
      'certificateStatusMaterial',
    ]);
    need(
      Number.isSafeInteger(knowledge.knowledgeTime) && knowledge.knowledgeTime >= 0,
      'ORG_VECTOR_KNOWLEDGE',
    );
    for (const name of ['statusMaterial', 'certificateStatusMaterial']) {
      need(Array.isArray(knowledge[name]) && knowledge[name].length <= 64, 'ORG_VECTOR_KNOWLEDGE');
      for (const member of knowledge[name]) {
        keys(member, ['cms', 'issuerCertificate'], ['evidenceRecord']);
        need(
          Buffer.isBuffer(member.cms) && Buffer.isBuffer(member.issuerCertificate),
          'ORG_VECTOR_KNOWLEDGE',
        );
        if (Object.hasOwn(member, 'evidenceRecord'))
          need(Buffer.isBuffer(member.evidenceRecord), 'ORG_VECTOR_KNOWLEDGE');
      }
    }
    need(Array.isArray(knowledge.authorityHistory), 'ORG_VECTOR_KNOWLEDGE');
    for (const member of knowledge.authorityHistory) {
      keys(member, ['manifest', 'signatures', 'publicationProof']);
      need(
        Buffer.isBuffer(member.manifest) &&
          Buffer.isBuffer(member.publicationProof) &&
          Array.isArray(member.signatures),
        'ORG_VECTOR_KNOWLEDGE',
      );
      for (const signature of member.signatures) {
        keys(signature, ['keyID', 'signature']);
        need(
          Buffer.isBuffer(signature.keyID) && Buffer.isBuffer(signature.signature),
          'ORG_VECTOR_KNOWLEDGE',
        );
      }
    }
    need(descriptors.get(entry.expected)?.encoding === 'utf8', 'ORG_VECTOR_JSON_REFERENCE');
  }
  readJSON(manifest.provenance);
  return Object.freeze({
    directory: root,
    manifest: freeze(manifest),
    read,
    config,
    expected: (entry) => readJSON(entry.expected),
    input: (entry) => ({
      id: entry.id,
      configuration: config(entry.policy),
      knowledge: config(entry.knowledge),
      originalBytes: read(entry.originalBytes),
      evidenceRecord: read(entry.evidenceRecord),
    }),
  });
}

import { createVectorReader } from './vector-corpus.mjs';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash, createPublicKey, X509Certificate } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { createVerifier as sourceVerifier } from './sdk/index.mjs';
import { createAuthorityResolver } from './authority-history.mjs';
import { createRetainedAuthorityResolver } from './retained-authorities.mjs';
import { decodeCBOR } from './core.mjs';
import { verifyCMS, OID } from './pki.mjs';
import { verifyTimestampToken } from './timestamp.mjs';
import { verifyERSPreservation } from './archive.mjs';
import { verifyPreservedDocument } from './historical-validation.mjs';

export const defaultVectorDirectory = fileURLToPath(
  new URL('./vectors/document-acceptance-mtc07-rar2-mdoc2/', import.meta.url),
);
const outcomes = new Set(['VALID', 'INVALID', 'INDETERMINATE', 'UNSUPPORTED']);
const dimensions = new Set([
  'integrity',
  'issuerTrust',
  'qualification',
  'keyBinding',
  'authorization',
  'status',
  'time',
  'transparency',
]);
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const instant = (value) => Number.isSafeInteger(value) && value >= 0;
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
function need(condition, code) {
  if (!condition) throw Object.assign(new Error(code), { code });
}
function keys(value, required, optional = []) {
  need(
    object(value) &&
      required.every((name) => Object.hasOwn(value, name)) &&
      Object.keys(value).every((name) => required.includes(name) || optional.includes(name)),
    'VECTOR_SCHEMA',
  );
}
function freeze(value) {
  if (object(value) || Array.isArray(value)) {
    for (const entry of Object.values(value)) freeze(entry);
    Object.freeze(value);
  }
  return value;
}
function json(bytes) {
  need(bytes.length <= 4 * 1024 * 1024, 'VECTOR_JSON_SIZE');
  return JSON.parse(bytes.toString('utf8'));
}

/** The fixture inventory is integrity metadata, never an authority appointment. */
export function loadVectorCorpus(directory = defaultVectorDirectory) {
  const { root, readContained } = createVectorReader(directory);
  const manifest = json(readContained('manifest.json', 4 * 1024 * 1024, 'VECTOR_JSON_SIZE'));
  keys(manifest, [
    'schemaVersion',
    'profile',
    'description',
    'files',
    'documents',
    'preservation',
    'retained',
  ]);
  need(
    manifest.schemaVersion === 1 &&
      manifest.profile === 'certconcord-document-acceptance-vectors-draft-03-mtc07-rar2-mdoc2',
    'VECTOR_VERSION',
  );
  need(
    Array.isArray(manifest.files) && manifest.files.length > 0 && manifest.files.length <= 512,
    'VECTOR_FILE_LIMIT',
  );
  const files = new Map();
  let total = 0;
  for (const file of manifest.files) {
    keys(file, [
      'path',
      'bytes',
      'sha256',
      'mediaType',
      'encoding',
      'decodedBytes',
      'decodedSHA256',
    ]);
    need(
      !files.has(file.path) &&
        file.path !== 'manifest.json' &&
        Number.isSafeInteger(file.bytes) &&
        file.bytes >= 0 &&
        file.bytes <= 32 * 1024 * 1024 &&
        typeof file.sha256 === 'string' &&
        /^[0-9a-f]{64}$/.test(file.sha256) &&
        typeof file.mediaType === 'string' &&
        ['utf8', 'base64'].includes(file.encoding) &&
        Number.isSafeInteger(file.decodedBytes) &&
        file.decodedBytes >= 0 &&
        file.decodedBytes <= 32 * 1024 * 1024 &&
        /^[0-9a-f]{64}$/.test(file.decodedSHA256),
      'VECTOR_FILE_DESCRIPTOR',
    );
    total += file.bytes;
    need(total <= 128 * 1024 * 1024, 'VECTOR_TOTAL_SIZE');
    const bytes = readContained(file.path, 32 * 1024 * 1024, 'VECTOR_FILE_SIZE', file.bytes);
    need(bytes.length === file.bytes && sha256(bytes) === file.sha256, 'VECTOR_FILE_HASH');
    const decoded =
      file.encoding === 'base64' ? Buffer.from(bytes.toString('utf8'), 'base64') : bytes;
    if (file.encoding === 'base64')
      need(Buffer.from(decoded.toString('base64') + '\n').equals(bytes), 'VECTOR_BASE64');
    need(
      decoded.length === file.decodedBytes && sha256(decoded) === file.decodedSHA256,
      'VECTOR_DECODED_HASH',
    );
    files.set(file.path, decoded);
  }
  const read = (name) => {
    need(files.has(name), 'VECTOR_FILE_UNDECLARED');
    return Buffer.from(files.get(name));
  };
  const materialize = (value, depth = 0) => {
    need(depth <= 64, 'VECTOR_CONFIG_DEPTH');
    if (Array.isArray(value)) return value.map((entry) => materialize(entry, depth + 1));
    if (!object(value)) return value;
    if (Object.hasOwn(value, '$hex')) {
      keys(value, ['$hex']);
      need(
        typeof value.$hex === 'string' &&
          /^(?:[0-9a-f]{2})*$/.test(value.$hex) &&
          value.$hex.length <= 8192,
        'VECTOR_HEX',
      );
      return Buffer.from(value.$hex, 'hex');
    }
    if (Object.hasOwn(value, '$file')) {
      keys(value, ['$file', 'type']);
      const bytes = read(value.$file);
      if (value.type === 'bytes') return bytes;
      if (value.type === 'x509') return new X509Certificate(bytes);
      need(value.type === 'spki', 'VECTOR_MATERIAL_TYPE');
      const key = createPublicKey({ key: bytes, type: 'spki', format: 'der' });
      need(key.type === 'public', 'VECTOR_PUBLIC_KEY');
      return key;
    }
    need(
      Object.keys(value).every(
        (name) =>
          !name.startsWith('$') &&
          !['__proto__', 'prototype', 'constructor', 'privateKey', 'privateKeyDER'].includes(name),
      ),
      'VECTOR_CONFIG_FIELD',
    );
    return Object.fromEntries(
      Object.entries(value).map(([name, entry]) => [name, materialize(entry, depth + 1)]),
    );
  };
  const config = (name) => materialize(json(read(name)));
  const ids = new Set();
  for (const group of ['documents', 'preservation', 'retained']) {
    need(Array.isArray(manifest[group]) && manifest[group].length <= 128, 'VECTOR_CASE_LIMIT');
    for (const entry of manifest[group]) {
      const required =
        group === 'documents'
          ? ['id', 'description', 'format', 'bytes', 'trust', 'expected']
          : ['id', 'description', 'options', 'expected'];
      keys(entry, required);
      need(
        typeof entry.id === 'string' &&
          /^[a-z][a-z0-9-]{0,95}$/.test(entry.id) &&
          !ids.has(entry.id) &&
          typeof entry.description === 'string',
        'VECTOR_CASE_ID',
      );
      ids.add(entry.id);
      need(object(entry.expected), 'VECTOR_EXPECTED');
      if (group === 'documents') {
        need(['CMS', 'MDOC'].includes(entry.format), 'VECTOR_FORMAT');
        read(entry.bytes);
        read(entry.trust);
        stableDocumentResult(entry.expected);
      } else read(entry.options);
    }
  }
  return Object.freeze({ directory: root, manifest: freeze(manifest), read, config });
}

function timestampStatus(certificate, record) {
  keys(record, ['status', 'publishedAt', 'nextUpdate'], ['effectiveTime', 'compromiseStart']);
  need(
    ['GOOD', 'REVOKED'].includes(record.status) &&
      instant(record.publishedAt) &&
      instant(record.nextUpdate) &&
      record.nextUpdate > record.publishedAt,
    'VECTOR_STATUS',
  );
  if (record.status === 'REVOKED')
    need(
      instant(record.effectiveTime) &&
        (record.compromiseStart === undefined || instant(record.compromiseStart)),
      'VECTOR_STATUS',
    );
  return (query) => {
    if (
      !Buffer.isBuffer(query?.certificate) ||
      !certificate.equals(query.certificate) ||
      !Number.isFinite(query.stateTime) ||
      !Number.isFinite(query.knowledgeTime) ||
      query.stateTime > query.knowledgeTime
    )
      return { overall: 'INVALID', reason: 'TIMESTAMP_STATUS_BINDING' };
    if (record.publishedAt > query.knowledgeTime)
      return { overall: 'INDETERMINATE', reason: 'TIMESTAMP_STATUS_NOT_YET_KNOWN' };
    if (
      record.status === 'REVOKED' &&
      query.stateTime >= Math.min(record.effectiveTime, record.compromiseStart ?? Infinity)
    )
      return { overall: 'INVALID', reason: 'TIMESTAMP_STATUS_REVOKED' };
    if (query.knowledgeTime >= record.nextUpdate)
      return { overall: 'INDETERMINATE', reason: 'TIMESTAMP_STATUS_STALE' };
    return { overall: 'VALID', reason: 'TIMESTAMP_STATUS_GOOD' };
  };
}

function loadTrust(corpus, name) {
  const input = corpus.config(name);
  keys(input, ['schemaVersion', 'trust', 'authorities', 'timestampStatus']);
  need(input.schemaVersion === 1 && instant(input.trust?.knowledgeTime), 'VECTOR_TRUST_TIME');
  const trust = input.trust;
  need(
    !Object.hasOwn(trust, 'authorityResolver') && !Object.hasOwn(trust.timestamp ?? {}, 'status'),
    'VECTOR_CALLBACK_INPUT',
  );
  trust.authorityResolver = createAuthorityResolver({
    trustDomainID: trust.trustDomainID,
    authorities: input.authorities,
  });
  if (trust.timestamp)
    trust.timestamp.status = timestampStatus(trust.timestamp.certificate, input.timestampStatus);
  return trust;
}

/** Compare only the stable public result contract; retain details in the returned actual result. */
export function stableDocumentResult(result) {
  need(
    object(result) &&
      outcomes.has(result.overall) &&
      typeof result.reason === 'string' &&
      result.reason.length > 0 &&
      result.coreRevision === 'draft-03' &&
      (result.profile === null || typeof result.profile === 'string') &&
      object(result.dimensions),
    'VECTOR_RESULT_CONTRACT',
  );
  for (const [name, decision] of Object.entries(result.dimensions)) {
    keys(decision, ['overall', 'reason']);
    need(
      dimensions.has(name) &&
        outcomes.has(decision.overall) &&
        typeof decision.reason === 'string' &&
        decision.reason.length > 0,
      'VECTOR_DIMENSION',
    );
  }
  return {
    overall: result.overall,
    reason: result.reason,
    coreRevision: result.coreRevision,
    profile: result.profile,
    dimensions: result.dimensions,
  };
}
function compare(id, actual, expected, details) {
  if (!isDeepStrictEqual(actual, expected)) {
    throw Object.assign(new Error('VECTOR_EXPECTATION_MISMATCH: ' + id), {
      code: 'VECTOR_EXPECTATION_MISMATCH',
      id,
      actual,
      expected,
      details,
    });
  }
  return Object.freeze({ id, actual, details });
}

/** Inject only the installed SDK's public createVerifier export for package-consumer replay. */
export function runDocumentVectors({ directory, createVerifier = sourceVerifier } = {}) {
  need(typeof createVerifier === 'function', 'VECTOR_VERIFIER_FACTORY');
  const corpus = loadVectorCorpus(directory);
  return corpus.manifest.documents.map((entry) => {
    const result = createVerifier({
      format: entry.format,
      trust: loadTrust(corpus, entry.trust),
    }).verify(corpus.read(entry.bytes));
    return compare(entry.id, stableDocumentResult(result), entry.expected, result);
  });
}

function captured(action) {
  try {
    return { outcome: 'RETURNED', result: action() };
  } catch (error) {
    return { outcome: 'THREW', code: error.code ?? error.message };
  }
}
function archivePolicy(input, resolver, domain) {
  keys(input, ['at', 'dataValidUntil', 'hashValidUntil', 'timestampAuthorities']);
  need(
    instant(input.at) &&
      Array.isArray(input.timestampAuthorities) &&
      input.timestampAuthorities.length > 0 &&
      input.timestampAuthorities.length <= 16,
    'VECTOR_ARCHIVE_POLICY',
  );
  const authorities = input.timestampAuthorities.map((entry) => {
    keys(entry, ['certificate', 'issuerKey', 'policy', 'validUntil'], ['status', 'revokedAt']);
    return {
      ...entry,
      status: resolver
        ? ({ certificate, stateTime, knowledgeTime }) =>
            resolver({
              certificate,
              role: 'TIMESTAMP_AUTHORITY',
              scope: { trustDomainID: domain },
              stateTime,
              knowledgeTime,
            })
        : timestampStatus(entry.certificate, entry.status),
    };
  });
  return {
    at: input.at,
    dataValidUntil: input.dataValidUntil,
    hashValidUntil: input.hashValidUntil,
    resolveTimestamp(token) {
      const cert = verifyCMS(token, { expectedContentType: OID.tstInfo }).certificate;
      const matches = authorities.filter((entry) => entry.certificate.equals(cert));
      return matches.length === 1 ? matches[0] : undefined;
    },
  };
}

export function runPreservationVectors({ directory } = {}) {
  const corpus = loadVectorCorpus(directory);
  return corpus.manifest.preservation.map((entry) => {
    const input = corpus.config(entry.options);
    keys(input, ['schemaVersion', 'record', 'data', 'policy']);
    need(input.schemaVersion === 1, 'VECTOR_VERSION');
    const result = captured(() =>
      verifyERSPreservation(input.record, input.data, archivePolicy(input.policy)),
    );
    return compare(entry.id, result, entry.expected, result);
  });
}

export function runRetainedVectors({ directory } = {}) {
  const corpus = loadVectorCorpus(directory);
  return corpus.manifest.retained.map((entry) => {
    const input = corpus.config(entry.options);
    keys(
      input,
      [
        'schemaVersion',
        'format',
        'originalBytes',
        'currentBytes',
        'evidenceRecord',
        'historicalTrust',
        'currentTrust',
        'history',
        'historyTrust',
        'publicationTSA',
        'preservationPolicy',
        'historicalKnowledgeTime',
        'currentKnowledgeTime',
      ],
      ['originalStatusProof'],
    );
    need(input.schemaVersion === 1 && ['CMS', 'MDOC'].includes(input.format), 'VECTOR_VERSION');
    const publication = input.publicationTSA;
    const resolver = createRetainedAuthorityResolver({
      ...input.historyTrust,
      history: decodeCBOR(input.history),
      verifyPublication: ({ imprint, proof, at }) => ({
        overall: 'VALID',
        ...verifyTimestampToken(proof, { ...publication, imprint, at, maxFutureSkew: 0 }),
      }),
    });
    const policy = archivePolicy(
      input.preservationPolicy,
      resolver,
      input.historyTrust.trustDomainID,
    );
    const result = verifyPreservedDocument({
      ...input,
      authorityResolver: resolver,
      preservationPolicy: policy,
      historicalTrust: loadTrust(corpus, input.historicalTrust),
      currentTrust: loadTrust(corpus, input.currentTrust),
      ...(Object.hasOwn(input, 'originalStatusProof')
        ? {
            originalStatusProof:
              input.originalStatusProof == null || !object(input.originalStatusProof)
                ? input.originalStatusProof
                : {
                    ...input.originalStatusProof,
                    ...(input.originalStatusProof.preservationPolicy != null
                      ? {
                          preservationPolicy: archivePolicy(
                            input.originalStatusProof.preservationPolicy,
                            resolver,
                            input.historyTrust.trustDomainID,
                          ),
                        }
                      : {}),
                  },
          }
        : {}),
    });
    const decision = (value) => ({
      overall: value.overall,
      ...(value.reason ? { reason: value.reason } : {}),
    });
    const stable = {
      overall: result.overall,
      preservation: decision(result.preservation),
      historicalAuthorization: decision(result.historicalAuthorization),
      currentAdmissibility: decision(result.currentAdmissibility),
      historicalKnowledgeTime: result.historicalKnowledgeTime,
      currentKnowledgeTime: result.currentKnowledgeTime,
      ...(Object.hasOwn(result, 'originalStatusProof')
        ? {
            originalStatusProof: {
              ...decision(result.originalStatusProof),
              ...(result.originalStatusProof.overall === 'VALID'
                ? {
                    proofOfExistenceUpperBound:
                      result.originalStatusProof.proofOfExistenceUpperBound,
                  }
                : {}),
            },
            historicalBytesVisibility: decision(result.historicalBytesVisibility),
          }
        : {}),
    };
    return compare(entry.id, stable, entry.expected, result);
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    need(process.argv.length <= 3, 'VECTOR_ARGUMENTS');
    const options = process.argv[2] ? { directory: resolve(process.argv[2]) } : {};
    const documents = runDocumentVectors(options),
      preservation = runPreservationVectors(options),
      retained = runRetainedVectors(options);
    console.log(
      JSON.stringify(
        {
          documents: documents.map(({ id, actual }) => ({ id, ...actual })),
          preservation: preservation.map(({ id, actual }) => ({ id, ...actual })),
          retained: retained.map(({ id, actual }) => ({ id, ...actual })),
        },
        null,
        2,
      ),
    );
  } catch (error) {
    console.error(
      JSON.stringify(
        {
          error: error.code ?? error.message,
          id: error.id,
          actual: error.actual,
          expected: error.expected,
        },
        null,
        2,
      ),
    );
    process.exitCode = 1;
  }
}

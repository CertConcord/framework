import { types } from 'node:util';
import {
  dcbor,
  decodeCBOR,
  equal,
  fields,
  keyID,
  parseDER,
  publicFromDER,
  spki,
  sha256,
} from './core.mjs';
import { parseCertificate } from './pki.mjs';
import { verifyTimestampToken } from './timestamp.mjs';
import {
  createRetainedAuthorityResolver,
  authenticateRetainedAuthorityEntry,
} from './retained-authorities.mjs';
import { OrganizationHistoryKnowledgeStore } from './organization-history-knowledge.mjs';
import { record, snapshot } from './organization-delegation-state.mjs';
import {
  VerificationError,
  verificationOutcome,
  verificationResult,
} from './verification-result.mjs';

const MiB = 1024 * 1024;
const sources = new WeakMap();
const instant = (value) => Number.isSafeInteger(value) && value >= 0;
const oid = /^(?:0|1|2)(?:\.(?:0|[1-9][0-9]*))+$/;
const need = (condition, code, overall = 'INVALID') => {
  if (!condition) throw new VerificationError(code, overall);
};
function binary(value, maximum, length = 1) {
  need(Buffer.isBuffer(value) && value.length >= length, 'ORG_HISTORY_SOURCE_BINARY');
  need(value.length <= maximum, 'ORG_HISTORY_SOURCE_LIMIT', 'UNSUPPORTED');
  return value;
}
function list(value, maximum, minimum = 0) {
  need(Array.isArray(value) && value.length >= minimum, 'ORG_HISTORY_SOURCE_ARRAY');
  need(value.length <= maximum, 'ORG_HISTORY_SOURCE_LIMIT', 'UNSUPPORTED');
  return value;
}
function copy(value, maximum) {
  const result = snapshot(value);
  need(dcbor(result).length <= maximum, 'ORG_HISTORY_SOURCE_LIMIT', 'UNSUPPORTED');
  return result;
}
function deadlines(value, pattern) {
  need(value && typeof value === 'object' && !Array.isArray(value), 'ORG_HISTORY_SOURCE_DEADLINES');
  need(Object.keys(value).length <= 4096, 'ORG_HISTORY_SOURCE_LIMIT', 'UNSUPPORTED');
  for (const [name, deadline] of Object.entries(value))
    need(pattern.test(name) && instant(deadline) && deadline > 0, 'ORG_HISTORY_SOURCE_DEADLINES');
}
function publicKey(raw) {
  binary(raw, 65536);
  const key = publicFromDER(raw);
  need(key.type === 'public' && equal(spki(key), raw), 'ORG_HISTORY_SOURCE_PUBLIC_KEY');
  return key;
}
function governance(value) {
  fields(value, ['roots', 'threshold']);
  const ids = new Set();
  for (const root of list(value.roots, 64, 1)) {
    fields(root, ['publicKeyDER', 'validFrom', 'validUntil']);
    need(
      instant(root.validFrom) && instant(root.validUntil) && root.validFrom < root.validUntil,
      'ORG_HISTORY_SOURCE_ROOT_INTERVAL',
    );
    const id = keyID(publicKey(root.publicKeyDER)).toString('hex');
    need(!ids.has(id), 'ORG_HISTORY_SOURCE_DUPLICATE_ROOT');
    ids.add(id);
  }
  need(
    instant(value.threshold) && value.threshold > 0 && value.threshold <= ids.size,
    'ORG_HISTORY_SOURCE_ROOT_THRESHOLD',
  );
}
function timestampPins(values, publication) {
  const ids = new Set();
  return list(values, 64, 1).map((pin) => {
    fields(
      pin,
      [
        'certificate',
        'issuerPublicKeyDER',
        'policy',
        'validUntil',
        'signatureProfile',
        ...(publication ? ['validFrom', 'knowledgeValidUntil'] : []),
      ],
      ['revokedAt'],
    );
    binary(pin.certificate, 65536);
    const certificate = parseCertificate(pin.certificate);
    need(
      typeof pin.policy === 'string' &&
        oid.test(pin.policy) &&
        instant(pin.validUntil) &&
        pin.validUntil > 0 &&
        ['CERTCONCORD-PQ', 'EXTERNAL-RFC3161'].includes(pin.signatureProfile),
      'ORG_HISTORY_SOURCE_TIMESTAMP_POLICY',
    );
    if (Object.hasOwn(pin, 'revokedAt'))
      need(instant(pin.revokedAt), 'ORG_HISTORY_SOURCE_TIMESTAMP_POLICY');
    if (publication)
      need(
        instant(pin.validFrom) &&
          pin.validFrom < pin.validUntil &&
          instant(pin.knowledgeValidUntil) &&
          pin.knowledgeValidUntil > pin.validFrom,
        'ORG_HISTORY_SOURCE_PUBLICATION_INTERVAL',
      );
    const id = pin.certificate.toString('hex');
    need(!ids.has(id), 'ORG_HISTORY_SOURCE_DUPLICATE_TIMESTAMP');
    ids.add(id);
    return { ...pin, issuerKey: publicKey(pin.issuerPublicKeyDER), parsed: certificate };
  });
}
function trustShape(trust) {
  fields(trust, [
    'trustDomainID',
    'organizationID',
    'issuerID',
    'identityNamespace',
    'policy',
    'controlTrust',
    'credentialTrust',
    'algorithmDeadlines',
    'hashDeadlines',
    'keyDeadlines',
  ]);
  binary(trust.trustDomainID, 32, 32);
  binary(trust.organizationID, 32, 32);
  need(
    typeof trust.issuerID === 'string' &&
      trust.issuerID.length > 0 &&
      trust.issuerID.length <= 128 &&
      typeof trust.identityNamespace === 'string' &&
      /^[\x21-\x7e]{1,128}$/.test(trust.identityNamespace),
    'ORG_HISTORY_SOURCE_SCOPE',
  );
  fields(trust.policy, [
    'schemaVersion',
    'activationMode',
    'allowedProfiles',
    'allowedOrigins',
    'rpID',
    'audience',
    'maxActivationLifetime',
    'requireTrustedTime',
    'executionBinding',
    'organizationDelegation',
  ]);
  fields(trust.policy.executionBinding, ['profile', 'providerID', 'maxLeaseSeconds']);
  fields(trust.policy.organizationDelegation, [
    'profile',
    'mode',
    'identityNamespace',
    'minimumApprovers',
  ]);
  for (const member of list(trust.controlTrust, 64)) {
    fields(member, [
      'certificate',
      'organizationID',
      'identityNamespace',
      'issuerID',
      'purpose',
      'objectTypes',
    ]);
    binary(member.certificate, 65536);
    list(member.objectTypes, 3);
  }
  const credential = trust.credentialTrust;
  fields(credential, [
    'certificate',
    'registrationAuthorization',
    'issuerCertificate',
    'raCertificate',
    'statusCertificate',
    'issuanceScope',
  ]);
  for (const name of ['certificate', 'issuerCertificate', 'raCertificate', 'statusCertificate'])
    binary(credential[name], 65536);
  binary(credential.registrationAuthorization, 131072);
  fields(credential.issuanceScope, ['trustDomainID', 'issuerID', 'issuerKeyID', 'representation']);
  deadlines(trust.algorithmDeadlines, oid);
  deadlines(trust.hashDeadlines, oid);
  deadlines(trust.keyDeadlines, /^[a-f0-9]{128}$/);
}
function configuration(input) {
  const value = copy(input, 4 * MiB);
  fields(value, ['schemaVersion', 'trust', 'retainedAuthorities', 'preservation']);
  need(value.schemaVersion === 1, 'ORG_HISTORY_SOURCE_SCHEMA', 'UNSUPPORTED');
  trustShape(value.trust);
  const retained = value.retainedAuthorities;
  fields(retained, ['governance', 'algorithmDeadlines', 'publication']);
  governance(retained.governance);
  deadlines(retained.algorithmDeadlines, /^[a-z][a-z0-9-]{0,63}$/);
  fields(retained.publication, ['format', 'timestampAuthorities', 'hashValidUntil']);
  need(
    retained.publication.format === 'RFC3161',
    'ORG_HISTORY_SOURCE_PUBLICATION_FORMAT',
    'UNSUPPORTED',
  );
  deadlines(retained.publication.hashValidUntil, oid);
  fields(value.preservation, ['hashValidUntil', 'timestampAuthorities'], ['dataValidUntil']);
  deadlines(value.preservation.hashValidUntil, oid);
  if (Object.hasOwn(value.preservation, 'dataValidUntil'))
    need(
      instant(value.preservation.dataValidUntil) && value.preservation.dataValidUntil > 0,
      'ORG_HISTORY_SOURCE_PROTECTION',
    );
  return {
    value,
    publication: timestampPins(retained.publication.timestampAuthorities, true),
    archive: timestampPins(value.preservation.timestampAuthorities, false),
  };
}
function material(values) {
  for (const member of list(values, 64)) {
    fields(member, ['cms', 'issuerCertificate'], ['evidenceRecord']);
    binary(member.cms, 131072);
    binary(member.issuerCertificate, 65536);
    if (Object.hasOwn(member, 'evidenceRecord')) binary(member.evidenceRecord, 16 * MiB);
  }
}
function knowledge(input) {
  const value = copy(input, 16 * MiB);
  fields(value, [
    'knowledgeTime',
    'authorityHistory',
    'statusMaterial',
    'certificateStatusMaterial',
  ]);
  need(instant(value.knowledgeTime), 'ORG_KNOWLEDGE_TIME');
  material(value.statusMaterial);
  material(value.certificateStatusMaterial);
  const history = list(value.authorityHistory, 256).map((entry) => {
    fields(entry, ['manifest', 'signatures', 'publicationProof']);
    binary(entry.manifest, 16 * MiB);
    binary(entry.publicationProof, 16 * MiB);
    const manifest = decodeCBOR(entry.manifest);
    need(equal(dcbor(manifest), entry.manifest), 'ORG_HISTORY_SOURCE_MANIFEST_CANONICAL');
    for (const signature of list(entry.signatures, 64, 1)) {
      fields(signature, ['keyID', 'signature']);
      binary(signature.keyID, 64, 64);
      binary(signature.signature, 65536);
    }
    return { ...entry, manifest };
  });
  return { value, history };
}
function selectTimestamp(token, pins) {
  // The certificate set selects a candidate only. The existing verifier still
  // checks the signer, signature, exact certificate, imprint and issuer below.
  binary(token, 16 * MiB);
  const root = parseDER(token),
    set = root.children?.[1]?.children?.[0]?.children?.[3];
  need(set?.tag === 0xa0 && Array.isArray(set.children), 'ORG_HISTORY_SOURCE_TIMESTAMP');
  const candidates = pins.filter((pin) =>
    set.children.some((node) => equal(node.raw, pin.certificate)),
  );
  need(candidates.length !== 0, 'ORG_HISTORY_SOURCE_TIMESTAMP_PIN', 'INDETERMINATE');
  need(candidates.length === 1, 'ORG_HISTORY_SOURCE_TIMESTAMP_AMBIGUOUS', 'UNSUPPORTED');
  return candidates[0];
}
function publicationProof(proof, imprint, at, knowledgeTime, selected) {
  const pin = selectTimestamp(proof, selected.publication);
  const info = verifyTimestampToken(proof, { ...pin, imprint, at, maxFutureSkew: 0 });
  need(
    Number.isFinite(info.accuracy) && info.accuracy >= 0 && Number.isFinite(info.poeUpperBound),
    'ORG_HISTORY_PUBLICATION_ACCURACY',
    'INDETERMINATE',
  );
  const first = info.genTime - info.accuracy,
    last = info.poeUpperBound;
  need(
    first >= Math.max(pin.parsed.notBefore, pin.validFrom) &&
      last < Math.min(pin.parsed.notAfter, pin.validUntil, pin.revokedAt ?? Infinity),
    'ORG_HISTORY_PUBLICATION_INTERVAL',
  );
  // Authenticated future publications are skipped by the retained resolver.
  // Their later appointment/coverage cannot erase an already supported P view.
  if (last <= knowledgeTime) {
    const deadline = selected.value.retainedAuthorities.publication.hashValidUntil[info.hashOID];
    need(
      instant(deadline) && deadline > 0,
      'ORG_HISTORY_PUBLICATION_HASH_DEADLINE',
      'INDETERMINATE',
    );
    need(
      knowledgeTime <
        Math.min(pin.knowledgeValidUntil, pin.parsed.notAfter, pin.validUntil, deadline),
      'ORG_HISTORY_PUBLICATION_COVERAGE',
      'INDETERMINATE',
    );
    need(knowledgeTime < (pin.revokedAt ?? Infinity), 'ORG_HISTORY_PUBLICATION_REVOKED');
  }
  return { overall: 'VALID', ...info };
}

/** Public-data source for the existing offline organization history verifier. */
export function createOrganizationHistorySource(options) {
  record(options, ['configuration', 'readKnowledge'], ['databasePath']);
  need(typeof options.readKnowledge === 'function', 'ORG_HISTORY_SOURCE_READER');
  const selected = configuration(options.configuration),
    read = options.readKnowledge;
  if (Object.hasOwn(options, 'databasePath'))
    need(
      typeof options.databasePath === 'string' &&
        options.databasePath.length > 0 &&
        options.databasePath !== ':memory:' &&
        !options.databasePath.includes('\0'),
      'ORG_HISTORY_DATABASE_PATH',
    );
  const store =
    options.databasePath === undefined
      ? null
      : new OrganizationHistoryKnowledgeStore(options.databasePath, selected.value);
  const state = {
    selected,
    read,
    store,
    closed: false,
    active: null,
    verifier: null,
    ledger: null,
    poisoned: false,
  };
  const source = Object.freeze({
    close() {
      if (state.closed) return;
      state.closed = true;
      state.active = null;
      state.store?.close();
    },
    readEvidence(evidenceID) {
      if (!state.store) return undefined;
      need(!state.closed && !state.poisoned, 'ORG_HISTORY_SOURCE_UNAVAILABLE', 'INDETERMINATE');
      return state.store.readEvidence(evidenceID);
    },
  });
  sources.set(source, state);
  return source;
}

// Internal connection only: no SDK consumer can import observations or outcomes.
export function connectOrganizationHistorySource(source, createVerifier) {
  const state = sources.get(source);
  need(state, 'ORG_HISTORY_SOURCE_REQUIRED');
  if (state.verifier) return state.verifier;
  if (state.store) {
    state.verifier = durableVerifier(state, createVerifier);
    return state.verifier;
  }
  state.verifier = createVerifier(
    verifierOptions(state, () => {
      state.active = null;
      need(!state.closed, 'ORG_HISTORY_SOURCE_CLOSED', 'INDETERMINATE');
      state.active = readSnapshot(state);
      const { authorityHistory: ignored, ...current } = state.active.value;
      return current;
    }),
  );
  return state.verifier;
}
function readSnapshot(state) {
  let raw;
  try {
    raw = state.read();
  } catch {
    throw new VerificationError('ORG_HISTORY_SOURCE_READER_UNAVAILABLE', 'INDETERMINATE');
  }
  if (types.isPromise(raw)) {
    Promise.prototype.then.call(raw, undefined, () => {});
    throw new VerificationError('ORG_HISTORY_SOURCE_ASYNC', 'INDETERMINATE');
  }
  return knowledge(raw);
}
function verifierOptions(state, readKnowledge) {
  const { selected } = state,
    config = selected.value;
  const resolve = (query) => {
    try {
      need(!state.closed && state.active, 'ORG_HISTORY_SOURCE_UNAVAILABLE', 'INDETERMINATE');
      const negative = state.ledger?.negative(query);
      if (negative) return negative;
      const { value, history } = state.active;
      return createRetainedAuthorityResolver({
        trustDomainID: config.trust.trustDomainID,
        governance: config.retainedAuthorities.governance,
        algorithmDeadlines: config.retainedAuthorities.algorithmDeadlines,
        history,
        validationTime: value.knowledgeTime,
        verifyPublication: ({ imprint, proof, at }) => {
          try {
            return publicationProof(proof, imprint, at, query.knowledgeTime, selected);
          } catch (error) {
            return verificationOutcome(error);
          }
        },
      })(query);
    } catch (error) {
      return verificationOutcome(error);
    }
  };
  const { timestampAuthorities: ignored, ...preservation } = config.preservation;
  return {
    trust: config.trust,
    authorityResolver: resolve,
    readKnowledge,
    preservationPolicy: {
      ...preservation,
      resolveTimestamp(token) {
        const pin = selectTimestamp(token, selected.archive);
        return {
          ...pin,
          status: ({ certificate, stateTime, knowledgeTime }) =>
            resolve({
              certificate,
              stateTime,
              knowledgeTime,
              role: 'TIMESTAMP_AUTHORITY',
              scope: { trustDomainID: config.trust.trustDomainID },
            }),
        };
      },
    },
  };
}

const rawID = (value) => sha256(dcbor(value)).toString('hex');
class RetainedHistory {
  constructor(selected) {
    this.selected = selected;
    this.nodes = new Map();
  }
  add(entries, K) {
    const admitted = [],
      updates = [],
      failures = [],
      config = this.selected.value;
    for (const raw of entries) {
      try {
        const manifest = decodeCBOR(raw.manifest);
        need(equal(dcbor(manifest), raw.manifest), 'ORG_HISTORY_SOURCE_MANIFEST_CANONICAL');
        const previous =
          manifest.previousHash === null
            ? undefined
            : this.nodes.get(manifest.previousHash?.toString('hex'));
        need(manifest.serial === 0 || previous, 'HISTORY_PREDECESSOR_MISSING', 'INDETERMINATE');
        const checkpoint = authenticateRetainedAuthorityEntry({
          trustDomainID: config.trust.trustDomainID,
          governance: config.retainedAuthorities.governance,
          algorithmDeadlines: config.retainedAuthorities.algorithmDeadlines,
          entry: { ...raw, manifest },
          previous: previous?.checkpoint,
          validationTime: K,
          knowledgeTime: K,
          strictRecords: true,
          verifyPublication: ({ proof, imprint, at }) =>
            publicationProof(proof, imprint, at, K, this.selected),
        });
        if (!checkpoint) continue;
        const id = checkpoint.hash.toString('hex'),
          old = this.nodes.get(id);
        if (!old || checkpoint.published < old.checkpoint.published) {
          this.nodes.set(id, { raw, manifest, checkpoint });
          updates.push(raw);
        }
        admitted.push(raw);
      } catch (error) {
        failures.push(verificationOutcome(error));
      }
    }
    return { admitted, updates, failures };
  }
  chain() {
    let node = [...this.nodes.values()].sort((a, b) => b.manifest.serial - a.manifest.serial)[0];
    const entries = [];
    while (node) {
      entries.unshift({ ...node.raw, manifest: node.manifest });
      node =
        node.manifest.previousHash === null
          ? undefined
          : this.nodes.get(node.manifest.previousHash.toString('hex'));
    }
    return entries;
  }
  negative(query) {
    const nodes = [...this.nodes.values()]
      .filter((n) => n.checkpoint.published <= query.knowledgeTime)
      .sort((a, b) => a.manifest.serial - b.manifest.serial);
    const serials = new Map(),
      statuses = new Map();
    let requested;
    try {
      requested = keyID(
        query.certificate
          ? parseCertificate(query.certificate).publicKey
          : publicFromDER(query.publicKeyDER),
      ).toString('hex');
    } catch {
      return { overall: 'INVALID', reason: 'AUTHORITY_IDENTITY' };
    }
    for (const node of nodes) {
      const serial = node.manifest.serial,
        id = node.checkpoint.hash.toString('hex');
      if (serials.has(serial) && serials.get(serial) !== id)
        return { overall: 'INVALID', reason: 'HISTORY_FORK' };
      serials.set(serial, id);
      for (const record of node.manifest.authorities) {
        const status = record.status,
          key = status.authorityID.toString('hex');
        const previous = statuses.get(key);
        if (
          previous &&
          (status.publishedAt < previous.publishedAt ||
            (status.publishedAt === previous.publishedAt && !equal(dcbor(status), dcbor(previous))))
        )
          return {
            overall: 'INVALID',
            reason:
              status.publishedAt < previous.publishedAt
                ? 'HISTORY_STATUS_ROLLBACK'
                : 'HISTORY_STATUS_CONFLICT',
          };
        statuses.set(key, status);
        if (
          key === requested &&
          status.status === 'REVOKED' &&
          Math.min(status.effectiveTime, status.compromiseStart ?? Infinity) <= query.stateTime
        )
          return { overall: 'INVALID', reason: 'AUTHORITY_REVOKED' };
      }
    }
    return null;
  }
}
function collector() {
  const status = new Map(),
    certificate = new Map(),
    observations = new Set(),
    independent = new Set();
  return {
    observe(event) {
      const semantic =
        event.kind === 'certificate-status' ? event.body : event.observation.semanticHash;
      const id = rawID({ kind: event.kind, semantic });
      observations.add(id);
      if (event.kind === 'certificate-status' && !event.original) independent.add(id);
      if (event.original || !event.material) return;
      const map = event.kind === 'organization-status' ? status : certificate;
      map.set(rawID(event.material), event.material);
    },
    get statusMaterial() {
      return [...status.values()];
    },
    get certificateStatusMaterial() {
      return [...certificate.values()];
    },
    get observations() {
      return [...observations];
    },
    originalRequired(previous) {
      return [...observations].some((id) => !previous.includes(id) && !independent.has(id));
    },
  };
}
function addFailure(result, decision) {
  const order = ['VALID', 'INDETERMINATE', 'UNSUPPORTED', 'INVALID'];
  const stronger = order.indexOf(decision.overall) > order.indexOf(result.overall);
  const old = result.dimensions.status;
  return verificationResult({
    ...result,
    ...(stronger ? { overall: decision.overall, reason: decision.reason } : {}),
    dimensions: {
      ...result.dimensions,
      ...(!old || order.indexOf(decision.overall) > order.indexOf(old.overall)
        ? { status: decision }
        : {}),
    },
    checks: [...result.checks, { check: 'durable-knowledge', ...decision }],
  });
}
function durableVerifier(state, createVerifier) {
  const store = state.store;
  const receipt = (status, revision = null, evidenceID = null) => ({
    mode: 'SQLITE',
    state: status,
    scopeID: store.scopeID,
    configurationID: store.configurationID,
    revision,
    evidenceID,
  });
  const failed = (input, error, base) => {
    const decision = verificationOutcome(error);
    const result =
      base ??
      createVerifier(
        verifierOptions(state, () => {
          throw error;
        }),
      ).verify(input);
    return verificationResult({
      ...addFailure(result, decision),
      knowledgeReceipt: receipt(error.commitState ?? 'NOT_COMMITTED'),
    });
  };
  return Object.freeze({
    verify(input) {
      let result,
        captured,
        knownOverflow = false;
      state.active = null;
      state.ledger = null;
      try {
        need(!state.closed && !state.poisoned, 'ORG_HISTORY_SOURCE_UNAVAILABLE', 'INDETERMINATE');
        record(input, ['originalBytes', 'evidenceRecord']);
        binary(input.originalBytes, 64 * MiB);
        binary(input.evidenceRecord, 16 * MiB);
        input = {
          originalBytes: Buffer.from(input.originalBytes),
          evidenceRecord: Buffer.from(input.evidenceRecord),
        };
        captured = readSnapshot(state); // The only caller read, before BEGIN IMMEDIATE.
        const commit = store.transact((row) => {
          const head = row.value,
            K = captured.value.knowledgeTime;
          knownOverflow = head.overflow;
          need(
            head.selectedKnowledge === null || K >= head.selectedKnowledge,
            'ORG_KNOWLEDGE_ROLLBACK',
          );
          const ledger = new RetainedHistory(state.selected);
          state.ledger = ledger;
          const replayedObservations = new Set();
          let observed = collector();
          const verifier = createVerifier(
            verifierOptions(state, () => {
              const { authorityHistory: ignored, ...current } = state.active.value;
              return current;
            }),
            (event) => observed.observe(event),
          );
          let previousK = 0;
          for (const id of head.frames) {
            const frame = store.frame(id, head);
            need(frame.knowledgeTime >= previousK, 'ORG_HISTORY_STORAGE_CORRUPT', 'INDETERMINATE');
            previousK = frame.knowledgeTime;
            const authenticated = ledger.add(frame.authorityHistory, frame.knowledgeTime);
            need(
              !authenticated.failures.length &&
                authenticated.admitted.length === frame.authorityHistory.length,
              'ORG_HISTORY_REPLAY_AUTHENTICATION',
              'INDETERMINATE',
            );
            need(ledger.nodes.size <= 256, 'ORG_HISTORY_STORAGE_CORRUPT', 'INDETERMINATE');
            state.active = {
              value: {
                knowledgeTime: frame.knowledgeTime,
                statusMaterial: frame.statusMaterial,
                certificateStatusMaterial: frame.certificateStatusMaterial,
              },
              history: ledger.chain(),
            };
            observed = collector();
            // An authority/selected-credential-only frame has no original to
            // replay. Empty input cannot admit an original target or status.
            const artifact = frame.evidenceID
              ? store.evidence(head, frame.evidenceID)
              : { originalBytes: Buffer.alloc(0), evidenceRecord: Buffer.alloc(0) };
            verifier.verify({
              originalBytes: artifact.originalBytes,
              evidenceRecord: artifact.evidenceRecord,
            });
            for (const id of observed.observations) replayedObservations.add(id);
            need(replayedObservations.size <= 4096, 'ORG_HISTORY_STORAGE_CORRUPT', 'INDETERMINATE');
            for (const name of ['statusMaterial', 'certificateStatusMaterial']) {
              const admitted = new Set(observed[name].map(rawID));
              need(
                frame[name].every((m) => admitted.has(rawID(m))),
                'ORG_HISTORY_REPLAY_AUTHENTICATION',
                'INDETERMINATE',
              );
            }
          }
          const replayedHistory = new Set([...ledger.nodes.values()].map((n) => rawID(n.manifest)));
          need(
            replayedObservations.size === head.observations.length &&
              head.observations.every((id) => replayedObservations.has(id)) &&
              replayedHistory.size === head.historySemantics.length &&
              head.historySemantics.every((id) => replayedHistory.has(id)),
            'ORG_HISTORY_STORAGE_CORRUPT',
            'INDETERMINATE',
          );
          const authenticated = ledger.add(captured.value.authorityHistory, K);
          state.active = { value: captured.value, history: ledger.chain() };
          observed = collector();
          result = verifier.verify(input);
          for (const failure of authenticated.failures) result = addFailure(result, failure);
          const originalRequired = observed.originalRequired(head.observations);
          const commit = store.append(row, input, K, {
            authorityHistory: authenticated.updates,
            statusMaterial: originalRequired ? observed.statusMaterial : [],
            certificateStatusMaterial: observed.certificateStatusMaterial,
            observations: observed.observations,
            historySemantics: [...ledger.nodes.values()].map((n) => rawID(n.manifest)),
            originalRequired,
          });
          if (commit.overflow)
            result = addFailure(result, {
              overall: 'UNSUPPORTED',
              reason: 'ORG_HISTORY_KNOWLEDGE_LIMIT',
            });
          return commit;
        });
        return verificationResult({
          ...result,
          knowledgeReceipt: receipt('COMMITTED', commit.revision, commit.evidenceID),
        });
      } catch (error) {
        if (error.commitState === 'UNKNOWN') state.poisoned = true;
        const failure = failed(input, error, result);
        return knownOverflow &&
          !failure.checks.some((c) => c.reason === 'ORG_HISTORY_KNOWLEDGE_LIMIT')
          ? addFailure(failure, { overall: 'UNSUPPORTED', reason: 'ORG_HISTORY_KNOWLEDGE_LIMIT' })
          : failure;
      } finally {
        state.active = null;
        state.ledger = null;
      }
    },
  });
}

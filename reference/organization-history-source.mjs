import { types } from 'node:util';
import { dcbor, decodeCBOR, equal, fields, keyID, parseDER, publicFromDER, spki } from './core.mjs';
import { parseCertificate } from './pki.mjs';
import { verifyTimestampToken } from './timestamp.mjs';
import { createRetainedAuthorityResolver } from './retained-authorities.mjs';
import { record, snapshot } from './organization-delegation-state.mjs';
import { VerificationError, verificationOutcome } from './verification-result.mjs';

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
    fields(member, ['cms', 'issuerCertificate']);
    binary(member.cms, 131072);
    binary(member.issuerCertificate, 65536);
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
  record(options, ['configuration', 'readKnowledge']);
  need(typeof options.readKnowledge === 'function', 'ORG_HISTORY_SOURCE_READER');
  const selected = configuration(options.configuration),
    read = options.readKnowledge;
  const state = { selected, read, closed: false, active: null, verifier: null };
  const source = Object.freeze({
    close() {
      state.closed = true;
      state.active = null;
    },
    readEvidence() {
      return undefined;
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
  const { selected } = state,
    config = selected.value;
  const resolve = (query) => {
    try {
      need(!state.closed && state.active, 'ORG_HISTORY_SOURCE_UNAVAILABLE', 'INDETERMINATE');
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
  state.verifier = createVerifier({
    trust: config.trust,
    authorityResolver: resolve,
    readKnowledge() {
      state.active = null;
      need(!state.closed, 'ORG_HISTORY_SOURCE_CLOSED', 'INDETERMINATE');
      const raw = state.read();
      if (types.isPromise(raw)) {
        Promise.prototype.then.call(raw, undefined, () => {});
        throw new VerificationError('ORG_HISTORY_SOURCE_ASYNC', 'INDETERMINATE');
      }
      const active = knowledge(raw);
      state.active = active;
      const { authorityHistory: ignored, ...current } = active.value;
      return current;
    },
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
  });
  return state.verifier;
}

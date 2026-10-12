import {
  D, H, dcbor, decodeCBOR, equal, keyID, publicFromDER, verify, sha512,
  requireThat, fields, b64u,
} from './core.mjs';
import { parseCertificate } from './pki.mjs';
import { createAuthorityResolver, AuthorityError, requireAuthority } from './authority-history.mjs';
import { parseTimestampRequest, verifyTimestampToken } from './timestamp.mjs';

const copy = (value) => decodeCBOR(dcbor(value));
const fail = (overall, reason) => { throw new AuthorityError({ overall, reason }); };
const validTime = (value) => Number.isSafeInteger(value) && value >= 0;
const outcome = (error) => ({ overall: error.overall ?? 'INVALID', reason: error.code ?? 'HISTORY_INVALID' });

function rootPolicy(policy) {
  fields(policy, ['roots', 'threshold']);
  requireThat(Array.isArray(policy.roots) && Number.isSafeInteger(policy.threshold) &&
    policy.threshold > 0 && policy.threshold <= policy.roots.length, 'HISTORY_ROOT_THRESHOLD');
  const roots = policy.roots.map((root) => {
    fields(root, ['publicKeyDER', 'validFrom', 'validUntil']);
    requireThat(validTime(root.validFrom) && validTime(root.validUntil) &&
      root.validFrom < root.validUntil, 'HISTORY_ROOT_LIFETIME');
    const publicKey = publicFromDER(root.publicKeyDER);
    return { ...root, publicKey, keyID: keyID(publicKey) };
  });
  requireThat(new Set(roots.map((root) => b64u(root.keyID))).size === roots.length, 'HISTORY_ROOT_DUPLICATE');
  return { roots, threshold: policy.threshold };
}

function threshold(manifest, signatures, policy, at, deadlines) {
  const good = new Set();
  for (const signature of signatures) {
    const root = policy.roots.find((root) => equal(root.keyID, signature.keyID));
    if (!root) continue;
    const deadline = deadlines[root.publicKey.asymmetricKeyType];
    if (!validTime(deadline)) fail('INDETERMINATE', 'HISTORY_ALGORITHM_DEADLINE_REQUIRED');
    if (root.validFrom <= at && at < Math.min(root.validUntil, deadline) &&
      verify(D('RootTrustManifest', manifest), signature.signature, root.publicKey)) good.add(b64u(root.keyID));
  }
  requireThat(good.size >= policy.threshold, 'HISTORY_ROOT_AUTHORIZATION');
}

export const manifestPublicationImprint = ({ manifest, signatures }) =>
  H('RootTrustManifestPublication', { manifest, signatures });

/**
 * Resolve retained RTM snapshots with authenticated publication time and explicit
 * root succession. verifyPublication verifies an existing RFC 3161/ERS proof;
 * it must return its conservative proof-of-existence upper bound, never a claimed date.
 */
export function createRetainedAuthorityResolver({ trustDomainID, governance, history, algorithmDeadlines, verifyPublication, validationTime }) {
  requireThat(Buffer.isBuffer(trustDomainID) && trustDomainID.length === 32 &&
    Array.isArray(history) && typeof verifyPublication === 'function' && algorithmDeadlines && validTime(validationTime),
  'HISTORY_CONFIGURATION');
  const domain = Buffer.from(trustDomainID), retained = copy(history), initial = copy(governance), deadlines = copy(algorithmDeadlines);
  rootPolicy(initial);
  return Object.freeze((query) => {
    try {
      requireThat(Number.isFinite(query.knowledgeTime) && query.stateTime <= query.knowledgeTime &&
        query.knowledgeTime <= validationTime, 'HISTORY_TIME');
      let policy = rootPolicy(initial), previousHash = null, serial = -1, previousPublication = -1, selected, atState;
      const appointments = new Map();
      const incidents = new Map();
      const currentStatus = new Map();
      for (const entry of retained) {
        fields(entry, ['manifest', 'signatures', 'publicationProof']);
        const { manifest, signatures } = entry;
        const publication = verifyPublication({ imprint: manifestPublicationImprint(entry),
          proof: Buffer.from(entry.publicationProof), at: validationTime });
        if (publication?.overall !== 'VALID' || !Number.isFinite(publication.poeUpperBound))
          fail(publication?.overall ?? 'INDETERMINATE', publication?.reason ?? 'HISTORY_PUBLICATION_PROOF_REQUIRED');
        const published = publication.poeUpperBound;
        // A valid future proof is not admissible at the selected knowledge time.
        if (published > query.knowledgeTime) break;
        fields(manifest, ['schemaVersion', 'trustDomainID', 'serial', 'previousHash', 'issuedAt',
          'notBefore', 'notAfter', 'coverageUntil', 'authorities'], ['successor']);
        requireThat(manifest.schemaVersion === 2 && equal(manifest.trustDomainID, domain) &&
          validTime(manifest.serial) && manifest.serial === serial + 1 &&
          (previousHash === null ? manifest.previousHash === null : equal(manifest.previousHash, previousHash)) &&
          [manifest.issuedAt, manifest.notBefore, manifest.notAfter, manifest.coverageUntil].every(validTime) &&
          manifest.issuedAt <= published && manifest.notBefore <= published && published < manifest.notAfter &&
          published < manifest.coverageUntil && published >= previousPublication && Array.isArray(manifest.authorities),
        'HISTORY_MANIFEST_CHAIN');
        threshold(manifest, signatures, policy, published, deadlines);
        if (manifest.successor) {
          const successor = rootPolicy(manifest.successor);
          // Both governments authorize the identical RTM, including its predecessor.
          threshold(manifest, signatures, successor, published, deadlines);
          policy = successor;
        }
        const records = manifest.authorities.map((record) => {
          const { status, knownAt, ...appointment } = record;
          const appointmentHash = b64u(H('AuthorityAppointment', appointment));
          if (!appointments.has(appointmentHash)) appointments.set(appointmentHash, Math.ceil(published));
          const admittedAt = appointments.get(appointmentHash);
          const publicKey = record.mode === 'CERTIFICATE'
            ? parseCertificate(record.certificate).publicKey : publicFromDER(record.publicKeyDER);
          const authorityID = keyID(publicKey), id = b64u(authorityID);
          requireThat(status && equal(status.authorityID, authorityID) && equal(status.trustDomainID, domain) &&
            status.publishedAt <= published && status.nextUpdate <= manifest.coverageUntil,
          'HISTORY_STATUS_BINDING');
          const priorStatus = currentStatus.get(id);
          requireThat(!priorStatus || status.publishedAt >= priorStatus.publishedAt,
            'HISTORY_STATUS_ROLLBACK');
          if (priorStatus?.publishedAt === status.publishedAt)
            requireThat(equal(dcbor(priorStatus), dcbor(status)), 'HISTORY_STATUS_CONFLICT');
          currentStatus.set(id, status);
          if (status.status === 'REVOKED') {
            const prior = incidents.get(id);
            if (!prior || Math.min(status.effectiveTime, status.compromiseStart ?? Infinity) <
              Math.min(prior.effectiveTime, prior.compromiseStart ?? Infinity)) incidents.set(id, status);
          }
          const deadline = deadlines[publicKey.asymmetricKeyType];
          if (!validTime(deadline)) fail('INDETERMINATE', 'HISTORY_ALGORITHM_DEADLINE_REQUIRED');
          return { ...record, knownAt: admittedAt,
            validFrom: Math.max(record.validFrom, admittedAt),
            algorithmValidUntil: Math.min(record.algorithmValidUntil ?? deadline, deadline),
            status: incidents.has(id) ? { ...incidents.get(id), nextUpdate: status.nextUpdate } : status };
        });
        selected = { manifest, records };
        // Select appointments at the operation time; use subsequently learned status below.
        if (published <= query.stateTime) atState = selected;
        previousHash = H('RootTrustManifest', manifest);
        serial = manifest.serial;
        previousPublication = published;
      }
      if (!selected) fail('INDETERMINATE', 'HISTORY_MISSING');
      const requestedKey = query.certificate ? parseCertificate(query.certificate).publicKey : publicFromDER(query.publicKeyDER);
      const incident = incidents.get(b64u(keyID(requestedKey)));
      if (incident && Math.min(incident.effectiveTime, incident.compromiseStart ?? Infinity) <= query.stateTime)
        fail('INVALID', 'AUTHORITY_REVOKED');
      if (!atState) fail('INVALID', 'HISTORY_AUTHORITY_NOT_YET_ADMITTED');
      const historicalRecords = atState.records.map((record) => {
        const publicKey = record.mode === 'CERTIFICATE'
          ? parseCertificate(record.certificate).publicKey : publicFromDER(record.publicKeyDER);
        const id = b64u(keyID(publicKey)), latest = currentStatus.get(id);
        return { ...record, status: incidents.has(id)
          ? { ...incidents.get(id), nextUpdate: latest.nextUpdate } : latest };
      });
      const resolve = createAuthorityResolver({ trustDomainID: domain, authorities: historicalRecords });
      const result = resolve(query);
      if (result.overall === 'INVALID') return result;
      if (query.knowledgeTime >= selected.manifest.coverageUntil)
        fail('INDETERMINATE', 'HISTORY_KNOWLEDGE_COVERAGE');
      return result;
    } catch (error) { return outcome(error); }
  });
}

/** One SQLite commit publishes the RTM/custodian history and the existing ERS bytes. */
export class ArchivePublicationStore {
  constructor(journal, { validatePublication, crash = () => {} }) {
    requireThat(typeof validatePublication === 'function', 'ARCHIVE_VALIDATOR_REQUIRED');
    Object.assign(this, { journal, validatePublication, crash });
  }
  publish(input) {
    const publication = copy(input);
    fields(publication, ['archiveID', 'previousHash', 'dataHash', 'evidenceRecord', 'history']);
    requireThat(typeof publication.archiveID === 'string' && publication.archiveID.length > 0 &&
      Buffer.isBuffer(publication.dataHash) && publication.dataHash.length === 64 &&
      Buffer.isBuffer(publication.evidenceRecord) && Array.isArray(publication.history), 'ARCHIVE_PUBLICATION');
    const digest = sha512(dcbor(publication));
    const previous = this.journal.get('archive-publication', publication.archiveID);
    if (previous && equal(previous.value.digest, digest)) return previous.value;
    const validation = this.validatePublication(copy(publication));
    requireThat(validation?.overall === 'VALID' && !validation.then, 'ARCHIVE_PUBLICATION_VALIDATION');
    return this.journal.transaction(() => {
      const current = this.journal.get('archive-publication', publication.archiveID);
      if (current && equal(current.value.digest, digest)) return current.value;
      requireThat(current ? equal(current.value.digest, publication.previousHash) &&
        equal(current.value.publication.dataHash, publication.dataHash) : publication.previousHash === null,
      'ARCHIVE_PUBLICATION_CONFLICT');
      const value = { digest, publication };
      this.crash('before-publication');
      this.journal.put('archive-publication', publication.archiveID, value, current?.revision ?? -1);
      this.crash('after-publication-before-commit');
      return value;
    });
  }
  read(archiveID) { return this.journal.get('archive-publication', archiveID)?.value; }
}

/** Reserve a renewal before contacting the TSA; uncertain requests are reconciled, never repeated. */
export class ArchiveRenewalCoordinator {
  constructor({ journal, store, requestTimestamp, timestampTrust, buildPublication, clock }) {
    requireThat(store?.journal === journal && typeof requestTimestamp === 'function' &&
      typeof buildPublication === 'function' && typeof clock === 'function', 'ARCHIVE_RENEWAL_CONFIGURATION');
    Object.assign(this, { journal, store, requestTimestamp, timestampTrust, buildPublication, clock });
  }
  async renew(input) {
    const request = copy(input);
    fields(request, ['operationID', 'archiveID', 'previousHash', 'timestampRequest', 'protectionDeadline']);
    requireThat(Buffer.isBuffer(request.operationID) && request.operationID.length === 32 &&
      typeof request.archiveID === 'string' && request.archiveID.length > 0 &&
      validTime(request.protectionDeadline), 'ARCHIVE_RENEWAL_REQUEST');
    const parsed = parseTimestampRequest(request.timestampRequest);
    requireThat(parsed.nonce !== undefined && parsed.policy === this.timestampTrust.policy,
      'ARCHIVE_RENEWAL_BINDING');
    const id = 'archive-renewal:' + b64u(request.operationID), digest = H('ArchiveRenewalRequest', request);
    const prior = this.journal.transaction(() => {
      const previous = this.journal.reserve(id, digest);
      if (previous) return previous;
      const head = this.store.read(request.archiveID);
      requireThat(head ? equal(head.digest, request.previousHash) : request.previousHash === null,
        'ARCHIVE_PUBLICATION_CONFLICT');
      requireThat(this.clock() < request.protectionDeadline, 'ARCHIVE_RENEWAL_LATE');
      this.journal.put('archive-renewal-request', id, request);
      return null;
    });
    if (prior) {
      if (prior.status === 'COMPLETED') return decodeCBOR(prior.result);
      fail('INDETERMINATE', 'ARCHIVE_RENEWAL_UNKNOWN');
    }
    try {
      const token = await this.requestTimestamp(Buffer.from(request.timestampRequest));
      return this.reconcile(request.operationID, token);
    } catch (error) { this.journal.uncertain(id); throw error; }
  }
  reconcile(operationID, rawToken) {
    const id = 'archive-renewal:' + b64u(operationID), saved = this.journal.get('archive-renewal-request', id);
    requireThat(saved, 'ARCHIVE_RENEWAL_REQUEST_MISSING');
    const request = saved.value, token = Buffer.from(rawToken), parsed = parseTimestampRequest(request.timestampRequest);
    const time = verifyTimestampToken(token, { ...this.timestampTrust, ...parsed, at: this.clock(), maxFutureSkew: 0 });
    requireAuthority(this.timestampTrust.authorityResolver, {
      certificate: this.timestampTrust.certificate, role: 'TIMESTAMP_AUTHORITY',
      scope: { trustDomainID: this.timestampTrust.trustDomainID, purpose: 'ARCHIVE_PRESERVATION' },
      stateTime: time.poeUpperBound, knowledgeTime: this.clock(),
    });
    requireThat(Number.isFinite(time.poeUpperBound) && time.poeUpperBound < request.protectionDeadline,
      'ARCHIVE_RENEWAL_LATE');
    const publication = this.buildPublication(copy(request), Buffer.from(token));
    requireThat(publication.archiveID === request.archiveID &&
      (request.previousHash === null ? publication.previousHash === null : equal(publication.previousHash, request.previousHash)),
    'ARCHIVE_RENEWAL_PUBLICATION_BINDING');
    return this.journal.transaction(() => {
      const existing = this.journal.result(id);
      if (existing.status === 'COMPLETED') return decodeCBOR(existing.result);
      const published = this.store.publish(publication);
      this.journal.reconcile(id, dcbor(published));
      return published;
    });
  }
  result(operationID) { return this.journal.result('archive-renewal:' + b64u(operationID)); }
}

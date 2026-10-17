import { H, dcbor, decodeCBOR, equal, fields, sha256 } from './core.mjs';
import { Journal } from './state.mjs';
import { VerificationError } from './verification-result.mjs';
import { existsSync, statSync } from 'node:fs';

const MiB = 1024 * 1024;
const namespace = 'organization-history-v1';
const hex = /^[a-f0-9]{64}$/;
const integer = (v) => Number.isSafeInteger(v) && v >= 0;
const need = (value, code = 'ORG_HISTORY_STORAGE_CORRUPT') => {
  if (!value) throw new VerificationError(code, 'INDETERMINATE');
};
const digest = (bytes) => sha256(bytes).toString('hex');
const pairID = (input) =>
  digest(
    dcbor({
      original: digest(input.originalBytes),
      record: digest(input.evidenceRecord),
      originalLength: input.originalBytes.length,
      recordLength: input.evidenceRecord.length,
    }),
  );
const ids = (values, maximum) => {
  need(
    Array.isArray(values) &&
      values.length <= maximum &&
      values.every((v) => hex.test(v)) &&
      new Set(values).size === values.length,
  );
};

/** Internal raw-material journal. No operation, nonce, or authorization projection. */
export class OrganizationHistoryKnowledgeStore {
  constructor(path, configuration) {
    const trust = configuration.trust;
    this.configurationID = H('OrganizationHistoryConfiguration', {
      revision: 1,
      capability: 'organization-history-sqlite-v1',
      configuration,
    }).toString('hex');
    this.scopeID = H('OrganizationHistoryScope', {
      profile: 'certconcord-organization-delegation-v1',
      trustDomainID: trust.trustDomainID,
      organizationID: trust.organizationID,
      issuerID: trust.issuerID,
      identityNamespace: trust.identityNamespace,
    }).toString('hex');
    this.binding = {
      schemaVersion: 1,
      scopeID: this.scopeID,
      configurationID: this.configurationID,
      configuration: dcbor(configuration),
    };
    const nonempty = existsSync(path) && statSync(path).size > 0;
    this.journal = new Journal(path);
    try {
      this.journal.transaction(() => {
        this.exclusive();
        const old = this.journal.get(namespace, 'binding');
        if (old) {
          need(equal(dcbor(old.value), dcbor(this.binding)), 'ORG_HISTORY_CONFIGURATION_MISMATCH');
          this.head();
        } else {
          need(!nonempty, 'ORG_HISTORY_DATABASE_NOT_DEDICATED');
          need(this.journal.list(namespace).length === 0, 'ORG_HISTORY_STORAGE_CORRUPT');
          this.journal.put(namespace, 'binding', this.binding);
          this.journal.put(namespace, 'head', {
            schemaVersion: 1,
            selectedKnowledge: null,
            overflow: false,
            frames: [],
            artifacts: [],
            observations: [],
            historySemantics: [],
            bytes: this.binding.configuration.length,
          });
        }
      });
    } catch (error) {
      this.journal.close();
      throw error;
    }
  }
  exclusive() {
    need(
      !this.journal.db.prepare('SELECT 1 FROM operations LIMIT 1').get() &&
        !this.journal.db.prepare('SELECT 1 FROM nonce LIMIT 1').get() &&
        !this.journal.db.prepare('SELECT 1 FROM state WHERE namespace<>? LIMIT 1').get(namespace),
      'ORG_HISTORY_DATABASE_NOT_DEDICATED',
    );
  }
  head() {
    this.exclusive();
    const binding = this.journal.get(namespace, 'binding');
    need(
      binding && equal(dcbor(binding.value), dcbor(this.binding)),
      'ORG_HISTORY_CONFIGURATION_MISMATCH',
    );
    const row = this.journal.get(namespace, 'head');
    need(row && integer(row.revision));
    const h = row.value;
    fields(h, [
      'schemaVersion',
      'selectedKnowledge',
      'overflow',
      'frames',
      'artifacts',
      'observations',
      'historySemantics',
      'bytes',
    ]);
    need(
      h.schemaVersion === 1 &&
        (h.selectedKnowledge === null || integer(h.selectedKnowledge)) &&
        typeof h.overflow === 'boolean' &&
        integer(h.bytes) &&
        h.bytes <= 256 * MiB,
    );
    ids(h.frames, 256);
    ids(h.observations, 4096);
    ids(h.historySemantics, 256);
    need(Array.isArray(h.artifacts) && h.artifacts.length <= 1024);
    const seen = new Set();
    for (const a of h.artifacts) {
      fields(a, ['id', 'original', 'record']);
      need([a.id, a.original, a.record].every((v) => hex.test(v)) && !seen.has(a.id));
      seen.add(a.id);
    }
    return row;
  }
  blob(id) {
    need(typeof id === 'string' && hex.test(id));
    const row = this.journal.get(namespace, 'blob:' + id);
    need(row && row.revision === 0);
    const manifest = row.value;
    fields(manifest, ['length', 'chunks']);
    need(
      integer(manifest.length) &&
        manifest.length > 0 &&
        manifest.length <= 64 * MiB &&
        Array.isArray(manifest.chunks) &&
        manifest.chunks.length === Math.ceil(manifest.length / MiB),
    );
    const chunks = manifest.chunks.map((hash, i) => {
      need(typeof hash === 'string' && hex.test(hash));
      const chunk = this.journal.get(namespace, 'chunk:' + hash);
      need(
        chunk &&
          chunk.revision === 0 &&
          Buffer.isBuffer(chunk.value) &&
          chunk.value.length === Math.min(MiB, manifest.length - i * MiB) &&
          digest(chunk.value) === hash,
      );
      return chunk.value;
    });
    const bytes = Buffer.concat(chunks);
    need(bytes.length === manifest.length && digest(bytes) === id);
    return bytes;
  }
  evidence(head, evidenceID) {
    const entry = head.artifacts.find((v) => v.id === evidenceID);
    if (!entry) return undefined;
    const originalBytes = this.blob(entry.original),
      evidenceRecord = this.blob(entry.record);
    need(
      digest(
        dcbor({
          original: entry.original,
          record: entry.record,
          originalLength: originalBytes.length,
          recordLength: evidenceRecord.length,
        }),
      ) === evidenceID,
    );
    return {
      classification: 'UNVERIFIED_BYTES',
      originalBytes,
      evidenceRecord,
    };
  }
  readEvidence(id) {
    need(typeof id === 'string' && hex.test(id), 'ORG_HISTORY_EVIDENCE_ID');
    return this.journal.transaction(() => this.evidence(this.head().value, id));
  }
  frame(id, head) {
    const frame = decodeCBOR(this.blob(id));
    fields(frame, [
      'knowledgeTime',
      'evidenceID',
      'authorityHistory',
      'statusMaterial',
      'certificateStatusMaterial',
    ]);
    need(
      integer(frame.knowledgeTime) &&
        frame.knowledgeTime <= head.selectedKnowledge &&
        (frame.evidenceID === null || head.artifacts.some((a) => a.id === frame.evidenceID)),
    );
    for (const [name, max] of [
      ['authorityHistory', 256],
      ['statusMaterial', 64],
      ['certificateStatusMaterial', 64],
    ]) {
      ids(frame[name], max);
      frame[name] = frame[name].map((ref) => decodeCBOR(this.blob(ref)));
    }
    need(frame.evidenceID !== null || frame.statusMaterial.length === 0);
    return frame;
  }
  transact(action) {
    let entered = false,
      bodyComplete = false;
    try {
      return this.journal.transaction(() => {
        entered = true;
        const row = this.head();
        const result = action(row);
        bodyComplete = true;
        return result;
      });
    } catch (error) {
      // Once the transaction body completed, a COMMIT acknowledgement may have
      // been lost. Reopen and reauthenticate; never guess from an exception text.
      const failure = new VerificationError(
        error instanceof VerificationError ? error.code : 'ORG_HISTORY_STORAGE_UNAVAILABLE',
        error instanceof VerificationError ? error.overall : 'INDETERMINATE',
      );
      failure.commitState = entered && bodyComplete ? 'UNKNOWN' : 'NOT_COMMITTED';
      throw failure;
    }
  }
  append(row, input, knowledgeTime, admitted) {
    const old = row.value;
    const hasNewKnowledge =
      admitted.authorityHistory.length ||
      admitted.observations.some((id) => !old.observations.includes(id)) ||
      admitted.historySemantics.some((id) => !old.historySemantics.includes(id));
    if (old.overflow || !hasNewKnowledge) {
      const selectedKnowledge = Math.max(old.selectedKnowledge ?? 0, knowledgeTime);
      const revision =
        selectedKnowledge === old.selectedKnowledge
          ? row.revision
          : this.journal.put(namespace, 'head', { ...old, selectedKnowledge }, row.revision);
      const existing = !old.overflow && old.artifacts.length ? pairID(input) : null;
      return {
        revision,
        evidenceID: old.artifacts.some((a) => a.id === existing) ? existing : null,
        overflow: old.overflow,
      };
    }
    const planned = new Map();
    const blob = (bytes) => {
      need(Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= 64 * MiB);
      const id = digest(bytes);
      if (!this.journal.get(namespace, 'blob:' + id)) planned.set(id, bytes);
      else need(equal(this.blob(id), bytes));
      return id;
    };
    need(typeof admitted.originalRequired === 'boolean');
    const requestedID = pairID(input),
      evidenceID = admitted.originalRequired ? requestedID : null;
    const original = evidenceID ? blob(input.originalBytes) : null,
      record = evidenceID ? blob(input.evidenceRecord) : null;
    const frame = {
      knowledgeTime,
      evidenceID,
      authorityHistory: admitted.authorityHistory.map((v) => blob(dcbor(v))),
      statusMaterial: admitted.statusMaterial.map((v) => blob(dcbor(v))),
      certificateStatusMaterial: admitted.certificateStatusMaterial.map((v) => blob(dcbor(v))),
    };
    for (const name of ['authorityHistory', 'statusMaterial', 'certificateStatusMaterial'])
      frame[name] = [...new Set(frame[name])];
    const hasAdmissions =
      admitted.observations.length ||
      frame.authorityHistory.length ||
      frame.statusMaterial.length ||
      frame.certificateStatusMaterial.length;
    const frameID = hasAdmissions ? blob(dcbor(frame)) : null;
    const head = {
      ...old,
      selectedKnowledge: Math.max(old.selectedKnowledge ?? 0, knowledgeTime),
      frames: [...new Set([...old.frames, ...(frameID ? [frameID] : [])])],
      artifacts:
        !evidenceID || old.artifacts.some((a) => a.id === evidenceID)
          ? old.artifacts
          : [...old.artifacts, { id: evidenceID, original, record }],
      observations: [...new Set([...old.observations, ...admitted.observations])],
      historySemantics: [...new Set([...old.historySemantics, ...admitted.historySemantics])],
      bytes: old.bytes + [...planned.values()].reduce((sum, bytes) => sum + bytes.length, 0),
    };
    if (
      head.frames.length > 256 ||
      head.artifacts.length > 1024 ||
      head.observations.length > 4096 ||
      head.historySemantics.length > 256 ||
      head.bytes > 256 * MiB
    ) {
      const revision = this.journal.put(
        namespace,
        'head',
        { ...old, overflow: true, selectedKnowledge: head.selectedKnowledge },
        row.revision,
      );
      return { revision, evidenceID: null, overflow: true };
    }
    for (const [id, bytes] of planned) {
      const chunks = [];
      for (let i = 0; i < bytes.length; i += MiB) {
        const chunk = bytes.subarray(i, i + MiB),
          hash = digest(chunk);
        const existing = this.journal.get(namespace, 'chunk:' + hash);
        if (!existing) this.journal.put(namespace, 'chunk:' + hash, chunk);
        else
          need(
            existing.revision === 0 &&
              Buffer.isBuffer(existing.value) &&
              equal(existing.value, chunk),
          );
        chunks.push(hash);
      }
      this.journal.put(namespace, 'blob:' + id, { length: bytes.length, chunks });
    }
    const revision = equal(dcbor(head), dcbor(old))
      ? row.revision
      : this.journal.put(namespace, 'head', head, row.revision);
    return {
      revision,
      evidenceID: head.artifacts.some((a) => a.id === requestedID) ? requestedID : null,
      overflow: false,
    };
  }
  close() {
    this.journal.close();
  }
}

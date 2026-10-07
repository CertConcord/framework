import { H, D, b64u, dcbor, equal, requireThat, keyID, spki } from './core.mjs';
import { evaluateInclusion, leafHash } from './mtc.mjs';
import { witnessRequest, verifyNote } from './transparency.mjs';
import { IndexedMerkleLog } from './storage/merkle.mjs';
import { checkpointBody, noteSignature, indexedMirrorUpload } from './transparency.mjs';

// Native mdoc entries have their own domain; they are not draft-06 TBSCertificateLogEntry values.
export class CredentialLog {
  constructor({ journal, log, mirrors, maxEntries = 2 ** 40, maxBytes = Number.MAX_SAFE_INTEGER }) {
    Object.assign(this, { journal, log, mirrors, maxEntries, maxBytes });
    requireThat(
      !journal.get('credential-log', log.name) ||
        journal.get('log-migration', 'credential:' + log.name),
      'LOG_MIGRATION_REQUIRED',
    );
    this.store = new IndexedMerkleLog(journal, 'credential:' + log.name, { maxEntries, maxBytes });
  }
  append(entry) {
    const id = b64u(H('CredentialLogEntry', entry));
    const index = this.store.append(D('PersonalMdocLogEntry', entry), id),
      size = this.store.head().size,
      body = checkpointBody(this.log.name, size, this.store.root(size)),
      checkpoint = body + '\n' + noteSignature(body, this.log),
      receipts = [];
    for (const peer of this.mirrors) {
      try {
        const old = peer.service.journal.get('mirror-pending', this.log.name)?.value;
        const q = peer.service.addCheckpoint(
          witnessRequest(
            old?.size ?? 0,
            old ? this.store.consistency(0, Number(old.size), size) : [],
            checkpoint,
          ),
        );
        requireThat(q.status === 200, 'CREDENTIAL_LOG_CHECKPOINT');
        const stored = peer.service.storedSize(this.log.name);
        for (let at = stored; at < size; at = Math.min(size, (Math.floor(at / 256) + 1) * 256)) {
          const upload = peer.service.addEntries(
            indexedMirrorUpload(this.log.name, this.store, at, size),
          );
          requireThat([200, 202].includes(upload.status), 'CREDENTIAL_LOG_MIRROR');
        }
        receipts.push({
          operatorID: peer.operatorID,
          note: peer.service.checkpoint(this.log.name),
        });
      } catch {
        /* An unavailable mirror contributes no receipt; the caller enforces the quorum. */
      }
    }
    return {
      schemaVersion: 1,
      adapterID: 'certconcord-mdoc-issuance-log-v1',
      entry: D('PersonalMdocLogEntry', entry),
      index,
      size,
      root: this.store.root(size),
      path: this.store.inclusion(index, size),
      checkpoint,
      receipts,
    };
  }
}

export function verifyCredentialLog(proof, expectedEntry, { log, members, threshold }) {
  requireThat(
    proof.schemaVersion === 1 &&
      proof.adapterID === 'certconcord-mdoc-issuance-log-v1' &&
      threshold > 0 &&
      threshold <= members.length &&
      Number.isSafeInteger(proof.index) &&
      Number.isSafeInteger(proof.size) &&
      proof.index >= 0 &&
      proof.index < proof.size &&
      equal(proof.entry, D('PersonalMdocLogEntry', expectedEntry)),
    'CREDENTIAL_LOG_ENTRY',
  );
  const cp = verifyNote(proof.checkpoint, log);
  requireThat(
    cp.origin === log.name &&
      cp.size === BigInt(proof.size) &&
      equal(cp.root, proof.root) &&
      equal(
        evaluateInclusion(leafHash(proof.entry), proof.index, 0, proof.size, proof.path),
        proof.root,
      ),
    'CREDENTIAL_LOG_INCLUSION',
  );
  const operators = new Set(),
    keys = new Set(),
    verifiedMirrors = [];
  for (const receipt of proof.receipts) {
    const member = members.find((m) => m.operatorID === receipt.operatorID);
    if (!member) continue;
    const signed = verifyNote(receipt.note, member),
      id = b64u(keyID(member.publicKey));
    requireThat(
      signed.origin === cp.origin &&
        signed.size === cp.size &&
        equal(signed.root, cp.root) &&
        !keys.has(id) &&
        !equal(keyID(member.publicKey), keyID(log.publicKey)),
      'CREDENTIAL_LOG_MIRROR_PROOF',
    );
    keys.add(id);
    operators.add(member.operatorID);
    verifiedMirrors.push({ operatorID: member.operatorID, publicKeyDER: spki(member.publicKey) });
  }
  requireThat(operators.size >= threshold, 'CREDENTIAL_LOG_QUORUM');
  return {
    status: 'VALID',
    operatorCount: operators.size,
    logPublicKeyDER: spki(log.publicKey),
    verifiedMirrors,
  };
}

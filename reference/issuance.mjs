import { createPublicKey } from 'node:crypto';
import {
  H,
  D,
  sha512,
  equal,
  requireThat,
  now,
  b64u,
  octet,
  sign,
  dcbor,
  decodeCBOR,
} from './core.mjs';
import {
  snapshotIssuanceScope,
  issuanceRequestID,
  issuanceAuthorityScope,
  requireIssuanceAuthority,
} from './enrollment-scope.mjs';
import { requireAuthorityQuorum } from './control-authority.mjs';
import { verifyCSR } from './enrollment.mjs';
import { readControl } from './state.mjs';
import { RRA, OID, extension, certificateFromTBS, parseCertificate } from './pki.mjs';
import { IndexedMerkleLog } from './storage/merkle.mjs';
import { createMTCTBS, logEntryFromTBS, cosignedMessage, encodeProof, verifyMTC } from './mtc.mjs';

export class MTCIssuer {
  constructor({
    journal,
    raCertificate,
    caID,
    logNumber,
    privateKey,
    policyHash,
    rtmHash,
    membershipEpoch,
    members,
    threshold,
    mirrors,
    allowedProfiles,
    maxEntries = 2 ** 40,
    maxLogBytes = Number.MAX_SAFE_INTEGER,
    keyBindings,
    validatePossessionCertificate,
    issuanceScope,
    authorityResolver,
    issuerCertificate,
  }) {
    requireThat(mirrors.length >= threshold, 'MTC_MIRRORS');
    Object.assign(this, {
      journal,
      raCertificate,
      caID,
      logNumber,
      privateKey,
      policyHash,
      rtmHash,
      membershipEpoch,
      members,
      threshold,
      mirrors,
      allowedProfiles,
      maxEntries,
      maxLogBytes,
      keyBindings,
      validatePossessionCertificate,
      issuanceScope: snapshotIssuanceScope(issuanceScope),
      authorityResolver,
      issuerCertificate,
    });
    requireThat(
      this.issuanceScope.representation === 'MTC' && this.issuanceScope.issuerID === caID,
      'ISSUANCE_SCOPE',
    );
    const origin = this.caID + '.0.' + this.logNumber;
    requireThat(
      !journal.get('mtc-log', origin) || journal.get('log-migration', 'mtc:' + origin),
      'LOG_MIGRATION_REQUIRED',
    );
    this.log = new IndexedMerkleLog(journal, 'mtc:' + origin, {
      maxEntries,
      maxBytes: maxLogBytes,
    });
  }
  async issue({ csr, rar }) {
    ({ csr, rar } = decodeCBOR(dcbor({ csr, rar })));
    const a = readControl(rar, 'RegistrationAuthorization', this.raCertificate),
      q = verifyCSR(csr, { validatePossessionCertificate: this.validatePossessionCertificate }),
      id = issuanceRequestID(a),
      origin = this.caID + '.0.' + this.logNumber;
    requireIssuanceAuthority(a, this);
    requireThat(
      a.schemaVersion === 1 &&
        a.issuedAt <= now() &&
        a.expiresAt > now() &&
        equal(a.policyHash, this.policyHash) &&
        this.allowedProfiles.includes(a.profileID) &&
        equal(a.csrHash, sha512(csr)) &&
        equal(a.spkiHash, sha512(q.spki)) &&
        a.possessionMode === q.possessionMode,
      'MTC_REGISTRATION_AUTHORITY',
    );
    requireThat(
      a.profileID !== 'CERTCONCORD-PERSON-PASSKEY-SIGN-v1' || (this.keyBindings && a.keyBindingID),
      'PASSKEY_ADMISSION_REQUIRED',
    );
    const admission =
      a.profileID === 'CERTCONCORD-PERSON-PASSKEY-SIGN-v1'
        ? this.keyBindings.forIssuance(a.keyBindingID, { ...a, csr })
        : null;
    if (admission) requireThat(equal(admission.hash, a.keyBindingHash), 'PASSKEY_RA_BINDING');
    let issuance = this.journal.transaction(() => {
      const old = this.journal.get('mtc-issuance', id);
      if (old) {
        requireThat(equal(old.value.rarHash, sha512(rar)), 'MTC_ISSUANCE_CONFLICT');
        return old.value;
      }
      const index = this.log.head().size,
        tbs = createMTCTBS(
          {
            publicKey: q.publicKey,
            subject: q.subject,
            profileID: a.profileID,
            ...(admission
              ? { notAfter: Math.min(now() + 86400, admission.binding.expiresAt) }
              : {}),
            extraExtensions: [
              extension(
                RRA['id-pe-certconcordAuthorizationID'],
                octet(H('RegistrationAuthorization', a)),
              ),
              extension(
                RRA['id-pe-certconcordKeyAssurance'],
                octet(
                  D(
                    'KeyAssurance',
                    admission?.assurance ?? { level: 'KAL1', custody: 'UNASSESSED' },
                  ),
                ),
              ),
              ...(admission
                ? [extension(RRA['id-pe-certconcordPasskeyBinding'], octet(admission.hash), true)]
                : []),
            ],
          },
          { caID: this.caID, logNumber: this.logNumber, index },
        ),
        entry = logEntryFromTBS(tbs);
      requireThat(this.log.append(entry, id) === index, 'MTC_LOG_INDEX');
      const value = { state: 'APPENDED', tbs, index, rarHash: sha512(rar), profileID: a.profileID };
      this.journal.put('mtc-issuance', id, value);
      return value;
    });
    const verifyCosigners = (certificate) => {
      const at = now(),
        proof = verifyMTC(certificate, {
          caID: this.caID,
          caPublicKey: createPublicKey(this.privateKey),
          members: this.members,
          threshold: this.threshold,
          policyHash: this.policyHash,
          rtmHash: this.rtmHash,
          membershipEpoch: this.membershipEpoch,
          profileID: issuance.profileID,
          at,
        });
      requireAuthorityQuorum(this.authorityResolver, {
        members: proof.verifiedCosigners,
        threshold: this.threshold,
        role: 'COSIGNER',
        scope: issuanceAuthorityScope(a),
        stateTime: at,
        knowledgeTime: at,
      });
    };
    if (issuance.state === 'CERTIFIED') {
      verifyCosigners(issuance.certificate);
      return issuance.certificate;
    }
    const size = this.log.head().size,
      root = this.log.root(size),
      params = { caID: this.caID, logNumber: this.logNumber, start: 0, end: size, root },
      signatures = [
        {
          cosignerID: this.caID,
          signature: sign(cosignedMessage({ ...params, cosignerID: this.caID }), this.privateKey),
        },
      ];
    const responses = await Promise.allSettled(
      this.mirrors.map((m) =>
        m.cosign({ caID: this.caID, logNumber: this.logNumber, source: this.log, size }),
      ),
    );
    for (const r of responses) if (r.status === 'fulfilled') signatures.push(r.value);
    const certificate = certificateFromTBS(
      issuance.tbs,
      OID.mtc,
      encodeProof({
        start: 0,
        end: size,
        inclusion: this.log.inclusion(issuance.index, size),
        signatures,
      }),
    );
    verifyCosigners(certificate);
    return this.journal.transaction(() => {
      requireIssuanceAuthority(a, this);
      if (admission) this.keyBindings.forIssuance(a.keyBindingID, { ...a, csr });
      const old = this.journal.get('mtc-issuance', id);
      if (old.value.state === 'CERTIFIED') return old.value.certificate;
      this.journal.put(
        'mtc-issuance',
        id,
        { ...old.value, state: 'CERTIFIED', certificate },
        old.revision,
      );
      return certificate;
    });
  }
}

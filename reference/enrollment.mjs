import {
  seq,
  set,
  oid,
  octet,
  bit,
  integer,
  der,
  parseDER,
  oidText,
  intValue,
  spki,
  publicFromDER,
  sign,
  verify,
  equal,
  requireThat,
  now,
  D,
  H,
  sha512,
  keyID,
  b64u,
  random,
} from './core.mjs';
import {
  algID,
  attribute,
  signCMS,
  parseCertificate,
  issueCertificate,
  extension,
  RRA,
} from './pki.mjs';
import { readControl } from './state.mjs';
import { kemChallenge } from './protection.mjs';
export const possessionOID = '1.3.6.1.4.1.22112.2.1';
export class KEMPossessionService {
  constructor({ journal, audience }) {
    Object.assign(this, { journal, audience });
  }
  challenge(publicKey, { subjectID }) {
    const result = kemChallenge(publicKey, { subjectID, audience: this.audience }),
      id = b64u(result.challenge.context.requestID);
    this.journal.put('kem-pop', id, {
      context: result.challenge.context,
      spki: spki(publicKey),
      expected: result.expected,
      used: false,
    });
    return result.challenge;
  }
  verify(requestID, response, { subjectID, publicKey }) {
    return this.journal.transaction(() => {
      const id = b64u(requestID),
        r = this.journal.get('kem-pop', id);
      requireThat(
        r &&
          !r.value.used &&
          r.value.context.expiresAt > now() &&
          r.value.context.audience === this.audience &&
          equal(r.value.context.subjectID, subjectID) &&
          equal(r.value.spki, spki(publicKey)) &&
          equal(r.value.expected, response),
        'KEM_POP_INVALID_OR_REPLAY',
      );
      this.journal.put(
        'kem-pop',
        id,
        { context: r.value.context, spki: r.value.spki, used: true },
        r.revision,
      );
      return {
        possessionMode: 'DIRECT_PROOF',
        requestID,
        subjectID,
        keyID: keyID(publicKey),
        evidenceHash: H('KEMPossessionEvidence', { context: r.value.context, response }),
      };
    });
  }
}
export function createCSR({
  subject,
  publicKey,
  privateKey,
  attributes = [],
  possessionCertificate,
}) {
  if (possessionCertificate) {
    const c = parseCertificate(possessionCertificate);
    attributes = [
      ...attributes,
      attribute(possessionOID, seq(seq(c.issuer, integer(c.serial)), possessionCertificate)),
    ];
  }
  const info = seq(
    integer(0),
    subject,
    spki(publicKey),
    der(0xa0, parseDER(set(...attributes)).value),
  );
  return seq(info, algID(privateKey.asymmetricKeyType), bit(sign(info, privateKey)));
}
export function prepareCSR({ subject, publicKey, attributes = [] }) {
  const info = seq(
    integer(0),
    subject,
    spki(publicKey),
    der(0xa0, parseDER(set(...attributes)).value),
  );
  return { info, publicKey, algorithm: algID(publicKey.asymmetricKeyType) };
}
export function completeCSR(prepared, signature) {
  requireThat(verify(prepared.info, signature, prepared.publicKey), 'CSR_SIGNATURE');
  const csr = seq(prepared.info, prepared.algorithm, bit(signature));
  verifyCSR(csr);
  return csr;
}
export function verifyCSR(
  raw,
  { validatePossessionCertificate, expectedSubject, expectedSPKI } = {},
) {
  const r = parseDER(raw),
    [info, algorithm, signature] = r.children;
  requireThat(
    r.children.length === 3 && info.children.length === 4 && intValue(info.children[0]) === 0n,
    'CSR_STRUCTURE',
  );
  const [_, subject, pub, attributes] = info.children,
    publicKey = publicFromDER(pub.raw),
    attrs = new Map();
  requireThat(attributes.tag === 0xa0, 'CSR_ATTRIBUTES');
  parseDER(der(0x31, attributes.value));
  for (const a of attributes.children) {
    const id = oidText(a.children[0]);
    requireThat(!attrs.has(id) && a.children[1].children.length === 1, 'CSR_DUPLICATE_ATTRIBUTE');
    attrs.set(id, a.children[1].children[0]);
  }
  let signingKey = publicKey,
    mode = 'DIRECT_SIGNATURE';
  if (attrs.has(possessionOID)) {
    requireThat(
      publicKey.asymmetricKeyType.startsWith('ml-kem-') &&
        typeof validatePossessionCertificate === 'function',
      'CSR_POSSESSION_POLICY',
    );
    const statement = attrs.get(possessionOID);
    requireThat(statement.children.length === 2, 'CSR_POSSESSION_CERTIFICATE_REQUIRED');
    const rawCert = statement.children[1].raw;
    requireThat(validatePossessionCertificate(rawCert) === true, 'CSR_POSSESSION_TRUST');
    const cert = parseCertificate(rawCert);
    requireThat(
      equal(statement.children[0].raw, seq(cert.issuer, integer(cert.serial))),
      'CSR_POSSESSION_SIGNER',
    );
    requireThat(equal(cert.subject, subject.raw), 'CSR_POSSESSION_SUBJECT');
    const san = attrs.get('1.2.840.113549.1.9.14');
    if (san) {
      const requestedSAN = san.children.find((e) => oidText(e.children[0]) === '2.5.29.17');
      if (requestedSAN)
        requireThat(
          equal(requestedSAN.children.at(-1).value, cert.extensions.get('2.5.29.17')?.value),
          'CSR_POSSESSION_SAN',
        );
    }
    signingKey = cert.publicKey;
    mode = 'SIGNED_STATEMENT';
  }
  requireThat(
    equal(algorithm.raw, algID(signingKey.asymmetricKeyType)) &&
      signature.value[0] === 0 &&
      verify(info.raw, signature.value.subarray(1), signingKey),
    'CSR_SIGNATURE',
  );
  if (expectedSubject) requireThat(equal(subject.raw, expectedSubject), 'CSR_SUBJECT');
  if (expectedSPKI) requireThat(equal(pub.raw, expectedSPKI), 'CSR_SPKI');
  return {
    subject: subject.raw,
    spki: pub.raw,
    publicKey,
    attributes: attrs,
    possessionMode: mode,
    requestHash: sha512(raw),
  };
}
export function issueRAR(request, { privateKey, certificate }) {
  requireThat(
    request.schemaVersion === 1 &&
      request.expiresAt > now() &&
      request.expiresAt - now() <= 300 &&
      request.requestID.length === 32 &&
      request.subjectID.length === 32 &&
      request.spkiHash.length === 64 &&
      request.policyHash.length === 64,
    'RAR_FIELDS',
  );
  return signCMS({ content: D('RegistrationAuthorization', request), certificate }, privateKey);
}
export class RegistrationAuthority {
  constructor({ journal, certificate, privateKey, approve, keyBindings, kemPossession }) {
    requireThat(typeof approve === 'function', 'RA_POLICY_REQUIRED');
    Object.assign(this, { journal, certificate, privateKey, approve, keyBindings, kemPossession });
  }
  async authorize({
    csr,
    subjectID,
    profileID,
    policyHash,
    identityEvidenceHash,
    validatePossessionCertificate,
    keyBindingID,
    kemProof,
  }) {
    requireThat(
      profileID !== 'CERTCONCORD-PERSON-PASSKEY-SIGN-v1' || (this.keyBindings && keyBindingID),
      'PASSKEY_ADMISSION_REQUIRED',
    );
    const admission =
      profileID === 'CERTCONCORD-PERSON-PASSKEY-SIGN-v1'
        ? this.keyBindings.forIssuance(keyBindingID, {
            csr,
            subjectID,
            profileID,
            policyHash,
            identityEvidenceHash,
          })
        : null;
    const parsed = verifyCSR(csr, { validatePossessionCertificate });
    let possession;
    if (profileID === 'CERTCONCORD-DOC-ENC-v1') {
      requireThat(this.kemPossession && kemProof, 'RA_KEM_POSSESSION_REQUIRED');
      possession = this.kemPossession.verify(kemProof.requestID, kemProof.response, {
        subjectID,
        publicKey: parsed.publicKey,
      });
    }
    const decision = await this.approve({
      subjectID,
      profileID,
      policyHash,
      identityEvidenceHash,
      csr: parsed,
      ...(admission ? { keyBinding: admission.binding } : {}),
    });
    requireThat(decision?.approved === true, 'RA_DENIED');
    const request = {
      schemaVersion: 1,
      requestID: random(),
      subjectID,
      profileID,
      policyHash,
      identityEvidenceHash,
      spkiHash: sha512(parsed.spki),
      csrHash: sha512(csr),
      possessionMode: parsed.possessionMode,
      issuedAt: now(),
      expiresAt: now() + 120,
      ...(possession ? { kemPossessionEvidenceHash: possession.evidenceHash } : {}),
      ...(admission
        ? { keyBindingID: admission.binding.bindingID, keyBindingHash: admission.hash }
        : {}),
    };
    return issueRAR(request, this);
  }
}
export class AuthorizedIssuer {
  constructor({
    journal,
    raCertificate,
    privateKey,
    issuer,
    policyHash,
    allowedProfiles,
    validatePossessionCertificate,
    approvedExtensions = () => [],
    keyAssurance = { level: 'KAL1', custody: 'SOFTWARE' },
    keyBindings,
  }) {
    Object.assign(this, {
      journal,
      raCertificate,
      privateKey,
      issuer,
      policyHash,
      allowedProfiles,
      validatePossessionCertificate,
      approvedExtensions,
      keyAssurance,
      keyBindings,
    });
  }
  issue({ csr, rar }) {
    const r = readControl(rar, 'RegistrationAuthorization', this.raCertificate),
      p = verifyCSR(csr, { validatePossessionCertificate: this.validatePossessionCertificate });
    requireThat(
      r.schemaVersion === 1 &&
        r.expiresAt > now() &&
        r.issuedAt <= now() &&
        r.expiresAt - r.issuedAt <= 300 &&
        equal(r.policyHash, this.policyHash) &&
        this.allowedProfiles.includes(r.profileID) &&
        equal(r.spkiHash, sha512(p.spki)) &&
        equal(r.csrHash, sha512(csr)) &&
        r.possessionMode === p.possessionMode,
      'ISSUANCE_AUTHORIZATION',
    );
    requireThat(
      r.profileID !== 'CERTCONCORD-PERSON-PASSKEY-SIGN-v1' || (this.keyBindings && r.keyBindingID),
      'PASSKEY_ADMISSION_REQUIRED',
    );
    const admission =
      r.profileID === 'CERTCONCORD-PERSON-PASSKEY-SIGN-v1'
        ? this.keyBindings.forIssuance(r.keyBindingID, { ...r, csr })
        : null;
    if (admission) requireThat(equal(admission.hash, r.keyBindingHash), 'PASSKEY_RA_BINDING');
    return this.journal.transaction(() => {
      const id = b64u(r.requestID),
        prior = this.journal.get('issuance', id);
      if (prior) {
        requireThat(equal(prior.value.rarHash, sha512(rar)), 'ISSUANCE_CONFLICT');
        return prior.value.certificate;
      }
      const serial = BigInt('0x' + random(16).toString('hex')),
        extraExtensions = [
          extension(RRA['id-pe-certconcordAuthorizationID'], octet(H('RegistrationAuthorization', r))),
          extension(
            RRA['id-pe-certconcordKeyAssurance'],
            octet(D('KeyAssurance', admission?.assurance ?? this.keyAssurance)),
          ),
          ...(admission
            ? [extension(RRA['id-pe-certconcordPasskeyBinding'], octet(admission.hash), true)]
            : []),
          ...this.approvedExtensions(p, r),
        ],
        certificate = issueCertificate(
          {
            publicKey: p.publicKey,
            subject: p.subject,
            issuer: this.issuer,
            serial,
            profileID: r.profileID,
            extraExtensions,
            ...(admission
              ? { notAfter: Math.min(now() + 86400, admission.binding.expiresAt) }
              : {}),
          },
          this.privateKey,
        );
      parseCertificate(certificate);
      this.journal.put('issuance', id, { rarHash: sha512(rar), certificate });
      return certificate;
    });
  }
}

import { createPublicKey } from 'node:crypto';
import {
  dcbor,
  decodeCBOR,
  fields,
  requireThat,
  equal,
  sha512,
  keyID,
  now,
  random,
  parseDER,
  spki,
} from './core.mjs';
import { parseCertificate, validateCertificate, OID } from './pki.mjs';
import { verifyMTC } from './mtc.mjs';
import { readControl, evaluateStatus } from './state.mjs';
import { verifyRegistrationBinding } from './document-evidence.mjs';
import { encryptCMS, decryptCMS } from './protection.mjs';
import { snapshotIssuanceScope, issuanceAuthorityScope } from './enrollment-scope.mjs';
import { requireAuthorities } from './control-authority.mjs';
import { AuthorityError } from './authority-history.mjs';

export const DOCUMENT_ENCRYPTION_PROFILE = 'certconcord-document-encryption-draft-03';
const suite = 'ML-KEM-HKDF-SHA256-AES256KW-AES256GCM';
const maxBytes = 16 * 1024 * 1024;
function recipientBinding(certificate, subjectID) {
  const cert = parseCertificate(certificate);
  requireThat(
    ['ml-kem-768', 'ml-kem-1024'].includes(cert.publicKey.asymmetricKeyType) &&
      Buffer.isBuffer(subjectID) &&
      subjectID.length === 32,
    'DOCUMENT_RECIPIENT_KEY',
  );
  const ski = cert.extensions.get('2.5.29.14');
  requireThat(ski, 'DOCUMENT_RECIPIENT_SKI');
  const identifier = parseDER(ski.value);
  requireThat(identifier.tag === 4 && identifier.value.length > 0, 'DOCUMENT_RECIPIENT_SKI');
  return {
    publicKey: cert.publicKey,
    subjectKeyIdentifier: identifier.value,
    binding: {
      subjectID,
      certificateID: cert.certificateID,
      representationHash: cert.representationHash,
      keyID: keyID(cert.publicKey),
    },
  };
}

export function admitDocumentRecipient({ certificate, rar, status }, trust, at = now()) {
  const profileID = 'CERTCONCORD-DOC-ENC-v1',
    cert = parseCertificate(certificate),
    knowledgeTime = trust.knowledgeTime ?? at;
  requireThat(
    Number.isSafeInteger(at) &&
      at >= 0 &&
      Number.isSafeInteger(knowledgeTime) &&
      knowledgeTime >= at &&
      Buffer.isBuffer(trust.trustDomainID) &&
      trust.trustDomainID.length === 32,
    'DOCUMENT_RECIPIENT_TRUST',
  );
  let mtcProof;
  if (cert.algorithm === OID.mtc) {
    requireThat(trust.mtc, 'DOCUMENT_RECIPIENT_MTC_TRUST');
    mtcProof = verifyMTC(certificate, { ...trust.mtc, at, profileID, trustedSubtrees: [] });
  } else {
    requireThat(trust.issuerPublicKey, 'DOCUMENT_RECIPIENT_ISSUER_TRUST');
    validateCertificate(certificate, trust.issuerPublicKey, { at, profileID });
  }
  const authorization = verifyRegistrationBinding(rar, certificate, {
    raCertificate: trust.raCertificate,
    subjectID: trust.subjectID,
    profileID,
    policyHash: trust.policyHash,
    at,
    issuanceScope: trust.issuanceScope,
  });
  requireThat(
    Buffer.isBuffer(authorization.kemPossessionEvidenceHash) &&
      authorization.kemPossessionEvidenceHash.length === 64,
    'DOCUMENT_RECIPIENT_POSSESSION',
  );
  const statement = readControl(status, 'CertificateStatus', trust.statusCertificate);
  requireThat(
    equal(statement.certificateID, cert.certificateID) &&
      equal(statement.trustDomainID, trust.trustDomainID),
    'DOCUMENT_RECIPIENT_STATUS_BINDING',
  );
  const statusAssessment = evaluateStatus(statement, {
    stateTime: at,
    knowledgeTime,
    scope: 'CERTIFICATE',
  });
  const selectedScope = snapshotIssuanceScope(trust.issuanceScope),
    scope = issuanceAuthorityScope(authorization),
    issuerKey = cert.algorithm === OID.mtc ? trust.mtc.caPublicKey : trust.issuerPublicKey;
  requireThat(
    equal(selectedScope.trustDomainID, trust.trustDomainID) &&
      selectedScope.representation === (cert.algorithm === OID.mtc ? 'MTC' : 'X509') &&
      equal(selectedScope.issuerKeyID, keyID(issuerKey)),
    'ISSUANCE_SCOPE',
  );
  if (trust.issuerCertificate)
    requireThat(
      equal(keyID(parseCertificate(trust.issuerCertificate).publicKey), keyID(issuerKey)),
      'ISSUER_KEY_BINDING',
    );
  requireAuthorities(
    trust.authorityResolver,
    [
      {
        certificate: trust.raCertificate,
        role: 'REGISTRATION_AUTHORITY',
        scope,
        stateTime: authorization.issuedAt,
        knowledgeTime,
      },
      {
        ...(trust.issuerCertificate
          ? { certificate: trust.issuerCertificate }
          : { publicKeyDER: spki(issuerKey) }),
        role: 'ISSUER',
        scope,
        stateTime: authorization.issuedAt,
        knowledgeTime,
      },
      ...(statement.publishedAt <= knowledgeTime
        ? [
            {
              certificate: trust.statusCertificate,
              role: 'STATUS_AUTHORITY',
              scope,
              stateTime: statement.publishedAt,
              knowledgeTime,
            },
          ]
        : []),
    ],
    statusAssessment.overall === 'INDETERMINATE'
      ? ['DOCUMENT_RECIPIENT_' + statusAssessment.reason]
      : [],
    ['INVALID', 'UNSUPPORTED'].includes(statusAssessment.overall)
      ? [
          new AuthorityError({
            ...statusAssessment,
            reason: 'DOCUMENT_RECIPIENT_' + statusAssessment.reason,
          }),
        ]
      : [],
    mtcProof
      ? [
          {
            members: mtcProof.verifiedCosigners,
            threshold: trust.mtc.threshold,
            role: 'COSIGNER',
            scope,
            stateTimes: [authorization.issuedAt, at],
            knowledgeTime,
          },
        ]
      : [],
  );
  return recipientBinding(certificate, trust.subjectID);
}

export function encryptDocument(
  document,
  recipients,
  { trustDomainID, deliveryID = random(), at = now() } = {},
) {
  requireThat(
    Buffer.isBuffer(document) &&
      document.length <= maxBytes &&
      Array.isArray(recipients) &&
      recipients.length >= 1 &&
      recipients.length <= 100 &&
      Buffer.isBuffer(trustDomainID) &&
      trustDomainID.length === 32 &&
      Buffer.isBuffer(deliveryID) &&
      deliveryID.length === 32,
    'DOCUMENT_ENCRYPTION_INPUT',
  );
  const admitted = recipients.map(({ evidence, trust }) => {
    requireThat(equal(trust.trustDomainID, trustDomainID), 'DOCUMENT_RECIPIENT_DOMAIN');
    return admitDocumentRecipient(evidence, trust, at);
  });
  requireThat(
    new Set(admitted.map((r) => r.binding.keyID.toString('hex'))).size === admitted.length,
    'DOCUMENT_DUPLICATE_RECIPIENT',
  );
  const header = {
    schemaVersion: 1,
    profile: DOCUMENT_ENCRYPTION_PROFILE,
    suite,
    trustDomainID,
    deliveryID,
  };
  const content = dcbor({
    ...header,
    createdAt: at,
    recipients: admitted.map((r) => r.binding),
    documentHash: sha512(document),
    document,
  });
  try {
    return { ...header, ciphertext: encryptCMS(content, admitted) };
  } finally {
    content.fill(0);
  }
}

export function decryptDocument(
  envelope,
  { privateKey, certificate, subjectID, trustDomainID, expectedDeliveryID },
) {
  fields(envelope, [
    'schemaVersion',
    'profile',
    'suite',
    'trustDomainID',
    'deliveryID',
    'ciphertext',
  ]);
  requireThat(
    envelope.schemaVersion === 1 &&
      envelope.profile === DOCUMENT_ENCRYPTION_PROFILE &&
      envelope.suite === suite &&
      Buffer.isBuffer(trustDomainID) &&
      trustDomainID.length === 32 &&
      Buffer.isBuffer(expectedDeliveryID) &&
      expectedDeliveryID.length === 32 &&
      equal(envelope.trustDomainID, trustDomainID) &&
      equal(envelope.deliveryID, expectedDeliveryID) &&
      Buffer.isBuffer(envelope.ciphertext) &&
      envelope.ciphertext.length <= maxBytes + 1024 * 1024,
    'DOCUMENT_DELIVERY_BINDING',
  );
  const recipient = recipientBinding(certificate, subjectID);
  requireThat(
    equal(keyID(createPublicKey(privateKey)), recipient.binding.keyID),
    'DOCUMENT_DECRYPTION_KEY',
  );
  const plaintext = decryptCMS(envelope.ciphertext, {
    privateKey,
    subjectKeyIdentifier: recipient.subjectKeyIdentifier,
  });
  try {
    const content = decodeCBOR(plaintext, { maxBytes: maxBytes + 1024 * 1024, maxItems: 2000 });
    fields(content, [
      'schemaVersion',
      'profile',
      'suite',
      'trustDomainID',
      'deliveryID',
      'createdAt',
      'recipients',
      'documentHash',
      'document',
    ]);
    requireThat(
      content.schemaVersion === 1 &&
        content.profile === envelope.profile &&
        content.suite === suite &&
        equal(content.trustDomainID, trustDomainID) &&
        equal(content.deliveryID, expectedDeliveryID) &&
        Number.isSafeInteger(content.createdAt) &&
        content.createdAt >= 0 &&
        Array.isArray(content.recipients) &&
        content.recipients.length >= 1 &&
        content.recipients.length <= 100 &&
        content.recipients.filter((r) => equal(dcbor(r), dcbor(recipient.binding))).length === 1 &&
        Buffer.isBuffer(content.document) &&
        content.document.length <= maxBytes &&
        equal(content.documentHash, sha512(content.document)),
      'DOCUMENT_PLAINTEXT_BINDING',
    );
    for (const binding of content.recipients) {
      fields(binding, ['subjectID', 'certificateID', 'representationHash', 'keyID']);
      for (const [name, size] of [
        ['subjectID', 32],
        ['certificateID', 64],
        ['representationHash', 64],
        ['keyID', 64],
      ])
        requireThat(
          Buffer.isBuffer(binding[name]) && binding[name].length === size,
          'DOCUMENT_RECIPIENT_BINDING',
        );
    }
    requireThat(
      new Set(content.recipients.map((r) => r.keyID.toString('hex'))).size ===
        content.recipients.length,
      'DOCUMENT_DUPLICATE_RECIPIENT',
    );
    return Buffer.from(content.document);
  } finally {
    plaintext.fill(0);
  }
}

import { createPrivateKey } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { Journal, activationContext, issuePermit, SigningGateway, readControl } from './state.mjs';
import { createCSR, RegistrationAuthority, KEMPossessionService } from './enrollment.mjs';
import { MTCIssuer } from './issuance.mjs';
import { Mirror } from './mtc.mjs';
import { SoftwareProvider } from './providers.mjs';
import { DOCUMENT_EVIDENCE_PROFILE } from './document-evidence.mjs';
import { createSignaturePackage } from './evidence.mjs';
import { createVerifier } from './sdk/index.mjs';
import {
  encryptDocument,
  decryptDocument,
  admitDocumentRecipient,
} from './document-encryption.mjs';
import { answerKEMChallenge, encryptVault, decryptVault, decryptCMS } from './protection.mjs';
import { EncryptionRecoveryService } from './lifecycle.mjs';
import { exampleTimestamp } from './example-timestamp.mjs';
import { exampleAuthorityResolver } from './example-authorities.mjs';

export async function runDocumentDemo({ onComplete, timestampOptions } = {}) {
  const journal = new Journal(),
    mirrorJournals = [0, 1, 2].map(() => new Journal());
  const root = c.random();
  try {
    const ca = c.generate('ml-dsa-87'),
      raKey = c.generate('ml-dsa-87');
    const sealKey = c.generate(),
      controlKey = c.generate(),
      organizationKey = c.generate();
    const cert = (key, serial, label, profileID = 'CERTCONCORD-EVIDENCE-SIGN-v1') =>
      p.issueCertificate(
        {
          publicKey: key.publicKey,
          serial,
          subject: p.name(label),
          issuer: p.name('Synthetic CA'),
          profileID,
        },
        ca.privateKey,
      );
    const raCertificate = cert(raKey, 1, 'Synthetic RA');
    const controlCertificate = cert(controlKey, 2, 'Synthetic Execution Authority');
    const organizationCertificate = cert(organizationKey, 3, 'Synthetic Organization Authority');
    const trustDomainID = c.random(),
      organizationID = c.random(),
      recipientID = c.random();
    const issuanceScope = { trustDomainID, issuerID: '32473.10', issuerKeyID: c.keyID(ca.publicKey), representation: 'MTC' },
      timestamp = exampleTimestamp(journal, timestampOptions),
      authorityResolver = exampleAuthorityResolver({ trustDomainID, authorities: [
        { certificate: raCertificate, roles: ['REGISTRATION_AUTHORITY'] },
        { certificate: controlCertificate, roles: ['PERMIT_AUTHORITY', 'RECEIPT_AUTHORITY', 'STATUS_AUTHORITY'] },
        { certificate: organizationCertificate, roles: ['ORGANIZATION_AUTHORITY', 'STATUS_AUTHORITY'] },
        { certificate: timestamp.trust.certificate, roles: ['TIMESTAMP_AUTHORITY'] },
        { mode: 'RAW_KEY', publicKeyDER: c.spki(ca.publicKey), knownAt: c.now() - 60, validFrom: c.now() - 60, validUntil: c.now() + 86400, roles: ['ISSUER'] },
      ] });
    const policy = {
      schemaVersion: 1,
      activationMode: 'WORKLOAD',
      allowedProfiles: ['CERTCONCORD-ORG-SEAL-v1'],
      allowedOrigins: ['https://documents.example'],
      rpID: 'documents.example',
      audience: 'document-seal',
      maxActivationLifetime: 120,
      requireTrustedTime: true,
      documentEvidence: { profile: DOCUMENT_EVIDENCE_PROFILE, organizationAuthorization: true },
    };
    const policyHash = c.H('SignaturePolicy', policy);
    const members = mirrorJournals.map((_, i) => ({
      id: '32473.' + (20 + i),
      operatorID: 'synthetic-operator-' + i,
      ...c.generate('ml-dsa-87'),
    }));
    const mtc = {
      caID: '32473.10',
      caPublicKey: ca.publicKey,
      members,
      threshold: 2,
      policyHash,
      rtmHash: c.H('SyntheticRTM', { trustDomainID, policyHash }),
      membershipEpoch: 1,
    };
    const possessionKey = c.generate(),
      possessionSubject = p.name('Synthetic Recipient');
    const possessionCertificate = cert(
      possessionKey,
      4,
      'Synthetic Recipient',
      'CERTCONCORD-PERSON-SIGN-v1',
    );
    const validatePossessionCertificate = (raw) => {
      p.validateCertificate(raw, ca.publicKey, { profileID: 'CERTCONCORD-PERSON-SIGN-v1' });
      return c.equal(raw, possessionCertificate);
    };
    const kemPossession = new KEMPossessionService({ journal, audience: 'document-recipient-ra' });
    const ra = new RegistrationAuthority({
      journal,
      certificate: raCertificate,
      privateKey: raKey.privateKey,
      kemPossession,
      approve: async (r) => ({
        approved:
          c.equal(r.policyHash, policyHash) &&
          ((r.profileID === 'CERTCONCORD-ORG-SEAL-v1' && c.equal(r.subjectID, organizationID)) ||
            (r.profileID === 'CERTCONCORD-DOC-ENC-v1' && c.equal(r.subjectID, recipientID))),
      }),
    });
    const issuer = new MTCIssuer({
      issuanceScope,
      authorityResolver,
      ...mtc,
      journal,
      raCertificate,
      privateKey: ca.privateKey,
      logNumber: 1,
      allowedProfiles: ['CERTCONCORD-ORG-SEAL-v1', 'CERTCONCORD-DOC-ENC-v1'],
      validatePossessionCertificate,
      mirrors: members.map(
        (m, i) => new Mirror({ journal: mirrorJournals[i], id: m.id, privateKey: m.privateKey }),
      ),
    });
    const signControl = (
      label,
      body,
      authority = { certificate: controlCertificate, privateKey: controlKey.privateKey },
    ) =>
      p.signCMS(
        { content: c.D(label, body), certificate: authority.certificate },
        authority.privateKey,
      );
    const statusFor = (certificate, changes = {}) =>
      signControl('CertificateStatus', {
        schemaVersion: 1,
        trustDomainID,
        certificateID: p.parseCertificate(certificate).certificateID,
        scope: 'CERTIFICATE',
        status: 'GOOD',
        publishedAt: c.now(),
        nextUpdate: c.now() + 300,
        ...changes,
      });
    const csr = createCSR({ subject: p.name('Synthetic Organization'), ...sealKey });
    const rar = await ra.authorize({
      issuanceScope,
      csr,
      subjectID: organizationID,
      profileID: 'CERTCONCORD-ORG-SEAL-v1',
      policyHash,
      identityEvidenceHash: c.H('SyntheticOrganizationAdmission', { organizationID }),
    });
    const certificate = await issuer.issue({ csr, rar }),
      parsed = p.parseCertificate(certificate);
    const document = Buffer.from(
      'Synthetic organization document for signing and encrypted delivery.\n',
    );
    const sim = {
      schemaVersion: 1,
      trustDomainID,
      transactionID: c.random(),
      subjectID: organizationID,
      profileID: 'CERTCONCORD-ORG-SEAL-v1',
      keyID: c.keyID(sealKey.publicKey),
      certificateID: parsed.certificateID,
      certificateRepresentationHash: parsed.representationHash,
      container: 'CMS',
      adapterID: 'certconcord-cms-v1',
      organizationAuthorizationID: c.random(),
      documents: [
        {
          documentID: c.random(),
          mediaType: 'text/plain',
          digestAlgorithm: 'SHA-512',
          digest: c.sha512(document),
          scope: 'CMS_CONTENT',
          displayName: 'Synthetic organization document',
        },
      ],
      purpose: 'ORGANIZATION_SEAL',
      origin: policy.allowedOrigins[0],
      policyHash,
      issuedAt: c.now(),
      expiresAt: c.now() + 120,
      nonce: c.random(),
      displayText: 'Apply the organizational seal to the specified document.',
    };
    const prepared = p.prepareCMS({
      content: document,
      certificate,
      detached: true,
      context: {
        schemaVersion: 1,
        trustDomainID,
        profileID: sim.profileID,
        container: 'CMS',
        adapterID: 'certconcord-cms-v1',
      },
      simHash: c.H('SIM', sim),
      policyHash,
    });
    const activation = activationContext({
      trustDomainID,
      tbsKind: 'CMS_SIGNED_ATTRS_DER',
      tbs: prepared.tbs,
      publicKey: sealKey.publicKey,
      simHash: c.H('SIM', sim),
      certificateID: parsed.certificateID,
      certificateRepresentationHash: parsed.representationHash,
      transactionID: sim.transactionID,
      policyHash,
      origin: sim.origin,
      rpID: policy.rpID,
      audience: policy.audience,
      expiresAt: sim.expiresAt,
    });
    const authorizationBody = {
      schemaVersion: 1,
      authorizationID: sim.organizationAuthorizationID,
      trustDomainID,
      organizationID,
      actorID: c.random(),
      actorType: 'WORKLOAD',
      keyID: sim.keyID,
      certificateID: sim.certificateID,
      purpose: 'ORGANIZATION_SEAL',
      activationHash: c.H('ActivationContext', activation),
      policyHash,
      issuedAt: activation.issuedAt,
      expiresAt: activation.expiresAt,
    };
    const organizationAuthority = {
      certificate: organizationCertificate,
      privateKey: organizationKey.privateKey,
    };
    const organizationAuthorization = signControl(
      'OrganizationAuthorization',
      authorizationBody,
      organizationAuthority,
    );
    const organizationStatus = (changes = {}) =>
      signControl(
        'OrganizationAuthorizationStatus',
        {
          schemaVersion: 1,
          trustDomainID,
          authorizationID: authorizationBody.authorizationID,
          authorizationHash: c.sha512(organizationAuthorization),
          scope: 'ORGANIZATION_AUTHORIZATION',
          status: 'GOOD',
          publishedAt: c.now(),
          nextUpdate: c.now() + 300,
          ...changes,
        },
        organizationAuthority,
      );
    const permit = issuePermit(activation, {
      certificate: controlCertificate,
      privateKey: controlKey.privateKey,
      activationEvidenceHash: c.sha512(organizationAuthorization),
      proofMode: 'WORKLOAD',
    });
    const gateway = new SigningGateway({
      authorityResolver,
      journal,
      permitCertificate: controlCertificate,
      receiptCertificate: controlCertificate,
      receiptKey: controlKey.privateKey,
      audience: policy.audience,
      backend: new SoftwareProvider(new Map([['seal', sealKey]])),
      authorize: async ({ permit: candidate }) =>
        c.equal(candidate.activationEvidenceHash, c.sha512(organizationAuthorization)),
    });
    const execution = await gateway.execute({ permit, tbs: prepared.tbs, keyRef: 'seal' });
    const bundle = createSignaturePackage({
      document,
      certificate,
      sim,
      policy,
      activation,
      permit,
      receipt: execution.receipt,
      status: statusFor(certificate),
      cms: prepared.finish(execution.signature),
      documentEvidence: {
        RegistrationAuthorization: rar,
        OrganizationAuthorization: organizationAuthorization,
        OrganizationAuthorizationStatus: organizationStatus(),
        DocumentTimestamp: timestamp.issue,
      },
    });
    const trust = {
      issuanceScope,
      authorityResolver,
      mtc,
      raCertificate,
      permitCertificate: controlCertificate,
      receiptCertificate: controlCertificate,
      statusCertificate: controlCertificate,
      expectedPolicy: policy,
      trustDomainID,
      timestamp: timestamp.trust,
      organizationAuthorities: [
        {
          organizationID,
          certificate: organizationCertificate,
          statusCertificate: organizationCertificate,
        },
      ],
      knowledgeTime: c.now() + (timestampOptions?.accuracySeconds ?? 0),
    };
    const verification = createVerifier({ format: 'CMS', trust }).verify(c.dcbor(bundle));
    c.requireThat(verification.overall === 'VALID', verification.reason);

    const enrollRecipient = async () => {
      const key = c.generate('ml-kem-768');
      const request = createCSR({
        subject: possessionSubject,
        publicKey: key.publicKey,
        privateKey: possessionKey.privateKey,
        possessionCertificate,
      });
      const challenge = kemPossession.challenge(key.publicKey, { subjectID: recipientID });
      const kemProof = {
        requestID: challenge.context.requestID,
        response: answerKEMChallenge(key.privateKey, challenge, {
          audience: 'document-recipient-ra',
        }),
      };
      const authorization = await ra.authorize({
        issuanceScope,
        csr: request,
        subjectID: recipientID,
        profileID: 'CERTCONCORD-DOC-ENC-v1',
        policyHash,
        validatePossessionCertificate,
        kemProof,
        identityEvidenceHash: c.H('SyntheticRecipientAdmission', { recipientID }),
      });
      const issued = await issuer.issue({ csr: request, rar: authorization });
      return {
        key,
        evidence: { certificate: issued, rar: authorization, status: statusFor(issued) },
        trust: {
          issuanceScope,
          authorityResolver,
          mtc,
          raCertificate,
          statusCertificate: controlCertificate,
          trustDomainID,
          subjectID: recipientID,
          policyHash,
        },
        request,
        kemProof,
      };
    };
    const recipient = await enrollRecipient(),
      replacement = await enrollRecipient();
    const delivery = encryptDocument(c.dcbor(bundle), [recipient], { trustDomainID });
    const decryption = {
      privateKey: recipient.key.privateKey,
      certificate: recipient.evidence.certificate,
      subjectID: recipientID,
      trustDomainID,
      expectedDeliveryID: delivery.deliveryID,
    };
    const opened = decryptDocument(delivery, decryption);
    c.requireThat(
      createVerifier({ format: 'CMS', trust }).verify(opened).overall === 'VALID',
      'DOCUMENT_DELIVERY_VERIFICATION',
    );

    const rootID = c.random(),
      objectID = c.random();
    const encodedKey = recipient.key.privateKey.export({ type: 'pkcs8', format: 'der' });
    const vault = encryptVault(root, encodedKey, {
      rootID,
      objectID,
      purpose: 'ENCRYPTION_PRIVATE_KEY',
    });
    encodedKey.fill(0);
    const approvers = [0, 1].map((i) => {
      const key = c.generate();
      return {
        privateKey: key.privateKey,
        certificate: cert(key, 10 + i, 'Synthetic Recovery Operator ' + i),
        operatorID: 'recovery-operator-' + i,
      };
    });
    const recovery = new EncryptionRecoveryService({
      journal,
      approvers,
      threshold: 2,
      graph: {
        nodes: ['operator0', 'operator1', 'encryption', 'signing'],
        edges: [{ from: ['operator0', 'operator1'], threshold: 2, to: 'encryption' }],
      },
      attackerRoots: ['operator0', 'operator1'],
      signingTargets: ['signing'],
      loadEncryptionRoot: async (r) => {
        c.requireThat(
          c.equal(r.rootID, rootID) &&
            c.equal(r.subjectID, recipientID) &&
            r.purpose === 'ENCRYPTION_VAULT_WRAP',
          'RECOVERY_ROOT_BINDING',
        );
        return Buffer.from(root);
      },
      certificate: controlCertificate,
      privateKey: controlKey.privateKey,
    });
    const admitted = admitDocumentRecipient(replacement.evidence, replacement.trust);
    const request = {
      schemaVersion: 1,
      requestID: c.random(),
      targetRootID: rootID,
      subjectID: recipientID,
      recipientKeyID: admitted.binding.keyID,
      purpose: 'ENCRYPTION_VAULT_WRAP',
      issuedAt: c.now(),
      expiresAt: c.now() + 120,
    };
    const approvals = approvers.map((a) =>
      signControl(
        'EncryptionRecoveryApproval',
        {
          requestHash: c.H('EncryptionRecoveryRequest', request),
          approved: true,
          expiresAt: request.expiresAt,
        },
        a,
      ),
    );
    const result = c.decodeCBOR(await recovery.recover(request, approvals, admitted.publicKey));
    const recoveryReceipt = readControl(
      result.receipt,
      'EncryptionRecoveryResult',
      controlCertificate,
    );
    c.requireThat(
      c.equal(recoveryReceipt.requestHash, c.H('EncryptionRecoveryRequest', request)) &&
        c.equal(recoveryReceipt.ciphertextHash, c.sha512(result.encrypted)),
      'RECOVERY_RESULT_BINDING',
    );
    const recoveredBytes = decryptCMS(result.encrypted, {
      privateKey: replacement.key.privateKey,
      subjectKeyIdentifier: request.recipientKeyID,
    });
    const recovered = c.decodeCBOR(recoveredBytes);
    c.requireThat(
      c.equal(recovered.requestHash, c.H('EncryptionRecoveryRequest', request)),
      'RECOVERY_RESULT_BINDING',
    );
    const restoredBytes = decryptVault(recovered.root, vault, {
      expectedRootID: rootID,
      expectedObjectID: objectID,
    });
    const restoredKey = createPrivateKey({ key: restoredBytes, format: 'der', type: 'pkcs8' });
    restoredBytes.fill(0);
    recovered.root.fill(0);
    recoveredBytes.fill(0);
    c.requireThat(
      c.equal(decryptDocument(delivery, { ...decryption, privateKey: restoredKey }), opened),
      'RECOVERED_DOCUMENT_MISMATCH',
    );
    if (onComplete)
      await onComplete({
        bundle,
        trust,
        recipient,
        replacement,
        delivery,
        decryption,
        statusFor,
        organizationStatus,
        signControl,
        organizationAuthority,
        authorizationBody,
        timestamp,
        ra,
        validatePossessionCertificate,
        policyHash,
        recovery,
        request,
        approvals,
      });
    return {
      bundle,
      trust,
      delivery,
      summary: {
        verification,
        encryption: 'ML-KEM-768',
        delivery: 'DECRYPTED_AND_VERIFIED',
        recovery: 'TWO_OPERATOR_ENCRYPTION_KEY_RECOVERY',
        recoveredDocument: 'DECRYPTED_AND_VERIFIED',
        keyCustody: 'SYNTHETIC_SOFTWARE',
        clockAssurance: 'SYNTHETIC_CLOCK',
      },
    };
  } finally {
    root.fill(0);
    journal.close();
    mirrorJournals.forEach((j) => j.close());
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  console.log(JSON.stringify((await runDocumentDemo()).summary, null, 2));

import { pathToFileURL } from 'node:url';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { Journal, activationContext } from './state.mjs';
import { RegistrationAuthority, AuthorizedIssuer } from './enrollment.mjs';
import {
  PasskeySigningRegistry,
  PasskeySigningService,
  verifyPasskeyOperation,
} from './passkey-credentials.mjs';
import { PASSKEY_SIGN_PROFILE } from './raw-signing.mjs';
import { createRawSigningKey, rawSign, publicAssertion } from './browser.mjs';
import { authorizeHumanActivation } from './webauthn.mjs';
import { examplePasskey } from './example-passkey.mjs';
import { MTCIssuer } from './issuance.mjs';
import { Mirror, verifyMTC } from './mtc.mjs';
import { createSignaturePackage, verifySignaturePackage } from './evidence.mjs';
import { exampleAuthorityResolver } from './example-authorities.mjs';

export async function runPasskeyDemo({
  version = 'previewSign5-2026-09-09',
  algorithm = -9,
  mtc = false,
  onComplete,
} = {}) {
  const journal = new Journal(),
    caJournal = new Journal(),
    mirrorJournals = [new Journal(), new Journal(), new Journal()];
  try {
    const subjectID = c.random(),
      trustDomainID = c.random(),
      identityEvidenceHash = c.H('SyntheticIdentity', {});
    const profileID = PASSKEY_SIGN_PROFILE,
      rpID = 'website.example',
      origin = 'https://website.example';
    const policy = {
      activationMode: 'HUMAN_WEBAUTHN',
      allowedProfiles: [profileID],
      rpID,
      allowedOrigins: [origin],
      maxActivationLifetime: 120,
      audience: 'certconcord-passkey-signing',
    };
    const policyHash = c.H('SignaturePolicy', policy),
      ca = c.generate('ml-dsa-87');
    const issuer = p.name('Synthetic Passkey CA');
    const control = (label) => {
      const key = c.generate('ml-dsa-87');
      return {
        privateKey: key.privateKey,
        publicKey: key.publicKey,
        certificate: p.issueCertificate(
          {
            publicKey: key.publicKey,
            issuer,
            subject: p.name(label),
            serial: BigInt('0x' + c.random(8).toString('hex')),
            profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1',
          },
          ca.privateKey,
        ),
      };
    };
    const raControl = control('Synthetic RA'),
      permitControl = control('Synthetic Activation'),
      receiptControl = control('Synthetic Receipt'),
      statusControl = control('Synthetic Status'),
      authenticator = examplePasskey({ version, algorithm });
    const issuanceScope = { trustDomainID, issuerID: '32473.10', issuerKeyID: c.keyID(ca.publicKey), representation: mtc ? 'MTC' : 'X509' },
      authorityResolver = exampleAuthorityResolver({ trustDomainID, authorities: [
        { certificate: raControl.certificate, roles: ['REGISTRATION_AUTHORITY'] },
        { certificate: permitControl.certificate, roles: ['PERMIT_AUTHORITY'] },
        { certificate: receiptControl.certificate, roles: ['RECEIPT_AUTHORITY'] },
        { certificate: statusControl.certificate, roles: ['STATUS_AUTHORITY'] },
        { mode: 'RAW_KEY', publicKeyDER: c.spki(ca.publicKey), knownAt: c.now() - 60, validFrom: c.now() - 60, validUntil: c.now() + 86400, roles: ['ISSUER'] },
      ] });
    const members = mirrorJournals.map((_, i) => ({
      id: '32473.' + (20 + i),
      operatorID: 'synthetic-mirror-' + i,
      ...c.generate('ml-dsa-87'),
    }));
    const mtcTrust = {
      caID: '32473.10',
      caPublicKey: ca.publicKey,
      members,
      threshold: 2,
      policyHash,
      rtmHash: c.H('SyntheticRTM', { trustDomainID, policyHash }),
      membershipEpoch: 1,
    };
    const certificateVerifier = (raw, options) => {
      if (mtc) verifyMTC(raw, { ...mtcTrust, ...options });
      else p.validateCertificate(raw, ca.publicKey, options);
      return true;
    };
    const registry = new PasskeySigningRegistry({
      journal,
      trustDomainID,
      policyHash,
      rpID,
      origin,
      attestationPolicy: authenticator.attestationPolicy,
      registrationAuthorityCertificate: raControl.certificate,
      certificateVerifier,
    });
    const enrollment = registry.begin({
      subjectID,
      subject: p.name('Synthetic Person'),
      identityEvidenceHash,
      version,
      algorithms: [algorithm],
    });
    const generated = await createRawSigningKey(
      {
        challenge: enrollment.challenge,
        rp: { id: rpID, name: 'Example' },
        user: { id: subjectID, name: 'example', displayName: 'Synthetic Person' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        attestation: 'direct',
      },
      { version, algorithms: [algorithm], credentials: authenticator.credentials },
    );
    const request = registry.stage({
      requestID: enrollment.context.requestID,
      ceremony: generated.registration,
      generatedKey: Object.fromEntries(
        Object.entries(generated.key).map(([k, v]) => [k, k === 'algorithm' ? v : Buffer.from(v)]),
      ),
      ...(algorithm === -65539 ? { derivationIKM: c.random() } : {}),
    });
    const possession = await rawSign({ ...request, credentials: authenticator.credentials });
    const admitted = registry.finish({
      bindingID: request.bindingID,
      assertion: possession.assertion,
      signature: Buffer.from(possession.signature),
    });
    const ra = new RegistrationAuthority({
      journal,
      ...raControl,
      keyBindings: registry,
      approve: async (r) => ({
        approved:
          c.equal(r.identityEvidenceHash, identityEvidenceHash) &&
          c.equal(r.keyBinding.subjectID, subjectID) &&
          r.profileID === profileID,
      }),
    });
    const rar = await ra.authorize({
      issuanceScope,
      csr: admitted.csr,
      subjectID,
      profileID,
      policyHash,
      identityEvidenceHash,
      keyBindingID: request.bindingID,
    });
    const options = {
      issuanceScope,
      authorityResolver,
      journal: caJournal,
      raCertificate: raControl.certificate,
      privateKey: ca.privateKey,
      issuer,
      policyHash,
      allowedProfiles: [profileID],
      keyBindings: registry,
    };
    const issuingCA = mtc
      ? new MTCIssuer({
          ...options,
          ...mtcTrust,
          logNumber: 1,
          mirrors: members.map(
            (m, i) =>
              new Mirror({ journal: mirrorJournals[i], id: m.id, privateKey: m.privateKey }),
          ),
        })
      : new AuthorizedIssuer(options);
    const certificate = await issuingCA.issue({ csr: admitted.csr, rar });
    registry.activate(request.bindingID, { certificate, rar });
    const cert = p.parseCertificate(certificate),
      document = Buffer.from('Synthetic Passkey-authorized agreement.\n');
    const sim = {
      schemaVersion: 1,
      trustDomainID,
      transactionID: c.random(),
      subjectID,
      profileID,
      keyID: c.keyID(cert.publicKey),
      certificateID: cert.certificateID,
      certificateRepresentationHash: cert.representationHash,
      container: 'CMS',
      adapterID: 'certconcord-cms-passkey-v1',
      documents: [
        {
          documentID: c.random(),
          mediaType: 'text/plain',
          digestAlgorithm: 'SHA-512',
          digest: c.sha512(document),
          scope: 'CMS_CONTENT',
          displayName: 'Synthetic agreement',
        },
      ],
      purpose: 'Approve the agreement',
      displayText: 'Approve the exact synthetic agreement.',
      origin,
      policyHash,
      issuedAt: c.now(),
      expiresAt: c.now() + 120,
      nonce: c.random(),
    };
    const context = {
      schemaVersion: 1,
      trustDomainID,
      profileID,
      container: 'CMS',
      adapterID: 'certconcord-cms-passkey-v1',
    };
    const prepared = p.prepareCMS({
      content: document,
      certificate,
      detached: true,
      context,
      simHash: c.H('SIM', sim),
      policyHash,
    });
    const activation = activationContext({
      trustDomainID,
      tbsKind: 'CMS_SIGNED_ATTRS_DER',
      tbs: prepared.tbs,
      publicKey: cert.publicKey,
      simHash: c.H('SIM', sim),
      certificateID: cert.certificateID,
      certificateRepresentationHash: cert.representationHash,
      transactionID: sim.transactionID,
      policyHash,
      origin,
      rpID,
      audience: policy.audience,
      expiresAt: sim.expiresAt,
      serverNonce: c.unb64u(journal.issueNonce('activation')),
    });
    const activationRegistration = registry.registration(request.bindingID);
    const activationProof = publicAssertion(
      await authenticator.credentials.get({
        publicKey: {
          challenge: c.H('ActivationContext', activation),
          rpId: rpID,
          userVerification: 'required',
          allowCredentials: [{ type: 'public-key', id: authenticator.credentialID }],
        },
      }),
    );
    const permit = authorizeHumanActivation({
      activation,
      assertion: activationProof,
      registration: activationRegistration,
      policy,
      sim,
      journal,
      permitCertificate: permitControl.certificate,
      permitKey: permitControl.privateKey,
    });
    const service = new PasskeySigningService({
      authorityResolver,
      journal,
      registry,
      permitCertificate: permitControl.certificate,
      receiptCertificate: receiptControl.certificate,
      receiptKey: receiptControl.privateKey,
      audience: policy.audience,
      authorize: async ({ permit: pp }) => c.equal(pp.activation.simHash, c.H('SIM', sim)),
    });
    const operation = await service.begin({
      bindingID: request.bindingID,
      permit,
      tbs: prepared.tbs,
    });
    const registration = registry.registration(request.bindingID);
    const raw = await rawSign({ ...operation, credentials: authenticator.credentials });
    const result = await service.complete({
      operationID: operation.operationID,
      assertion: raw.assertion,
      signature: Buffer.from(raw.signature),
    });
    const cms = prepared.finish(result.signature);
    p.verifyCMS(cms, {
      content: document,
      expectedCertificate: certificate,
      ...(!mtc ? { issuerKey: ca.publicKey } : {}),
      profileID,
      context,
      simHash: c.H('SIM', sim),
      policyHash,
    });
    const evidence = {
      permit,
      tbs: prepared.tbs,
      ...result,
      binding: admitted.binding,
      registration,
      certificate,
    };
    const trust = {
      authorityResolver,
      permitCertificate: permitControl.certificate,
      receiptCertificate: receiptControl.certificate,
      certificateVerifier,
      audience: policy.audience,
      status: () => true,
    };
    const verification = verifyPasskeyOperation(evidence, trust);
    const status = p.signCMS(
      {
        content: c.D('CertificateStatus', {
          schemaVersion: 1,
          trustDomainID,
          certificateID: cert.certificateID,
          scope: 'CERTIFICATE',
          status: 'GOOD',
          publishedAt: c.now(),
          nextUpdate: c.now() + 300,
        }),
        certificate: statusControl.certificate,
      },
      statusControl.privateKey,
    );
    const bundle = createSignaturePackage({
      document,
      certificate,
      sim,
      policy,
      activation,
      permit,
      receipt: result.receipt,
      status,
      cms,
      passkeyEvidence: {
        binding: admitted.binding,
        assertion: result.assertion,
        registration: {
          credentialID: registration.credentialID,
          publicKeyDER: c.spki(registration.publicKey),
          counter: registration.counter,
          backupEligible: registration.backupEligible,
          origin: registration.origin,
          rpID: registration.rpID,
        },
      },
    });
    const packageTrust = {
      issuanceScope,
      authorityResolver,
      ...(mtc ? { mtc: mtcTrust } : { issuerPublicKey: ca.publicKey }),
      permitCertificate: permitControl.certificate,
      receiptCertificate: receiptControl.certificate,
      statusCertificate: statusControl.certificate,
      expectedPolicy: policy,
      trustDomainID,
      passkeyStatus: () => true,
    };
    const packageVerification = verifySignaturePackage(bundle, packageTrust);
    if (onComplete)
      await onComplete({
        journal,
        caJournal,
        registry,
        authenticator,
        service,
        issuingCA,
        ra,
        raControl,
        ca,
        issuer,
        permitControl,
        receiptControl,
        bindingID: request.bindingID,
        operation,
        result,
        evidence,
        admitted,
        rar,
        prepared,
        sim,
        policy,
        activation,
      });
    return {
      verification,
      bundle,
      packageTrust,
      packageVerification,
      evidence,
      trust,
      cms,
      document,
      csr: admitted.csr,
      rar,
      sim,
      context,
      policy,
      identityEvidenceHash,
      activationProof,
      caPublicKey: ca.publicKey,
      summary: {
        profileID,
        version,
        algorithm,
        credential: mtc ? 'MTC' : 'X509',
        container: 'CMS',
        enrollment: 'ATTESTED_KEY_AND_CSR_POSSESSION',
        authorization: verification.authorization,
        signature: verification.cryptographicValidity,
        quantumResistance: verification.quantumResistance,
        evidence: packageVerification.profile,
        closure: packageVerification.closure,
      },
    };
  } finally {
    journal.close();
    caJournal.close();
    for (const j of mirrorJournals) j.close();
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  c.requireThat(
    !(process.argv.includes('--arkg') && process.argv.includes('--split')),
    'CONFLICTING_ALGORITHM_OPTIONS',
  );
  const version = process.argv.includes('--v4') ? 'previewSign-4' : 'previewSign5-2026-09-09';
  const algorithm = process.argv.includes('--arkg')
    ? -65539
    : process.argv.includes('--split')
      ? -300
      : -9;
  console.log(
    JSON.stringify(
      (await runPasskeyDemo({ version, algorithm, mtc: process.argv.includes('--mtc') })).summary,
      null,
      2,
    ),
  );
}

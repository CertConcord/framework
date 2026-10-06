import { createServer } from 'node:http';
import { listenLoopback } from './example-network.mjs';
import { X509Certificate } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { Journal, activationContext, SigningGateway } from './state.mjs';
import { issueIACA, issueMdocCertificate } from './mdoc-pki.mjs';
import { issueMdoc, annexCPresent } from './mdoc.mjs';
import { createCSR } from './enrollment.mjs';
import { issueCRL } from './revocation.mjs';
import { publicJWK } from './jose.mjs';
import { PresentationVerifier, walletMdocPresentation } from './openid.mjs';
import { AnnexCVerifier } from './annex-verifier.mjs';
import { IdentityAdmission, identityCRLValidator } from './identity.mjs';
import { identityProfiles } from './identity-profiles.mjs';
import { authorizeHumanActivation } from './webauthn.mjs';
import { exampleAssertion } from './example-authenticator.mjs';
import { examplePasskey } from './example-passkey.mjs';
import { createRawSigningKey, rawSign, publicAssertion } from './browser.mjs';
import { PasskeySigningRegistry, PasskeySigningService } from './passkey-credentials.mjs';
import { PASSKEY_SIGN_PROFILE } from './raw-signing.mjs';
import { DeviceBindingRegistry, authorizeMdocActivation } from './bridge.mjs';
import { OpenIDWallet } from './wallet.mjs';
import { createProtocolHandler } from './http.mjs';
import { SoftwareProvider } from './providers.mjs';
import { CredentialLog } from './credential-log.mjs';
import { TlogMirror } from './transparency.mjs';
import {
  PersonalMdocCA,
  SIGNER_DOCTYPE,
  SIGNER_NAMESPACE,
  prepareMdocDocument,
  verifyPersonalMdoc,
  createMdocSignaturePackage,
  verifyMdocSignaturePackage,
} from './signer-mdoc.mjs';

import { exampleExecutionGateway, exampleExecutionPolicy } from './example-execution.mjs';
import { exampleTimestamp } from './example-timestamp.mjs';
import { DOCUMENT_EVIDENCE_PROFILE } from './document-evidence.mjs';

export async function runFoundationDemo({
  executionBinding = false,
  trustedTime = false,
  identityTransport = 'openid4vp',
  issuerModel = 'delegated',
  documentKeyMode = 'INDEPENDENT_PQ',
  identityType = 'custom',
  activationMode = 'HUMAN_MDOC',
  attestationFactory,
  passkeyVersion = 'previewSign5-2026-09-09',
  passkeyAlgorithm = -9,
  onComplete,
  journalFactory = () => new Journal(),
} = {}) {
  c.requireThat(['openid4vp', 'annex-c'].includes(identityTransport), 'IDENTITY_TRANSPORT');
  c.requireThat(
    !executionBinding || documentKeyMode !== 'PASSKEY_KEY',
    'EXECUTION_PASSKEY_COMPOSITION_UNDEFINED',
  );
  c.requireThat(['delegated', 'direct'].includes(issuerModel), 'ISSUER_MODEL');
  c.requireThat(
    ['INDEPENDENT_PQ', 'DEVICE_KEY', 'PASSKEY_KEY'].includes(documentKeyMode),
    'DOCUMENT_KEY_MODE',
  );
  c.requireThat(
    documentKeyMode !== 'PASSKEY_KEY' || activationMode === 'HUMAN_WEBAUTHN',
    'PASSKEY_PREAUTHORIZATION',
  );
  c.requireThat(Object.hasOwn(identityProfiles, identityType), 'IDENTITY_TYPE');
  c.requireThat(['HUMAN_MDOC', 'HUMAN_WEBAUTHN'].includes(activationMode), 'ACTIVATION_MODE');
  const identityProfile = {
    ...identityProfiles[identityType],
    statusMode: 'ISSUER_AND_VALIDITY',
    maxCredentialLifetime: 86400,
  };
  const identityClaims = Object.fromEntries(
    Object.entries(identityProfile.namespaces).map(([ns, fields]) => [
      ns,
      Object.fromEntries(
        Object.entries(fields).map(([name, rule]) => [
          name,
          rule.type === 'boolean'
            ? true
            : name === 'family_name'
              ? 'Applicant'
              : name === 'given_name'
                ? 'Synthetic'
                : 'sample-identifier',
        ]),
      ),
    ]),
  );
  const identityPaths = Object.entries(identityProfile.namespaces).flatMap(([ns, fields]) =>
    Object.keys(fields).map((name) => [ns, name]),
  );
  const signerDocType = issuerModel === 'direct' ? identityProfile.docType : SIGNER_DOCTYPE;
  const signerCertificateProfile =
    issuerModel === 'direct' ? (identityProfile.certificateProfile ?? 'ISO_MDOC') : 'ISO_MDOC';
  const journal = journalFactory('authority'),
    logJournal = journalFactory('log'),
    mirrorJournals = Array.from({ length: 3 }, (_, i) => journalFactory('mirror-' + i)),
    log = {
      ...c.generate('ed25519'),
      name: 'synthetic.example/personal-mdoc',
      scheme: 'ed25519-log',
    },
    members = mirrorJournals.map((_, i) => ({
      ...c.generate('ml-dsa-87'),
      name: 'synthetic-mirror-' + i,
      operatorID: 'synthetic-operator-' + i,
      scheme: 'CERTCONCORD-MLDSA87-SUBTREE-v1',
    })),
    credentialLogTrust = { log, members, threshold: 2 },
    credentialLog = new CredentialLog({
      journal: logJournal,
      log,
      mirrors: members.map((m, i) => ({
        operatorID: m.operatorID,
        service: new TlogMirror({
          journal: mirrorJournals[i],
          signer: m,
          logs: new Map([[log.name, log]]),
        }),
      })),
    }),
    rootKey = c.generate('ec'),
    root = issueIACA({
      publicKey: rootKey.publicKey,
      privateKey: rootKey.privateKey,
      subject: p.name('Synthetic IACA'),
      serial: 1,
      issuerAltName: 'https://synthetic.example',
      crlURL: 'https://synthetic.example/crl',
    }),
    roots = [new X509Certificate(root)];
  const entity = (label, serial, reader = false, certificateProfile = 'ISO_MDOC') => {
    const k = c.generate('ec');
    return {
      ...k,
      certificate: issueMdocCertificate({
        publicKey: k.publicKey,
        subject: p.name(label),
        serial,
        issuerCertificate: root,
        issuerKey: rootKey.privateKey,
        reader,
        certificateProfile,
      }),
    };
  };
  const government = entity(
      'Synthetic identity issuer',
      2,
      false,
      identityProfile.certificateProfile,
    ),
    ca = issuerModel === 'direct' ? government : entity('Synthetic personal mdoc CA', 3),
    reader = entity('Synthetic identity reader', 4, true, identityProfile.certificateProfile),
    signingReader = entity('Synthetic signing reader', 8, true, signerCertificateProfile),
    govHolder = c.generate('ec'),
    holder = c.generate('ec'),
    documentKey = documentKeyMode === 'DEVICE_KEY' ? holder : c.generate(),
    walletKey = c.generate('ec'),
    dpop = c.generate('ec');
  const control = (label, serial) => {
    const k = c.generate('ml-dsa-87');
    return {
      ...k,
      certificate: p.issueCertificate(
        {
          publicKey: k.publicKey,
          subject: p.name(label),
          issuer: p.name(label),
          serial,
          profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1',
        },
        k.privateKey,
      ),
    };
  };
  const ra = control('Synthetic RA', 5),
    activationAuthority = control('Synthetic activation authority', 6),
    sealAuthority = control('Synthetic PQ credential authority', 7),
    trustDomainID = c.random(),
    subjectID = c.random(),
    profileID =
      documentKeyMode === 'DEVICE_KEY'
        ? 'CERTCONCORD-PERSON-DEVICE-SIGN-v1'
        : documentKeyMode === 'PASSKEY_KEY'
          ? PASSKEY_SIGN_PROFILE
          : 'CERTCONCORD-PERSON-SIGN-v1',
    policy = {
      schemaVersion: 1,
      activationMode,
      ...(executionBinding ? { executionBinding: exampleExecutionPolicy() } : {}),
      holderKeyAdmission: attestationFactory ? 'HARDWARE_KEY_VERIFIED' : 'UNATTESTED',
      requirePostQuantumDocument: documentKeyMode === 'INDEPENDENT_PQ',
      maxSAL: activationMode === 'HUMAN_WEBAUTHN' && documentKeyMode !== 'PASSKEY_KEY' ? 2 : 1,
      allowedOrigins: ['https://website.example'],
      allowedProfiles: [profileID],
      acceptedQualifications: ['IDENTITY_EVIDENCE_VERIFIED'],
      rpID: 'website.example',
      audience: 'certconcord-personal-mdoc-signer',
      maxActivationLifetime: 120,
      requireTrustedTime: trustedTime,
      ...(trustedTime
        ? {
            documentEvidence: {
              profile: DOCUMENT_EVIDENCE_PROFILE,
              organizationAuthorization: false,
            },
          }
        : {}),
    },
    policyHash = c.H('SignaturePolicy', policy);
  let csr = createCSR({
    subject: p.name('Synthetic Applicant'),
    publicKey: documentKey.publicKey,
    privateKey: documentKey.privateKey,
  });
  let passkeyRegistry, rawAuthenticator, passkeyBindingID;
  if (documentKeyMode === 'PASSKEY_KEY') {
    rawAuthenticator = examplePasskey({ version: passkeyVersion, algorithm: passkeyAlgorithm });
    passkeyRegistry = new PasskeySigningRegistry({
      journal,
      trustDomainID,
      policyHash,
      origin: policy.allowedOrigins[0],
      rpID: policy.rpID,
      registrationAuthorityCertificate: ra.certificate,
      attestationPolicy: rawAuthenticator.attestationPolicy,
      mdocVerifier: () => {
        throw Error('MDOC_NOT_ISSUED');
      },
    });
    const enrollment = passkeyRegistry.begin({
      subjectID,
      subject: p.name('Synthetic Applicant'),
      version: passkeyVersion,
      algorithms: [passkeyAlgorithm],
    });
    const generation = await createRawSigningKey(
      {
        challenge: enrollment.challenge,
        rp: { id: policy.rpID, name: 'Example' },
        user: { id: subjectID, name: 'example', displayName: 'Synthetic Applicant' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        attestation: 'direct',
      },
      {
        version: passkeyVersion,
        algorithms: [passkeyAlgorithm],
        credentials: rawAuthenticator.credentials,
      },
    );
    const request = passkeyRegistry.stage({
      requestID: enrollment.context.requestID,
      ceremony: generation.registration,
      generatedKey: Object.fromEntries(
        Object.entries(generation.key).map(([k, v]) => [k, k === 'algorithm' ? v : Buffer.from(v)]),
      ),
      ...(passkeyAlgorithm === -65539 ? { derivationIKM: c.random() } : {}),
    });
    const proof = await rawSign({ ...request, credentials: rawAuthenticator.credentials });
    const admitted = passkeyRegistry.finish({
      bindingID: request.bindingID,
      assertion: proof.assertion,
      signature: Buffer.from(proof.signature),
    });
    csr = admitted.csr;
    documentKey.publicKey = c.publicFromDER(admitted.binding.documentSPKI);
    delete documentKey.privateKey;
    passkeyBindingID = request.bindingID;
  }
  let handler;
  const server = createServer((req, res) => handler(req, res));
  await listenLoopback(server);
  const issuerURL = 'http://127.0.0.1:' + server.address().port,
    governmentID = issuerModel === 'direct' ? issuerURL : 'https://government.example',
    govDocType = identityProfile.docType,
    govNamespace = identityProfile.namespace,
    sessionID = c.b64u(c.random());
  try {
    const crl = issueCRL({
        issuer: p.parseCertificate(root).subject,
        privateKey: rootKey.privateKey,
        number: 1,
      }),
      identityRegistry = new Map([
        [
          governmentID,
          {
            publicKey: government.publicKey,
            certificate: government.certificate,
            identityProfile,
            validateIdentityStatus: identityCRLValidator({
              journal,
              issuerCertificate: root,
              fetchCRL: async () => crl,
            }),
          },
        ],
      ]),
      IdentityVerifier = identityTransport === 'annex-c' ? AnnexCVerifier : PresentationVerifier,
      identityVerifier = new IdentityVerifier({
        baseURL: issuerURL + '/ra',
        journal,
        privateKey: reader.privateKey,
        certificate: reader.certificate,
        issuerRegistry: identityRegistry,
        trustRoots: roots,
      }),
      admission = new IdentityAdmission({
        journal,
        verifier: identityVerifier,
        trustDomainID,
        policyHash,
        certificate: ra.certificate,
        privateKey: ra.privateKey,
        issuanceAudience: issuerURL,
        keyBindings: passkeyRegistry,
        decide: ({ evidence, csr: request }) => ({
          approved:
            evidence.issuerID === governmentID &&
            evidence.docType === govDocType &&
            identityPaths.every(
              ([ns, name]) => evidence.namespaces[ns]?.[name] === identityClaims[ns][name],
            ) &&
            c.equal(request.subject, p.name('Synthetic Applicant')),
          subjectID,
          assurance: 'IDENTITY_EVIDENCE_VERIFIED',
        }),
      });
    const govCredential = issueMdoc({
        claims: identityClaims[govNamespace],
        additionalNamespaces: Object.fromEntries(
          Object.entries(identityClaims).filter(([ns]) => ns !== govNamespace),
        ),
        certificateProfile: identityProfile.certificateProfile,
        holderJWK: publicJWK(govHolder.publicKey),
        privateKey: government.privateKey,
        certificate: government.certificate,
        docType: govDocType,
        namespace: govNamespace,
      }),
      identityRequest = admission.begin({
        csr,
        sessionID,
        issuerID: governmentID,
        claims: identityPaths,
        origin: policy.allowedOrigins[0],
        profileID,
        ...(passkeyBindingID ? { keyBindingID: passkeyBindingID } : {}),
      });
    if (identityTransport === 'annex-c') {
      const response = await annexCPresent(identityRequest.request, {
        origin: policy.allowedOrigins[0],
        credential: govCredential,
        holderKey: govHolder.privateKey,
        readerPublicKey: reader.publicKey,
        readerCertificate: reader.certificate,
        readerCertificateProfile: identityProfile.certificateProfile,
      });
      await identityVerifier.response(identityRequest.id, response, {
        sessionID,
        origin: policy.allowedOrigins[0],
      });
    } else {
      const response = await walletMdocPresentation(identityRequest.signed, {
        credential: c.b64u(govCredential),
        holderKey: govHolder.privateKey,
        verifierRoots: roots,
        origin: policy.allowedOrigins[0],
        docType: govDocType,
        namespace: govNamespace,
        namespaces: Object.keys(identityProfile.namespaces),
      });
      await identityVerifier.response(identityRequest.id, response.response, {
        sessionID,
        mode: 'dc_api.jwt',
      });
    }
    const identity = admission.authorize(identityRequest.id, { sessionID }),
      bindings = new DeviceBindingRegistry({
        allowUnattested: !attestationFactory,
        journal,
        registrationAuthorityCertificate: ra.certificate,
        trustDomainID,
        policyHash,
      }),
      registrationNonce = bindings.challenge({
        subjectID,
        profileID,
        sessionID,
        ...(documentKeyMode !== 'DEVICE_KEY'
          ? { documentKeyID: c.keyID(documentKey.publicKey) }
          : {}),
      }),
      fixture = attestationFactory?.(holder.publicKey, registrationNonce);
    if (fixture) bindings.attestationPolicy = fixture.policy;
    const assessment = bindings.assess({
        holderPublicKey: holder.publicKey,
        nonce: registrationNonce,
        sessionID,
        evidence: fixture?.evidence,
      }),
      authorization = p.signCMS(
        {
          certificate: ra.certificate,
          content: c.D('DeviceRegistrationAuthorization', {
            schemaVersion: 1,
            trustDomainID,
            subjectID: identity.subjectID,
            profileID,
            holderKeyID: c.keyID(holder.publicKey),
            documentKeyID: c.keyID(documentKey.publicKey),
            policyHash,
            attestationEvidenceHash: assessment.evidenceHash,
            keyAssurance: assessment.keyAssurance,
            localUVPolicy: assessment.localUVPolicy,
            audience: 'certconcord-device-registry',
            issuedAt: c.now(),
            expiresAt: c.now() + 300,
            bindingExpiresAt: c.now() + 86400,
          }),
        },
        ra.privateKey,
      ),
      binding = bindings.enroll({
        authorization,
        holderPublicKey: holder.publicKey,
        nonce: registrationNonce,
        sessionID,
        attestation: fixture?.evidence,
        proof: c.sign(
          c.D('DeviceRegistrationProof', {
            schemaVersion: 1,
            authorizationHash: c.sha512(authorization),
            nonce: registrationNonce,
            audience: 'certconcord-device-registry',
          }),
          holder.privateKey,
        ),
      });
    const clientID = 'https://wallet.example',
      issuer = new PersonalMdocCA({
        issuer: issuerURL,
        journal,
        privateKey: ca.privateKey,
        certificate: ca.certificate,
        clients: new Map([
          [
            clientID,
            { publicKey: walletKey.publicKey, redirectURIs: ['https://wallet.example/return'] },
          ],
        ]),
        enforceDPoPNonce: true,
        bindings,
        raCertificate: ra.certificate,
        sealCertificate: sealAuthority.certificate,
        sealKey: sealAuthority.privateKey,
        credentialLog,
        credentialLogTrust,
        docType: signerDocType,
        certificateProfile: signerCertificateProfile,
        allowedProfiles: [profileID],
        keyBindings: passkeyRegistry,
        additionalNamespaces: () => (issuerModel === 'direct' ? identityClaims : {}),
      }),
      issuerRegistry = new Map([
        [
          issuerURL,
          {
            publicKey: ca.publicKey,
            certificate: ca.certificate,
            certificateProfile: signerCertificateProfile,
            statusURI: issuerURL + '/status/1',
            fetchStatus: async () => issuer.status.token(),
          },
        ],
      ]),
      verifier = new PresentationVerifier({
        baseURL: issuerURL + '/website',
        journal,
        privateKey: signingReader.privateKey,
        certificate: signingReader.certificate,
        issuerRegistry,
        trustRoots: roots,
      });
    handler = createProtocolHandler({
      issuer,
      verifier,
      approveAuthorization: async () => ({ approved: true, subjectID: c.b64u(subjectID) }),
    });
    const credentialTrust = {
        issuerCertificate: ca.certificate,
        issuerPublicKey: ca.publicKey,
        issuerRoots: roots,
        sealCertificate: sealAuthority.certificate,
        trustDomainID,
        policyHash,
        statusURI: issuerURL + '/status/1',
        credentialLogTrust,
        docType: signerDocType,
        certificateProfile: signerCertificateProfile,
      },
      wallet = new OpenIDWallet({
        issuer: issuerURL,
        clientID,
        clientKey: walletKey.privateKey,
        dpopKey: dpop.privateKey,
        holderKey: holder.privateKey,
        issuerCertificate: ca.certificate,
        issuerRoots: roots,
        mdocDocType: signerDocType,
        mdocNamespace: SIGNER_NAMESPACE,
        mdocCertificateProfile: signerCertificateProfile,
        allowLoopback: true,
        verifyCredentialExtension: async (item) =>
          verifyPersonalMdoc(c.unb64u(item.credential), {
            ...credentialTrust,
            seal: c.unb64u(item.certconcord_credential_seal),
            statusToken: issuer.status.token(),
          }),
      }),
      offer = issuer.offer({ csr, rar: identity.rar, bindingID: binding.bindingID }),
      authorizationSession = await wallet.startAuthorization(offer, {
        redirectURI: 'https://wallet.example/return',
      }),
      redirect = await fetch(authorizationSession.authorizationURL, { redirect: 'manual' }),
      stored = await wallet.finishAuthorization(
        redirect.headers.get('location'),
        authorizationSession,
        { encryptionKey: c.generate('ec').privateKey },
      ),
      credential = c.unb64u(stored.credential),
      seal = c.unb64u(stored.certconcordCredentialSeal),
      signer = verifyPersonalMdoc(credential, {
        ...credentialTrust,
        seal,
        statusToken: issuer.status.token(),
      });
    if (passkeyRegistry) {
      passkeyRegistry.mdocVerifier = (raw, options) => {
        bindings.active(binding.bindingID);
        return verifyPersonalMdoc(raw, {
          ...credentialTrust,
          ...options,
          statusToken: issuer.status.token(),
        });
      };
      passkeyRegistry.activateMdoc(passkeyBindingID, { credential, seal, rar: identity.rar });
    }
    const document = Buffer.from(
        'Document authenticated by a personal signer mdoc using ' + documentKeyMode + '.\n',
      ),
      sim = {
        schemaVersion: 1,
        trustDomainID,
        transactionID: c.random(),
        subjectID,
        profileID,
        keyID: c.keyID(documentKey.publicKey),
        certificateID: signer.credentialID,
        certificateRepresentationHash: signer.representationHash,
        credentialType: 'MDOC',
        container: 'COSE',
        adapterID: 'certconcord-mdoc-document-v1',
        documents: [
          {
            documentID: c.random(),
            mediaType: 'text/plain',
            digestAlgorithm: 'SHA-512',
            digest: c.sha512(document),
            scope: 'COSE_PAYLOAD',
            displayName: 'Synthetic document',
          },
        ],
        purpose: 'DOCUMENT_SIGN',
        origin: policy.allowedOrigins[0],
        policyHash,
        issuedAt: c.now(),
        expiresAt: c.now() + 120,
        nonce: c.random(),
        displayText:
          'Sign the exact synthetic document using the key certified by the personal mdoc.',
      },
      context = {
        schemaVersion: 1,
        trustDomainID,
        profileID,
        container: 'COSE',
        adapterID: sim.adapterID,
        credentialType: 'MDOC',
      },
      prepared = prepareMdocDocument(document, {
        credential,
        publicKey: documentKey.publicKey,
        context,
        simHash: c.H('SIM', sim),
        policyHash,
      }),
      activation = activationContext({
        trustDomainID,
        tbs: prepared.tbs,
        publicKey: documentKey.publicKey,
        simHash: c.H('SIM', sim),
        certificateID: signer.credentialID,
        certificateRepresentationHash: signer.representationHash,
        transactionID: sim.transactionID,
        policyHash,
        origin: sim.origin,
        rpID: policy.rpID,
        audience: policy.audience,
        expiresAt: sim.expiresAt,
        serverNonce: c.unb64u(journal.issueNonce('activation')),
      });
    let permit;
    if (activationMode === 'HUMAN_MDOC') {
      const request = verifier.request({
          sessionID,
          claims: ['qualification', 'device_binding_id', 'binding_epoch'],
          activationHash: c.H('ActivationContext', activation),
          mode: 'dc_api.jwt',
          origin: sim.origin,
          displayText: sim.displayText,
          docType: signerDocType,
          namespace: SIGNER_NAMESPACE,
        }),
        presentation = await walletMdocPresentation(request.signed, {
          credential: stored.credential,
          holderKey: holder.privateKey,
          verifierRoots: roots,
          origin: sim.origin,
          docType: signerDocType,
          namespace: SIGNER_NAMESPACE,
          approveTransaction: async (t) =>
            t.activation_hash === c.b64u(c.H('ActivationContext', activation)) &&
            t.display_text === sim.displayText,
        });
      await verifier.response(request.id, presentation.response, { sessionID, mode: 'dc_api.jwt' });
      permit = authorizeMdocActivation({
        verifier,
        presentationID: request.id,
        sessionID,
        activation,
        tbs: prepared.tbs,
        documentPublicKey: documentKey.publicKey,
        sim,
        policy,
        bindings,
        journal,
        permitCertificate: activationAuthority.certificate,
        permitKey: activationAuthority.privateKey,
      });
    } else {
      const example = passkeyRegistry
        ? {
            registration: passkeyRegistry.registration(passkeyBindingID),
            assertion: publicAssertion(
              await rawAuthenticator.credentials.get({
                publicKey: {
                  challenge: c.H('ActivationContext', activation),
                  rpId: policy.rpID,
                  userVerification: 'required',
                  allowCredentials: [{ type: 'public-key', id: rawAuthenticator.credentialID }],
                },
              }),
            ),
          }
        : exampleAssertion({
            challenge: c.H('ActivationContext', activation),
            origin: sim.origin,
            rpID: policy.rpID,
            keyID: c.keyID(documentKey.publicKey),
            subjectID,
          });
      const { registration, assertion } = example;
      bindings.active(binding.bindingID);
      permit = authorizeHumanActivation({
        activation,
        assertion,
        registration,
        policy,
        sim,
        journal,
        permitCertificate: activationAuthority.certificate,
        permitKey: activationAuthority.privateKey,
      });
    }
    let passkeyEvidence;
    const gatewayOptions = {
        journal,
        permitCertificate: activationAuthority.certificate,
        receiptCertificate: activationAuthority.certificate,
        receiptKey: activationAuthority.privateKey,
        audience: policy.audience,
        backend: new SoftwareProvider(new Map([['document', documentKey]])),
        keyRef: 'document',
        authorize: async ({ permit: p, keyRef }) => {
          c.requireThat(
            keyRef === 'document' &&
              p.proofMode === activationMode &&
              c.equal(p.activation.policyHash, policyHash),
            'DOCUMENT_POLICY',
          );
          bindings.active(binding.bindingID);
          return true;
        },
      },
      gateway = executionBinding
        ? exampleExecutionGateway({
            ...gatewayOptions,
            policy,
            trustDomainID,
            publicKey: documentKey.publicKey,
          })
        : new SigningGateway(gatewayOptions),
      result = passkeyRegistry
        ? await (async () => {
            const service = new PasskeySigningService({
              journal,
              registry: passkeyRegistry,
              permitCertificate: activationAuthority.certificate,
              receiptCertificate: activationAuthority.certificate,
              receiptKey: activationAuthority.privateKey,
              audience: policy.audience,
              authorize: async () => {
                bindings.active(binding.bindingID);
                return true;
              },
            });
            const request = await service.begin({
              bindingID: passkeyBindingID,
              permit,
              tbs: prepared.tbs,
            });
            const registration = passkeyRegistry.registration(passkeyBindingID);
            const proof = await rawSign({ ...request, credentials: rawAuthenticator.credentials });
            const result = await service.complete({
              operationID: request.operationID,
              assertion: proof.assertion,
              signature: Buffer.from(proof.signature),
            });
            passkeyEvidence = {
              assertion: result.assertion,
              registration: {
                credentialID: registration.credentialID,
                publicKeyDER: c.spki(registration.publicKey),
                counter: registration.counter,
                backupEligible: registration.backupEligible,
                origin: registration.origin,
                rpID: registration.rpID,
              },
            };
            return result;
          })()
        : await gateway.execute({
            permit,
            tbs: prepared.tbs,
            ...(executionBinding ? { sim } : { keyRef: 'document' }),
          }),
      signature = prepared.finish(result.signature),
      timestamp = trustedTime ? exampleTimestamp(journal) : undefined,
      bundle = createMdocSignaturePackage({
        document,
        credential,
        seal,
        statusToken: issuer.status.token(),
        sim,
        policy,
        activation,
        permit,
        receipt: result.receipt,
        signature,
        passkeyEvidence,
        executionEvidence: result.executionEvidence,
        ...(timestamp ? { documentEvidence: { DocumentTimestamp: timestamp.issue } } : {}),
      }),
      trust = {
        ...credentialTrust,
        expectedPolicy: policy,
        permitCertificate: activationAuthority.certificate,
        receiptCertificate: activationAuthority.certificate,
        ...(timestamp ? { timestamp: timestamp.trust } : {}),
        ...(passkeyRegistry ? { passkeyStatus: () => true } : {}),
        ...(executionBinding
          ? {
              executionBindingCertificate: activationAuthority.certificate,
              executionStatus: () => true,
            }
          : {}),
      },
      verification = verifyMdocSignaturePackage(bundle, trust);
    if (onComplete)
      await onComplete({
        journal,
        issuer,
        passkeyRegistry,
        passkeyBindingID,
        credential,
        seal,
        credentialTrust,
        ra,
        bindings,
        binding,
        verification,
      });
    return {
      bundle,
      trust,
      verification,
      summary: {
        release: '0.2.0-draft.1',
        identitySource: 'SYNTHETIC_IDENTITY_MDOC',
        identityType,
        identityDocType: govDocType,
        activationMode,
        identityTransport,
        issuerModel,
        flow: [
          'approved identity type, issuer and holder proof',
          'RA identity admission',
          'CA personal signer mdoc via OpenID4VCI',
          activationMode === 'HUMAN_WEBAUTHN'
            ? 'WebAuthn document-bound activation'
            : 'QTB consent',
          documentKeyMode === 'PASSKEY_KEY'
            ? 'attested Passkey-associated ES256 document signature'
            : documentKeyMode === 'DEVICE_KEY'
              ? 'explicitly authorized DeviceKey ES256 document signature'
              : 'separate ML-DSA document signature',
          'semantic evidence verification without a personal X.509 certificate',
        ],
        custody: attestationFactory ? 'SYNTHETIC_ATTESTATION_FIXTURE' : 'SYNTHETIC_SOFTWARE',
        ...verification,
      },
    };
  } finally {
    await new Promise((r) => server.close(r));
    journal.close();
    logJournal.close();
    for (const j of mirrorJournals) j.close();
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  c.requireThat(
    !(process.argv.includes('--arkg') && process.argv.includes('--split')),
    'CONFLICTING_ALGORITHM_OPTIONS',
  );
  c.requireThat(
    !(process.argv.includes('--raw-passkey') && process.argv.includes('--device-key')),
    'CONFLICTING_KEY_MODE_OPTIONS',
  );
  console.log(
    JSON.stringify(
      (
        await runFoundationDemo({
          executionBinding: process.argv.includes('--execution-binding'),
          trustedTime: process.argv.includes('--trusted-time'),
          identityTransport: process.argv.includes('--annex-c') ? 'annex-c' : 'openid4vp',
          issuerModel: process.argv.includes('--direct') ? 'direct' : 'delegated',
          documentKeyMode: process.argv.includes('--raw-passkey')
            ? 'PASSKEY_KEY'
            : process.argv.includes('--device-key')
              ? 'DEVICE_KEY'
              : 'INDEPENDENT_PQ',
          passkeyVersion: process.argv.includes('--v4')
            ? 'previewSign-4'
            : 'previewSign5-2026-09-09',
          passkeyAlgorithm: process.argv.includes('--arkg')
            ? -65539
            : process.argv.includes('--split')
              ? -300
              : -9,
          identityType:
            process.argv.find((arg) => arg.startsWith('--identity='))?.split('=')[1] ?? 'custom',
          activationMode:
            process.argv.includes('--passkey') || process.argv.includes('--raw-passkey')
              ? 'HUMAN_WEBAUTHN'
              : 'HUMAN_MDOC',
        })
      ).summary,
      null,
      2,
    ),
  );
}

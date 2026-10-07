import { issueIACA, issueMdocCertificate } from './mdoc-pki.mjs';
import { createServer } from 'node:http';
import { listenLoopback } from './example-network.mjs';
import { X509Certificate } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { mkdir, writeFile } from 'node:fs/promises';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { Journal, SigningGateway, activationContext } from './state.mjs';
import { DeviceBindingRegistry, RRACredentialIssuer, authorizeMdocActivation } from './bridge.mjs';
import { CredentialIssuer, PresentationVerifier, walletMdocPresentation } from './openid.mjs';
import { OpenIDWallet } from './wallet.mjs';
import { createProtocolHandler } from './http.mjs';
import { SoftwareProvider } from './providers.mjs';
import { createSignaturePackage, verifySignaturePackage } from './evidence.mjs';
import { createCSR, RegistrationAuthority } from './enrollment.mjs';
import { MTCIssuer } from './issuance.mjs';
import { Mirror } from './mtc.mjs';
import { AnnexCVerifier } from './annex-verifier.mjs';
import { annexCPresent } from './mdoc.mjs';
import { authorizeHumanActivation } from './webauthn.mjs';
import { exampleAssertion } from './example-authenticator.mjs';
import { exampleExecutionGateway, exampleExecutionPolicy } from './example-execution.mjs';
import { exampleTimestamp } from './example-timestamp.mjs';
import { DOCUMENT_EVIDENCE_PROFILE } from './document-evidence.mjs';
import { exampleAuthorityResolver } from './example-authorities.mjs';

export async function runDemo({
  outputDirectory,
  presentationTransport = 'openid4vp',
  grantType = 'pre-authorized',
  activationMode = 'HUMAN_MDOC',
  executionBinding = false,
  trustedTime = false,
  journalFactory = () => new Journal(),
  onComplete,
} = {}) {
  c.requireThat(
    ['openid4vp', 'annex-c'].includes(presentationTransport) &&
      ['pre-authorized', 'authorization-code'].includes(grantType) &&
      ['HUMAN_MDOC', 'HUMAN_WEBAUTHN'].includes(activationMode),
    'DEMO_PROFILE',
  );
  const journal = journalFactory('authority'),
    pqCA = c.generate('ml-dsa-87'),
    raKey = c.generate('ml-dsa-87'),
    documentKey = c.generate(),
    authorityKey = c.generate('ml-dsa-87'),
    iaca = c.generate('ec'),
    issuerKey = c.generate('ec'),
    readerKey = c.generate('ec'),
    holder = c.generate('ec'),
    walletKey = c.generate('ec'),
    dpop = c.generate('ec');
  const issuerName = p.name('Synthetic RRA Issuer'),
    raCertificate = p.issueCertificate(
      {
        publicKey: raKey.publicKey,
        issuer: issuerName,
        subject: p.name('Synthetic RA'),
        serial: 1,
        profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1',
      },
      pqCA.privateKey,
    ),
    authorityCertificate = p.issueCertificate(
      {
        publicKey: authorityKey.publicKey,
        issuer: issuerName,
        subject: p.name('Synthetic Activation Authority'),
        serial: 2,
        profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1',
      },
      pqCA.privateKey,
    ),
    root = issueIACA({
      publicKey: iaca.publicKey,
      privateKey: iaca.privateKey,
      subject: p.name('Synthetic IACA'),
      serial: 3,
      issuerAltName: 'https://issuer.example',
      crlURL: 'https://issuer.example/iaca.crl',
    }),
    nativeCert = (key, serial) =>
      issueMdocCertificate({
        publicKey: key,
        subject: p.name('Synthetic mdoc Entity'),
        serial,
        issuerCertificate: root,
        issuerKey: iaca.privateKey,
        reader: serial === 5,
      }),
    issuerCertificate = nativeCert(issuerKey.publicKey, 4),
    readerCertificate = nativeCert(readerKey.publicKey, 5),
    roots = [new X509Certificate(root)];
  const mirrorJournals = [0, 1, 2].map((i) => journalFactory('mirror-' + i)),
    members = mirrorJournals.map((_, i) => ({
      id: '32473.' + (20 + i),
      operatorID: 'synthetic-mirror-' + i,
      ...c.generate('ml-dsa-87'),
    }));
  const trustDomainID = c.random(),
    issuanceScope = {
      trustDomainID,
      issuerID: '32473.10',
      issuerKeyID: c.keyID(pqCA.publicKey),
      representation: 'MTC',
    },
    timestamp = trustedTime ? exampleTimestamp(journal) : undefined,
    authorityResolver = exampleAuthorityResolver({
      trustDomainID,
      authorities: [
        { certificate: raCertificate, roles: ['REGISTRATION_AUTHORITY'] },
        {
          certificate: authorityCertificate,
          roles: [
            'PERMIT_AUTHORITY',
            'RECEIPT_AUTHORITY',
            'STATUS_AUTHORITY',
            'EXECUTION_BINDING_AUTHORITY',
          ],
        },
        {
          mode: 'RAW_KEY',
          publicKeyDER: c.spki(pqCA.publicKey),
          knownAt: c.now() - 60,
          validFrom: c.now() - 60,
          validUntil: c.now() + 86400,
          roles: ['ISSUER'],
        },
        ...members.map((member) => ({
          mode: 'RAW_KEY',
          publicKeyDER: c.spki(member.publicKey),
          knownAt: c.now() - 60,
          validFrom: c.now() - 60,
          validUntil: c.now() + 86400,
          roles: ['COSIGNER'],
        })),
        ...(timestamp
          ? [{ certificate: timestamp.trust.certificate, roles: ['TIMESTAMP_AUTHORITY'] }]
          : []),
      ],
    }),
    subjectID = c.random(),
    profileID = 'CERTCONCORD-PERSON-SIGN-v1',
    policy = {
      schemaVersion: 1,
      activationMode,
      ...(executionBinding ? { executionBinding: exampleExecutionPolicy() } : {}),
      maxSAL: activationMode === 'HUMAN_WEBAUTHN' ? 2 : 1,
      allowedOrigins: ['https://website.example'],
      allowedProfiles: [profileID],
      acceptedQualifications: ['CERTCONCORD-IAL2'],
      rpID: 'website.example',
      audience: 'certconcord-example-signer',
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
    policyHash = c.H('SignaturePolicy', policy),
    csr = createCSR({
      subject: p.name('Synthetic Document Subject'),
      publicKey: documentKey.publicKey,
      privateKey: documentKey.privateKey,
    });
  const mirrors = members.map(
      (m, i) => new Mirror({ journal: mirrorJournals[i], id: m.id, privateKey: m.privateKey }),
    ),
    mtcTrust = {
      caID: '32473.10',
      caPublicKey: pqCA.publicKey,
      members,
      threshold: 2,
      policyHash,
      rtmHash: c.H('SyntheticRTM', { trustDomainID, policyHash }),
      membershipEpoch: 1,
    };
  let handler;
  const server = createServer((req, res) => handler(req, res));
  await listenLoopback(server);
  const issuerURL = 'http://127.0.0.1:' + server.address().port;
  try {
    const ra = new RegistrationAuthority({
        journal,
        certificate: raCertificate,
        privateKey: raKey.privateKey,
        approve: async (request) => ({
          approved:
            c.equal(request.subjectID, subjectID) &&
            request.profileID === profileID &&
            c.equal(request.policyHash, policyHash),
        }),
      }),
      rar = await ra.authorize({
        issuanceScope,
        csr,
        subjectID,
        profileID,
        policyHash,
        identityEvidenceHash: c.H('SyntheticIdentity', { subjectID }),
      }),
      issuer = new MTCIssuer({
        issuanceScope,
        authorityResolver,
        ...mtcTrust,
        journal,
        raCertificate,
        privateKey: pqCA.privateKey,
        logNumber: 1,
        mirrors,
        allowedProfiles: [profileID],
      }),
      certificate = await issuer.issue({ csr, rar }),
      cert = p.parseCertificate(certificate);
    const bindings = new DeviceBindingRegistry({
        allowUnattested: true,
        journal,
        registrationAuthorityCertificate: raCertificate,
        trustDomainID,
        policyHash,
      }),
      nonce = bindings.challenge(),
      authorization = p.signCMS(
        {
          content: c.D('DeviceRegistrationAuthorization', {
            schemaVersion: 1,
            trustDomainID,
            policyHash,
            holderKeyID: c.keyID(holder.publicKey),
            subjectID,
            documentKeyID: c.keyID(documentKey.publicKey),
            audience: 'certconcord-device-registry',
            issuedAt: c.now(),
            expiresAt: c.now() + 300,
            attestationEvidenceHash: c.H('SyntheticSoftwareHolder', {}),
            keyAssurance: 'KAL1',
            localUVPolicy: 'UNASSESSED',
          }),
          certificate: raCertificate,
        },
        raKey.privateKey,
      ),
      proof = c.sign(
        c.D('DeviceRegistrationProof', {
          schemaVersion: 1,
          authorizationHash: c.sha512(authorization),
          nonce,
          audience: 'certconcord-device-registry',
        }),
        holder.privateKey,
      ),
      binding = bindings.enroll({ authorization, holderPublicKey: holder.publicKey, nonce, proof });
    const clientID = 'https://wallet.example',
      credentialIssuer = new RRACredentialIssuer({
        bindings,
        qualificationAllowed: (b, q) => c.equal(b.subjectID, subjectID) && q === 'CERTCONCORD-IAL2',
        issuer: issuerURL,
        journal,
        privateKey: issuerKey.privateKey,
        certificate: issuerCertificate,
        enforceDPoPNonce: true,
        clients: new Map([
          [
            clientID,
            { publicKey: walletKey.publicKey, redirectURIs: ['https://wallet.example/return'] },
          ],
        ]),
      }),
      verifier = new (presentationTransport === 'annex-c' ? AnnexCVerifier : PresentationVerifier)({
        baseURL: issuerURL + '/website',
        journal,
        privateKey: readerKey.privateKey,
        certificate: readerCertificate,
        trustRoots: roots,
        issuerRegistry: new Map([
          [
            issuerURL,
            {
              publicKey: issuerKey.publicKey,
              certificate: issuerCertificate,
              statusURI: issuerURL + '/status/1',
              fetchStatus: async () => credentialIssuer.status.token(),
            },
          ],
        ]),
      });
    handler = createProtocolHandler({
      issuer: credentialIssuer,
      verifier: presentationTransport === 'openid4vp' ? verifier : undefined,
      approveAuthorization: async () => ({ approved: true, subjectID: c.b64u(subjectID) }),
    });
    const wallet = new OpenIDWallet({
        issuer: issuerURL,
        clientID,
        clientKey: walletKey.privateKey,
        dpopKey: dpop.privateKey,
        holderKey: holder.privateKey,
        issuerCertificate,
        issuerRoots: roots,
        allowLoopback: true,
      }),
      offer = credentialIssuer.offer({
        bindingID: binding.bindingID,
        qualification: 'CERTCONCORD-IAL2',
        preAuthorized: grantType === 'pre-authorized',
        txCode: '162839',
      });
    let stored;
    const encryptionKey = c.generate('ec').privateKey;
    if (grantType === 'pre-authorized')
      stored = await wallet.preAuthorized(offer, { txCode: '162839', encryptionKey });
    else {
      const session = await wallet.startAuthorization(offer, {
          redirectURI: 'https://wallet.example/return',
        }),
        redirect = await fetch(session.authorizationURL, { redirect: 'manual' });
      c.requireThat(redirect.status === 302, 'DEMO_AUTHORIZATION');
      stored = await wallet.finishAuthorization(redirect.headers.get('location'), session, {
        encryptionKey,
      });
    }
    const document = Buffer.from('CertConcord synthetic document.\n'),
      sim = {
        schemaVersion: 1,
        trustDomainID,
        transactionID: c.random(),
        subjectID,
        profileID,
        keyID: c.keyID(documentKey.publicKey),
        certificateID: cert.certificateID,
        certificateRepresentationHash: cert.representationHash,
        container: 'CMS',
        adapterID: 'certconcord-cms-v1',
        documents: [
          {
            documentID: c.random(),
            mediaType: 'text/plain',
            digestAlgorithm: 'SHA-512',
            digest: c.sha512(document),
            scope: 'CMS_CONTENT',
            displayName: 'Synthetic document',
          },
        ],
        purpose: 'Approve the synthetic document',
        origin: 'https://website.example',
        policyHash,
        issuedAt: c.now(),
        expiresAt: c.now() + 120,
        nonce: c.random(),
        displayText: 'Approve the exact synthetic document with the registered document key.',
      },
      context = {
        schemaVersion: 1,
        trustDomainID,
        profileID,
        container: 'CMS',
        adapterID: 'certconcord-cms-v1',
      },
      prepared = p.prepareCMS({
        content: document,
        certificate,
        detached: true,
        context,
        simHash: c.H('SIM', sim),
        policyHash,
      }),
      activation = activationContext({
        trustDomainID,
        tbsKind: 'CMS_SIGNED_ATTRS_DER',
        tbs: prepared.tbs,
        publicKey: documentKey.publicKey,
        simHash: c.H('SIM', sim),
        certificateID: cert.certificateID,
        certificateRepresentationHash: cert.representationHash,
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
      const sessionID = c.b64u(c.random()),
        request = verifier.request({
          sessionID,
          issuerID: issuerURL,
          claims: ['qualification', 'device_binding_id', 'binding_epoch'],
          activationHash: c.H('ActivationContext', activation),
          mode: 'dc_api.jwt',
          origin: sim.origin,
          displayText: sim.displayText,
        });
      if (presentationTransport === 'annex-c') {
        const presentation = await annexCPresent(request.request, {
          origin: sim.origin,
          credential: c.unb64u(stored.credential),
          holderKey: holder.privateKey,
          readerPublicKey: readerKey.publicKey,
          readerCertificate,
          approveTransaction: async (t) =>
            c.equal(t.activationHash, c.H('ActivationContext', activation)) &&
            t.displayText === sim.displayText,
        });
        await verifier.response(request.id, presentation, { sessionID, origin: sim.origin });
      } else {
        const presentation = await walletMdocPresentation(request.signed, {
          credential: stored.credential,
          holderKey: holder.privateKey,
          verifierRoots: roots,
          origin: sim.origin,
          approveTransaction: async (t) =>
            t.activation_hash === c.b64u(c.H('ActivationContext', activation)) &&
            t.display_text === sim.displayText,
        });
        await verifier.response(request.id, presentation.response, {
          sessionID,
          mode: 'dc_api.jwt',
        });
      }
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
        permitCertificate: authorityCertificate,
        permitKey: authorityKey.privateKey,
      });
    } else {
      const approval = exampleAssertion({
        challenge: c.H('ActivationContext', activation),
        origin: sim.origin,
        rpID: policy.rpID,
        keyID: c.keyID(documentKey.publicKey),
        subjectID,
      });
      bindings.active(binding.bindingID);
      permit = authorizeHumanActivation({
        ...approval,
        activation,
        sim,
        policy,
        journal,
        permitCertificate: authorityCertificate,
        permitKey: authorityKey.privateKey,
      });
    }
    const backend = new SoftwareProvider(new Map([['document-key', documentKey]])),
      gatewayOptions = {
        authorityResolver,
        journal,
        permitCertificate: authorityCertificate,
        receiptCertificate: authorityCertificate,
        receiptKey: authorityKey.privateKey,
        audience: policy.audience,
        backend,
        keyRef: 'document-key',
        authorize: async ({ permit: p, keyRef }) => {
          c.requireThat(
            keyRef === 'document-key' &&
              p.proofMode === policy.activationMode &&
              c.equal(p.activation.policyHash, policyHash),
            'SIGNER_POLICY',
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
      result = await gateway.execute({
        permit,
        tbs: prepared.tbs,
        ...(executionBinding ? { sim } : { keyRef: 'document-key' }),
      }),
      cms = prepared.finish(result.signature),
      status = p.signCMS(
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
          certificate: authorityCertificate,
        },
        authorityKey.privateKey,
      ),
      bundle = createSignaturePackage({
        document,
        certificate,
        registrationAuthorization: rar,
        sim,
        policy,
        permit,
        receipt: result.receipt,
        status,
        cms,
        executionEvidence: result.executionEvidence,
        ...(timestamp
          ? {
              documentEvidence: {
                DocumentTimestamp: timestamp.issue,
              },
            }
          : {}),
      }),
      trust = {
        raCertificate,
        authorityResolver,
        issuanceScope,
        mtc: mtcTrust,
        permitCertificate: authorityCertificate,
        receiptCertificate: authorityCertificate,
        statusCertificate: authorityCertificate,
        expectedPolicy: policy,
        trustDomainID,
        ...(timestamp ? { timestamp: timestamp.trust } : {}),
        ...(executionBinding
          ? { executionBindingCertificate: authorityCertificate, executionStatus: () => true }
          : {}),
      },
      verification = verifySignaturePackage(bundle, trust);
    if (onComplete)
      await onComplete({
        bundle,
        trust,
        timestamp,
        signStatus: (statement) =>
          p.signCMS(
            { content: c.D('CertificateStatus', statement), certificate: authorityCertificate },
            authorityKey.privateKey,
          ),
      });
    if (outputDirectory) {
      await mkdir(outputDirectory, { recursive: true });
      await writeFile(outputDirectory + '/document.txt', document);
      await writeFile(outputDirectory + '/signature.p7s', cms);
      await writeFile(outputDirectory + '/evidence.cbor', c.dcbor(bundle));
      await writeFile(
        outputDirectory + '/verification.json',
        JSON.stringify(verification, null, 2) + '\n',
      );
    }
    return {
      verification,
      bundle,
      trust,
      summary: {
        release: '0.3.0-draft.1',
        activationMode,
        flow: [
          'RA approval',
          'MTC issuance with CA and independent mirror journals',
          'device binding',
          'OpenID4VCI with DPoP nonce and encrypted mdoc',
          activationMode === 'HUMAN_WEBAUTHN'
            ? 'WebAuthn document-bound activation'
            : presentationTransport + ' with device-signed activation hash',
          'one-use permit',
          'ML-DSA document signature',
          'independent ECP semantic verification',
        ],
        holderCustody: 'SYNTHETIC_SOFTWARE',
        documentCustody: 'SYNTHETIC_SOFTWARE',
        ...verification,
      },
    };
  } finally {
    await new Promise((r) => server.close(r));
    journal.close();
    mirrorJournals.forEach((j) => j.close());
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const r = await runDemo({
    outputDirectory: '.runtime/demo',
    executionBinding: process.argv.includes('--execution-binding'),
    trustedTime: process.argv.includes('--trusted-time'),
    activationMode: process.argv.includes('--passkey') ? 'HUMAN_WEBAUTHN' : 'HUMAN_MDOC',
    presentationTransport: process.argv.includes('--annex-c') ? 'annex-c' : 'openid4vp',
    grantType: process.argv.includes('--authorization-code')
      ? 'authorization-code'
      : 'pre-authorized',
  });
  console.log(JSON.stringify(r.summary, null, 2));
}

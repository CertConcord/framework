import { H, keyID, generate, random, now, sign } from '../core.mjs';
import { issueCertificate, name } from '../pki.mjs';
import { Journal, activationContext, issuePermit, readControl } from '../state.mjs';
import { exampleExecutionGateway, exampleExecutionPolicy } from '../example-execution.mjs';
import { exampleAuthorityResolver } from '../example-authorities.mjs';

// Construct a complete cryptographic execution without network or upstream service fixtures.
export async function executionFixture() {
  const document = generate(),
    authority = generate('ml-dsa-87'),
    journal = new Journal();
  try {
    const certificate = issueCertificate(
      {
        publicKey: authority.publicKey,
        issuer: name('Synthetic execution control'),
        subject: name('Synthetic execution control'),
        serial: 1,
        profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1',
      },
      authority.privateKey,
    );
    const policy = {
      schemaVersion: 1,
      activationMode: 'HUMAN_WEBAUTHN',
      allowedProfiles: ['CERTCONCORD-PERSON-SIGN-v1'],
      allowedOrigins: ['https://website.example'],
      audience: 'synthetic-execution',
      maxActivationLifetime: 120,
      executionBinding: exampleExecutionPolicy(),
    };
    const issuedAt = now(),
      trustDomainID = random(),
      authorityResolver = exampleAuthorityResolver({
        trustDomainID,
        authorities: [
          {
            certificate,
            roles: ['PERMIT_AUTHORITY', 'RECEIPT_AUTHORITY', 'EXECUTION_BINDING_AUTHORITY'],
          },
        ],
        at: issuedAt,
      }),
      tbs = Buffer.from('Synthetic exact signing input');
    const sim = {
      schemaVersion: 1,
      trustDomainID,
      transactionID: random(),
      subjectID: random(),
      profileID: 'CERTCONCORD-PERSON-SIGN-v1',
      keyID: keyID(document.publicKey),
      certificateID: random(64),
      certificateRepresentationHash: random(64),
      policyHash: H('SignaturePolicy', policy),
      origin: policy.allowedOrigins[0],
      issuedAt,
      expiresAt: issuedAt + 120,
    };
    const activation = activationContext({
      ...sim,
      tbs,
      publicKey: document.publicKey,
      simHash: H('SIM', sim),
      rpID: 'website.example',
      audience: policy.audience,
    });
    const permit = issuePermit(activation, {
      certificate,
      privateKey: authority.privateKey,
      activationEvidenceHash: random(64),
      proofMode: 'HUMAN_WEBAUTHN',
    });
    const gateway = exampleExecutionGateway({
      publicKey: document.publicKey,
      policy,
      trustDomainID,
      journal,
      authorityResolver,
      permitCertificate: certificate,
      receiptCertificate: certificate,
      receiptKey: authority.privateKey,
      backend: {
        capabilities: async () => ({ publicKey: document.publicKey, input: 'MESSAGE' }),
        sign: async ({ tbs }) => sign(tbs, document.privateKey),
      },
      keyRef: 'synthetic-key',
      authorize: async () => true,
    });
    const result = await gateway.execute({ permit, tbs, sim });
    const at = readControl(result.receipt, 'ExecutionReceipt', certificate).executedAt;
    return {
      input: {
        policy,
        sim,
        permit,
        tbs,
        signature: result.signature,
        publicKey: document.publicKey,
        receipt: result.receipt,
        evidence: result.executionEvidence,
      },
      trust: {
        authorityResolver,
        bindingCertificate: certificate,
        permitCertificate: certificate,
        receiptCertificate: certificate,
        trustDomainID,
        at,
        knowledgeTime: at,
        status: () => true,
      },
    };
  } finally {
    journal.close();
  }
}

import { createPrivateKey, createPublicKey } from 'node:crypto';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { Journal, activationContext, readControl } from './state.mjs';
import { createCSR, verifyCSR } from './enrollment.mjs';
import { exampleAuthorityResolver } from './example-authorities.mjs';
import { EXECUTION_BINDING_PROFILE, issueExecutionBinding } from './execution-binding.mjs';
import { evidenceLeaf } from './evidence-plan.mjs';

export const ORGANIZATION_PROFILE = 'certconcord-organization-delegation-v1';
export const ORGANIZATION_PLAN = 'certconcord-ecp-cms-organization-delegation-v1';
export const SEAL_PROFILE = 'CERTCONCORD-ORG-SEAL-v1';

export function copy(value) {
  if (Buffer.isBuffer(value)) return Buffer.from(value);
  if (Array.isArray(value)) return value.map(copy);
  if (
    value &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)
  )
    return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, copy(entry)]));
  return value;
}

export function certificateTuple(certificate) {
  const parsed = p.parseCertificate(certificate);
  return {
    keyID: c.keyID(parsed.publicKey),
    certificateID: parsed.certificateID,
    certificateRepresentationHash: parsed.representationHash,
  };
}

export const canonicalSet = (values) =>
  values.map(copy).sort((left, right) => Buffer.compare(c.dcbor(left), c.dcbor(right)));

export function signOrganizationControl(label, body, authority) {
  return p.signCMS(
    { content: c.D(label, body), certificate: authority.certificate },
    authority.privateKey,
  );
}

export function rawApproval(request, registration, key, changes = {}) {
  const personID = changes.personID ?? registration.personID;
  const challenge =
    changes.challenge ??
    c.H('OrganizationApprovalChallenge', {
      schemaVersion: 1,
      profile: ORGANIZATION_PROFILE,
      requestHash: c.H('OrganizationApprovalRequest', request),
      personID,
      credentialIDHash: c.sha512(registration.credentialID),
    });
  const clientDataJSON =
    changes.clientDataJSON ??
    Buffer.from(
      JSON.stringify({
        type: 'webauthn.get',
        challenge: c.b64u(challenge),
        origin: changes.origin ?? request.roster.find((r) => c.equal(r.personID, personID)).origin,
        crossOrigin: false,
      }),
    );
  const authenticatorData = changes.authenticatorData ?? Buffer.alloc(37);
  if (!changes.authenticatorData) {
    c.sha256(Buffer.from(changes.rpID ?? registration.rpID)).copy(authenticatorData);
    authenticatorData[32] = changes.flags ?? (registration.backupEligible ? 13 : 5);
    authenticatorData.writeUInt32BE(changes.counter ?? registration.counter + 1, 33);
  }
  return {
    credentialID: Buffer.from(changes.credentialID ?? registration.credentialID),
    clientDataJSON: Buffer.from(clientDataJSON),
    authenticatorData: Buffer.from(authenticatorData),
    signature:
      changes.signature ??
      c.sign(Buffer.concat([authenticatorData, c.sha256(clientDataJSON)]), key.privateKey),
  };
}

export const emptyOrganizationState = () => ({
  knowledgeTime: null,
  targets: [],
  heads: [],
  terminalObservations: [],
  keyIncidents: [],
  executions: [],
});

const numberedID = (number) => {
  const result = Buffer.alloc(32);
  result.writeUInt32BE(number, 28);
  return result;
};

function material({ at, pathLength, people }) {
  const trustDomainID = c.random(),
    organizationID = c.random(),
    operatorID = c.random(),
    operationID = c.random();
  const keys = {};
  for (const name of [
    'issuer',
    'ra',
    'certificateStatus',
    'root',
    'terminal',
    'registrar',
    'status',
    'permit',
    'receipt',
    'binding',
    'seal',
    ...Array.from({ length: pathLength - 1 }, (_, i) => `delegate${i}`),
  ]) {
    keys[name] = c.generate(name === 'issuer' ? 'ml-dsa-87' : 'ml-dsa-65');
  }
  const issuerName = p.name('Organization fixture issuer');
  let serial = 1;
  for (const [name, key] of Object.entries(keys)) {
    if (name === 'seal') continue;
    key.certificate = p.issueCertificate(
      {
        publicKey: key.publicKey,
        issuer: issuerName,
        subject: name === 'issuer' ? issuerName : p.name(`Organization fixture ${name}`),
        serial: serial++,
        profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1',
        notBefore: at - 60,
        notAfter: at + 3600,
      },
      keys.issuer.privateKey,
    );
  }
  const identityNamespace = 'fixture-personnel-v1',
    issuerID = 'fixture-organization',
    policy = {
      schemaVersion: 1,
      activationMode: 'WORKLOAD',
      allowedProfiles: [SEAL_PROFILE],
      allowedOrigins: ['https://organization.example'],
      rpID: 'organization.example',
      audience: 'organization-seal',
      maxActivationLifetime: 120,
      executionBinding: {
        profile: EXECUTION_BINDING_PROFILE,
        providerID: 'organization-fixture-backend',
        maxLeaseSeconds: 300,
      },
      organizationDelegation: {
        profile: ORGANIZATION_PROFILE,
        mode: 'CURRENT_STATE_ONLY',
        identityNamespace,
        minimumApprovers: people,
      },
    };
  const issuanceScope = {
      trustDomainID,
      issuerID: 'fixture-certificate-issuer',
      issuerKeyID: c.keyID(keys.issuer.publicKey),
      representation: 'X509',
    },
    csr = createCSR({ ...keys.seal, subject: p.name('Organization fixture seal') }),
    rarBody = {
      schemaVersion: 1,
      requestID: c.random(),
      subjectID: organizationID,
      profileID: SEAL_PROFILE,
      policyHash: c.H('SignaturePolicy', policy),
      identityEvidenceHash: c.H('SyntheticOrganizationRegistration', { organizationID }),
      issuanceScope,
      spkiHash: c.sha512(c.spki(keys.seal.publicKey)),
      csrHash: c.sha512(csr),
      possessionMode: verifyCSR(csr).possessionMode,
      issuedAt: at - 10,
      expiresAt: at + 110,
    },
    registrationAuthorization = signOrganizationControl(
      'RegistrationAuthorization',
      rarBody,
      keys.ra,
    );
  keys.seal.certificate = p.issueCertificate(
    {
      publicKey: keys.seal.publicKey,
      issuer: issuerName,
      subject: p.name('Organization fixture seal'),
      serial: serial++,
      profileID: SEAL_PROFILE,
      notBefore: at - 10,
      notAfter: at + 3600,
      extraExtensions: [
        p.extension(
          p.RRA['id-pe-certconcordAuthorizationID'],
          c.octet(c.H('RegistrationAuthorization', rarBody)),
        ),
      ],
    },
    keys.issuer.privateKey,
  );
  const persons = Array.from({ length: people }, (_, i) => {
    const name = `person${i}`,
      key = c.generate('ec');
    keys[name] = key;
    const body = {
      schemaVersion: 1,
      profile: ORGANIZATION_PROFILE,
      trustDomainID,
      organizationID,
      identityNamespace,
      registrationID: numberedID(100 + i),
      personID: numberedID(1 + i),
      credentialID: c.random(),
      publicKeyDER: c.spki(key.publicKey),
      keyID: c.keyID(key.publicKey),
      purpose: 'ORGANIZATION_OPERATION_APPROVAL',
      rpID: policy.rpID,
      origins: copy(policy.allowedOrigins),
      backupEligible: false,
      counter: 0,
      issuedAt: at - 10,
      knownAt: at - 10,
      validFrom: at - 10,
      validUntil: at + 1800,
    };
    return { keyName: name, body };
  });
  const entitlement = {
    purpose: 'ORGANIZATION_SEAL',
    container: 'CMS',
    adapterID: 'certconcord-cms-v1',
    operatorType: 'WORKLOAD',
    allowedOperatorIDs: [operatorID],
    sealKeys: [certificateTuple(keys.seal.certificate)],
    policyHashes: [c.H('SignaturePolicy', policy)],
    audiences: [policy.audience],
    origins: copy(policy.allowedOrigins),
    rpIDs: [policy.rpID],
    eligiblePersonIDs: persons.map(({ body }) => body.personID),
    minimumApprovers: people,
  };
  const grants = Array.from({ length: pathLength }, (_, i) => ({
    issuerName: i === 0 ? 'root' : `delegate${i - 1}`,
    delegateName: i === pathLength - 1 ? 'terminal' : `delegate${i}`,
    body: {
      schemaVersion: 1,
      profile: ORGANIZATION_PROFILE,
      trustDomainID,
      organizationID,
      identityNamespace,
      grantID: numberedID(200 + i),
      parentGrantHash: null,
      issuerKeyID: c.keyID(keys[i === 0 ? 'root' : `delegate${i - 1}`].publicKey),
      delegateAuthority: certificateTuple(
        keys[i === pathLength - 1 ? 'terminal' : `delegate${i}`].certificate,
      ),
      entitlement: copy(entitlement),
      remainingDelegations: pathLength - 1 - i,
      issuedAt: at - 10,
      knownAt: at - 10,
      validFrom: at - 10,
      validUntil: at + 1800,
    },
  }));
  const document = Buffer.from('Original organizational decision.\r\n\x00Exact signed bytes.\n');
  const sim = {
    schemaVersion: 1,
    trustDomainID,
    transactionID: c.random(),
    subjectID: organizationID,
    organizationID,
    profileID: SEAL_PROFILE,
    ...certificateTuple(keys.seal.certificate),
    container: 'CMS',
    adapterID: 'certconcord-cms-v1',
    organizationAuthorizationID: c.random(),
    documents: [
      {
        documentID: c.random(),
        mediaType: 'application/octet-stream',
        digestAlgorithm: 'SHA-512',
        digest: c.sha512(document),
        scope: 'CMS_CONTENT',
        displayName: 'Original organizational decision',
      },
    ],
    purpose: 'ORGANIZATION_SEAL',
    origin: policy.allowedOrigins[0],
    policyHash: c.H('SignaturePolicy', policy),
    issuedAt: at,
    expiresAt: at + 120,
    nonce: c.random(),
    displayText: 'Apply the organizational seal to the specified decision.',
  };
  return {
    at,
    keys,
    persons,
    grants,
    document,
    sim,
    policy,
    trustDomainID,
    organizationID,
    operatorID,
    operationID,
    issuerID,
    identityNamespace,
    issuanceScope,
    registrationAuthorization,
  };
}

export function createOrganizationFixture({
  at = c.now(),
  pathLength = 2,
  people = 2,
  path,
  snapshot,
} = {}) {
  let m;
  if (snapshot) {
    m = copy(c.decodeCBOR(snapshot, { maxBytes: 8 * 1024 * 1024 }));
    m.keys = Object.fromEntries(
      Object.entries(m.keys).map(([name, value]) => {
        const privateKey = createPrivateKey({
          key: value.privateKey,
          type: 'pkcs8',
          format: 'der',
        });
        return [name, { ...value, privateKey, publicKey: createPublicKey(privateKey) }];
      }),
    );
  } else m = material({ at, pathLength, people });
  const journal = new Journal(path),
    { keys } = m,
    queries = [],
    calls = { capabilities: 0, sign: 0 },
    hooks = {};
  const scope = (purpose) => ({
      trustDomainID: m.trustDomainID,
      profileID: ORGANIZATION_PROFILE,
      issuerID: m.issuerID,
      representation: 'X509',
      purpose,
    }),
    credentialScope = {
      trustDomainID: m.trustDomainID,
      profileID: SEAL_PROFILE,
      issuerID: m.issuanceScope.issuerID,
      representation: 'X509',
    };
  const mappings = [
    ['root', 'ORGANIZATION_AUTHORITY', 'ORGANIZATION_DELEGATION_ROOT'],
    ...m.grants
      .slice(1)
      .map((grant) => [
        grant.issuerName,
        'ORGANIZATION_AUTHORITY',
        'ORGANIZATION_DELEGATION_ISSUE',
      ]),
    ['terminal', 'ORGANIZATION_AUTHORITY', 'ORGANIZATION_FINAL_AUTHORIZATION'],
    ['registrar', 'REGISTRATION_AUTHORITY', 'ORGANIZATION_APPROVER_REGISTRATION'],
    ['status', 'STATUS_AUTHORITY', 'ORGANIZATION_DELEGATION_STATUS'],
    ['permit', 'PERMIT_AUTHORITY', 'ORGANIZATION_DELEGATION_PERMIT'],
    ['receipt', 'RECEIPT_AUTHORITY', 'ORGANIZATION_DELEGATION_RECEIPT'],
    ['binding', 'EXECUTION_BINDING_AUTHORITY', 'ORGANIZATION_DELEGATION_EXECUTION_BINDING'],
  ];
  const authorities = [
    ...mappings.map(([name, role, purpose]) => ({
      certificate: keys[name].certificate,
      roles: [role],
      scopes: [scope(purpose)],
    })),
    {
      certificate: keys.seal.certificate,
      roles: ['DOCUMENT_SEAL'],
      scopes: [scope('ORGANIZATION_SEAL')],
    },
    ...[
      ['issuer', 'ISSUER'],
      ['ra', 'REGISTRATION_AUTHORITY'],
      ['certificateStatus', 'STATUS_AUTHORITY'],
    ].map(([name, role]) => ({
      certificate: keys[name].certificate,
      roles: [role],
      scopes: [credentialScope],
    })),
  ];
  const baseResolver = exampleAuthorityResolver({
    trustDomainID: m.trustDomainID,
    authorities,
    at: m.at - 20,
    nextUpdate: m.at + 3600,
  });
  const authorityResolver = (query) => {
    queries.push(copy(query));
    return hooks.authority?.(query) ?? baseResolver(query);
  };
  const context = {
    knowledgeTime: m.at,
    trustDomainID: m.trustDomainID,
    organizationID: m.organizationID,
    issuerID: m.issuerID,
    identityNamespace: m.identityNamespace,
    operator: {
      type: 'WORKLOAD',
      id: m.operatorID,
      active: true,
      knownAt: m.at - 10,
      validFrom: m.at - 10,
      validUntil: m.at + 1800,
    },
    policy: m.policy,
    authorityResolver,
    controlTrust: mappings.map(([name, , purpose]) => ({
      certificate: keys[name].certificate,
      organizationID: m.organizationID,
      identityNamespace: m.identityNamespace,
      issuerID: m.issuerID,
      purpose,
      objectTypes:
        purpose === 'ORGANIZATION_DELEGATION_STATUS'
          ? ['GRANT', 'APPROVER_REGISTRATION', 'FINAL_AUTHORIZATION']
          : [],
    })),
    credentialTrust: {
      certificate: keys.seal.certificate,
      registrationAuthorization: m.registrationAuthorization,
      issuerCertificate: keys.issuer.certificate,
      raCertificate: keys.ra.certificate,
      statusCertificate: keys.certificateStatus.certificate,
      issuanceScope: m.issuanceScope,
      currentCertificateStatus:
        m.wire?.currentCertificateStatus ??
        signOrganizationControl(
          'CertificateStatus',
          {
            schemaVersion: 1,
            trustDomainID: m.trustDomainID,
            certificateID: m.sim.certificateID,
            scope: 'CERTIFICATE',
            status: 'GOOD',
            publishedAt: m.at - 1,
            nextUpdate: m.at + 299,
          },
          keys.certificateStatus,
        ),
    },
    statusMaterial: [],
    algorithmDeadlines: Object.fromEntries(
      ['ml-dsa-65', 'ml-dsa-87', 'ec'].map((name) => [c.ALG[name].oid, m.at + 10000]),
    ),
    hashDeadlines: {
      '2.16.840.1.101.3.4.2.1': m.at + 10000,
      '2.16.840.1.101.3.4.2.3': m.at + 10000,
    },
    keyDeadlines: Object.fromEntries(
      Object.values(keys).map((key) => [c.keyID(key.publicKey).toString('hex'), m.at + 10000]),
    ),
    executionCurrent: null,
  };
  const readContext = () => hooks.context?.() ?? copy(context);
  const backend = {
    id: m.policy.executionBinding.providerID,
    capabilities: async (input) => {
      calls.capabilities++;
      await hooks.capabilities?.(input);
      return { publicKey: keys.seal.publicKey, input: 'MESSAGE' };
    },
    sign: async (input) => {
      calls.sign++;
      await hooks.beforeSign?.(input);
      const signature = c.sign(input.tbs, keys.seal.privateKey);
      await hooks.afterSign?.({ ...input, signature });
      return signature;
    },
  };
  const bindingBody = {
      schemaVersion: 1,
      profile: EXECUTION_BINDING_PROFILE,
      trustDomainID: m.trustDomainID,
      providerID: m.policy.executionBinding.providerID,
      epoch: 1,
      status: 'ACTIVE',
      keyID: m.sim.keyID,
      permitKeyID: c.keyID(keys.permit.publicKey),
      receiptKeyID: c.keyID(keys.receipt.publicKey),
      policyHash: m.sim.policyHash,
      audience: m.policy.audience,
      enforcement: 'BROKER_ENFORCED',
      issuedAt: m.at,
      expiresAt: m.at + 300,
    },
    binding = m.wire?.binding ?? issueExecutionBinding(bindingBody, keys.binding);
  context.executionCurrent = { binding, observedAt: m.at };
  const prepared = p.prepareCMS({
    content: m.document,
    certificate: keys.seal.certificate,
    detached: true,
    context: {
      schemaVersion: 1,
      trustDomainID: m.trustDomainID,
      profileID: SEAL_PROFILE,
      container: 'CMS',
      adapterID: 'certconcord-cms-v1',
    },
    simHash: c.H('SIM', m.sim),
    policyHash: m.sim.policyHash,
  });
  const activation =
    m.wire?.activation ??
    activationContext({
      trustDomainID: m.trustDomainID,
      tbsKind: 'CMS_SIGNED_ATTRS_DER',
      tbs: prepared.tbs,
      publicKey: keys.seal.publicKey,
      simHash: c.H('SIM', m.sim),
      ...certificateTuple(keys.seal.certificate),
      transactionID: m.sim.transactionID,
      operationID: m.operationID,
      policyHash: m.sim.policyHash,
      origin: m.sim.origin,
      rpID: m.policy.rpID,
      audience: m.policy.audience,
      issuedAt: m.at,
      expiresAt: m.sim.expiresAt,
    });
  const grants = [],
    registrations = [];
  function signPath() {
    grants.length = 0;
    for (const [i, grant] of m.grants.entries()) {
      grant.body.parentGrantHash = i ? c.sha512(grants[i - 1].cms) : null;
      const authority = keys[grant.issuerName];
      grants.push({
        cms: signOrganizationControl('OrganizationDelegationGrant', grant.body, authority),
        issuerCertificate: authority.certificate,
        delegateCertificate: keys[grant.delegateName].certificate,
      });
    }
  }
  function signRegistrations() {
    registrations.length = 0;
    for (const person of m.persons) {
      registrations.push({
        cms: signOrganizationControl(
          'OrganizationApproverRegistration',
          person.body,
          keys.registrar,
        ),
        issuerCertificate: keys.registrar.certificate,
      });
    }
  }
  function status(objectType, target, changes = {}) {
    const label = {
      GRANT: 'OrganizationDelegationGrant',
      APPROVER_REGISTRATION: 'OrganizationApproverRegistration',
      FINAL_AUTHORIZATION: 'OrganizationAuthorization',
    }[objectType];
    const body = readControl(target.cms, label, target.issuerCertificate);
    const signedBody = {
      schemaVersion: 1,
      profile: ORGANIZATION_PROFILE,
      trustDomainID: m.trustDomainID,
      organizationID: m.organizationID,
      scope: 'ORGANIZATION_DELEGATION',
      objectType,
      objectID: body.grantID ?? body.registrationID ?? body.authorizationID,
      objectHash: c.sha512(target.cms),
      subjectKeyID:
        objectType === 'GRANT'
          ? body.delegateAuthority.keyID
          : objectType === 'APPROVER_REGISTRATION'
            ? body.keyID
            : c.keyID(p.parseCertificate(target.issuerCertificate).publicKey),
      epoch: 1,
      status: 'GOOD',
      publishedAt: m.at - 1,
      nextUpdate: m.at + 299,
      ...changes,
    };
    return {
      cms: signOrganizationControl('OrganizationDelegationStatus', signedBody, keys.status),
      issuerCertificate: keys.status.certificate,
    };
  }
  function refreshStatuses() {
    context.statusMaterial = [
      ...grants.map((grant) => status('GRANT', grant)),
      ...registrations.map((registration) => status('APPROVER_REGISTRATION', registration)),
    ];
  }
  if (m.wire) {
    grants.push(...copy(m.wire.grants));
    registrations.push(...copy(m.wire.registrations));
    context.statusMaterial = copy(m.wire.statusMaterial);
    context.knowledgeTime = m.wire.knowledgeTime;
    context.executionCurrent = copy(m.wire.executionCurrent);
    context.operator = copy(m.wire.operator);
  } else {
    signPath();
    signRegistrations();
    refreshStatuses();
  }
  const pathBytes = () => c.dcbor({ schemaVersion: 1, profile: ORGANIZATION_PROFILE, grants });
  const statusBytes = (statements = context.statusMaterial) => {
    const ordered = statements.map((statement) => ({
      statement,
      body: readControl(statement.cms, 'OrganizationDelegationStatus', statement.issuerCertificate),
    }));
    ordered.sort(
      (a, b) =>
        (a.body.objectType < b.body.objectType
          ? -1
          : a.body.objectType > b.body.objectType
            ? 1
            : 0) ||
        Buffer.compare(a.body.objectID, b.body.objectID) ||
        a.body.epoch - b.body.epoch ||
        Buffer.compare(
          c.H('OrganizationDelegationStatus', a.body),
          c.H('OrganizationDelegationStatus', b.body),
        ),
    );
    return c.dcbor({
      schemaVersion: 1,
      profile: ORGANIZATION_PROFILE,
      statements: ordered.map(({ statement }) => statement),
    });
  };
  const applicationOptions = {
    journal,
    readContext,
    authorization: { certificate: keys.terminal.certificate, privateKey: keys.terminal.privateKey },
    permit: { certificate: keys.permit.certificate, privateKey: keys.permit.privateKey },
    status: { certificate: keys.status.certificate, privateKey: keys.status.privateKey },
    execution: {
      binding,
      bindingCertificate: keys.binding.certificate,
      receiptCertificate: keys.receipt.certificate,
      receiptKey: keys.receipt.privateKey,
      backend,
      keyRef: 'organization-seal',
    },
  };
  const rosterNonces = m.wire?.rosterNonces ?? m.persons.map(() => c.random());
  return {
    ...m,
    journal,
    context,
    readContext,
    authorityResolver,
    authorities,
    scope,
    credentialScope,
    queries,
    calls,
    hooks,
    backend,
    binding,
    bindingBody,
    prepared,
    activation,
    grants,
    grantRecords: m.grants,
    registrations,
    signPath,
    signRegistrations,
    status,
    refreshStatuses,
    pathBytes,
    statusBytes,
    applicationOptions,
    advance(seconds) {
      context.knowledgeTime += seconds;
      context.executionCurrent.observedAt = context.knowledgeTime;
    },
    prepareInput() {
      return copy({
        operationID: m.operationID,
        document: m.document,
        sim: m.sim,
        delegationPath: pathBytes(),
        approverRegistrations: registrations,
      });
    },
    pureInput() {
      return {
        context: readContext(),
        state: emptyOrganizationState(),
        sim: copy(m.sim),
        activation: copy(activation),
        tbs: Buffer.from(prepared.tbs),
        delegationPath: pathBytes(),
        approverRegistrations: copy(registrations),
        rosterNonces: copy(rosterNonces),
      };
    },
    assertion(request, index = 0, changes = {}) {
      const person = m.persons[index];
      return rawApproval(request, person.body, keys[person.keyName], changes);
    },
    approvalSet(request, assertions = m.persons.map((_, i) => this.assertion(request, i))) {
      return c.dcbor({
        schemaVersion: 1,
        profile: ORGANIZATION_PROFILE,
        request,
        approvals: assertions.map((assertion, i) => ({
          personID: m.persons[i].body.personID,
          registrationCMS: registrations[i].cms,
          registrationIssuerCertificate: registrations[i].issuerCertificate,
          assertion,
        })),
      });
    },
    finalControls(request, approvalSet) {
      const issuedAt = context.knowledgeTime,
        expiresAt = Math.min(issuedAt + 30, request.expiresAt, activation.expiresAt);
      const body = {
        schemaVersion: 2,
        profile: ORGANIZATION_PROFILE,
        authorizationID: m.sim.organizationAuthorizationID,
        trustDomainID: m.trustDomainID,
        organizationID: m.organizationID,
        identityNamespace: m.identityNamespace,
        actorID: m.operatorID,
        actorType: 'WORKLOAD',
        ...certificateTuple(keys.seal.certificate),
        purpose: 'ORGANIZATION_SEAL',
        activationHash: c.H('ActivationContext', activation),
        policyHash: m.sim.policyHash,
        requestHash: c.H('OrganizationApprovalRequest', request),
        approvalPolicyHash: request.approvalPolicyHash,
        delegationPathLeafID: evidenceLeaf('OrganizationDelegationPath', pathBytes()).id,
        approvalSetLeafID: evidenceLeaf('OrganizationApprovalSet', approvalSet).id,
        issuedAt,
        expiresAt,
      };
      const authorization = {
        cms: signOrganizationControl('OrganizationAuthorization', body, keys.terminal),
        issuerCertificate: keys.terminal.certificate,
      };
      const permit = {
        cms: signOrganizationControl(
          'OperationPermit',
          {
            schemaVersion: 1,
            activation,
            activationEvidenceHash: c.sha512(authorization.cms),
            proofMode: 'WORKLOAD',
            issuedAt,
            expiresAt,
          },
          keys.permit,
        ),
        issuerCertificate: keys.permit.certificate,
      };
      const authorizationStatus = status('FINAL_AUTHORIZATION', authorization, {
        publishedAt: issuedAt,
        nextUpdate: issuedAt + 300,
      });
      return { body, authorization, permit, authorizationStatus };
    },
    snapshot() {
      return c.dcbor({
        ...m,
        wire: {
          grants,
          registrations,
          binding,
          activation,
          rosterNonces,
          currentCertificateStatus: context.credentialTrust.currentCertificateStatus,
          statusMaterial: context.statusMaterial,
          knowledgeTime: context.knowledgeTime,
          executionCurrent: context.executionCurrent,
          operator: context.operator,
        },
        keys: Object.fromEntries(
          Object.entries(keys).map(([name, key]) => [
            name,
            {
              privateKey: key.privateKey.export({ type: 'pkcs8', format: 'der' }),
              ...(key.certificate ? { certificate: key.certificate } : {}),
            },
          ]),
        ),
      });
    },
    close() {
      journal.close();
    },
  };
}

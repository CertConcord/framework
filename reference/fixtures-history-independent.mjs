import assert from 'node:assert/strict';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { Journal, readControl } from './state.mjs';
import { OrganizationDelegationApplication } from './organization-delegation.mjs';
import { createOrganizationFixture, copy, signOrganizationControl } from './organization-delegation-fixtures.mjs';
import { createEvidencePackage, evidenceLeaf } from './evidence-plan.mjs';
import { TimestampAuthority, timestampRequest, tokenFromResponse, verifyTimestampToken } from './timestamp.mjs';
import { createERS, renewERS } from './archive.mjs';
import { createRetainedAuthorityResolver, manifestPublicationImprint } from './retained-authorities.mjs';

export const HISTORY_FIXTURE_TIME = 1_800_000_000;

/** Synthetic original organization workflow and independently signed retained authority history. */
export async function createIndependentOrganizationHistoryFixture({
  at = HISTORY_FIXTURE_TIME,
  proofDelay = 1,
  knowledgeDelay = 7200,
  firstAccuracyMillis = 0,
} = {}) {
  const source = createOrganizationFixture({ at });
  const archiveJournal = new Journal();
  let clock = at - 30;
  const root = c.generate('ml-dsa-87'), successorRoot = c.generate('ml-dsa-87');
  const K = at + knowledgeDelay, P = at + proofDelay + firstAccuracyMillis / 1000;
  const end = Math.max(K + 2000, at + 10000);
  const app = new OrganizationDelegationApplication(source.applicationOptions);
  const prepared = app.prepare(source.prepareInput());
  assert.equal(prepared.overall, 'VALID', JSON.stringify(prepared));
  for (let i = 0; i < source.persons.length; i++) {
    const approved = app.approve({ operationID: source.operationID,
      personID: source.persons[i].body.personID, ...source.assertion(prepared.request, i, { counter: 1 }) });
    assert.equal(approved.overall, 'VALID', JSON.stringify(approved));
  }
  assert.equal(app.authorize({ operationID: source.operationID }).overall, 'VALID');
  const completed = await app.execute({ operationID: source.operationID });
  assert.equal(completed.overall, 'VALID', JSON.stringify(completed));
  assert.equal(source.calls.sign, 1);
  const originalBytes = Buffer.from(completed.bundle), bundle = c.decodeCBOR(originalBytes);
  const leaves = Object.fromEntries(bundle.objects.map((leaf) => [leaf.type, leaf.payload]));

  let certificateSerial = 800;
  function authority(name, notBefore = at - 60, notAfter = end) {
    const key = c.generate('ml-dsa-87');
    const certificate = p.issueCertificate({ publicKey: key.publicKey, serial: certificateSerial++,
      issuer: p.name('Independent historical governance'), subject: p.name(name),
      profileID: name.includes('TSA') ? 'CERTCONCORD-TSA-v1' : 'CERTCONCORD-EVIDENCE-SIGN-v1',
      notBefore, notAfter }, root.privateKey);
    return { ...key, certificate };
  }
  function tsa(name, notAfter) {
    const identity = authority(name, at - 60, notAfter);
    const policy = '1.3.6.1.4.1.32473.77.3';
    const service = new TimestampAuthority({ certificate: identity.certificate, privateKey: identity.privateKey,
      journal: archiveJournal, policy, clock: () => clock, accuracySeconds: 0 });
    return { ...identity, policy, issuerKey: root.publicKey, validUntil: notAfter,
      issue(imprint, hashOID = p.OID.sha512, milliseconds = 0) {
        const request = timestampRequest(imprint, { policy, hashOID }).der;
        let token = tokenFromResponse(service.issue(request));
        if (milliseconds) {
          assert(Number.isInteger(milliseconds) && milliseconds > 0 && milliseconds < 1000);
          const body = c.parseDER(p.verifyCMS(token, { expectedContentType: p.OID.tstInfo }).content);
          const accuracy = c.seq(c.der(0x80, c.parseDER(c.integer(milliseconds)).value));
          const info = c.seq(...body.children.map((child, index) => index === 5 ? accuracy : child.raw));
          token = p.signCMS({ content: info, contentType: p.OID.tstInfo, certificate: identity.certificate }, identity.privateKey);
        }
        return token;
      } };
  }
  const publicationTSA = tsa('Independent publication TSA', end);
  const initialTSA = tsa('Independent initial TSA', at + 80);
  const renewalTSA = tsa('Independent renewal TSA', end);
  const statusSuccessor = authority('Independent organization status successor', at + 60, end);
  const certificateStatusSuccessor = authority('Independent credential status successor', at + 60, end);
  const rootPolicy = (key) => ({ roots: [{ publicKeyDER: c.spki(key.publicKey),
    validFrom: at - 60, validUntil: end }], threshold: 1 });
  const initialAuthorities = [...source.authorities.map((record) => ({
    mode: 'CERTIFICATE', certificate: record.certificate, roles: record.roles, scopes: record.scopes,
    knownAt: at - 30, validFrom: at - 30, validUntil: at + 40,
  })), ...[initialTSA, renewalTSA].map((identity) => ({ mode: 'CERTIFICATE',
    certificate: identity.certificate, roles: ['TIMESTAMP_AUTHORITY'],
    scopes: [{ trustDomainID: source.trustDomainID }],
    knownAt: at - 30, validFrom: at - 30, validUntil: end,
  }))].map((record) => ({ ...record, status: {
    authorityID: c.keyID(p.parseCertificate(record.certificate).publicKey),
    trustDomainID: source.trustDomainID, scope: 'AUTHORITY', status: 'GOOD',
    publishedAt: at - 30, nextUpdate: at + 200,
  } }));
  const refreshAuthorities = [
    { identity: statusSuccessor, scope: source.scope('ORGANIZATION_DELEGATION_STATUS') },
    { identity: certificateStatusSuccessor, scope: source.credentialScope },
  ].map(({ identity, scope }) => ({ mode: 'CERTIFICATE', certificate: identity.certificate,
    roles: ['STATUS_AUTHORITY'], scopes: [scope], knownAt: at + 60, validFrom: at + 60, validUntil: end,
    status: { authorityID: c.keyID(identity.publicKey), trustDomainID: source.trustDomainID,
      scope: 'AUTHORITY', status: 'GOOD', publishedAt: K - 1, nextUpdate: K + 300 } }));
  function manifest(records, published, previous = null, { replacement = false, signers } = {}) {
    const body = { schemaVersion: 2, trustDomainID: source.trustDomainID,
      serial: previous ? previous.manifest.serial + 1 : 0,
      previousHash: previous ? c.H('RootTrustManifest', previous.manifest) : null,
      issuedAt: published, notBefore: published, notAfter: end,
      coverageUntil: published < at ? at + 200 : K + 300,
      authorities: records, ...(replacement ? { successor: rootPolicy(successorRoot) } : {}) };
    const signatures = (signers ?? [root, ...(replacement ? [successorRoot] : [])]).map((key) => ({
      keyID: c.keyID(key.publicKey), signature: c.sign(c.D('RootTrustManifest', body), key.privateKey),
    }));
    clock = published;
    return { manifest: body, signatures, publicationProof: publicationTSA.issue(manifestPublicationImprint({ manifest: body, signatures })) };
  }
  const firstManifest = manifest(initialAuthorities, at - 30);
  const currentAuthorities = [...initialAuthorities.map((record) => ({ ...record,
    status: { ...record.status, publishedAt: K - 1, nextUpdate: K + 300 } })), ...refreshAuthorities];
  const latestManifest = manifest(currentAuthorities, K - 1, firstManifest, { replacement: true });
  const history = [firstManifest, latestManifest];
  const queries = [];
  function resolver(selected = history, validationTime = K) {
    const underlying = createRetainedAuthorityResolver({ trustDomainID: source.trustDomainID,
      governance: rootPolicy(root), history: selected, algorithmDeadlines: { 'ml-dsa-65': end, 'ml-dsa-87': end, ec: end },
      validationTime, verifyPublication: ({ imprint, proof, at }) => ({ overall: 'VALID',
        ...verifyTimestampToken(proof, { ...publicationTSA, imprint, at, maxFutureSkew: 0 }) }),
    });
    return (query) => { queries.push(copy(query)); return underlying(query); };
  }
  const authorityResolver = resolver();
  const originalStatusMembers = c.decodeCBOR(leaves.OrganizationDelegationStatus).statements;
  function organizationStatus(member, changes = {}, signer = statusSuccessor) {
    const body = readControl(member.cms, 'OrganizationDelegationStatus', member.issuerCertificate);
    return { cms: signOrganizationControl('OrganizationDelegationStatus', {
      ...body, epoch: body.epoch + 1, publishedAt: K - 1, nextUpdate: K + 299, ...changes,
    }, signer), issuerCertificate: signer.certificate };
  }
  function certificateStatus(changes = {}, signer = certificateStatusSuccessor) {
    const body = readControl(leaves.CertificateStatus, 'CertificateStatus', source.keys.certificateStatus.certificate);
    return { cms: signOrganizationControl('CertificateStatus', {
      ...body, publishedAt: K - 1, nextUpdate: K + 299, ...changes,
    }, signer), issuerCertificate: signer.certificate };
  }
  const knowledge = { knowledgeTime: K,
    statusMaterial: originalStatusMembers.map((member) => organizationStatus(member)),
    certificateStatusMaterial: [certificateStatus()],
  };
  const { currentCertificateStatus, ...credentialTrust } = source.context.credentialTrust;
  const trust = { trustDomainID: source.trustDomainID, organizationID: source.organizationID,
    issuerID: source.issuerID, identityNamespace: source.identityNamespace, policy: copy(source.policy),
    controlTrust: [...copy(source.context.controlTrust), {
      certificate: statusSuccessor.certificate, organizationID: source.organizationID,
      identityNamespace: source.identityNamespace, issuerID: source.issuerID,
      purpose: 'ORGANIZATION_DELEGATION_STATUS', objectTypes: ['GRANT', 'APPROVER_REGISTRATION', 'FINAL_AUTHORIZATION'],
    }], credentialTrust: copy(credentialTrust),
    algorithmDeadlines: copy(source.context.algorithmDeadlines), hashDeadlines: copy(source.context.hashDeadlines),
    keyDeadlines: { ...source.context.keyDeadlines,
      [c.keyID(statusSuccessor.publicKey).toString('hex')]: end,
      [c.keyID(certificateStatusSuccessor.publicKey).toString('hex')]: end },
  };
  const preservationPolicy = { dataValidUntil: at + 600,
    hashValidUntil: { [p.OID.sha512]: end, [p.OID.sha256]: at + 70 },
    resolveTimestamp(token) {
      const certificate = p.verifyCMS(token, { expectedContentType: p.OID.tstInfo }).certificate;
      const selected = [initialTSA, renewalTSA].find((identity) => c.equal(identity.certificate, certificate));
      return selected && { ...selected, status: ({ certificate, stateTime, knowledgeTime }) => authorityResolver({
        certificate, role: 'TIMESTAMP_AUTHORITY', scope: { trustDomainID: source.trustDomainID }, stateTime, knowledgeTime,
      }) };
    },
  };
  async function preserve(bytes, { firstAt = at + proofDelay, milliseconds = firstAccuracyMillis, renewalAt = at + 50 } = {}) {
    clock = firstAt;
    const first = await createERS(bytes, { tsa: (imprint, hashOID) => initialTSA.issue(imprint, hashOID, milliseconds) });
    clock = renewalAt;
    return renewERS(first, bytes, { tsa: renewalTSA.issue });
  }
  const evidenceRecord = await preserve(originalBytes);
  // Public-only declarative inputs for the separately reviewed corpus authoring
  // utility. No signing key or callback crosses this return-field boundary.
  const publicPin = (identity) => ({ certificate: Buffer.from(identity.certificate),
    issuerPublicKeyDER: c.spki(identity.issuerKey), policy: identity.policy,
    validUntil: identity.validUntil, signatureProfile: 'CERTCONCORD-PQ' });
  const publicSourceConfiguration = { schemaVersion: 1, trust: copy(trust),
    retainedAuthorities: { governance: rootPolicy(root),
      algorithmDeadlines: { 'ml-dsa-65': end, 'ml-dsa-87': end, ec: end },
      publication: { format: 'RFC3161',
        timestampAuthorities: [{ ...publicPin(publicationTSA), validFrom: at - 60, knowledgeValidUntil: end }],
        hashValidUntil: { [p.OID.sha512]: end, [p.OID.sha256]: end } } },
    preservation: { dataValidUntil: preservationPolicy.dataValidUntil,
      hashValidUntil: copy(preservationPolicy.hashValidUntil),
      timestampAuthorities: [publicPin(initialTSA), publicPin(renewalTSA)] } };
  return { source, app, completed, originalBytes, bundle, leaves, evidenceRecord, at, A: at, P, K, end,
    trust, knowledge, history, firstManifest, latestManifest, initialAuthorities, currentAuthorities,
    root, successorRoot, statusSuccessor, certificateStatusSuccessor, initialTSA, renewalTSA,
    queries, resolver, manifest, preserve, organizationStatus, certificateStatus, originalStatusMembers,
    publicSourceConfiguration,
    options: { trust, authorityResolver, readKnowledge: () => copy(knowledge), preservationPolicy },
    input: { originalBytes, evidenceRecord },
    replaceLeaf(type, payload) {
      return c.dcbor(createEvidencePackage(bundle.plan.profile, bundle.objects.map((leaf) =>
        leaf.type === type ? evidenceLeaf(type, payload) : leaf)));
    },
    close() { source.close(); archiveJournal.close(); },
  };
}

import test from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { Journal, evidenceObject } from './state.mjs';
import { runDemo } from './demo.mjs';
import { runFoundationDemo } from './foundation-demo.mjs';
import { createVerifier } from './sdk/index.mjs';
import { decodeJWS, signJWS } from './jose.mjs';
import { TimestampAuthority, timestampRequest, tokenFromResponse, verifyTimestampToken } from './timestamp.mjs';
import { createERS, renewERS, verifyERSPreservation } from './archive.mjs';
import { createRetainedAuthorityResolver, manifestPublicationImprint, ArchivePublicationStore } from './retained-authorities.mjs';
import { verifyPreservedDocument } from './historical-validation.mjs';

function replaceLeaf(bundle, type, payload) {
  const objects = bundle.objects.filter((o) => o.type !== 'VerificationPlan')
    .map((o) => o.type === type ? evidenceObject(type, payload) : o);
  const prior = c.decodeCBOR(bundle.objects.find((o) => o.type === 'VerificationPlan').payload);
  const plan = evidenceObject('VerificationPlan', c.dcbor({ ...prior,
    objects: Object.fromEntries(objects.map((o) => [o.type, o.id])) }), objects.map((o) => o.id));
  return { schemaVersion: 1, root: plan.id, objects: [...objects, plan] };
}

async function fixture(r, format) {
  const verified = createVerifier({ format, trust: r.trust }).verify(c.dcbor(r.bundle));
  assert.equal(verified.overall, 'VALID');
  const operationTime = verified.proofOfExistenceUpperBound,
    firstPublication = Math.floor(operationTime) - 30,
    historicalTime = Math.ceil(operationTime) + 2,
    currentTime = historicalTime + 2 * 86400,
    horizon = currentTime + 600,
    end = currentTime + 10 * 86400,
    domain = r.trust.trustDomainID,
    governance = c.generate('ml-dsa-87'), successor = c.generate('ml-dsa-87'),
    custodian = c.generate('ml-dsa-87'), successorCustodian = c.generate('ml-dsa-87'),
    journal = new Journal();
  let clock = firstPublication;
  const tsa = (serial, notAfter) => {
    const key = c.generate('ml-dsa-87'), certificate = p.issueCertificate({ publicKey: key.publicKey,
      serial, issuer: p.name('Synthetic archive governance'), subject: p.name('Archive TSA ' + serial),
      profileID: 'CERTCONCORD-TSA-v1', notBefore: firstPublication - 60, notAfter }, governance.privateKey);
    const service = new TimestampAuthority({ certificate, privateKey: key.privateKey, journal,
      policy: '1.3.6.1.4.1.32473.99.2', clock: () => clock, accuracySeconds: 0 });
    return { ...key, certificate, issuerKey: governance.publicKey, policy: service.policy, validUntil: notAfter,
      issue: (imprint, hashOID = p.OID.sha512) => tokenFromResponse(service.issue(timestampRequest(imprint, { policy: service.policy, hashOID }).der)) };
  };
  const publicationTSA = tsa(1, end), initialTSA = tsa(2, historicalTime + 3000), renewalTSA = tsa(3, end);
  const selected = new Map();
  // These are explicit synthetic relying-party appointments, not inferred evidence trust.
  const appoint = (key, roles) => {
    const id = c.b64u(c.keyID(key)), prior = selected.get(id);
    selected.set(id, { mode: 'RAW_KEY', publicKeyDER: c.spki(key), knownAt: firstPublication,
      validFrom: firstPublication, validUntil: end,
      roles: [...new Set([...(prior?.roles ?? []), ...roles])], scopes: [{ trustDomainID: domain }],
      status: { authorityID: c.keyID(key), trustDomainID: domain, scope: 'AUTHORITY', status: 'GOOD',
        publishedAt: firstPublication, nextUpdate: historicalTime + 300 } });
  };
  const certKey = (cert) => p.parseCertificate(cert).publicKey;
  appoint(certKey(r.trust.raCertificate), ['REGISTRATION_AUTHORITY']);
  appoint(certKey(r.trust.permitCertificate), ['PERMIT_AUTHORITY']);
  appoint(certKey(r.trust.receiptCertificate), ['RECEIPT_AUTHORITY']);
  appoint(certKey(r.trust.timestamp.certificate), ['TIMESTAMP_AUTHORITY']);
  if (format === 'CMS') {
    appoint(r.trust.mtc.caPublicKey, ['ISSUER']);
    appoint(certKey(r.trust.statusCertificate), ['STATUS_AUTHORITY']);
  } else {
    appoint(r.trust.issuerPublicKey, ['ISSUER', 'STATUS_AUTHORITY']);
    appoint(certKey(r.trust.sealCertificate), ['DOCUMENT_SEAL']);
  }
  appoint(initialTSA.publicKey, ['TIMESTAMP_AUTHORITY']);
  appoint(renewalTSA.publicKey, ['TIMESTAMP_AUTHORITY']);
  appoint(custodian.publicKey, ['ARCHIVE_CUSTODIAN']);
  const rootPolicy = (key) => ({ roots: [{ publicKeyDER: c.spki(key.publicKey),
    validFrom: firstPublication - 60, validUntil: end }], threshold: 1 });
  const snapshot = (records, published, previous, replacement) => {
    const manifest = { schemaVersion: 2, trustDomainID: domain,
      serial: previous ? previous.manifest.serial + 1 : 0,
      previousHash: previous ? c.H('RootTrustManifest', previous.manifest) : null,
      issuedAt: published, notBefore: published, notAfter: end,
      coverageUntil: previous ? horizon : historicalTime + 300, authorities: records,
      ...(replacement ? { successor: rootPolicy(successor) } : {}) };
    const signatures = [governance, ...(replacement ? [successor] : [])].map((key) => ({
      keyID: c.keyID(key.publicKey), signature: c.sign(c.D('RootTrustManifest', manifest), key.privateKey) }));
    clock = published;
    return { manifest, signatures, publicationProof: publicationTSA.issue(manifestPublicationImprint({ manifest, signatures })) };
  };
  const initialHistory = snapshot([...selected.values()], firstPublication);
  appoint(successorCustodian.publicKey, ['ARCHIVE_CUSTODIAN']);
  const currentRecords = [...selected.values()].filter((record) => !c.equal(record.publicKeyDER, c.spki(custodian.publicKey)))
    .map((record) => ({ ...record, status: { ...record.status, publishedAt: currentTime - 1, nextUpdate: horizon } }));
  const finalHistory = snapshot(currentRecords, currentTime - 1, initialHistory, true);
  const history = [initialHistory, finalHistory];
  const historyTrust = { trustDomainID: domain, governance: rootPolicy(governance),
    validationTime: currentTime, algorithmDeadlines: { 'ml-dsa-87': end, 'ml-dsa-65': end, ec: end, ed25519: end },
    verifyPublication: ({ imprint, proof, at }) => ({ overall: 'VALID', ...verifyTimestampToken(proof,
      { ...publicationTSA, imprint, at, maxFutureSkew: 0 }) }) };
  const authorityResolver = createRetainedAuthorityResolver({ ...historyTrust, history });
  const bytes = c.dcbor(r.bundle);
  clock = historicalTime;
  const first = await createERS(bytes, { tsa: initialTSA.issue, hashOID: p.OID.sha256 });
  clock = historicalTime + 1000;
  const renewed = await renewERS(first, bytes, { tsa: renewalTSA.issue });
  clock = historicalTime + 2000;
  const record = await renewERS(renewed, bytes, { tsa: renewalTSA.issue, hashRenewal: true, hashOID: p.OID.sha512 });
  const preservationPolicy = { dataValidUntil: historicalTime + 86400,
    hashValidUntil: { [p.OID.sha256]: historicalTime + 2500, [p.OID.sha512]: end },
    resolveTimestamp: (token) => {
      const cert = p.verifyCMS(token, { expectedContentType: p.OID.tstInfo }).certificate;
      const selectedTSA = [initialTSA, renewalTSA].find((value) => c.equal(value.certificate, cert));
      return selectedTSA && { ...selectedTSA, status: ({ stateTime, knowledgeTime }) => authorityResolver({
        certificate: cert, role: 'TIMESTAMP_AUTHORITY', scope: { trustDomainID: domain },
        stateTime, knowledgeTime }).overall === 'VALID' };
    } };
  let payload;
  const statusType = format === 'CMS' ? 'CertificateStatus' : 'CredentialStatusList';
  if (format === 'CMS') {
    const originalStatus = c.decodeCBOR(p.verifyCMS(r.bundle.objects.find((o) => o.type === statusType).payload).content)[3];
    payload = r.signStatus({ ...originalStatus, publishedAt: currentTime, nextUpdate: currentTime + 300 });
  } else {
    const prior = JSON.parse(decodeJWS(r.bundle.objects.find((o) => o.type === statusType).payload.toString()).payload.toString());
    payload = Buffer.from(signJWS({ ...prior, iat: currentTime, exp: currentTime + 300 }, r.issuer.status.privateKey,
      { typ: 'statuslist+jwt', x5c: [r.trust.issuerCertificate.toString('base64')] }));
  }
  const currentBytes = c.dcbor(replaceLeaf(r.bundle, statusType, payload));
  const options = { format, originalBytes: bytes, currentBytes, evidenceRecord: record,
    preservationPolicy, historicalTrust: r.trust, currentTrust: r.trust, authorityResolver,
    historicalKnowledgeTime: historicalTime, currentKnowledgeTime: currentTime };
  const withIncident = () => {
    const compromised = c.keyID(certKey(r.trust.permitCertificate));
    const manifest = { ...finalHistory.manifest, serial: 2,
      previousHash: c.H('RootTrustManifest', finalHistory.manifest),
      issuedAt: currentTime, notBefore: currentTime,
      authorities: currentRecords.map((record) => ({ ...record, status: { ...record.status,
        publishedAt: currentTime, ...(c.equal(record.status.authorityID, compromised)
          ? { status: 'REVOKED', effectiveTime: currentTime, compromiseStart: firstPublication + 1 } : {}) } })) };
    delete manifest.successor;
    const signatures = [{ keyID: c.keyID(successor.publicKey),
      signature: c.sign(c.D('RootTrustManifest', manifest), successor.privateKey) }];
    clock = currentTime;
    return createRetainedAuthorityResolver({ ...historyTrust, history: [...history,
      { manifest, signatures, publicationProof: publicationTSA.issue(manifestPublicationImprint({ manifest, signatures })) }] });
  };
  return { bytes, record, first, renewed, history, historyTrust, options, domain, initialTSA, withIncident,
    currentTime, historicalTime, custodian, successorCustodian, journal, authorityResolver,
    close: () => journal.close() };
}

for (const format of ['CMS', 'MDOC']) test(`${format} retains offline authorization, renewed preservation and later admissibility separately`, async (t) => {
  await (format === 'CMS' ? runDemo : runFoundationDemo)({ trustedTime: true, activationMode: 'HUMAN_WEBAUTHN',
    onComplete: async (r) => {
      const f = await fixture(r, format);
      try {
        const network = t.mock.method(globalThis, 'fetch', () => { throw Error('Issuer unavailable'); });
        const result = verifyPreservedDocument(f.options);
        assert.equal(result.preservation.overall, 'VALID', result.preservation.reason);
        assert.equal(result.historicalAuthorization.overall, 'VALID', result.historicalAuthorization.reason);
        assert.equal(result.currentAdmissibility.overall, 'VALID', result.currentAdmissibility.reason);
        assert.equal(result.overall, 'VALID');
        const compromised = verifyPreservedDocument({ ...f.options, authorityResolver: f.withIncident() });
        assert.equal(compromised.preservation.overall, 'VALID');
        assert.equal(compromised.historicalAuthorization.overall, 'VALID');
        assert.equal(compromised.currentAdmissibility.overall, 'INVALID');
        assert.equal(compromised.currentAdmissibility.reason, 'AUTHORITY_REVOKED');
        const stale = verifyPreservedDocument({ ...f.options, currentBytes: f.bytes });
        assert.equal(stale.preservation.overall, 'VALID');
        assert.equal(stale.historicalAuthorization.overall, 'VALID');
        assert.equal(stale.currentAdmissibility.overall, 'INDETERMINATE');
        const uncovered = createRetainedAuthorityResolver({ ...f.historyTrust, history: [f.history[0]] });
        assert.equal(verifyPreservedDocument({ ...f.options, authorityResolver: uncovered }).currentAdmissibility.overall, 'INDETERMINATE');
        const changed = c.decodeCBOR(f.options.currentBytes);
        const bad = replaceLeaf(changed, 'Document', Buffer.from('different document'));
        assert.equal(verifyPreservedDocument({ ...f.options, currentBytes: c.dcbor(bad) }).currentAdmissibility.reason, 'HISTORICAL_OPERATION_CHANGED');
        let publicationTime = f.historicalTime, expectedCustodian = f.custodian.publicKey;
        const store = new ArchivePublicationStore(f.journal, { validatePublication: (publication) => {
          verifyERSPreservation(publication.evidenceRecord, f.bytes, { ...f.options.preservationPolicy, at: publicationTime });
          return createRetainedAuthorityResolver({ ...f.historyTrust, history: publication.history })({
            publicKeyDER: c.spki(expectedCustodian), role: 'ARCHIVE_CUSTODIAN',
            scope: { trustDomainID: f.domain }, stateTime: publicationTime, knowledgeTime: publicationTime });
        } });
        const initial = store.publish({ archiveID: format + '-document', previousHash: null,
          dataHash: c.sha512(f.bytes), evidenceRecord: f.first, history: [f.history[0]] });
        publicationTime = f.currentTime; expectedCustodian = f.successorCustodian.publicKey;
        const final = store.publish({ archiveID: format + '-document', previousHash: initial.digest,
          dataHash: c.sha512(f.bytes), evidenceRecord: f.record, history: f.history });
        assert.equal(final.publication.history.length, 2);
        assert.deepEqual(final.publication.evidenceRecord, f.record);
        assert.equal(network.mock.callCount(), 0);
        network.mock.restore();
      } finally { f.close(); }
    } });
});

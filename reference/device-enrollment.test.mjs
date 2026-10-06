import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { X509Certificate } from 'node:crypto';
import { DOMParser } from '@xmldom/xmldom';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { encode } from './cose.mjs';
import { Journal } from './state.mjs';
import { DeviceBindingRegistry } from './bridge.mjs';
import { createCSR, verifyCSR } from './enrollment.mjs';
import { ACMEClient, ACMEService } from './acme.mjs';
import { readBody, sendJSON } from './transport.mjs';
import { parseJSON } from './json.mjs';
import { appleFixture, tpmFixture, syntheticAttestationCA } from './attestation-fixtures.mjs';
import {
  appleACMEAttestation,
  appleManagedProfile,
  platformEvidenceFromJSON,
  platformEvidenceToJSON,
} from './device-enrollment.mjs';

async function laboratory() {
  const journal = new Journal(),
    ca = c.generate('ec'),
    holder = c.generate('ec'),
    ra = c.generate('ml-dsa-87'),
    authority = syntheticAttestationCA(),
    profile = 'CERTCONCORD-PERSON-DEVICE-SIGN-v1',
    sessionID = c.b64u(c.random()),
    subjectID = c.random(),
    raCertificate = p.issueCertificate(
      { publicKey: ra.publicKey, subject: p.name('RA'), issuer: p.name('RA'), serial: 1 },
      ra.privateKey,
    ),
    policy = appleFixture(holder.publicKey, 'initial', {}, authority).policy,
    bindings = new DeviceBindingRegistry({
      journal,
      registrationAuthorityCertificate: raCertificate,
      trustDomainID: c.random(),
      policyHash: c.random(64),
      attestationPolicy: policy,
    });
  let service,
    sequence = 0,
    approved;
  const server = createServer(async (req, res) => {
    try {
      if (req.method === 'GET' && req.url === '/directory')
        return sendJSON(res, 200, service.directory());
      if (req.method === 'HEAD' && req.url === '/new-nonce') {
        res.writeHead(200, { 'replay-nonce': service.nonce() });
        return res.end();
      }
      const r = await service.handle(req.url, parseJSON((await readBody(req)).toString('utf8')));
      if (r.body) {
        res.writeHead(r.status, r.headers);
        res.end(r.body);
      } else sendJSON(res, r.status, r.json, r.headers);
    } catch (e) {
      sendJSON(res, 400, { type: e.message }, { 'replay-nonce': service.nonce() });
    }
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const baseURL = 'http://127.0.0.1:' + server.address().port;
  service = new ACMEService({
    baseURL,
    journal,
    profiles: [profile],
    defaultProfile: profile,
    deviceAttestation: appleACMEAttestation({
      policy,
      profiles: [profile],
      authorizeOrder: async ({ identifier }) => {
        c.requireThat(identifier.value === 'SYNTHETIC-SERIAL', 'ENROLLMENT_INVENTORY');
        return {
          token: bindings.challenge({ subjectID, profileID: profile, sessionID }),
          expiresAt: c.now() + 120,
        };
      },
    }),
    authorizeFinalize: async ({ csr, deviceProofs, order }) => {
      const proof = deviceProofs[0],
        q = verifyCSR(csr);
      approved = {
        proof,
        assessment: bindings.assess({
          holderPublicKey: q.publicKey,
          nonce: proof.nonce,
          evidence: proof.evidence,
          sessionID,
        }),
      };
      assert.equal(order.profile, profile);
      return approved;
    },
    issue: async ({ csr }) => {
      sequence++;
      const q = verifyCSR(csr);
      return p.issueCertificate(
        {
          publicKey: q.publicKey,
          subject: q.subject,
          issuer: p.name('Managed device CA'),
          serial: sequence,
        },
        ca.privateKey,
      );
    },
    revoke: async () => {},
  });
  const client = new ACMEClient({
    directoryURL: baseURL + '/directory',
    privateKey: c.generate('ec').privateKey,
    allowLoopback: true,
  });
  await client.createAccount();
  return {
    journal,
    ca,
    holder,
    profile,
    bindings,
    ra,
    raCertificate,
    subjectID,
    sessionID,
    client,
    order: () =>
      client.newOrder({
        identifiers: [{ type: 'permanent-identifier', value: 'SYNTHETIC-SERIAL' }],
      }),
    csr: (key) =>
      createCSR({
        subject: p.name('Holder'),
        publicKey: key.publicKey,
        privateKey: key.privateKey,
      }),
    response: (token, changes = {}) => ({
      attObj: c.b64u(
        encode({
          fmt: 'apple',
          attStmt: { x5c: appleFixture(holder.publicKey, token, changes, authority).evidence.x5c },
        }),
      ),
      ignoredExtension: true,
    }),
    get approved() {
      return approved;
    },
    get issued() {
      return sequence;
    },
    close: async () => {
      await new Promise((resolve) => server.close(resolve));
      journal.close();
    },
  };
}

test('Apple managed ACME binds the hardware challenge, CSR and DeviceBinding enrollment over HTTP', async () => {
  const lab = await laboratory();
  try {
    const order = await lab.order(),
      pem = await lab.client.complete(order, {
        csr: () => lab.csr(lab.holder),
        attestDevice: async ({ token }) => lab.response(token),
        pollMilliseconds: 1,
      });
    const cert = new X509Certificate(pem);
    assert(cert.verify(lab.ca.publicKey));
    assert.deepEqual(c.spki(cert.publicKey), c.spki(lab.holder.publicKey));
    assert.equal(p.parseCertificate(cert.raw).extensions.has('2.5.29.17'), false);
    const { proof: deviceProof, assessment } = lab.approved,
      registry = lab.bindings;
    const authorization = p.signCMS(
        {
          certificate: lab.raCertificate,
          content: c.D('DeviceRegistrationAuthorization', {
            schemaVersion: 1,
            trustDomainID: registry.trustDomainID,
            subjectID: lab.subjectID,
            profileID: lab.profile,
            holderKeyID: c.keyID(lab.holder.publicKey),
            documentKeyID: c.keyID(lab.holder.publicKey),
            policyHash: registry.policyHash,
            attestationEvidenceHash: assessment.evidenceHash,
            keyAssurance: assessment.keyAssurance,
            localUVPolicy: assessment.localUVPolicy,
            audience: registry.audience,
            issuedAt: c.now(),
            expiresAt: c.now() + 120,
            bindingExpiresAt: c.now() + 3600,
          }),
        },
        lab.ra.privateKey,
      ),
      proof = c.sign(
        c.D('DeviceRegistrationProof', {
          schemaVersion: 1,
          authorizationHash: c.sha512(authorization),
          nonce: deviceProof.nonce,
          audience: registry.audience,
        }),
        lab.holder.privateKey,
      );
    const binding = registry.enroll({
      authorization,
      holderPublicKey: lab.holder.publicKey,
      nonce: deviceProof.nonce,
      proof,
      attestation: deviceProof.evidence,
      sessionID: lab.sessionID,
    });
    assert.equal(registry.active(binding.bindingID).keyAdmission.boundary, 'APPLE_SECURE_ENCLAVE');
    const publicAuth = (await lab.client.post(order.authorizations[0], null)).json;
    assert(!publicAuth.attestation);
    assert(!publicAuth.keyAuthorization);
    await assert.rejects(
      lab.client.post(order.finalize, { csr: c.b64u(lab.csr(lab.holder)) }),
      /FINALIZE_STATE/,
    );
    assert.equal(lab.issued, 1);
  } finally {
    await lab.close();
  }
});
test('managed ACME rejects identifier, challenge, account and CSR substitution without issuing', async () => {
  const lab = await laboratory();
  try {
    for (const changes of [{ identifier: 'OTHER-SERIAL' }, { challenge: 'old-challenge' }]) {
      const order = await lab.order(),
        a = (await lab.client.post(order.authorizations[0], null)).json,
        ch = a.challenges[0];
      await assert.rejects(
        lab.client.post(ch.url, lab.response(ch.token, changes)),
        /badAttestationStatement/,
      );
      assert.equal((await lab.client.post(order.authorizations[0], null)).json.status, 'invalid');
      assert.equal((await lab.client.post(order.url, null)).json.status, 'invalid');
      await assert.rejects(lab.client.post(ch.url, lab.response(ch.token)), /CHALLENGE_STATE/);
    }
    const order = await lab.order(),
      attacker = new ACMEClient({
        directoryURL: lab.client.directoryURL,
        privateKey: c.generate('ec').privateKey,
        allowLoopback: true,
      });
    await attacker.createAccount();
    await assert.rejects(attacker.post(order.authorizations[0], null), /AUTHORIZATION/);
    await assert.rejects(
      lab.client.complete(order, {
        csr: lab.csr(c.generate('ec')),
        attestDevice: async ({ token }) => lab.response(token),
        pollMilliseconds: 1,
      }),
      /badCSR/,
    );
    assert.equal(lab.issued, 0);
    await assert.rejects(
      lab.client.newOrder({
        identifiers: [{ type: 'dns', value: 'example.org' }],
        profile: lab.profile,
      }),
      /ORDER/,
    );
  } finally {
    await lab.close();
  }
});
test('managed profile and platform evidence serialization preserve security settings and exact bytes', () => {
  const xml = appleManagedProfile({
    directoryURL: 'https://issuer.example/enroll/directory',
    clientIdentifier: 'SYNTHETIC-SERIAL',
    subjectCommonName: 'Holder & Identity',
  }).toString('utf8');
  const document = new DOMParser().parseFromString(xml, 'application/xml');
  assert.equal(document.documentElement.nodeName, 'plist');
  assert.match(xml, /<key>HardwareBound<\/key><true\/>/);
  assert.match(xml, /<key>Attest<\/key><true\/>/);
  assert.match(xml, /<key>AllowAllAppsAccess<\/key><false\/>/);
  assert.match(xml, /<key>KeyIsExtractable<\/key><false\/>/);
  assert.match(xml, /Holder &amp; Identity/);
  assert.throws(
    () => appleManagedProfile({ directoryURL: 'http://issuer.example', clientIdentifier: 'x' }),
    /PROFILE/,
  );
  const holder = c.generate('ec');
  for (const evidence of [
    appleFixture(holder.publicKey, 'test').evidence,
    tpmFixture(holder.publicKey, 'test').evidence,
  ]) {
    assert.deepEqual(platformEvidenceFromJSON(platformEvidenceToJSON(evidence)), evidence);
    assert.throws(
      () => platformEvidenceFromJSON({ ...platformEvidenceToJSON(evidence), hardware: true }),
      /UNKNOWN/,
    );
  }
});

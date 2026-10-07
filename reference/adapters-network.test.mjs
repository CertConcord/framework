import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import * as t from './transparency.mjs';
import { Journal } from './state.mjs';
import { treeHash, consistencyProof } from './mtc.mjs';
import { readBody, sendJSON } from './transport.mjs';
import { DeviceBindingRegistry, RRACredentialIssuer } from './bridge.mjs';
import { publicJWK } from './jose.mjs';

test('C2SP mirror HTTP checkpoint, entries, immutable tiles and sign-subtree', async () => {
  const journal = new Journal(),
    log = { ...c.generate('ed25519'), name: 'log.example/network', scheme: 'ed25519-log' },
    signer = {
      ...c.generate('ml-dsa-87'),
      name: 'mirror.example/network',
      scheme: 'CERTCONCORD-MLDSA87-SUBTREE-v1',
    },
    entries = [Buffer.from('a'), Buffer.from('b')],
    service = new t.TlogMirror({ journal, signer, logs: new Map([[log.name, log]]) }),
    server = createServer(t.createTransparencyHandler(service));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + server.address().port,
    hash = c.sha256(Buffer.from(log.name)).toString('hex'),
    post = (path, body) => fetch(base + path, { method: 'POST', body });
  try {
    assert.equal(
      (
        await post(
          '/add-checkpoint',
          t.witnessRequest(0, [], t.signedCheckpoint({ origin: log.name, entries, signer: log })),
        )
      ).status,
      200,
    );
    assert.equal((await post('/add-entries', t.mirrorUpload(log.name, entries))).status, 200);
    const cp = await (await fetch(base + '/' + hash + '/checkpoint')).text();
    t.verifyNote(cp, signer);
    t.verifyPublishedCheckpoint(cp, log);
    const tile = await fetch(base + '/' + hash + '/tile/0/000.p/2');
    assert.equal(tile.status, 200);
    assert.equal((await tile.arrayBuffer()).byteLength, 64);
    const bundle = await fetch(base + '/' + hash + '/tile/entries/000.p/2');
    assert(
      c.equal(
        Buffer.from(await bundle.arrayBuffer()),
        service.entryBundle(log.name, 0, { width: 2 }),
      ),
    );
    const q = t.subtreeRequest({
        start: 0,
        end: 2,
        root: treeHash(entries),
        proof: consistencyProof(entries, 0, 2),
        checkpoint: t.checkpointForSubtree(cp, signer),
      }),
      result = await post('/sign-subtree', q);
    assert.equal(result.status, 200);
    const response = await result.text();
    assert.equal(t.verifySubtreeResponse(response, t.parseSubtreeRequest(q), signer).length, 4627);
    const witnessOnly = t.checkpointForSubtree(cp, signer);
    const oldRequest = q.slice(0, -witnessOnly.length) + cp;
    assert.equal((await post('/sign-subtree', oldRequest)).status, 400);
    const bad = await post(
      '/sign-subtree',
      q.replace(treeHash(entries).toString('base64'), c.random().toString('base64')),
    );
    assert.equal(bad.status, 422);
  } finally {
    await new Promise((r) => server.close(r));
    journal.close();
  }
});

test('RRA VCI admission rejects foreign domain, changed holder, caller claims and revoked binding', () => {
  const journal = new Journal(),
    key = c.generate('ml-dsa-87'),
    holder = c.generate('ec'),
    certificate = p.issueCertificate(
      {
        publicKey: key.publicKey,
        subject: p.name('Synthetic RA'),
        issuer: p.name('Synthetic RA'),
        serial: 1,
        profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1',
      },
      key.privateKey,
    ),
    trustDomainID = c.random(),
    policyHash = c.random(64),
    subjectID = c.random(),
    registry = new DeviceBindingRegistry({
      allowUnattested: true,
      journal,
      registrationAuthorityCertificate: certificate,
      trustDomainID,
      policyHash,
    });
  const enroll = (domain) => {
    const authorization = p.signCMS(
        {
          certificate,
          content: c.D('DeviceRegistrationAuthorization', {
            schemaVersion: 1,
            trustDomainID: domain,
            policyHash,
            subjectID,
            holderKeyID: c.keyID(holder.publicKey),
            documentKeyID: c.random(64),
            audience: 'certconcord-device-registry',
            issuedAt: c.now(),
            expiresAt: c.now() + 60,
            attestationEvidenceHash: c.random(64),
            keyAssurance: 'KAL1',
            localUVPolicy: 'UNASSESSED',
          }),
        },
        key.privateKey,
      ),
      nonce = registry.challenge(),
      proof = c.sign(
        c.D('DeviceRegistrationProof', {
          schemaVersion: 1,
          authorizationHash: c.sha512(authorization),
          nonce,
          audience: 'certconcord-device-registry',
        }),
        holder.privateKey,
      );
    return registry.enroll({ authorization, nonce, proof, holderPublicKey: holder.publicKey });
  };
  try {
    assert.throws(() => enroll(c.random()), /REGISTRATION_AUTHORITY/);
    const binding = enroll(trustDomainID),
      offer = {
        subjectID: c.b64u(subjectID),
        claims: registry.qualificationClaims(binding.bindingID, {
          qualification: 'CERTCONCORD-IAL2',
        }),
      };
    assert.equal(
      registry.authorizeCredential({ offer, holderJWK: publicJWK(holder.publicKey) }),
      true,
    );
    assert.throws(
      () =>
        registry.authorizeCredential({ offer, holderJWK: publicJWK(c.generate('ec').publicKey) }),
      /DEVICE_BINDING/,
    );
    const issuer = new RRACredentialIssuer({
      issuer: 'https://issuer.example',
      journal,
      privateKey: key.privateKey,
      certificate,
      clients: new Map(),
      bindings: registry,
      qualificationAllowed: () => true,
    });
    assert.throws(
      () =>
        issuer.offer({
          bindingID: binding.bindingID,
          qualification: 'CERTCONCORD-IAL2',
          claims: { qualification: 'forged' },
        }),
      /OFFER_INPUT/,
    );
    registry.revoke(binding.bindingID, {
      authorization: p.signCMS(
        {
          certificate,
          content: c.D('DeviceBindingRevocation', {
            trustDomainID,
            bindingID: binding.bindingID,
            epoch: 0,
            expiresAt: c.now() + 60,
            reason: 'DEVICE_LOST',
          }),
        },
        key.privateKey,
      ),
    });
    assert.throws(
      () => registry.authorizeCredential({ offer, holderJWK: publicJWK(holder.publicKey) }),
      /INACTIVE/,
    );
  } finally {
    journal.close();
  }
});

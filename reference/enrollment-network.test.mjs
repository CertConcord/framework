import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { X509Certificate } from 'node:crypto';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { Journal } from './state.mjs';
import { createCSR, verifyCSR } from './enrollment.mjs';
import { ACMEClient, ACMEService } from './acme.mjs';
import { CMPClient, CMPService, protectCMP, verifyCMP } from './cmp.mjs';
import { readBody, sendJSON } from './transport.mjs';
import { parseJSON } from './json.mjs';

test('ACME HTTP account, DNS-01, profile, CSR, issuance, key rollover and revocation', async () => {
  const journal = new Journal(),
    account = c.generate('ec'),
    replacement = c.generate('ec'),
    occupied = c.generate('ec'),
    holder = c.generate(),
    ca = c.generate('ml-dsa-87'),
    dns = new Map(),
    revocations = [];
  let service;
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
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const baseURL = 'http://127.0.0.1:' + server.address().port;
  const profile = 'CERTCONCORD-PERSON-SIGN-v1';
  service = new ACMEService({
    baseURL,
    journal,
    profiles: [profile],
    verifyChallenge: async ({ identifier, keyAuthorization }) =>
      dns.get(identifier.value) === c.b64u(c.sha256(Buffer.from(keyAuthorization))),
    authorizeFinalize: async ({ csr, order }) => {
      assert.equal(verifyCSR(csr).possessionMode, 'DIRECT_SIGNATURE');
      assert.equal(order.profile, profile);
      return { approved: true };
    },
    issue: async ({ csr, approval }) => {
      assert(approval.approved);
      const q = verifyCSR(csr);
      return p.issueCertificate(
        {
          publicKey: q.publicKey,
          subject: q.subject,
          issuer: p.name('Synthetic ACME CA'),
          serial: 1,
          profileID: profile,
          extraExtensions: q.attributes.get('1.2.840.113549.1.9.14').children.map((e) => e.raw),
        },
        ca.privateKey,
      );
    },
    revoke: async (r) => revocations.push(r),
  });
  try {
    const client = new ACMEClient({
      directoryURL: baseURL + '/directory',
      privateKey: account.privateKey,
      allowLoopback: true,
    });
    await client.createAccount({ termsOfServiceAgreed: true });
    const originalURL = client.accountURL;
    const other = new ACMEClient({
      directoryURL: baseURL + '/directory',
      privateKey: occupied.privateKey,
      allowLoopback: true,
    });
    await other.createAccount({ termsOfServiceAgreed: true });
    await assert.rejects(client.changeAccountKey(occupied.privateKey), /acme:error:malformed/);
    assert.equal(client.privateKey, account.privateKey);
    assert.equal((await client.post(originalURL, null)).json.status, 'valid');
    const order = await client.newOrder({
        identifiers: [{ type: 'dns', value: 'document.example' }],
        profile,
      }),
      san = p.extension('2.5.29.17', c.seq(c.der(0x82, Buffer.from('document.example')))),
      csr = createCSR({
        subject: p.name('Synthetic Subject'),
        publicKey: holder.publicKey,
        privateKey: holder.privateKey,
        attributes: [p.attribute('1.2.840.113549.1.9.14', c.seq(san))],
      });
    const pem = await client.complete(order, {
      csr,
      provisionDNS01: async (x) => dns.set(x.identifier.value, x.recordValue),
      cleanupDNS01: async (x) => dns.delete(x.identifier.value),
      pollMilliseconds: 1,
    });
    const cert = new X509Certificate(pem);
    assert(cert.verify(ca.publicKey));
    assert.equal(dns.size, 0);
    assert.equal(
      (await client.post(originalURL, { contact: ['mailto:synthetic@example.org'] })).json
        .contact[0],
      'mailto:synthetic@example.org',
    );
    await client.changeAccountKey(replacement.privateKey);
    await assert.rejects(
      client.post(originalURL, null, { key: account.privateKey }),
      /JWS_SIGNATURE/,
    );
    await client.createAccount({ termsOfServiceAgreed: true });
    assert.equal(client.accountURL, originalURL);
    await client.revoke(cert.raw, 1);
    assert.equal(revocations.length, 1);
    await assert.rejects(
      client.revoke(
        p.issueCertificate(
          {
            publicKey: holder.publicKey,
            subject: p.name('Other'),
            issuer: p.name('Other'),
            serial: 9,
          },
          ca.privateKey,
        ),
      ),
      /REVOCATION_AUTHORITY/,
    );
    await client.post(originalURL, { status: 'deactivated' });
    await assert.rejects(
      client.newOrder({ identifiers: [{ type: 'dns', value: 'document.example' }], profile }),
      /ACCOUNT/,
    );
  } finally {
    await new Promise((r) => server.close(r));
    journal.close();
  }
});

test('CMP protected p10cr, explicit certificate confirmation, nonce and message substitution over HTTP', async () => {
  const journal = new Journal(),
    clientKey = c.generate(),
    serverKey = c.generate('ml-dsa-87'),
    holder = c.generate(),
    issuerKey = c.generate('ml-dsa-87'),
    sender = p.name('Synthetic CMP Client'),
    recipient = p.name('Synthetic CMP RA'),
    profile = 'CERTCONCORD-PERSON-SIGN-v1';
  let count = 0;
  const service = new CMPService({
    journal,
    privateKey: serverKey.privateKey,
    sender: recipient,
    clientName: sender,
    clientPublicKey: clientKey.publicKey,
    profiles: [profile],
    authorize: async () => ({ approved: true }),
    issue: async ({ csr }) => {
      count++;
      const q = verifyCSR(csr);
      return p.issueCertificate(
        {
          publicKey: q.publicKey,
          subject: q.subject,
          issuer: p.name('Synthetic CMP CA'),
          serial: count,
          profileID: profile,
        },
        issuerKey.privateKey,
      );
    },
    rejectCertificate: async () => {},
  });
  const server = createServer(async (req, res) => {
    try {
      const out = await service.handle(await readBody(req));
      res.writeHead(200, { 'content-type': 'application/pkixcmp' });
      res.end(out);
    } catch {
      res.writeHead(400);
      res.end();
    }
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    const client = new CMPClient({
        url: 'http://127.0.0.1:' + server.address().port,
        privateKey: clientKey.privateKey,
        sender,
        recipient,
        serverPublicKey: serverKey.publicKey,
        issuerPublicKey: issuerKey.publicKey,
        allowLoopback: true,
      }),
      csr = createCSR({
        subject: p.name('Synthetic Document Subject'),
        publicKey: holder.publicKey,
        privateKey: holder.privateKey,
      }),
      cert = await client.enroll({ csr, profile });
    assert(new X509Certificate(cert).verify(issuerKey.publicKey));
    assert.equal(count, 1);
    const request = protectCMP({
        sender,
        recipient,
        privateKey: clientKey.privateKey,
        bodyTag: 4,
        body: csr,
        profile,
      }),
      reply = await service.handle(request);
    assert(c.equal(reply, await service.handle(request)));
    assert.equal(count, 2);
    const changed = Buffer.from(request);
    changed[changed.length - 1] ^= 1;
    await assert.rejects(service.handle(changed), /SIGNATURE/);
    assert.throws(
      () =>
        verifyCMP(request, {
          sender,
          recipient,
          publicKey: clientKey.publicKey,
          transactionID: c.random(),
        }),
      /TRANSACTION/,
    );
  } finally {
    await new Promise((r) => server.close(r));
    journal.close();
  }
});

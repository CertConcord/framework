import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { Journal, readControl } from './state.mjs';
import { EncryptionRecoveryService } from './lifecycle.mjs';
import { decryptCMS } from './protection.mjs';
import { exampleAuthorityResolver } from './example-authorities.mjs';

function control() {
  const key = c.generate('ml-dsa-87'),
    name = p.name('Synthetic recovery authority');
  return {
    ...key,
    certificate: p.issueCertificate(
      {
        publicKey: key.publicKey,
        issuer: name,
        subject: name,
        serial: 1,
        profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1',
      },
      key.privateKey,
    ),
  };
}

function fixture(t, { durable = false } = {}) {
  const directory = durable ? mkdtempSync(join(tmpdir(), 'certconcord-recovery-')) : undefined,
    path = directory ? join(directory, 'recovery.sqlite') : ':memory:',
    journals = [],
    authorities = [control(), control()],
    receipt = control(),
    recipient = c.generate('ml-kem-768'),
    root = c.random(),
    trustDomainID = c.random(),
    authorityResolver = exampleAuthorityResolver({
      trustDomainID,
      authorities: [...authorities, receipt].map((authority) => ({
        certificate: authority.certificate,
        roles: ['RECOVERY_AUTHORITY'],
      })),
    }),
    request = {
      schemaVersion: 1,
      trustDomainID,
      requestID: c.random(),
      targetRootID: c.random(),
      subjectID: c.random(),
      recipientKeyID: c.keyID(recipient.publicKey),
      purpose: 'ENCRYPTION_VAULT_WRAP',
      issuedAt: c.now(),
      expiresAt: c.now() + 120,
    },
    approvedHash = c.H('EncryptionRecoveryRequest', request),
    approvals = authorities.map((authority) =>
      p.signCMS(
        {
          content: c.D('EncryptionRecoveryApproval', {
            requestHash: approvedHash,
            approved: true,
            expiresAt: request.expiresAt,
          }),
          certificate: authority.certificate,
        },
        authority.privateKey,
      ),
    );
  let current;
  const open = (loadEncryptionRoot = async () => Buffer.from(root), overrides = {}) => {
    if (current) {
      current.close();
      journals.pop();
    }
    current = new Journal(path);
    journals.push(current);
    return new EncryptionRecoveryService({
      journal: current,
      approvers: authorities.map((authority, index) => ({
        certificate: authority.certificate,
        operatorID: 'synthetic-recovery-operator-' + index,
      })),
      threshold: 2,
      graph: {
        nodes: ['admin', 'custodian', 'encryption', 'signing'],
        edges: [{ from: ['admin', 'custodian'], threshold: 2, to: 'encryption' }],
      },
      attackerRoots: ['admin', 'custodian'],
      signingTargets: ['signing'],
      loadEncryptionRoot,
      trustDomainID,
      authorityResolver,
      ...receipt,
      ...overrides,
    });
  };
  t.after(() => {
    journals.forEach((journal) => journal.close());
    if (directory) rmSync(directory, { recursive: true, force: true });
  });
  return {
    request,
    trustDomainID,
    authorities,
    receipt,
    approvals,
    approvedHash,
    root,
    recipient,
    open,
    recover: (service) => service.recover(request, approvals, recipient.publicKey),
    journal: () => current,
    operationID: 'recovery:' + c.b64u(trustDomainID) + ':' + c.b64u(request.requestID),
    unpack: (raw) => {
      const result = c.decodeCBOR(raw);
      return {
        receipt: readControl(result.receipt, 'EncryptionRecoveryResult', receipt.certificate),
        plaintext: c.decodeCBOR(
          decryptCMS(result.encrypted, {
            privateKey: recipient.privateKey,
            subjectKeyIdentifier: c.keyID(recipient.publicKey),
          }),
        ),
      };
    },
  };
}

function resolverFor(f, adjust = (record) => record, trustDomainID = f.trustDomainID) {
  return exampleAuthorityResolver({
    trustDomainID,
    authorities: [...f.authorities, f.receipt].map((authority, index) =>
      adjust(
        {
          certificate: authority.certificate,
          roles: ['RECOVERY_AUTHORITY'],
        },
        authority,
        index,
      ),
    ),
  });
}

function approveRequest(f, request) {
  return f.authorities.map((authority) =>
    p.signCMS(
      {
        content: c.D('EncryptionRecoveryApproval', {
          requestHash: c.H('EncryptionRecoveryRequest', request),
          approved: true,
          expiresAt: request.expiresAt,
        }),
        certificate: authority.certificate,
      },
      authority.privateKey,
    ),
  );
}

function revokedStatus(f, authority) {
  return {
    authorityID: c.keyID(authority.publicKey),
    trustDomainID: f.trustDomainID,
    scope: 'AUTHORITY',
    status: 'REVOKED',
    publishedAt: f.request.issuedAt,
    nextUpdate: f.request.expiresAt + 300,
    effectiveTime: f.request.issuedAt + 60,
    compromiseStart: f.request.issuedAt - 1,
  };
}

test('recovery snapshots the approved caller request before asynchronous root loading', async (t) => {
  const f = fixture(t),
    approvedDomain = Buffer.from(f.request.trustDomainID),
    approvedRootID = Buffer.from(f.request.targetRootID),
    approvedSubjectID = Buffer.from(f.request.subjectID),
    unapprovedRoot = c.random();
  let entered, release;
  const ready = new Promise((resolve) => {
      entered = resolve;
    }),
    gate = new Promise((resolve) => {
      release = resolve;
    }),
    service = f.open(async ({ rootID, subjectID }) => {
      entered();
      await gate;
      return Buffer.from(
        c.equal(rootID, approvedRootID) && c.equal(subjectID, approvedSubjectID)
          ? f.root
          : unapprovedRoot,
      );
    }),
    pending = f.recover(service);
  try {
    await ready;
    f.request.targetRootID.fill(0x41);
    f.request.subjectID.fill(0x42);
    f.request.trustDomainID.fill(0x45);
    release();
    const { plaintext, receipt } = f.unpack(await pending);
    assert.deepEqual(plaintext.requestHash, f.approvedHash);
    assert.deepEqual(receipt.requestHash, f.approvedHash);
    assert.deepEqual(plaintext.trustDomainID, approvedDomain);
    assert.deepEqual(receipt.trustDomainID, approvedDomain);
    assert(c.equal(plaintext.root, f.root), 'Only the approved root may be released');
  } finally {
    release();
    await pending.catch(() => {});
  }
});

test('recovery isolates loader input mutations from the approved caller request', async (t) => {
  const f = fixture(t),
    original = c.dcbor(f.request),
    service = f.open(async (input) => {
      input.rootID.fill(0x43);
      input.subjectID.fill(0x44);
      input.trustDomainID.fill(0x45);
      input.purpose = 'SIGNING_VAULT_WRAP';
      await Promise.resolve();
      return Buffer.from(f.root);
    }),
    { plaintext, receipt } = f.unpack(await f.recover(service));
  assert.deepEqual(plaintext.root, f.root);
  assert.deepEqual(plaintext.requestHash, f.approvedHash);
  assert.deepEqual(receipt.requestHash, f.approvedHash);
  assert(c.equal(c.dcbor(f.request), original), 'Loader callbacks cannot rewrite approved input');
});

test('recovery refuses release when approvals expire during asynchronous root loading', async (t) => {
  const f = fixture(t);
  let clock = f.request.issuedAt,
    loadedRoot;
  t.mock.method(Date, 'now', () => clock * 1000);
  const service = f.open(async () => {
    await Promise.resolve();
    clock = f.request.expiresAt;
    loadedRoot = Buffer.from(f.root);
    return loadedRoot;
  });
  await assert.rejects(f.recover(service), /RECOVERY_(REQUEST|EXPIRED)|AUTHORITY_EXPIRED/);
  assert.equal(f.journal().result(f.operationID).status, 'UNKNOWN_EXECUTION');
  assert.deepEqual(loadedRoot, Buffer.alloc(32), 'Loaded root bytes must be erased on rejection');
});

test('recovery durable retry returns the saved ciphertext without loading the root again', async (t) => {
  const f = fixture(t, { durable: true });
  let calls = 0,
    entered,
    release;
  const ready = new Promise((resolve) => {
      entered = resolve;
    }),
    gate = new Promise((resolve) => {
      release = resolve;
    });
  let service = f.open(async () => {
    calls++;
    entered();
    await gate;
    return Buffer.from(f.root);
  });
  const pending = f.recover(service);
  try {
    await ready;
    await assert.rejects(f.recover(service), /UNKNOWN_EXECUTION/);
    assert.equal(calls, 1);
    release();
    const completed = await pending;
    assert.deepEqual(f.unpack(completed).plaintext.root, f.root);
    service = f.open(async () => {
      calls++;
      assert.fail('A completed recovery must not load the root after restart');
    });
    assert.equal(f.journal().result(f.operationID).status, 'COMPLETED');
    assert.deepEqual(await f.recover(service), completed);
    assert.equal(calls, 1);
    t.mock.method(Date, 'now', () => (f.request.expiresAt + 1) * 1000);
    assert.deepEqual(service.result(f.request.requestID), {
      status: 'COMPLETED',
      result: completed,
    });
    await assert.rejects(f.recover(service), /RECOVERY_REQUEST/);
    assert.equal(
      calls,
      1,
      'Expired requests may retrieve a completed result but cannot execute again',
    );
  } finally {
    release();
    await pending.catch(() => {});
  }
});

test('recovery completion failure stays uncertain after restart and never reloads the root', async (t) => {
  const f = fixture(t, { durable: true });
  let calls = 0,
    loadedRoot;
  let service = f.open(async () => {
    calls++;
    loadedRoot = Buffer.from(f.root);
    return loadedRoot;
  });
  f.journal().complete = () => {
    throw Error('injected completion write failure');
  };
  await assert.rejects(f.recover(service), /injected completion write failure/);
  assert.deepEqual(loadedRoot, Buffer.alloc(32));
  service = f.open(async () => {
    calls++;
    assert.fail('An uncertain recovery must not be silently repeated after restart');
  });
  assert.equal(f.journal().result(f.operationID).status, 'UNKNOWN_EXECUTION');
  await assert.rejects(f.recover(service), /UNKNOWN_EXECUTION/);
  assert.equal(calls, 1);
});

for (const index of [0, 2])
  test(`recovery rejects the wrong role for ${index === 0 ? 'an approver' : 'the result signer'} before loading a root`, async (t) => {
    const f = fixture(t);
    let calls = 0;
    const service = f.open(
      async () => {
        calls++;
        return Buffer.from(f.root);
      },
      {
        authorityResolver: resolverFor(f, (record, _authority, selected) =>
          selected === index ? { ...record, roles: ['ISSUER'] } : record,
        ),
      },
    );
    await assert.rejects(f.recover(service), { code: 'AUTHORITY_ROLE' });
    assert.equal(calls, 0);
    assert.equal(service.result(f.request.requestID), undefined);
  });

test('recovery cannot reuse an authority appointment for a different purpose or a compromised key', async (t) => {
  for (const condition of ['purpose', 'compromise']) {
    const f = fixture(t);
    let calls = 0;
    const service = f.open(
      async () => {
        calls++;
        return Buffer.from(f.root);
      },
      {
        authorityResolver: resolverFor(f, (record, authority, index) =>
          index !== 0
            ? record
            : {
                ...record,
                ...(condition === 'purpose'
                  ? { scopes: [{ trustDomainID: f.trustDomainID, purpose: 'SIGNING_VAULT_WRAP' }] }
                  : { status: revokedStatus(f, authority) }),
              },
        ),
      },
    );
    await assert.rejects(f.recover(service), {
      code: condition === 'purpose' ? 'AUTHORITY_SCOPE' : 'AUTHORITY_REVOKED',
    });
    assert.equal(calls, 0);
    assert.equal(service.result(f.request.requestID), undefined);
  }
});

test('revocation learned during root loading prevents release and leaves an uncertain operation', async (t) => {
  const f = fixture(t, { durable: true });
  let revoked = false,
    calls = 0,
    loadedRoot;
  const authorityResolver = resolverFor(f, (record, authority, index) =>
    index !== 0
      ? record
      : {
          ...record,
          status: () =>
            revoked
              ? revokedStatus(f, authority)
              : {
                  ...revokedStatus(f, authority),
                  status: 'GOOD',
                  effectiveTime: undefined,
                  compromiseStart: undefined,
                },
        },
  );
  let service = f.open(
    async () => {
      calls++;
      await Promise.resolve();
      revoked = true;
      loadedRoot = Buffer.from(f.root);
      return loadedRoot;
    },
    { authorityResolver },
  );
  await assert.rejects(f.recover(service), { code: 'AUTHORITY_REVOKED' });
  assert.deepEqual(loadedRoot, Buffer.alloc(32));
  assert.equal(service.result(f.request.requestID).status, 'UNKNOWN_EXECUTION');
  revoked = false;
  service = f.open(
    async () => {
      calls++;
      assert.fail('An uncertain recovery cannot load again');
    },
    { authorityResolver },
  );
  await assert.rejects(f.recover(service), { code: 'UNKNOWN_EXECUTION' });
  assert.equal(calls, 1);
});

test('completed recovery result queries remain available after authority withdrawal without reexecution', async (t) => {
  const f = fixture(t, { durable: true });
  let calls = 0;
  let service = f.open(async () => {
    calls++;
    return Buffer.from(f.root);
  });
  const completed = await f.recover(service);
  service = f.open(
    async () => {
      calls++;
      assert.fail('Result lookup must not load a root');
    },
    {
      authorityResolver: () => assert.fail('Result lookup must not reauthorize an execution'),
    },
  );
  t.mock.method(Date, 'now', () => (f.request.expiresAt + 1) * 1000);
  assert.deepEqual(service.result(f.request.requestID), { status: 'COMPLETED', result: completed });
  assert.equal(calls, 1);
  assert.deepEqual(f.unpack(completed).plaintext.trustDomainID, f.trustDomainID);
  assert.deepEqual(f.unpack(completed).receipt.trustDomainID, f.trustDomainID);
});

test('recovery requests and saved results stay isolated across trust domains sharing a journal', async (t) => {
  const f = fixture(t),
    otherDomain = c.random();
  let calls = 0;
  const service = f.open(async () => {
      calls++;
      return Buffer.from(f.root);
    }),
    completed = await f.recover(service),
    other = new EncryptionRecoveryService({
      ...service,
      trustDomainID: otherDomain,
      authorityResolver: resolverFor(f, undefined, otherDomain),
    });
  assert.equal(other.result(f.request.requestID), undefined);
  await assert.rejects(f.recover(other), { code: 'RECOVERY_REQUEST' });
  assert.equal(calls, 1);
  const request = { ...f.request, trustDomainID: otherDomain },
    otherResult = await other.recover(request, approveRequest(f, request), f.recipient.publicKey);
  assert.equal(calls, 2);
  assert.deepEqual(service.result(f.request.requestID).result, completed);
  assert.deepEqual(other.result(request.requestID).result, otherResult);
  assert.deepEqual(f.unpack(otherResult).plaintext.trustDomainID, otherDomain);
  assert.deepEqual(f.unpack(otherResult).receipt.trustDomainID, otherDomain);
});

test('the recovery receipt certificate cannot authorize a different result signing key', async (t) => {
  const f = fixture(t);
  let calls = 0;
  const service = f.open(
    async () => {
      calls++;
      return Buffer.from(f.root);
    },
    {
      privateKey: c.generate('ml-dsa-87').privateKey,
    },
  );
  await assert.rejects(f.recover(service), { code: 'RECOVERY_RESULT_KEY_BINDING' });
  assert.equal(calls, 0);
  assert.equal(service.result(f.request.requestID), undefined);
});

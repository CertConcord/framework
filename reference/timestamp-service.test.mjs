import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import { Journal } from './state.mjs';
import { TimestampService, TimestampResponseVerifier } from './timestamp-service.mjs';
import { parseTimestampResponse } from './timestamp-protocol.mjs';
import {
  O,
  epoch,
  applicationFixture,
  deferred,
  operation,
  clone,
  assertVerdict,
  cmsView,
} from './timestamp-application-fixtures.mjs';

let f;
before(() => {
  f = applicationFixture();
});
after(() => f?.close());
function harness(t, overrides = {}) {
  const journal = overrides.journal ?? new Journal();
  if (!overrides.journal) t.after(() => journal.close());
  const state = {
    context: f.context(),
    reading: {
      sourceID: 'fixture-clock',
      genTime: epoch + 20,
      accuracyMicros: 0,
      synchronized: true,
    },
    signs: 0,
    clocks: 0,
    contexts: 0,
    signatures: [],
    ...overrides.state,
  };
  const authority = overrides.authority ?? f.tsa;
  const options = {
    journal,
    serviceID: overrides.serviceID ?? 'fixture-service',
    certificate: Buffer.from(authority.der),
    certificates: [Buffer.from(f.root.der)],
    signer: {
      publicKeyDER: c.spki(authority.publicKey),
      sign: async (tbs, metadata) => {
        state.signs++;
        assert.equal(journal.depth ?? 0, 0, 'external signer runs outside SQLite transaction');
        const signature = c.sign(tbs, authority.privateKey);
        state.signatures.push(Buffer.from(signature));
        return overrides.sign ? overrides.sign(tbs, metadata, signature, state) : signature;
      },
    },
    policyOID: O.policy,
    clock: {
      read: async () => {
        state.clocks++;
        return state.reading;
      },
    },
    readContext: async () => {
      state.contexts++;
      return overrides.readContext ? overrides.readContext(state) : state.context;
    },
  };
  return { service: new TimestampService(options), journal, state, options };
}
const persisted = (journal, op) => {
  const row = journal.db.prepare('SELECT value FROM state WHERE id=?').get(op.toString('hex'));
  return row && c.decodeCBOR(row.value);
};

for (const certReq of [true, false])
  test(`service emits a standard verifiable response for certReq=${certReq}`, async (t) => {
    const h = harness(t),
      requestDER = f.request({ certReq });
    const result = await h.service.issue({ operationID: operation(1), requestDER });
    assert.equal(result.state, 'COMPLETED');
    assertVerdict(result.verification, 'VALID');
    assert.equal(h.state.signs, 1);
    const token = parseTimestampResponse(result.responseDER).tokenDER;
    assert.equal(cmsView(token).certificates.length, certReq ? 2 : 0);
    assert.deepEqual(
      cmsView(token)
        .signed.map((node) => c.oidText(node.children[0]))
        .sort(),
      [O.contentType, O.messageDigest, O.ess].sort(),
    );
    assertVerdict(
      await new TimestampResponseVerifier({ readContext: async () => f.context() }).verify({
        requestDER,
        responseDER: result.responseDER,
      }),
      'VALID',
    );
    if (certReq) f.checkOpenSSL(token);
  });

test('service accepts a standard nonce-free request without asserting request freshness', async (t) => {
  const h = harness(t),
    result = await h.service.issue({
      operationID: operation(2),
      requestDER: f.request({ nonce: null }),
    });
  assertVerdict(result.verification, 'VALID');
  assert.equal(result.verification.nonceBound, false);
});

test('constructor binds the actual signing public key to the configured TSU certificate', (t) => {
  const h = harness(t);
  assert.throws(
    () =>
      new TimestampService({
        ...h.options,
        signer: { ...h.options.signer, publicKeyDER: c.spki(f.successor.publicKey) },
      }),
    { code: 'TSP_SIGNER_KEY_BINDING', overall: 'INVALID' },
  );
});

test('a callback signature from another key becomes a retained standard rejection', async (t) => {
  const h = harness(t, { sign: async (tbs) => c.sign(tbs, f.successor.privateKey) });
  const result = await h.service.issue({ operationID: operation(3), requestDER: f.request() });
  assert.equal(result.state, 'COMPLETED');
  assertVerdict(result.verification, 'INVALID');
  assert.equal(parseTimestampResponse(result.responseDER).status, 2);
  assert.deepEqual(parseTimestampResponse(result.responseDER).failureBits, [25]);
});

test('unaccepted policy is durably rejected before clock or signer callbacks', async (t) => {
  const h = harness(t),
    requestDER = f.request({ policyOID: '1.2.3.4' }),
    op = operation(4);
  const first = await h.service.issue({ operationID: op, requestDER });
  assert.equal(parseTimestampResponse(first.responseDER).status, 2);
  assert.deepEqual(parseTimestampResponse(first.responseDER).failureBits, [15]);
  const second = await h.service.issue({ operationID: op, requestDER });
  assert.deepEqual(second.responseDER, first.responseDER);
  assert.equal(h.state.signs + h.state.clocks + h.state.contexts, 0);
});

test('completed requests preserve exact randomized signature bytes without fresh callbacks', async (t) => {
  const h = harness(t),
    requestDER = f.request(),
    op = operation(5);
  const first = await h.service.issue({ operationID: op, requestDER });
  const expected = Buffer.from(first.responseDER),
    counts = [h.state.signs, h.state.clocks, h.state.contexts];
  first.responseDER.fill(0);
  first.verification.tokenDER.fill(0);
  first.operationID.fill(0);
  const lookup = h.service.result(op);
  assert.deepEqual(lookup.responseDER, expected);
  lookup.responseDER.fill(0);
  assert.deepEqual((await h.service.issue({ operationID: op, requestDER })).responseDER, expected);
  assert.deepEqual([h.state.signs, h.state.clocks, h.state.contexts], counts);
  await assert.rejects(
    h.service.issue({ operationID: op, requestDER: f.request({ nonce: 99n }) }),
    { code: 'IDEMPOTENCY_CONFLICT' },
  );
});

test('concurrent duplicate requests commit one serial and invoke the signer once', async (t) => {
  const entered = deferred(),
    release = deferred();
  const h = harness(t, {
    sign: async (_tbs, _metadata, signature) => {
      entered.resolve();
      await release.promise;
      return signature;
    },
  });
  const requestDER = f.request(),
    op = operation(6);
  const first = h.service.issue({ operationID: op, requestDER });
  await entered.promise;
  const retry = await h.service.issue({ operationID: op, requestDER });
  assert.equal(retry.state, 'UNKNOWN_EXECUTION');
  assert.equal(h.state.signs, 1);
  const reserved = persisted(h.journal, op);
  assert.equal(reserved.serial, '1');
  release.resolve();
  assertVerdict((await first).verification, 'VALID');
  assert.equal(h.state.signs, 1);
});

test('unknown signer outcome never repeats signing and reconciles the original signature', async (t) => {
  const h = harness(t, {
    sign: async () => {
      throw Error('connection lost after remote signing');
    },
  });
  const op = operation(7),
    requestDER = f.request();
  assert.equal((await h.service.issue({ operationID: op, requestDER })).state, 'UNKNOWN_EXECUTION');
  assert.equal((await h.service.issue({ operationID: op, requestDER })).state, 'UNKNOWN_EXECUTION');
  assert.equal(h.state.signs, 1);
  const reserved = persisted(h.journal, op);
  await assert.rejects(
    h.service.reconcile({
      operationID: op,
      signature: c.sign(reserved.tbs, f.successor.privateKey),
    }),
    { code: 'CADES_SIGNATURE_INVALID' },
  );
  const result = await h.service.reconcile({ operationID: op, signature: h.state.signatures[0] });
  assertVerdict(result.verification, 'VALID');
  assert.equal(persisted(h.journal, op).serial, reserved.serial);
  assert.equal(h.state.signs, 1);
});

test('nonzero accuracy retains the signed candidate until actual knowledge covers its upper bound', async (t) => {
  const h = harness(t);
  h.state.context.knowledgeTime = epoch + 20;
  h.state.reading.accuracyMicros = 500000;
  const op = operation(8),
    requestDER = f.request();
  const pending = await h.service.issue({ operationID: op, requestDER });
  assert.equal(pending.state, 'PENDING');
  assert.equal(pending.responseDER, undefined);
  assertVerdict(pending.verification, 'INDETERMINATE', 'TSP_NOT_YET_OBSERVABLE');
  const candidate = clone(persisted(h.journal, op));
  assert.equal(candidate.phase, 'SIGNED_PENDING');
  h.state.context.knowledgeTime++;
  const result = await h.service.reconcile({ operationID: op });
  assertVerdict(result.verification, 'VALID');
  assert.deepEqual(parseTimestampResponse(result.responseDER).tokenDER, candidate.tokenDER);
  assert.equal(persisted(h.journal, op).serial, candidate.serial);
  assert.equal(h.state.signs, 1);
});

test('clock withdrawal while signing prevents release of the already signed candidate', async (t) => {
  const h = harness(t, {
    sign: async (_tbs, _metadata, signature, state) => {
      state.context.clockAdmission.status = 'WITHDRAWN';
      return signature;
    },
  });
  const op = operation(9),
    result = await h.service.issue({ operationID: op, requestDER: f.request() });
  assert.equal(result.state, 'PENDING');
  assert.equal(result.responseDER, undefined);
  assertVerdict(result.verification, 'INDETERMINATE', 'TSP_CLOCK_NOT_ADMITTED');
  assert(persisted(h.journal, op).tokenDER);
  assert.equal(h.state.signs, 1);
});

test('authority withdrawal while signing prevents a successful response and retains audit bytes', async (t) => {
  const h = harness(t, {
    sign: async (_tbs, _metadata, signature, state) => {
      const base = state.context.policy.authorityResolver;
      state.context.policy.authorityResolver = (query) =>
        query.role === 'TIMESTAMP_AUTHORITY'
          ? { overall: 'INVALID', reason: 'TEST_AUTHORITY_WITHDRAWN' }
          : base(query);
      return signature;
    },
  });
  const op = operation(10),
    result = await h.service.issue({ operationID: op, requestDER: f.request() });
  assert.equal(result.state, 'COMPLETED');
  assertVerdict(result.verification, 'INVALID', 'TEST_AUTHORITY_WITHDRAWN');
  assert.equal(parseTimestampResponse(result.responseDER).status, 2);
  assert(persisted(h.journal, op).tokenDER);
});

for (const [name, change] of [
  [
    'unknown source',
    (s) => {
      s.reading.sourceID = 'unadmitted';
    },
  ],
  [
    'unsynchronized source',
    (s) => {
      s.reading.synchronized = false;
    },
  ],
  [
    'withdrawn admission',
    (s) => {
      s.context.clockAdmission.status = 'WITHDRAWN';
    },
  ],
  [
    'accuracy beyond admission',
    (s) => {
      s.context.clockAdmission.maxAccuracyMicros = 1;
      s.reading.accuracyMicros = 2;
    },
  ],
  [
    'interval crosses admission',
    (s) => {
      s.context.clockAdmission.validUntil = epoch + 20;
    },
  ],
])
  test(`${name} is rejected before signing`, async (t) => {
    const h = harness(t);
    change(h.state);
    const result = await h.service.issue({ operationID: operation(11), requestDER: f.request() });
    assert.equal(parseTimestampResponse(result.responseDER).status, 2);
    assert.deepEqual(parseTimestampResponse(result.responseDER).failureBits, [14]);
    assert.equal(h.state.signs, 0);
  });

test('knowledge and source-clock rollback are unavailable rather than clamped', async (t) => {
  const h = harness(t);
  assertVerdict(
    (await h.service.issue({ operationID: operation(12), requestDER: f.request() })).verification,
    'VALID',
  );
  h.state.reading.genTime--;
  const rollback = await h.service.issue({
    operationID: operation(13),
    requestDER: f.request({ nonce: 43n }),
  });
  assertVerdict(rollback.verification, 'INDETERMINATE', 'TSP_CLOCK_ROLLBACK');
  h.state.reading.genTime += 2;
  h.state.context.knowledgeTime--;
  const knowledge = await h.service.issue({
    operationID: operation(14),
    requestDER: f.request({ nonce: 44n }),
  });
  assertVerdict(knowledge.verification, 'INDETERMINATE', 'TSP_CLOCK_ROLLBACK');
  assert.equal(h.state.signs, 1);
});

test('caller and signer buffer mutation cannot rewrite reserved input or the certificate', async (t) => {
  const entered = deferred(),
    release = deferred();
  const h = harness(t, {
    readContext: async (state) => {
      if (state.contexts === 1) {
        entered.resolve();
        await release.promise;
      }
      return state.context;
    },
    sign: async (tbs, metadata, signature) => {
      tbs.fill(0);
      metadata.operationID.fill(0);
      metadata.certificateID.fill(0);
      return signature;
    },
  });
  const requestDER = f.request(),
    expected = Buffer.from(requestDER),
    op = operation(15),
    expectedID = Buffer.from(op);
  const pending = h.service.issue({ operationID: op, requestDER });
  await entered.promise;
  requestDER.fill(0);
  op.fill(0);
  h.options.certificate.fill(0);
  h.options.certificates[0].fill(0);
  h.options.signer.publicKeyDER.fill(0);
  release.resolve();
  const result = await pending;
  assertVerdict(result.verification, 'VALID');
  assert.deepEqual(persisted(h.journal, expectedID).requestDER, expected);
  assert.deepEqual(result.operationID, expectedID);
});

test('an operation reserved before await remains bound to its original issuing certificate', async (t) => {
  const entered = deferred(),
    release = deferred(),
    journal = new Journal();
  t.after(() => journal.close());
  const h = harness(t, {
    journal,
    readContext: async (state) => {
      entered.resolve();
      await release.promise;
      return state.context;
    },
  });
  const op = operation(16),
    requestDER = f.request(),
    pending = h.service.issue({ operationID: op, requestDER });
  await entered.promise;
  const other = harness(t, { journal, authority: f.successor });
  await assert.rejects(other.service.issue({ operationID: op, requestDER }), {
    code: 'TSP_RESERVED_ISSUER_BINDING',
  });
  assert.equal(other.state.signs, 0);
  release.resolve();
  assertVerdict((await pending).verification, 'VALID');
});

test('service serials and completed bytes survive restart and configured TSU rotation', async (t) => {
  const path = f.file('application-service.sqlite'),
    op = operation(17),
    requestDER = f.request();
  let journal = new Journal(path),
    h = harness(t, { journal });
  const first = await h.service.issue({ operationID: op, requestDER });
  const firstSerial = c.intValue(
    c.parseDER(cmsView(parseTimestampResponse(first.responseDER).tokenDER).embeddedContent)
      .children[3],
  );
  journal.close();
  journal = new Journal(path);
  t.after(() => journal.close());
  h = harness(t, { journal, authority: f.successor });
  assert.deepEqual(h.service.result(op).responseDER, first.responseDER);
  assert.equal(h.state.contexts + h.state.signs, 0);
  const second = await h.service.issue({
    operationID: operation(18),
    requestDER: f.request({ nonce: 43n }),
  });
  assertVerdict(second.verification, 'VALID');
  const secondSerial = c.intValue(
    c.parseDER(cmsView(parseTimestampResponse(second.responseDER).tokenDER).embeddedContent)
      .children[3],
  );
  assert.equal(secondSerial, firstSerial + 1n);
});

test('a failed signed-candidate write keeps an uncertain operation and requires exact reconciliation', async (t) => {
  const h = harness(t),
    original = h.journal.put.bind(h.journal);
  let failOnce = true;
  h.journal.put = (namespace, id, value, revision) => {
    if (failOnce && value.phase === 'SIGNED_PENDING') {
      failOnce = false;
      throw Error('simulated write failure');
    }
    return original(namespace, id, value, revision);
  };
  const op = operation(19),
    requestDER = f.request();
  const first = await h.service.issue({ operationID: op, requestDER });
  assert.equal(first.state, 'UNKNOWN_EXECUTION');
  assert.equal(first.responseDER, undefined);
  assert.equal((await h.service.issue({ operationID: op, requestDER })).state, 'UNKNOWN_EXECUTION');
  assert.equal(h.state.signs, 1);
  assertVerdict(
    (await h.service.reconcile({ operationID: op, signature: h.state.signatures[0] })).verification,
    'VALID',
  );
});

test('failed final completion cannot escape as success or cause a replacement signature', async (t) => {
  const h = harness(t),
    original = h.journal.reconcile.bind(h.journal);
  let failOnce = true;
  h.journal.reconcile = (...args) => {
    if (failOnce) {
      failOnce = false;
      throw Error('simulated completion commit failure');
    }
    return original(...args);
  };
  const op = operation(20),
    requestDER = f.request();
  const first = await h.service.issue({ operationID: op, requestDER });
  assert.equal(first.state, 'UNKNOWN_EXECUTION');
  assert.equal(first.responseDER, undefined);
  assert.equal(h.state.signs, 1);
  const result = await h.service.reconcile({ operationID: op });
  assertVerdict(result.verification, 'VALID');
  assert.equal(h.state.signs, 1);
});

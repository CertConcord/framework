import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import * as c from './core.mjs';
import { Journal } from './state.mjs';
import { TimestampService, TimestampClient } from './timestamp-service.mjs';
import { parseTimestampResponse } from './timestamp-protocol.mjs';
import {
  O,
  epoch,
  applicationFixture,
  operation,
  assertVerdict,
  cmsView,
} from './timestamp-application-fixtures.mjs';

let f;
before(() => {
  f = applicationFixture();
});
after(() => f?.close());
function crash(mode) {
  const requestDER = f.request(),
    context = f.context({ knowledgeTime: epoch + 20 });
  delete context.policy.authorityResolver;
  const authorities = [f.root, f.tsa, f.successor].map((authority) => ({
    mode: 'CERTIFICATE',
    certificate: authority.der,
    knownAt: epoch - 100,
    validFrom: epoch - 100,
    validUntil: epoch + 100000,
    roles: authority === f.root ? ['ISSUER', 'STATUS_AUTHORITY'] : ['TIMESTAMP_AUTHORITY'],
    scopes: [f.scope],
    status: {
      authorityID: c.keyID(authority.publicKey),
      trustDomainID: f.domain,
      scope: 'AUTHORITY',
      status: 'GOOD',
      publishedAt: epoch - 100,
      nextUpdate: epoch + 100000,
    },
  }));
  const config = {
    journalPath: f.file(`crash-${mode}.sqlite`),
    externalResultPath: f.file(`external-${mode}.cbor`),
    operationID: operation(mode === 'sign' ? 1 : 2),
    requestDER,
    context,
    authorities,
    certificate: f.tsa.der,
    certificates: [f.root.der],
    policyOID: O.policy,
    publicKeyDER: c.spki(f.tsa.publicKey),
    privateKeyDER: f.tsa.privateKey.export({ type: 'pkcs8', format: 'der' }),
    reading: {
      sourceID: 'fixture-clock',
      genTime: epoch + 20,
      accuracyMicros: 0,
      synchronized: true,
    },
    responseDER: f.response(requestDER),
  };
  const file = f.file(`crash-${mode}.cbor`);
  writeFileSync(file, c.dcbor(config));
  const child = spawnSync(
    process.execPath,
    [fileURLToPath(new URL('./timestamp-crash-fixture.mjs', import.meta.url)), file, mode],
    { encoding: 'utf8', timeout: 10000 },
  );
  assert.equal(child.error, undefined);
  assert.notEqual(child.status, 0);
  if (process.platform !== 'win32') assert.equal(child.signal, 'SIGKILL', child.stderr);
  return { config, external: c.decodeCBOR(readFileSync(config.externalResultPath)) };
}

test('process death after external signing preserves the reserved serial and forbids an automatic second signature', async (t) => {
  const { config, external } = crash('sign'),
    journal = new Journal(config.journalPath);
  t.after(() => journal.close());
  let signs = 0,
    contexts = 0;
  const service = new TimestampService({
    journal,
    serviceID: 'crash-service',
    certificate: f.tsa.der,
    certificates: [f.root.der],
    policyOID: O.policy,
    signer: {
      publicKeyDER: c.spki(f.tsa.publicKey),
      sign: async () => {
        signs++;
        throw Error('must not dispatch');
      },
    },
    clock: { read: async () => config.reading },
    readContext: async () => {
      contexts++;
      return f.context({ knowledgeTime: epoch + 20 });
    },
  });
  assert.equal(service.result(config.operationID).state, 'UNKNOWN_EXECUTION');
  assert.equal(
    (await service.issue({ operationID: config.operationID, requestDER: config.requestDER })).state,
    'UNKNOWN_EXECUTION',
  );
  assert.equal(signs + contexts, 0);
  const result = await service.reconcile({
    operationID: config.operationID,
    signature: external.signature,
  });
  assertVerdict(result.verification, 'VALID');
  const token = cmsView(parseTimestampResponse(result.responseDER).tokenDER);
  assert.deepEqual(token.signature, external.signature);
  assert.equal(
    c.intValue(c.parseDER(token.embeddedContent).children[3]).toString(),
    external.serial,
  );
  assert.equal(signs, 0);
});

test('process death after remote response creation preserves one dispatch and accepts only explicit reconciliation', async (t) => {
  const { config, external } = crash('send'),
    journal = new Journal(config.journalPath);
  t.after(() => journal.close());
  let sends = 0,
    contexts = 0;
  const client = new TimestampClient({
    journal,
    clientID: 'crash-client',
    send: async () => {
      sends++;
      throw Error('must not dispatch');
    },
    readContext: async () => {
      contexts++;
      return f.context({ knowledgeTime: epoch + 20 });
    },
  });
  assert.deepEqual(external.requestDER, config.requestDER);
  assert.equal(client.result(config.operationID).state, 'UNKNOWN_EXECUTION');
  assert.equal(
    (await client.request({ operationID: config.operationID, requestDER: config.requestDER }))
      .state,
    'UNKNOWN_EXECUTION',
  );
  assert.equal(sends + contexts, 0);
  const result = await client.reconcile({
    operationID: config.operationID,
    responseDER: external.responseDER,
  });
  assertVerdict(result.verification, 'VALID');
  assert.deepEqual(result.responseDER, external.responseDER);
  assert.equal(sends, 0);
});

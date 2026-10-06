import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { PostgresJournal } from './postgres.mjs';
import { IndexedMerkleLog } from './merkle.mjs';
import { runDemo } from '../demo.mjs';
import { runFoundationDemo } from '../foundation-demo.mjs';

// The dedicated CI job must provide a reachable PostgreSQL database; no skip or emulation path.
assert(process.env.CERTCONCORD_PG_HOST, 'CERTCONCORD_PG_HOST is required');
const connection = {
  host: process.env.CERTCONCORD_PG_HOST,
  port: Number(process.env.CERTCONCORD_PG_PORT ?? 5432),
  user: process.env.CERTCONCORD_PG_USER ?? 'certconcord_test',
  password: process.env.CERTCONCORD_PG_PASSWORD,
  database: process.env.CERTCONCORD_PG_DATABASE ?? 'postgres',
};
const tenant = 'test-' + randomUUID();
const config = { connection, tenant, allowLoopback: true };
const child = (mode, arg) =>
  new Promise((resolve, reject) => {
    const p = spawn(
      process.execPath,
      ['storage/concurrency-worker.mjs', mode, ...(arg ? [arg] : [])],
      {
        env: { ...process.env, CERTCONCORD_TEST_DB: JSON.stringify(config) },
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
      },
    );
    let out = '',
      err = '';
    p.stdout.on('data', (x) => (out += x));
    p.stderr.on('data', (x) => (err += x));
    p.on('error', reject);
    p.on('close', (code) =>
      code === 0 ? resolve(out) : reject(Error('Test child failed: ' + err)),
    );
  });
test('PostgreSQL atomicity, competing processes, crash rollback and immutable outcomes', async () => {
  const a = new PostgresJournal(config),
    b = new PostgresJournal(config);
  try {
    a.put('state', 'key', { n: 1 });
    assert.equal(b.get('state', 'key').value.n, 1);
    assert.throws(() => b.put('state', 'key', { n: 2 }), /CAS_CONFLICT/);
    assert.throws(
      () =>
        a.transaction(() => {
          a.put('state', 'key', { n: 3 }, 0);
          throw Error('rollback');
        }),
      /rollback/,
    );
    assert.equal(b.get('state', 'key').value.n, 1);
    a.transaction(() => {
      assert.throws(
        () =>
          a.transaction(() => {
            a.put('state', 'nested', { n: 4 });
            throw Error('nested');
          }),
        /nested/,
      );
      a.put('state', 'outer', { n: 5 });
    });
    assert.equal(b.get('state', 'nested'), undefined);
    assert.equal(b.get('state', 'outer').value.n, 5);
    const nonce = a.issueNonce('test');
    assert.deepEqual((await Promise.all([child('nonce', nonce), child('nonce', nonce)])).sort(), [
      'CONSUMED',
      'REPLAY',
    ]);
    await Promise.all([child('append', 'a'), child('append', 'b')]);
    assert.equal(new IndexedMerkleLog(a, 'race').head().size, 24);
    await child('crash');
    assert.equal(b.get('crash', 'uncommitted'), undefined);
    a.reserve('operation', Buffer.from('digest'));
    a.uncertain('operation');
    assert.equal(b.reserve('operation', Buffer.from('digest')).status, 'UNKNOWN_EXECUTION');
    assert.throws(() => b.complete('operation', Buffer.from('retry')), /OPERATION_STATE/);
    a.reserve('complete', Buffer.from('digest'));
    a.complete('complete', Buffer.from('result'));
    assert.deepEqual(b.result('complete'), { status: 'COMPLETED', result: Buffer.from('result') });
    assert.throws(() => b.complete('complete', Buffer.from('changed')), /OPERATION_STATE/);
  } finally {
    a.close();
    b.close();
  }
  const reopened = new PostgresJournal(config);
  assert.equal(reopened.result('operation').status, 'UNKNOWN_EXECUTION');
  reopened.close();
});
test('PostgreSQL backs complete MTC and signer-mdoc issuance, activation and verification', async () => {
  const factory = (prefix) => (role) =>
    new PostgresJournal({ ...config, tenant: tenant + ':' + prefix + ':' + role });
  assert.equal(
    (await runDemo({ journalFactory: factory('mtc') })).verification.overall,
    'VALID_UNDER_POLICY',
  );
  assert.equal(
    (await runFoundationDemo({ journalFactory: factory('mdoc'), identityType: 'photoid' }))
      .verification.overall,
    'VALID_UNDER_POLICY',
  );
  assert.equal(
    (
      await runFoundationDemo({
        journalFactory: factory('passkey'),
        identityType: 'custom',
        documentKeyMode: 'PASSKEY_KEY',
        activationMode: 'HUMAN_WEBAUTHN',
      })
    ).verification.overall,
    'VALID_UNDER_POLICY',
  );
  for (const format of ['CMS', 'MDOC']) {
    const options = {
      executionBinding: true,
      activationMode: 'HUMAN_WEBAUTHN',
      journalFactory: factory('execution-' + format),
    };
    const result = format === 'CMS' ? await runDemo(options) : await runFoundationDemo(options);
    assert.equal(result.verification.overall, 'VALID_UNDER_POLICY');
    assert.equal(result.verification.execution.enforcement, 'BROKER_ENFORCED');
  }
});
test('PostgreSQL lock timeout fails closed without leaving an idle transaction', async () => {
  const lock = new pg.Client(connection);
  await lock.connect();
  await lock.query('BEGIN');
  await lock.query('SELECT pg_advisory_xact_lock(hashtextextended($1,771927))', [tenant]);
  const blocked = new PostgresJournal({ ...config, timeoutMs: 200 });
  try {
    assert.throws(() => blocked.put('timeout', 'key', { n: 1 }), /POSTGRES_55P03|POSTGRES_57014/);
  } finally {
    await lock.query('ROLLBACK');
    await lock.end();
  }
  blocked.put('timeout', 'key', { n: 2 });
  assert.equal(blocked.get('timeout', 'key').value.n, 2);
  blocked.close();
});

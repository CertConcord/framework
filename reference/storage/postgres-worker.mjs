import { parentPort, workerData } from 'node:worker_threads';
import { serialize } from 'node:v8';
import pg from 'pg';

const { connection, tenant, timeoutMs } = workerData;
const client = new pg.Client({
  ...connection,
  connectionTimeoutMillis: timeoutMs,
  statement_timeout: timeoutMs,
  lock_timeout: timeoutMs,
  idle_in_transaction_session_timeout: timeoutMs * 2,
});
// Errors are returned as codes; connection strings and SQL parameter values never cross the boundary.
client.on('error', () => {});
const connected = client.connect();
const query = (sql, values = []) => client.query(sql, values);
const sql = {
  get: 'SELECT revision,value FROM certconcord_storage.state WHERE tenant=$1 AND namespace=$2 AND id=$3',
  list: 'SELECT id FROM certconcord_storage.state WHERE tenant=$1 AND namespace=$2 ORDER BY id',
  put: `INSERT INTO certconcord_storage.state VALUES($1,$2,$3,$4,$5)
    ON CONFLICT(tenant,namespace,id) DO UPDATE SET revision=EXCLUDED.revision,value=EXCLUDED.value`,
  issueNonce: 'INSERT INTO certconcord_storage.nonce VALUES($1,$2,$3,$4,false)',
  consumeNonce:
    'UPDATE certconcord_storage.nonce SET consumed=true WHERE tenant=$1 AND scope=$2 AND value=$3 AND consumed=false AND expires >= $4',
  operation: 'SELECT digest,status,result FROM certconcord_storage.operations WHERE tenant=$1 AND id=$2',
  reserve: "INSERT INTO certconcord_storage.operations VALUES($1,$2,$3,'DISPATCHED',NULL,$4)",
  complete:
    "UPDATE certconcord_storage.operations SET status='COMPLETED',result=$3,updated=$4 WHERE tenant=$1 AND id=$2 AND status='DISPATCHED'",
  uncertain:
    "UPDATE certconcord_storage.operations SET status='UNKNOWN_EXECUTION',updated=$3 WHERE tenant=$1 AND id=$2 AND status='DISPATCHED'",
  reconcile:
    "UPDATE certconcord_storage.operations SET status='COMPLETED',result=$3,updated=$4 WHERE tenant=$1 AND id=$2 AND status IN ('DISPATCHED','UNKNOWN_EXECUTION')",
};
parentPort.on('message', async ({ op, args, memory }) => {
  const header = new Int32Array(memory, 0, 2);
  let response;
  try {
    await connected;
    if (op === 'open')
      response =
        (await query('SELECT version FROM certconcord_storage.schema_version WHERE version=1')).rows
          .length === 1;
    else if (op === 'begin') {
      await query('BEGIN');
      await query("SELECT set_config('synchronous_commit','on',true)");
      // Every mutation uses this transaction-scoped lock, including nonce and operation updates.
      await query('SELECT pg_advisory_xact_lock(hashtextextended($1, 771927))', [tenant]);
      response = true;
    } else if (['commit', 'rollback'].includes(op)) {
      await query(op.toUpperCase());
      response = true;
    } else if (['savepoint', 'release', 'rollbackTo'].includes(op)) {
      if (!Number.isSafeInteger(args[0]) || args[0] < 1) throw Error('SAVEPOINT');
      await query(
        {
          savepoint: 'SAVEPOINT',
          release: 'RELEASE SAVEPOINT',
          rollbackTo: 'ROLLBACK TO SAVEPOINT',
        }[op] +
          ' certconcord_' +
          args[0],
      );
      response = true;
    } else if (op === 'close') {
      await client.end();
      response = true;
    } else {
      if (!Object.hasOwn(sql, op)) throw Error('RPC_OPERATION');
      const result = await query(sql[op], [
        tenant,
        ...args.map((a) => (a instanceof Uint8Array ? Buffer.from(a) : a)),
      ]);
      response = { rows: result.rows, changes: result.rowCount };
    }
    response = { ok: true, value: response };
  } catch (error) {
    if (op === 'begin') {
      try {
        await query('ROLLBACK');
      } catch {}
    }
    response = {
      ok: false,
      code: /^[0-9A-Z]{5}$/.test(error.code ?? '') ? error.code : 'UNAVAILABLE',
    };
  }
  let bytes = serialize(response);
  if (bytes.length > memory.byteLength - 8)
    bytes = serialize({ ok: false, code: 'RESPONSE_LIMIT' });
  new Uint8Array(memory, 8, bytes.length).set(bytes);
  Atomics.store(header, 1, bytes.length);
  Atomics.store(header, 0, 1);
  Atomics.notify(header, 0);
});

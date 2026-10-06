import { Worker } from 'node:worker_threads';
import { deserialize } from 'node:v8';
import {
  dcbor,
  decodeCBOR,
  requireThat,
  b64u,
  random,
  now,
  equal,
  ProtocolError,
} from '../core.mjs';

// The synchronous journal contract is used from a dedicated service worker, not a shared HTTP event loop.
export class PostgresJournal {
  constructor({ connection, tenant, timeoutMs = 10000, allowLoopback = false }) {
    requireThat(
      connection && !connection.connectionString && typeof connection.host === 'string',
      'POSTGRES_EXPLICIT_CONNECTION',
    );
    requireThat(/^[a-zA-Z0-9._:-]{1,128}$/.test(tenant), 'POSTGRES_TENANT');
    requireThat(
      Number.isInteger(timeoutMs) && timeoutMs >= 100 && timeoutMs <= 60000,
      'POSTGRES_TIMEOUT',
    );
    const loopback = ['127.0.0.1', '::1'].includes(connection.host);
    requireThat(
      (allowLoopback && loopback) ||
        (connection.ssl && connection.ssl.rejectUnauthorized !== false),
      'POSTGRES_TLS_REQUIRED',
    );
    this.timeoutMs = timeoutMs;
    this.memory = new SharedArrayBuffer(16 * 1024 * 1024 + 1024);
    this.worker = new Worker(new URL('./postgres-worker.mjs', import.meta.url), {
      workerData: { connection, tenant, timeoutMs },
    });
    this.worker.on('error', () => {
      this.poisoned = true;
    });
    this.depth = 0;
    try {
      requireThat(this.rpc('open'), 'POSTGRES_SCHEMA');
    } catch (error) {
      this.worker.terminate();
      throw error;
    }
  }
  rpc(op, args = []) {
    requireThat(!this.poisoned && !this.closed, 'JOURNAL_UNAVAILABLE');
    const memory = this.memory,
      header = new Int32Array(memory, 0, 2);
    Atomics.store(header, 0, 0);
    this.worker.postMessage({ op, args, memory });
    if (Atomics.wait(header, 0, 0, this.timeoutMs + 1000) === 'timed-out') {
      this.poisoned = true;
      this.worker.terminate();
      throw new ProtocolError('JOURNAL_OUTCOME_UNKNOWN');
    }
    const result = deserialize(Buffer.from(new Uint8Array(memory, 8, Atomics.load(header, 1))));
    if (!result.ok) {
      // A transport/commit failure must never trigger an automatic operation redispatch.
      if (
        ['UNAVAILABLE', '57P01', '57P02', '57P03', '08006', '08003'].includes(result.code) ||
        op === 'commit'
      ) {
        this.poisoned = true;
        this.worker.terminate();
      }
      throw new ProtocolError('POSTGRES_' + result.code);
    }
    return result.value;
  }
  transaction(fn) {
    const depth = this.depth;
    this.rpc(depth ? 'savepoint' : 'begin', [depth]);
    this.depth++;
    try {
      const result = fn();
      requireThat(!result?.then, 'ASYNC_SQL_TRANSACTION');
      this.rpc(depth ? 'release' : 'commit', [depth]);
      return result;
    } catch (error) {
      if (!this.poisoned) {
        try {
          this.rpc(depth ? 'rollbackTo' : 'rollback', [depth]);
          if (depth) this.rpc('release', [depth]);
        } catch {
          this.poisoned = true;
          this.worker.terminate();
        }
      }
      throw error;
    } finally {
      this.depth = depth;
    }
  }
  get(namespace, id) {
    const row = this.rpc('get', [namespace, id]).rows[0];
    return row && { revision: Number(row.revision), value: decodeCBOR(row.value) };
  }
  list(namespace) {
    return this.rpc('list', [namespace]).rows;
  }
  put(namespace, id, value, expectedRevision = -1) {
    return this.transaction(() => {
      const old = this.get(namespace, id);
      requireThat((old?.revision ?? -1) === expectedRevision, 'CAS_CONFLICT');
      const bytes = dcbor(value);
      requireThat(
        bytes.length <= 16 * 1024 * 1024 && Number.isSafeInteger(expectedRevision + 1),
        'STATE_LIMIT',
      );
      this.rpc('put', [namespace, id, expectedRevision + 1, bytes]);
      return expectedRevision + 1;
    });
  }
  issueNonce(scope, ttl = 120) {
    return this.transaction(() => {
      const value = b64u(random());
      this.rpc('issueNonce', [scope, value, now() + ttl]);
      return value;
    });
  }
  consumeNonce(scope, value, at = now()) {
    this.transaction(() =>
      requireThat(
        this.rpc('consumeNonce', [scope, value, at]).changes === 1,
        'NONCE_EXPIRED_OR_REPLAY',
      ),
    );
  }
  reserve(id, digest) {
    return this.transaction(() => {
      const row = this.rpc('operation', [id]).rows[0];
      if (row) {
        requireThat(equal(row.digest, digest), 'IDEMPOTENCY_CONFLICT');
        return row;
      }
      this.rpc('reserve', [id, digest, now()]);
      return null;
    });
  }
  complete(id, result) {
    this.transaction(() =>
      requireThat(this.rpc('complete', [id, result, now()]).changes === 1, 'OPERATION_STATE'),
    );
  }
  uncertain(id) {
    this.transaction(() => this.rpc('uncertain', [id, now()]));
  }
  reconcile(id, result) {
    this.transaction(() =>
      requireThat(this.rpc('reconcile', [id, result, now()]).changes === 1, 'OPERATION_STATE'),
    );
  }
  result(id) {
    const row = this.rpc('operation', [id]).rows[0];
    return (
      row && {
        status: row.status === 'DISPATCHED' ? 'UNKNOWN_EXECUTION' : row.status,
        result: row.result,
      }
    );
  }
  close() {
    if (!this.closed) {
      if (!this.poisoned) this.rpc('close');
      this.worker.terminate();
      this.closed = true;
    }
  }
}

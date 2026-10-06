# Durable state and indexed transparency

The storage contract preserves the core's atomic nonce consumption, revision checks, trust watermarks and immutable operation results. `Journal` provides local SQLite WAL persistence. `PostgresJournal` implements the same contract against PostgreSQL for multiple service processes/hosts. `IndexedMerkleLog` stores individual leaves, idempotency mappings and complete subtree hashes using either journal.

## PostgreSQL setup

Apply [schema.sql](../reference/storage/schema.sql) with a migration owner. Give runtime roles `USAGE` on `certconcord_storage`, `SELECT` on `schema_version`, and `SELECT, INSERT, UPDATE` on the state, nonce and operation tables. Runtime roles do not require schema creation, deletion or superuser privileges. Separate mutually untrusted operators into separately authorized databases/roles.

```js
import { PostgresJournal } from './storage/postgres.mjs';

const journal = new PostgresJournal({
  tenant: 'trust-domain-a:issuer',
  connection: {
    host: databaseHost,
    database: databaseName,
    user: runtimeUser,
    password: runtimeSecret,
    ssl: { ca: databaseCA, rejectUnauthorized: true },
  },
  timeoutMs: 10000,
});
```

All trust services accept this journal through their existing constructor. The complete exchanges in `storage/postgres.test.mjs` use it for authority, issuance log and independent mirror stores. Connection strings are disallowed to keep TLS and host policy explicit. `allowLoopback:true` permits unencrypted isolated local tests only for a literal approved loopback host; it does not allow arbitrary plaintext database endpoints.

The compatibility facade is synchronous. A private database worker owns its PostgreSQL connection, communicates through bounded shared-memory responses and uses parameterized SQL. Service hosts must place the facade in a dedicated service worker/process, because synchronous waits block that worker's event loop. Multiple hosts share database serialization, not process memory. A transaction-scoped advisory lock serializes writes within the selected tenant. This deliberately favors auditable atomicity over concurrent write throughput in one tenant; independent tenants can progress independently.

Nested transactions use savepoints. Every mutation obtains the same scoped lock. `synchronous_commit=on` is set for each transaction. This guarantees the configured database's acknowledgement behavior; a high-availability deployment must additionally configure synchronous standby requirements and fence the old primary. [PostgreSQL synchronous replication](https://www.postgresql.org/docs/18/warm-standby.html#SYNCHRONOUS-REPLICATION) documents those separate choices. The local acceptance job exercises real PostgreSQL process concurrency and crashes, while topology-specific failover and backup restoration remain deployment acceptance requirements.

On transport timeout the facade is poisoned and the worker terminated. Callers must reconcile durable state through a new connection. A lost commit acknowledgement is never treated as permission to repeat a signing invocation. `complete` accepts only a dispatched operation. `reconcile` accepts dispatched or uncertain operations only after the caller has verified the original result; completed records cannot be overwritten. No SQL adapter can make an external HSM call atomic with a database commit.

## Indexed logs and snapshots

Append atomically stores the leaf, its idempotency mapping, newly completed subtree hashes and the updated head. Inclusion and consistency proofs read retained hashes at an explicit prefix size. C2SP uploads use bounded 256-entry bundles; mirrors independently verify consistency and keep their own indexed leaves. Total log size is not capped by a single CBOR state value. Per-entry wire limits, safe index ranges, configured capacity and storage quotas still apply.

Issuance allocation remains in the same journal transaction as the issuance record. Merkle tree shape and wire proofs match the existing recursive implementation across power-of-two and tile boundaries. A retry returns the original allocation. A concurrent append cannot change the root of a retained prefix.

Legacy array-backed logs require an explicit offline migration using `migrateArrayLog`. Stop writers, retain a complete database/WAL backup, supply the original idempotency identifiers, migrate, compare every retained checkpoint/root and restart under the new implementation. Source rows remain available for verification. Tlog and MTC mirror metadata must be migrated using `migrateMirrorLog`; these helpers preserve the source rows in the migration archive before replacing array metadata. Migration to a different database additionally transfers all authority, operation, nonce and lifecycle namespaces in one consistent snapshot. Copying just log leaves or silently starting an empty log is prohibited.

## Acceptance

`npm run test:postgres` requires a reachable database configured by `CERTCONCORD_PG_HOST`, `CERTCONCORD_PG_PORT`, `CERTCONCORD_PG_USER`, `CERTCONCORD_PG_PASSWORD` and `CERTCONCORD_PG_DATABASE`; it never substitutes an in-memory backend. The tests use random isolated tenant names and synthetic keys. They cover concurrent nonce consumption, competing process appends, crash rollback, CAS, nested transactions, lock timeout, uncertain/completed outcomes, restart persistence and complete MTC/mdoc exchanges. The CI service is pinned by container digest.

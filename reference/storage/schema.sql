-- Apply with a migration owner. Runtime roles require only SELECT/INSERT/UPDATE.
BEGIN;
CREATE SCHEMA IF NOT EXISTS certconcord_storage;
CREATE TABLE IF NOT EXISTS certconcord_storage.schema_version (version integer PRIMARY KEY CHECK(version=1));
INSERT INTO certconcord_storage.schema_version VALUES(1) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS certconcord_storage.state (
  tenant text NOT NULL, namespace text NOT NULL, id text NOT NULL,
  revision bigint NOT NULL CHECK(revision >= 0 AND revision <= 9007199254740991),
  value bytea NOT NULL CHECK(octet_length(value) <= 16777216), PRIMARY KEY(tenant,namespace,id)
);
CREATE TABLE IF NOT EXISTS certconcord_storage.nonce (
  tenant text NOT NULL, scope text NOT NULL, value text NOT NULL,
  expires bigint NOT NULL, consumed boolean NOT NULL DEFAULT false, PRIMARY KEY(tenant,scope,value)
);
CREATE TABLE IF NOT EXISTS certconcord_storage.operations (
  tenant text NOT NULL, id text NOT NULL, digest bytea NOT NULL,
  status text NOT NULL CHECK(status IN ('DISPATCHED','COMPLETED','UNKNOWN_EXECUTION')),
  result bytea, updated bigint NOT NULL, PRIMARY KEY(tenant,id),
  CHECK((status='COMPLETED') = (result IS NOT NULL))
);
COMMIT;

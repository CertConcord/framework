import { DatabaseSync } from 'node:sqlite';
import { requireOperationAuthorities } from './control-authority.mjs';
import { statusResult, evaluateStatusEvidence } from './status-result.mjs';
import {
  D,
  H,
  dcbor,
  decodeCBOR,
  sha512,
  equal,
  requireThat,
  b64u,
  now,
  keyID,
  verify,
  random,
} from './core.mjs';
import { signCMS, verifyCMS } from './pki.mjs';

export class Journal {
  constructor(path = ':memory:') {
    this.db = new DatabaseSync(path);
    this.db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;');
    this.db
      .exec(`CREATE TABLE IF NOT EXISTS state (namespace TEXT NOT NULL, id TEXT NOT NULL, revision INTEGER NOT NULL, value BLOB NOT NULL, PRIMARY KEY(namespace,id));
      CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, digest BLOB NOT NULL, status TEXT NOT NULL, result BLOB, updated INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS nonce (scope TEXT NOT NULL, value TEXT NOT NULL, expires INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(scope,value));`);
  }
  close() {
    this.db.close();
  }
  transaction(fn) {
    const depth = this.depth ?? 0,
      savepoint = 'certconcord_' + depth;
    this.db.exec(depth ? 'SAVEPOINT ' + savepoint : 'BEGIN IMMEDIATE');
    this.depth = depth + 1;
    try {
      const result = fn();
      requireThat(!result?.then, 'ASYNC_SQL_TRANSACTION');
      this.db.exec(depth ? 'RELEASE ' + savepoint : 'COMMIT');
      return result;
    } catch (error) {
      this.db.exec(depth ? 'ROLLBACK TO ' + savepoint : 'ROLLBACK');
      if (depth) this.db.exec('RELEASE ' + savepoint);
      throw error;
    } finally {
      this.depth = depth;
    }
  }
  get(namespace, id) {
    const r = this.db.prepare('SELECT * FROM state WHERE namespace=? AND id=?').get(namespace, id);
    return r && { revision: r.revision, value: decodeCBOR(r.value) };
  }
  list(namespace) {
    return this.db.prepare('SELECT id FROM state WHERE namespace=? ORDER BY id').all(namespace);
  }
  put(namespace, id, value, expectedRevision = -1) {
    return this.transaction(() => {
      const current = this.get(namespace, id);
      requireThat((current?.revision ?? -1) === expectedRevision, 'CAS_CONFLICT');
      const revision = expectedRevision + 1;
      this.db
        .prepare(
          'INSERT INTO state VALUES(?,?,?,?) ON CONFLICT(namespace,id) DO UPDATE SET revision=excluded.revision,value=excluded.value',
        )
        .run(namespace, id, revision, dcbor(value));
      return revision;
    });
  }
  issueNonce(scope, ttl = 120) {
    const value = b64u(random());
    this.db
      .prepare('INSERT INTO nonce(scope,value,expires) VALUES(?,?,?)')
      .run(scope, value, now() + ttl);
    return value;
  }
  consumeNonce(scope, value, at = now()) {
    const r = this.db
      .prepare(
        'UPDATE nonce SET consumed=1 WHERE scope=? AND value=? AND consumed=0 AND expires>=?',
      )
      .run(scope, value, at);
    requireThat(r.changes === 1, 'NONCE_EXPIRED_OR_REPLAY');
  }
  reserve(id, digest) {
    return this.transaction(() => {
      const row = this.db.prepare('SELECT * FROM operations WHERE id=?').get(id);
      if (row) {
        requireThat(equal(Buffer.from(row.digest), digest), 'IDEMPOTENCY_CONFLICT');
        return row;
      }
      this.db
        .prepare('INSERT INTO operations VALUES(?,?,?,NULL,?)')
        .run(id, digest, 'DISPATCHED', now());
      return null;
    });
  }
  complete(id, result) {
    const r = this.db
      .prepare(
        "UPDATE operations SET status='COMPLETED', result=?, updated=? WHERE id=? AND status='DISPATCHED'",
      )
      .run(result, now(), id);
    requireThat(r.changes === 1, 'OPERATION_STATE');
  }
  uncertain(id) {
    this.db
      .prepare(
        "UPDATE operations SET status='UNKNOWN_EXECUTION',updated=? WHERE id=? AND status='DISPATCHED'",
      )
      .run(now(), id);
  }
  reconcile(id, result) {
    const r = this.db
      .prepare(
        "UPDATE operations SET status='COMPLETED',result=?,updated=? WHERE id=? AND status IN ('DISPATCHED','UNKNOWN_EXECUTION')",
      )
      .run(result, now(), id);
    requireThat(r.changes === 1, 'OPERATION_STATE');
  }
  result(id) {
    const r = this.db.prepare('SELECT status,result FROM operations WHERE id=?').get(id);
    return (
      r && {
        status: r.status === 'DISPATCHED' ? 'UNKNOWN_EXECUTION' : r.status,
        result: r.result && Buffer.from(r.result),
      }
    );
  }
}

export function activationContext({
  trustDomainID,
  tbsKind = 'ADAPTER_MESSAGE',
  simHash,
  tbs,
  publicKey,
  certificateID,
  certificateRepresentationHash,
  transactionID,
  operationID = random(),
  policyHash,
  origin,
  rpID,
  audience,
  issuedAt = now(),
  expiresAt = issuedAt + 120,
  serverNonce = random(),
  batchHash,
}) {
  requireThat(Buffer.isBuffer(trustDomainID) && trustDomainID.length === 32, 'TRUST_DOMAIN_ID');
  const v = {
    schemaVersion: 1,
    trustDomainID,
    tbsKind,
    simHash,
    tbsHash: sha512(tbs),
    keyID: keyID(publicKey),
    certificateID,
    certificateRepresentationHash,
    transactionID,
    operationID,
    policyHash,
    origin,
    rpID,
    audience,
    issuedAt,
    expiresAt,
    serverNonce,
  };
  if (batchHash) v.batchHash = batchHash;
  return v;
}
export function validateActivation(a, { tbs, publicKey, audience, at = now(), maxLifetime = 120 }) {
  requireThat(
    a.schemaVersion === 1 && equal(a.tbsHash, sha512(tbs)) && equal(a.keyID, keyID(publicKey)),
    'ACTIVATION_BINDING',
  );
  requireThat(
    Number.isSafeInteger(at) &&
      at >= 0 &&
      Number.isSafeInteger(a.issuedAt) &&
      a.issuedAt >= 0 &&
      Number.isSafeInteger(a.expiresAt) &&
      a.expiresAt > a.issuedAt &&
      a.audience === audience &&
      a.issuedAt <= at &&
      a.expiresAt > at &&
      a.expiresAt - a.issuedAt <= maxLifetime,
    'ACTIVATION_TIME_OR_AUDIENCE',
  );
  requireThat(
    ['ADAPTER_MESSAGE', 'CMS_SIGNED_ATTRS_DER', 'JWS_SIGNING_INPUT'].includes(a.tbsKind),
    'TBS_KIND',
  );
  for (const k of ['trustDomainID', 'transactionID', 'operationID', 'serverNonce'])
    requireThat(Buffer.isBuffer(a[k]) && a[k].length === 32, 'ACTIVATION_ID');
  for (const k of [
    'simHash',
    'tbsHash',
    'keyID',
    'certificateID',
    'certificateRepresentationHash',
    'policyHash',
  ])
    requireThat(Buffer.isBuffer(a[k]) && a[k].length === 64, 'ACTIVATION_HASH');
  return H('ActivationContext', a);
}
export function issuePermit(
  activation,
  {
    certificate,
    privateKey,
    activationEvidenceHash,
    proofMode,
    expiresAt = Math.min(activation.expiresAt, now() + 30),
  },
) {
  requireThat(
    ['HUMAN_WEBAUTHN', 'HUMAN_MDOC', 'WORKLOAD', 'HUMAN_SESSION'].includes(proofMode),
    'ACTIVATION_MODE',
  );
  const permit = {
    schemaVersion: 1,
    activation,
    activationEvidenceHash,
    proofMode,
    issuedAt: now(),
    expiresAt,
  };
  return signCMS({ content: D('OperationPermit', permit), certificate }, privateKey);
}
export function readControl(envelope, label, certificate) {
  const r = verifyCMS(envelope, { expectedCertificate: certificate });
  const a = decodeCBOR(r.content);
  requireThat(
    a.length === 4 && a[0] === 'CertConcord' && a[1] === 3 && a[2] === label,
    'CONTROL_DOMAIN',
  );
  return a[3];
}

// This gateway is a security boundary. Backend credentials must not be exposed elsewhere.
export class SigningGateway {
  constructor({
    journal,
    permitCertificate,
    receiptCertificate,
    receiptKey,
    audience,
    backend,
    authorize,
    authorityResolver,
    clock = now,
  }) {
    requireThat(typeof authorize === 'function', 'AUTHORIZATION_POLICY_REQUIRED');
    Object.assign(this, {
      journal,
      permitCertificate,
      receiptCertificate,
      receiptKey,
      audience,
      backend,
      authorize,
      authorityResolver,
      clock,
    });
  }
  async execute({ permit, tbs, keyRef }) {
    ({ permit, tbs, keyRef } = decodeCBOR(dcbor({ permit, tbs, keyRef })));
    const p = readControl(permit, 'OperationPermit', this.permitCertificate),
      a = p.activation;
    const checkTime = () => {
      const at = this.clock();
      requireThat(
        Number.isSafeInteger(at) &&
          at >= 0 &&
          Number.isSafeInteger(p.issuedAt) &&
          Number.isSafeInteger(p.expiresAt) &&
          p.issuedAt >= a.issuedAt &&
          p.expiresAt > at &&
          p.issuedAt <= at &&
          p.expiresAt <= a.expiresAt &&
          p.expiresAt > p.issuedAt &&
          p.expiresAt - p.issuedAt <= 30,
        'PERMIT_EXPIRED',
      );
      requireOperationAuthorities(this, { trustDomainID: a.trustDomainID }, at);
    };
    checkTime();
    const capabilities = await this.backend.capabilities(keyRef);
    const hash = validateActivation(a, {
      tbs,
      publicKey: capabilities.publicKey,
      audience: this.audience,
      at: this.clock(),
    });
    const authorize = async () =>
      requireThat(
        (await this.authorize({
          permit: decodeCBOR(dcbor(p)),
          keyRef,
          capabilities: { ...capabilities },
          activationHash: Buffer.from(hash),
        })) === true,
        'SIGNING_AUTHORIZATION_DENIED',
      );
    await authorize();
    checkTime();
    const id = b64u(a.operationID),
      digest = H('ProviderDispatch', { permitHash: sha512(permit), tbsHash: sha512(tbs), keyRef });
    const existing = this.journal.reserve(id, digest);
    if (existing) {
      requireThat(existing.status === 'COMPLETED', 'UNKNOWN_EXECUTION');
      return decodeCBOR(existing.result);
    }
    try {
      const signature = Buffer.from(
        await this.backend.sign({
          keyRef,
          tbs: Buffer.from(tbs),
          operationID: id,
          permit: Buffer.from(permit),
        }),
      );
      requireThat(verify(tbs, signature, capabilities.publicKey), 'PROVIDER_INVALID_SIGNATURE');
      await authorize();
      checkTime();
      const receipt = {
        schemaVersion: 1,
        operationID: a.operationID,
        activationHash: hash,
        permitHash: sha512(permit),
        keyID: a.keyID,
        tbsHash: a.tbsHash,
        signatureHash: sha512(signature),
        executedAt: this.clock(),
        provider: this.backend.id,
      };
      const result = {
        signature,
        receipt: signCMS(
          { content: D('ExecutionReceipt', receipt), certificate: this.receiptCertificate },
          this.receiptKey,
        ),
      };
      this.journal.complete(id, dcbor(result));
      return result;
    } catch (error) {
      this.journal.uncertain(id);
      throw error;
    }
  }
  getOperationResult(operationID) {
    return this.journal.result(operationID);
  }
}

export class TrustStore {
  constructor(journal, { domain, pins, threshold }) {
    requireThat(
      Array.isArray(pins) &&
        Number.isSafeInteger(threshold) &&
        threshold > 0 &&
        threshold <= pins.length &&
        new Set(pins.map((k) => b64u(keyID(k)))).size === pins.length,
      'ROOT_THRESHOLD',
    );
    this.journal = journal;
    this.domain = domain;
    this.domainID = Buffer.isBuffer(domain) ? b64u(domain) : domain;
    this.pins = Object.freeze([...pins]);
    this.threshold = threshold;
  }
  verify(manifest, signatures) {
    const good = new Set();
    for (const s of signatures) {
      const k = this.pins.find((k) => equal(keyID(k), s.keyID));
      if (k && verify(D('RootTrustManifest', manifest), s.signature, k)) good.add(b64u(s.keyID));
    }
    requireThat(good.size >= this.threshold, 'ROOT_SIGNATURE_THRESHOLD');
    requireThat(
      (equal(manifest.trustDomainID, this.domain) || manifest.trustDomainID === this.domain) &&
        (typeof manifest.serial === 'bigint' || Number.isSafeInteger(manifest.serial)) &&
        BigInt(manifest.serial) >= 0n &&
        BigInt(manifest.serial) <= 0xffffffffffffffffn,
      'RTM_DOMAIN_OR_SERIAL',
    );
    return H('RootTrustManifest', manifest);
  }
  accept(manifest, signatures, { mode = 'LIVE', at = now(), knowledgeTime = at } = {}) {
    const digest = this.verify(manifest, signatures);
    requireThat(
      manifest.issuedAt <= knowledgeTime && manifest.notBefore <= at && manifest.notAfter > at,
      'RTM_TIME',
    );
    if (mode === 'HISTORICAL') return { manifest, digest, mode, stateTime: at, knowledgeTime };
    requireThat(mode === 'LIVE', 'VALIDATION_MODE');
    this.journal.transaction(() => {
      const old = this.journal.get('rtm', this.domainID);
      if (old) {
        requireThat(manifest.serial >= old.value.serial, 'STALE_RTM');
        if (manifest.serial === old.value.serial)
          requireThat(equal(digest, old.value.digest), 'TRUST_FORK');
      }
      this.journal.put(
        'rtm',
        this.domainID,
        { serial: manifest.serial, digest },
        old?.revision ?? -1,
      );
    });
    return { manifest, digest, mode, stateTime: at, knowledgeTime };
  }
}

export function recoveryReachable({ nodes, edges }, initial) {
  requireThat(
    Array.isArray(nodes) &&
      nodes.length > 0 &&
      nodes.every((n) => typeof n === 'string' && n.length > 0) &&
      new Set(nodes).size === nodes.length &&
      Array.isArray(edges) &&
      Array.isArray(initial),
    'RCG_GRAPH',
  );
  const allowed = new Set(nodes);
  requireThat(
    initial.every((n) => allowed.has(n)),
    'RCG_UNKNOWN_NODE',
  );
  const reached = new Set(initial);
  for (const edge of edges)
    requireThat(
      allowed.has(edge.to) &&
        edge.from.length > 0 &&
        new Set(edge.from).size === edge.from.length &&
        edge.from.every((n) => allowed.has(n)) &&
        Number.isInteger(edge.threshold) &&
        edge.threshold > 0 &&
        edge.threshold <= edge.from.length,
      'RCG_EDGE',
    );
  let changed = true;
  while (changed) {
    changed = false;
    for (const e of edges)
      if (!reached.has(e.to) && e.from.filter((n) => reached.has(n)).length >= e.threshold) {
        reached.add(e.to);
        changed = true;
      }
  }
  return reached;
}
export function assertRecoverySeparation(graph, attackerRoots, signingSecrets) {
  const r = recoveryReachable(graph, attackerRoots);
  requireThat(
    Array.isArray(signingSecrets) &&
      signingSecrets.length > 0 &&
      new Set(signingSecrets).size === signingSecrets.length &&
      signingSecrets.every((s) => graph.nodes.includes(s)),
    'RCG_SIGNING_TARGETS',
  );
  requireThat(
    signingSecrets.every((s) => !r.has(s)),
    'SIGNING_ESCROW_PATH',
  );
  return true;
}
export function quorumProperties(n, q, f) {
  requireThat(
    [n, q, f].every(Number.isSafeInteger) && n > 0 && q > 0 && q <= n && f >= 0 && f < n,
    'QUORUM_PARAMETERS',
  );
  return {
    intersection: 2 * q - n,
    forkPrevention: 2 * q - n > f,
    availableWithFaults: q <= n - f,
  };
}

export function evaluateStatus(statement, context) {
  if (statement === undefined || statement === null) return statusResult('UNKNOWN', 'STATUS_MISSING');
  return evaluateStatusEvidence(() => {
    const status = classifyStatus(statement, context);
    return statusResult(status, status === 'GOOD' ? undefined : 'STATUS_' + status);
  }, 'STATUS');
}
function classifyStatus(statement, { stateTime = now(), knowledgeTime = now(), scope }) {
  requireThat(
    statement.scope === scope &&
      Number.isFinite(stateTime) &&
      Number.isFinite(knowledgeTime) &&
      stateTime >= 0 &&
      stateTime <= knowledgeTime &&
      Number.isSafeInteger(statement.publishedAt) &&
      statement.publishedAt >= 0 &&
      Number.isSafeInteger(statement.nextUpdate) &&
      statement.nextUpdate > statement.publishedAt,
    'STATUS_SCOPE_OR_KNOWLEDGE',
  );
  if (statement.status === 'REVOKED')
    requireThat(
      Number.isSafeInteger(statement.effectiveTime) &&
        statement.effectiveTime >= 0 &&
        (statement.compromiseStart === undefined ||
          (Number.isSafeInteger(statement.compromiseStart) && statement.compromiseStart >= 0)),
      'STATUS_REVOCATION_TIME',
    );
  if (statement.publishedAt > knowledgeTime) return 'NOT_YET_KNOWN';
  if (
    statement.status === 'REVOKED' &&
    Math.min(statement.effectiveTime, statement.compromiseStart ?? Infinity) <= stateTime
  )
    return 'REVOKED';
  if (statement.critical !== undefined) {
    requireThat(Array.isArray(statement.critical) && statement.critical.every((item) => typeof item === 'string'),
      'STATUS_CRITICAL_SCHEMA');
    if (statement.critical.length) return 'UNSUPPORTED';
  }
  if (statement.nextUpdate <= knowledgeTime) return 'STALE';
  return statement.status === 'GOOD' || statement.status === 'REVOKED' ? 'GOOD' : 'UNKNOWN';
}

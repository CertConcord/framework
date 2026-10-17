import test from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync,
  rmSync,
  writeFileSync,
  readFileSync,
  existsSync,
  copyFileSync,
} from 'node:fs';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as c from './core.mjs';
import * as p from './pki.mjs';
import { Journal, readControl } from './state.mjs';
import { signOrganizationControl } from './organization-delegation-fixtures.mjs';
import { OrganizationHistoryKnowledgeStore } from './organization-history-knowledge.mjs';
import { createIndependentOrganizationHistoryFixture } from './fixtures-history-independent.mjs';
import {
  createOrganizationHistorySource,
  createOrganizationHistoryVerifier,
} from './sdk/index.mjs';
const copy = (v) => c.decodeCBOR(c.dcbor(v));
let fixture;
test.before(async () => {
  fixture = await createIndependentOrganizationHistoryFixture();
});
test.after(() => fixture?.close());
function descriptor(f = fixture) {
  const pin = (tsa) => ({
    certificate: tsa.certificate,
    issuerPublicKeyDER: c.spki(tsa.issuerKey),
    policy: tsa.policy,
    validUntil: tsa.validUntil,
    signatureProfile: 'CERTCONCORD-PQ',
  });
  const publicationCertificate = p.verifyCMS(f.history[0].publicationProof, {
    expectedContentType: p.OID.tstInfo,
  }).certificate;
  return copy({
    configuration: {
      schemaVersion: 1,
      trust: f.trust,
      retainedAuthorities: {
        governance: {
          roots: [
            { publicKeyDER: c.spki(f.root.publicKey), validFrom: f.A - 60, validUntil: f.end },
          ],
          threshold: 1,
        },
        algorithmDeadlines: { 'ml-dsa-65': f.end, 'ml-dsa-87': f.end, ec: f.end },
        publication: {
          format: 'RFC3161',
          timestampAuthorities: [
            {
              certificate: publicationCertificate,
              issuerPublicKeyDER: c.spki(f.root.publicKey),
              policy: f.initialTSA.policy,
              validFrom: f.A - 60,
              validUntil: f.end,
              knowledgeValidUntil: f.end,
              signatureProfile: 'CERTCONCORD-PQ',
            },
          ],
          hashValidUntil: { [p.OID.sha512]: f.end },
        },
      },
      preservation: {
        hashValidUntil: f.options.preservationPolicy.hashValidUntil,
        dataValidUntil: f.options.preservationPolicy.dataValidUntil,
        timestampAuthorities: [pin(f.initialTSA), pin(f.renewalTSA)],
      },
    },
    knowledge: {
      ...f.knowledge,
      authorityHistory: f.history.map((entry) => ({
        manifest: c.dcbor(entry.manifest),
        signatures: entry.signatures,
        publicationProof: entry.publicationProof,
      })),
    },
  });
}

function harness(t, value = descriptor()) {
  const directory = mkdtempSync(join(tmpdir(), 'organization-knowledge-'));
  const databasePath = join(directory, 'history.sqlite');
  const sources = [];
  const open = () => {
    const source = createOrganizationHistorySource({
      configuration: value.configuration,
      readKnowledge: () => value.knowledge,
      databasePath,
    });
    sources.push(source);
    return { source, verifier: createOrganizationHistoryVerifier({ source }) };
  };
  t.after(() => {
    for (const source of sources) source.close();
    rmSync(directory, { recursive: true, force: true });
  });
  return { open, value, databasePath, directory };
}
const revoke = (f = fixture) =>
  f.organizationStatus(f.originalStatusMembers[0], {
    epoch: 3,
    status: 'REVOKED',
    effectiveTime: f.K - 1,
    compromiseStart: f.A,
  });
function refresh(value, f = fixture) {
  value.knowledge.knowledgeTime++;
  value.knowledge.statusMaterial = f.originalStatusMembers.map((m) =>
    f.organizationStatus(m, { epoch: 4, publishedAt: f.K }),
  );
  value.knowledge.certificateStatusMaterial = [f.certificateStatus({ publishedAt: f.K })];
}
function stripReceipt(result) {
  const { knowledgeReceipt, ...assessment } = result;
  return assessment;
}
test('durable source commits exact originals and preserves the complete fresh assessment', (t) => {
  const h = harness(t),
    { source, verifier } = h.open();
  const result = verifier.verify(fixture.input);
  assert.equal(result.overall, 'VALID', JSON.stringify(result));
  assert.equal(result.knowledgeReceipt.state, 'COMMITTED');
  assert.match(result.knowledgeReceipt.scopeID, /^[a-f0-9]{128}$/);
  assert.match(result.knowledgeReceipt.configurationID, /^[a-f0-9]{128}$/);
  assert.deepEqual(
    stripReceipt(result),
    createOrganizationHistoryVerifier(fixture.options).verify(fixture.input),
  );
  const retained = source.readEvidence(result.knowledgeReceipt.evidenceID);
  assert.equal(retained.classification, 'UNVERIFIED_BYTES');
  assert.deepEqual(retained.originalBytes, fixture.input.originalBytes);
  assert.deepEqual(retained.evidenceRecord, fixture.input.evidenceRecord);
  source.close();
  const reopened = h.open();
  assert.deepEqual(reopened.source.readEvidence(result.knowledgeReceipt.evidenceID), retained);
  assert.equal(reopened.verifier.verify(fixture.input).overall, 'VALID');
  assert.equal(fixture.source.calls.sign, 1);
});
test('INVALID admitted organization revocation survives close and reopen', (t) => {
  const h = harness(t);
  h.value.knowledge.statusMaterial.push(revoke());
  const first = h.open();
  const result = first.verifier.verify(fixture.input);
  assert.equal(result.overall, 'INVALID', JSON.stringify(result));
  assert.equal(result.knowledgeReceipt.state, 'COMMITTED');
  const memorySource = createOrganizationHistorySource({
    configuration: h.value.configuration,
    readKnowledge: () => h.value.knowledge,
  });
  const memory = createOrganizationHistoryVerifier({ source: memorySource });
  t.after(() => memorySource.close());
  assert.deepEqual(stripReceipt(result), memory.verify(fixture.input));
  first.source.close();
  refresh(h.value);
  const second = h.open().verifier.verify(fixture.input);
  assert.equal(second.currentAdmissibility.overall, 'INVALID', JSON.stringify(second));
  assert.equal(second.historicalAuthorization.overall, 'VALID');
  assert.equal(second.knowledgeReceipt.state, 'COMMITTED');
  assert.equal(second.knowledgeReceipt.evidenceID, result.knowledgeReceipt.evidenceID);
  assert.deepEqual(stripReceipt(second), memory.verify(fixture.input));
});
test('same-epoch semantic conflict survives a newer GOOD-only source after reopen', (t) => {
  const h = harness(t);
  const old = h.value.knowledge.statusMaterial[0];
  const body = c.decodeCBOR(p.verifyCMS(old.cms).content)[3];
  h.value.knowledge.statusMaterial.push(
    fixture.organizationStatus(fixture.originalStatusMembers[0], {
      epoch: body.epoch,
      nextUpdate: body.nextUpdate - 1,
    }),
  );
  const first = h.open();
  assert.equal(first.verifier.verify(fixture.input).overall, 'INVALID');
  first.source.close();
  refresh(h.value);
  const result = h.open().verifier.verify(fixture.input);
  assert.equal(result.overall, 'INVALID', JSON.stringify(result));
  assert.equal(result.knowledgeReceipt.state, 'COMMITTED');
});

for (const negative of [false, true])
  test(`omitted current status is ${negative ? 'dominated by a retained incident' : 'missing freshness, not rollback'}`, (t) => {
    const h = harness(t);
    if (negative) h.value.knowledge.statusMaterial.push(revoke());
    const first = h.open();
    assert.equal(first.verifier.verify(fixture.input).knowledgeReceipt.state, 'COMMITTED');
    first.source.close();
    h.value.knowledge.knowledgeTime++;
    h.value.knowledge.statusMaterial = [];
    h.value.knowledge.certificateStatusMaterial = [];
    const result = h.open().verifier.verify(fixture.input);
    assert.equal(result.overall, negative ? 'INVALID' : 'INDETERMINATE', JSON.stringify(result));
    assert.equal(result.historicalAuthorization.overall, 'VALID');
    assert.equal(result.knowledgeReceipt.state, 'COMMITTED');
    assert(
      !result.currentAdmissibility.checks.some((check) =>
        ['ORG_STATUS_ROLLBACK', 'ORG_CERTIFICATE_STATUS_ROLLBACK'].includes(check.reason),
      ),
      JSON.stringify(result.currentAdmissibility),
    );
  });
test('persisted selected K rejects rollback and accepts equality', (t) => {
  const h = harness(t),
    first = h.open();
  const before = first.verifier.verify(fixture.input);
  assert.equal(before.overall, 'VALID');
  first.source.close();
  h.value.knowledge.knowledgeTime--;
  const second = h.open();
  const rollback = second.verifier.verify(fixture.input);
  assert.equal(rollback.overall, 'INVALID');
  assert.equal(rollback.reason, 'ORG_KNOWLEDGE_ROLLBACK');
  h.value.knowledge.knowledgeTime++;
  assert.equal(second.verifier.verify(fixture.input).overall, 'VALID');
});

test('strictly newer GOOD certificate status cannot clear a committed compromise after restart', (t) => {
  const h = harness(t);
  h.value.knowledge.certificateStatusMaterial = [
    fixture.certificateStatus({
      status: 'REVOKED',
      effectiveTime: fixture.K - 1,
      compromiseStart: fixture.A,
    }),
  ];
  const first = h.open();
  const incident = first.verifier.verify(fixture.input);
  assert.equal(incident.overall, 'INVALID');
  assert.equal(incident.knowledgeReceipt.state, 'COMMITTED');
  first.source.close();
  refresh(h.value);
  const result = h.open().verifier.verify(fixture.input);
  assert.equal(result.overall, 'INVALID', JSON.stringify(result));
  assert.equal(result.historicalAuthorization.overall, 'VALID');
  assert.equal(result.currentAdmissibility.overall, 'INVALID');
});

test('valid admitted revocation persists while a forged sibling is excluded from replay storage', (t) => {
  const h = harness(t),
    negative = revoke(),
    forged = copy(negative);
  forged.cms[forged.cms.length - 1] ^= 1;
  h.value.knowledge.statusMaterial.push(negative, forged);
  const first = h.open();
  assert.equal(first.verifier.verify(fixture.input).knowledgeReceipt.state, 'COMMITTED');
  first.source.close();
  const db = new Journal(h.databasePath);
  try {
    assert(
      db.get('organization-history-v1', 'blob:' + c.sha256(c.dcbor(negative)).toString('hex')),
    );
    assert.equal(
      db.get('organization-history-v1', 'blob:' + c.sha256(c.dcbor(forged)).toString('hex')),
      undefined,
    );
  } finally {
    db.close();
  }
  refresh(h.value);
  const result = h.open().verifier.verify(fixture.input);
  assert.equal(result.overall, 'INVALID', JSON.stringify(result));
  assert.equal(result.knowledgeReceipt.state, 'COMMITTED');
});

test('a future negative is excluded and cannot poison a later GOOD-only verification', (t) => {
  const h = harness(t),
    future = fixture.organizationStatus(fixture.originalStatusMembers[0], {
      epoch: 10,
      status: 'REVOKED',
      publishedAt: fixture.K + 10,
      effectiveTime: fixture.K + 10,
      compromiseStart: fixture.A,
    });
  h.value.knowledge.statusMaterial.push(future);
  const first = h.open();
  assert.equal(first.verifier.verify(fixture.input).overall, 'VALID');
  first.source.close();
  const db = new Journal(h.databasePath);
  try {
    assert.equal(
      db.get('organization-history-v1', 'blob:' + c.sha256(c.dcbor(future)).toString('hex')),
      undefined,
    );
  } finally {
    db.close();
  }
  refresh(h.value);
  assert.equal(h.open().verifier.verify(fixture.input).overall, 'VALID');
});

test('missing SIM cannot discard independently bound organization revocation', async (t) => {
  const h = harness(t),
    bundle = copy(fixture.bundle);
  bundle.objects = bundle.objects.filter((leaf) => leaf.type !== 'SIM');
  const originalBytes = c.dcbor(bundle),
    evidenceRecord = await fixture.preserve(originalBytes);
  h.value.knowledge.statusMaterial.push(revoke());
  const first = h.open();
  const clock = Date.now;
  let clockReads = 0,
    incomplete;
  Date.now = () => {
    clockReads++;
    throw Error('history must not read a live clock');
  };
  try {
    incomplete = first.verifier.verify({ originalBytes, evidenceRecord });
  } finally {
    Date.now = clock;
  }
  assert.equal(clockReads, 0);
  assert.equal(incomplete.proofOfExistenceUpperBound, fixture.P);
  assert.equal(incomplete.operationTime, null);
  assert.equal(incomplete.knowledgeReceipt.state, 'COMMITTED');
  assert.notEqual(incomplete.overall, 'VALID');
  first.source.close();
  refresh(h.value);
  const recovered = h.open().verifier.verify(fixture.input);
  assert.equal(recovered.overall, 'INVALID', JSON.stringify(recovered));
  assert.equal(recovered.currentAdmissibility.overall, 'INVALID');
  assert.equal(recovered.historicalAuthorization.overall, 'VALID');
});

test('unavailable original PoE cannot discard independently authenticated credential compromise', (t) => {
  const h = harness(t);
  h.value.knowledge.certificateStatusMaterial = [
    fixture.certificateStatus({
      status: 'REVOKED',
      effectiveTime: fixture.K - 1,
      compromiseStart: fixture.A,
    }),
  ];
  const first = h.open();
  const broken = first.verifier.verify({
    originalBytes: fixture.input.originalBytes,
    evidenceRecord: Buffer.from('not an ERS'),
  });
  assert.equal(broken.proofOfExistenceUpperBound, null);
  assert.equal(broken.knowledgeReceipt.state, 'COMMITTED');
  first.source.close();
  refresh(h.value);
  const result = h.open().verifier.verify(fixture.input);
  assert.equal(result.overall, 'INVALID', JSON.stringify(result));
  assert.equal(result.knowledgeReceipt.state, 'COMMITTED');
});

test('a different original target sharing the subject key inherits a committed compromise', async (t) => {
  const h = harness(t),
    grants = c.decodeCBOR(fixture.leaves.OrganizationDelegationPath);
  const member = grants.grants[0],
    originalHash = c.sha512(member.cms);
  const body = readControl(member.cms, 'OrganizationDelegationGrant', member.issuerCertificate);
  const oldID = Buffer.from(body.grantID);
  body.grantID = c.random(32);
  member.cms = signOrganizationControl(
    'OrganizationDelegationGrant',
    body,
    fixture.source.keys.root,
  );
  const oldStatus = fixture.originalStatusMembers.find((m) => {
    const status = readControl(m.cms, 'OrganizationDelegationStatus', m.issuerCertificate);
    return status.objectType === 'GRANT' && c.equal(status.objectHash, originalHash);
  });
  assert(oldStatus);
  assert.notDeepEqual(body.grantID, oldID);
  const negative = fixture.organizationStatus(oldStatus, {
    objectID: body.grantID,
    objectHash: c.sha512(member.cms),
    epoch: 3,
    status: 'REVOKED',
    effectiveTime: fixture.K - 1,
    compromiseStart: fixture.A,
  });
  const originalBytes = fixture.replaceLeaf('OrganizationDelegationPath', c.dcbor(grants));
  const evidenceRecord = await fixture.preserve(originalBytes);
  h.value.knowledge.statusMaterial.push(negative);
  const first = h.open();
  const learned = first.verifier.verify({ originalBytes, evidenceRecord });
  assert.equal(learned.knowledgeReceipt.state, 'COMMITTED');
  first.source.close();
  refresh(h.value);
  const second = h.open().verifier.verify(fixture.input);
  assert.equal(second.overall, 'INVALID', JSON.stringify(second));
  assert(
    second.currentAdmissibility.checks.some((check) => check.reason === 'ORG_KEY_COMPROMISED'),
    JSON.stringify(second.currentAdmissibility),
  );
  assert.equal(second.historicalAuthorization.overall, 'VALID');
  assert.notEqual(second.knowledgeReceipt.evidenceID, learned.knowledgeReceipt.evidenceID);
});

for (const [name, mutate, index] of [
  [
    'future grant',
    (body, f) => {
      body.issuedAt = f.P + 1;
      body.knownAt = f.P + 1;
      body.validFrom = f.P + 1;
    },
    0,
  ],
  [
    'expired grant',
    (body, f) => {
      body.validUntil = f.P;
    },
    0,
  ],
  [
    'malformed grant time',
    (body) => {
      body.knownAt = 'not a time';
    },
    0,
  ],
  [
    'unauthorized root parent',
    (body) => {
      body.parentGrantHash = c.random(64);
    },
    0,
  ],
  [
    'expanded child delegation',
    (body) => {
      body.remainingDelegations = 7;
    },
    1,
  ],
])
  test(`${name} cannot admit a negative that poisons the shared key after reopen`, async (t) => {
    const h = harness(t),
      grants = c.decodeCBOR(fixture.leaves.OrganizationDelegationPath);
    const member = grants.grants[index],
      oldHash = c.sha512(member.cms);
    const body = readControl(member.cms, 'OrganizationDelegationGrant', member.issuerCertificate);
    body.grantID = c.random(32);
    mutate(body, fixture);
    const signer = Object.values(fixture.source.keys).find((key) =>
      c.equal(key.certificate, member.issuerCertificate),
    );
    assert(signer);
    member.cms = signOrganizationControl('OrganizationDelegationGrant', body, signer);
    const oldStatus = fixture.originalStatusMembers.find((m) =>
      c.equal(
        readControl(m.cms, 'OrganizationDelegationStatus', m.issuerCertificate).objectHash,
        oldHash,
      ),
    );
    assert(oldStatus);
    const negative = fixture.organizationStatus(oldStatus, {
      objectID: body.grantID,
      objectHash: c.sha512(member.cms),
      epoch: 3,
      status: 'REVOKED',
      effectiveTime: fixture.K - 1,
      compromiseStart: fixture.A,
    });
    h.value.knowledge.statusMaterial.push(negative);
    const originalBytes = fixture.replaceLeaf('OrganizationDelegationPath', c.dcbor(grants));
    const evidenceRecord = await fixture.preserve(originalBytes),
      first = h.open();
    const invalid = first.verifier.verify({ originalBytes, evidenceRecord });
    assert.notEqual(invalid.overall, 'VALID');
    assert.equal(invalid.knowledgeReceipt.state, 'COMMITTED');
    first.source.close();
    const db = new Journal(h.databasePath);
    try {
      assert.equal(
        db.get('organization-history-v1', 'blob:' + c.sha256(c.dcbor(negative)).toString('hex')),
        undefined,
      );
    } finally {
      db.close();
    }
    refresh(h.value);
    const unpoisoned = h.open().verifier.verify(fixture.input);
    assert.equal(unpoisoned.overall, 'VALID', JSON.stringify(unpoisoned));
  });

test('a future final authorization target cannot poison its shared signer key', async (t) => {
  const h = harness(t),
    cms = fixture.leaves.OrganizationAuthorization;
  const body = readControl(
    cms,
    'OrganizationAuthorization',
    fixture.source.keys.terminal.certificate,
  );
  body.authorizationID = c.random(32);
  body.issuedAt = fixture.P + 1;
  body.expiresAt = fixture.P + 20;
  const changed = signOrganizationControl(
    'OrganizationAuthorization',
    body,
    fixture.source.keys.terminal,
  );
  const oldStatus = fixture.originalStatusMembers.find(
    (m) =>
      readControl(m.cms, 'OrganizationDelegationStatus', m.issuerCertificate).objectType ===
      'FINAL_AUTHORIZATION',
  );
  const negative = fixture.organizationStatus(oldStatus, {
    objectID: body.authorizationID,
    objectHash: c.sha512(changed),
    epoch: 3,
    status: 'REVOKED',
    effectiveTime: fixture.K - 1,
    compromiseStart: fixture.A,
  });
  h.value.knowledge.statusMaterial.push(negative);
  const originalBytes = fixture.replaceLeaf('OrganizationAuthorization', changed),
    evidenceRecord = await fixture.preserve(originalBytes);
  const first = h.open();
  assert.equal(
    first.verifier.verify({ originalBytes, evidenceRecord }).knowledgeReceipt.state,
    'COMMITTED',
  );
  first.source.close();
  refresh(h.value);
  assert.equal(h.open().verifier.verify(fixture.input).overall, 'VALID');
});

test('an authenticated RTM fork survives a canonical GOOD-only source after reopen', (t) => {
  const h = harness(t),
    records = copy(fixture.currentAuthorities);
  records[0].validUntil--;
  const fork = fixture.manifest(records, fixture.K - 1, fixture.firstManifest, {
    replacement: true,
  });
  h.value.knowledge.authorityHistory.push({ ...fork, manifest: c.dcbor(fork.manifest) });
  const first = h.open();
  const result = first.verifier.verify(fixture.input);
  assert.equal(result.overall, 'INVALID');
  assert.equal(result.historicalAuthorization.overall, 'VALID');
  assert.equal(result.knowledgeReceipt.state, 'COMMITTED');
  first.source.close();
  h.value.knowledge.authorityHistory.pop();
  const second = h.open().verifier.verify(fixture.input);
  assert.equal(second.overall, 'INVALID', JSON.stringify(second));
  assert.equal(second.knowledgeReceipt.state, 'COMMITTED');
});

test('an unsigned RTM fork is excluded from durable trusted history', (t) => {
  const h = harness(t),
    bad = copy(h.value.knowledge.authorityHistory[1]);
  const manifest = c.decodeCBOR(bad.manifest);
  manifest.authorities[0].validUntil--;
  bad.manifest = c.dcbor(manifest);
  h.value.knowledge.authorityHistory.push(bad);
  const first = h.open();
  assert.equal(first.verifier.verify(fixture.input).overall, 'INVALID');
  first.source.close();
  h.value.knowledge.authorityHistory.pop();
  assert.equal(h.open().verifier.verify(fixture.input).overall, 'VALID');
});

test('retained predecessor accepts an authenticated successor suffix after reopen', (t) => {
  const h = harness(t),
    first = h.open();
  assert.equal(first.verifier.verify(fixture.input).overall, 'VALID');
  first.source.close();
  h.value.knowledge.authorityHistory = [h.value.knowledge.authorityHistory[1]];
  const result = h.open().verifier.verify(fixture.input);
  assert.equal(result.overall, 'VALID', JSON.stringify(result));
  assert.equal(result.knowledgeReceipt.state, 'COMMITTED');
});

test('database binding rejects valid changes to every selected configuration family', (t) => {
  const h = harness(t),
    first = h.open();
  first.source.close();
  const original = copy(h.value.configuration);
  const mutations = [
    (v) => {
      v.trust.trustDomainID[0] ^= 1;
    },
    (v) => {
      v.trust.organizationID[0] ^= 1;
    },
    (v) => {
      v.trust.issuerID += 'other';
    },
    (v) => {
      v.trust.identityNamespace += 'other';
    },
    (v) => {
      v.trust.policy.allowedOrigins.push('https://other.example');
    },
    (v) => {
      v.trust.controlTrust[0].issuerID += 'other';
    },
    (v) => {
      v.trust.credentialTrust.issuanceScope.issuerID += 'other';
    },
    (v) => {
      v.trust.algorithmDeadlines[Object.keys(v.trust.algorithmDeadlines)[0]]--;
    },
    (v) => {
      v.trust.hashDeadlines[Object.keys(v.trust.hashDeadlines)[0]]--;
    },
    (v) => {
      v.trust.keyDeadlines[Object.keys(v.trust.keyDeadlines)[0]]--;
    },
    (v) => {
      v.retainedAuthorities.governance.roots[0].validUntil--;
    },
    (v) => {
      v.retainedAuthorities.algorithmDeadlines.ec--;
    },
    (v) => {
      v.retainedAuthorities.publication.timestampAuthorities[0].knowledgeValidUntil--;
    },
    (v) => {
      v.retainedAuthorities.publication.timestampAuthorities[0].policy += '.1';
    },
    (v) => {
      v.retainedAuthorities.publication.hashValidUntil[p.OID.sha512]--;
    },
    (v) => {
      v.preservation.dataValidUntil--;
    },
    (v) => {
      v.preservation.hashValidUntil[p.OID.sha512]--;
    },
    (v) => {
      v.preservation.timestampAuthorities[0].validUntil--;
    },
  ];
  for (const mutate of mutations) {
    h.value.configuration = copy(original);
    mutate(h.value.configuration);
    assert.throws(() => h.open(), { code: 'ORG_HISTORY_CONFIGURATION_MISMATCH' });
  }
  h.value.configuration = original;
  assert.equal(h.open().verifier.verify(fixture.input).overall, 'VALID');
});

test('history source rejects an existing live journal without changing operation state', (t) => {
  const h = harness(t),
    live = new Journal(h.databasePath);
  live.reserve('live-operation', c.sha256(Buffer.from('request')));
  live.close();
  assert.throws(() => h.open(), { code: 'ORG_HISTORY_DATABASE_NOT_DEDICATED' });
  const reopened = new Journal(h.databasePath);
  try {
    assert.equal(reopened.result('live-operation').status, 'UNKNOWN_EXECUTION');
    assert.equal(reopened.get('organization-history-v1', 'binding'), undefined);
  } finally {
    reopened.close();
  }
});

test('malformed knowledge never advances persisted selected time or admits partial input', (t) => {
  const h = harness(t),
    first = h.open();
  const valid = first.verifier.verify(fixture.input);
  const knowledge = copy(h.value.knowledge);
  h.value.knowledge.knowledgeTime += 50;
  h.value.knowledge.certificateStatusMaterial = {};
  const invalid = first.verifier.verify(fixture.input);
  assert.notEqual(invalid.overall, 'VALID');
  assert.equal(invalid.knowledgeReceipt.state, 'NOT_COMMITTED');
  h.value.knowledge = knowledge;
  const retry = first.verifier.verify(fixture.input);
  assert.equal(retry.overall, 'VALID');
  assert.equal(retry.knowledgeReceipt.revision, valid.knowledgeReceipt.revision);
});

test('failed commit acknowledgement poisons the source and a new source reauthenticates the commit', (t) => {
  const h = harness(t),
    first = h.open();
  h.value.knowledge.statusMaterial.push(revoke());
  const original = Journal.prototype.transaction;
  let lost = false;
  Journal.prototype.transaction = function (fn) {
    const outer = !this.depth;
    const value = original.call(this, fn);
    if (outer && !lost) {
      lost = true;
      throw Error('lost commit acknowledgement');
    }
    return value;
  };
  let result;
  try {
    result = first.verifier.verify(fixture.input);
  } finally {
    Journal.prototype.transaction = original;
  }
  assert.equal(lost, true);
  assert.equal(result.overall, 'INVALID');
  assert.equal(result.knowledgeReceipt.state, 'UNKNOWN');
  assert.notEqual(first.verifier.verify(fixture.input).overall, 'VALID');
  first.source.close();
  refresh(h.value);
  const reopened = h.open().verifier.verify(fixture.input);
  assert.equal(reopened.overall, 'INVALID', JSON.stringify(reopened));
  assert.equal(reopened.knowledgeReceipt.state, 'COMMITTED');
});

test('latest missing coverage cannot erase an already committed terminal incident', (t) => {
  const h = harness(t);
  h.value.knowledge.statusMaterial.push(revoke());
  const first = h.open();
  assert.equal(first.verifier.verify(fixture.input).overall, 'INVALID');
  first.source.close();
  h.value.knowledge.knowledgeTime = fixture.K + 301;
  h.value.knowledge.authorityHistory = [];
  h.value.knowledge.statusMaterial = [];
  h.value.knowledge.certificateStatusMaterial = [];
  const result = h.open().verifier.verify(fixture.input);
  assert.equal(result.overall, 'INVALID', JSON.stringify(result));
  assert.equal(result.currentAdmissibility.overall, 'INVALID');
  assert.equal(result.historicalAuthorization.overall, 'VALID');
  assert.equal(result.preservation.overall, 'INDETERMINATE');
  assert.equal(result.knowledgeReceipt.state, 'COMMITTED');
});

test('an over-limit snapshot cannot clear previously committed incidents', (t) => {
  const h = harness(t),
    first = h.open();
  h.value.knowledge.statusMaterial.push(revoke());
  assert.equal(first.verifier.verify(fixture.input).overall, 'INVALID');
  first.source.close();
  const oversized = h.open();
  h.value.knowledge.statusMaterial = Array.from({ length: 65 }, () => revoke());
  const limit = oversized.verifier.verify(fixture.input);
  assert.equal(limit.overall, 'UNSUPPORTED');
  assert.equal(limit.knowledgeReceipt.state, 'NOT_COMMITTED');
  oversized.source.close();
  refresh(h.value);
  assert.equal(h.open().verifier.verify(fixture.input).overall, 'INVALID');
});

test('authenticated lower credential publication is not hidden by an older stored head', (t) => {
  const h = harness(t);
  h.value.knowledge.certificateStatusMaterial = [
    fixture.certificateStatus({ publishedAt: fixture.K }),
  ];
  const first = h.open();
  assert.equal(first.verifier.verify(fixture.input).overall, 'VALID');
  first.source.close();
  h.value.knowledge.knowledgeTime++;
  // The successor was authentically appointed at K-1. Both publications must
  // pass signer admission; a pre-appointment statement cannot establish rollback.
  h.value.knowledge.certificateStatusMaterial = [
    fixture.certificateStatus({ publishedAt: fixture.K - 1 }),
  ];
  const result = h.open().verifier.verify(fixture.input);
  assert.equal(result.overall, 'INVALID', JSON.stringify(result));
  assert(
    result.currentAdmissibility.checks.some((c) => c.reason === 'ORG_CERTIFICATE_STATUS_ROLLBACK'),
  );
});

test('original larger than the Journal decoder limit round trips as unverified atomic chunks', async (t) => {
  const h = harness(t),
    originalBytes = fixture.replaceLeaf('Document', Buffer.alloc(17 * 1024 * 1024, 0x45));
  const evidenceRecord = await fixture.preserve(originalBytes);
  assert(originalBytes.length > 16 * 1024 * 1024);
  const first = h.open(),
    result = first.verifier.verify({ originalBytes, evidenceRecord });
  assert.equal(result.overall, 'INVALID', 'altered document cannot use the old signature');
  assert.equal(result.knowledgeReceipt.state, 'COMMITTED');
  const id = result.knowledgeReceipt.evidenceID;
  first.source.close();
  const reopened = h.open(),
    stored = reopened.source.readEvidence(id);
  assert.deepEqual(stored.originalBytes, originalBytes);
  assert.deepEqual(stored.evidenceRecord, evidenceRecord);
  stored.originalBytes.fill(0);
  assert.deepEqual(reopened.source.readEvidence(id).originalBytes, originalBytes);
  assert.equal(stored.classification, 'UNVERIFIED_BYTES');
  assert.equal(fixture.source.calls.sign, 1);
  const db = new Journal(h.databasePath);
  try {
    const artifact = db
      .get('organization-history-v1', 'head')
      .value.artifacts.find((a) => a.id === id);
    const key = 'blob:' + artifact.original,
      manifest = db.get('organization-history-v1', key).value;
    manifest.chunks.reverse();
    db.db
      .prepare('UPDATE state SET value=? WHERE namespace=? AND id=?')
      .run(c.dcbor(manifest), 'organization-history-v1', key);
  } finally {
    db.close();
  }
  assert.throws(() => reopened.source.readEvidence(id), { code: 'ORG_HISTORY_STORAGE_CORRUPT' });
});

for (const damage of ['changed', 'missing', 'truncated'])
  test(`${damage} exact chunks fail closed after reopen`, (t) => {
    const h = harness(t),
      first = h.open();
    const result = first.verifier.verify(fixture.input);
    assert.equal(result.overall, 'VALID');
    first.source.close();
    const db = new Journal(h.databasePath);
    try {
      const head = db.get('organization-history-v1', 'head').value;
      const artifact = head.artifacts.find((a) => a.id === result.knowledgeReceipt.evidenceID);
      const manifest = db.get('organization-history-v1', 'blob:' + artifact.original).value;
      const chunkID = 'chunk:' + manifest.chunks[0];
      const chunk = db.get('organization-history-v1', chunkID).value;
      if (damage === 'missing')
        db.db
          .prepare('DELETE FROM state WHERE namespace=? AND id=?')
          .run('organization-history-v1', chunkID);
      else {
        chunk[0] ^= 1;
        db.db
          .prepare('UPDATE state SET value=? WHERE namespace=? AND id=?')
          .run(
            c.dcbor(damage === 'truncated' ? chunk.subarray(1) : chunk),
            'organization-history-v1',
            chunkID,
          );
      }
    } finally {
      db.close();
    }
    const reopened = h.open();
    assert.throws(() => reopened.source.readEvidence(result.knowledgeReceipt.evidenceID), {
      code: 'ORG_HISTORY_STORAGE_CORRUPT',
    });
    const rejected = reopened.verifier.verify(fixture.input);
    assert.equal(rejected.overall, 'INDETERMINATE');
    assert.equal(rejected.knowledgeReceipt.state, 'NOT_COMMITTED');
  });

test('storage frame capacity counts repeated replay positions and persists overflow without eviction', (t) => {
  // This is a storage-mechanism boundary test. It does not assert that arbitrary
  // inputs below passed cryptographic admission; that boundary has separate tests.
  const h = harness(t),
    store = new OrganizationHistoryKnowledgeStore(h.databasePath, h.value.configuration);
  const input = {
    originalBytes: Buffer.from('opaque original'),
    evidenceRecord: Buffer.from('opaque ERS'),
  };
  const admitted = {
    authorityHistory: [],
    statusMaterial: [],
    certificateStatusMaterial: [],
    observations: [c.sha256(Buffer.from('mechanism observation')).toString('hex')],
    historySemantics: [],
    originalRequired: true,
  };
  let last;
  for (let i = 0; i < 256; i++) {
    admitted.observations = [c.sha256(Buffer.from('mechanism observation ' + i)).toString('hex')];
    last = store.transact((row) => store.append(row, input, fixture.K, admitted));
    assert.equal(last.overflow, false);
  }
  const before = store.head().value;
  assert.equal(before.frames.length, 256);
  assert.equal(new Set(before.frames).size, 1);
  admitted.observations = [c.sha256(Buffer.from('mechanism observation 256')).toString('hex')];
  const overflow = store.transact((row) => store.append(row, input, fixture.K, admitted));
  assert.equal(overflow.overflow, true);
  assert.equal(overflow.evidenceID, null);
  assert.deepEqual(store.head().value.frames, before.frames);
  assert.equal(store.head().value.overflow, true);
  store.close();
  h.value.knowledge.knowledgeTime = fixture.K + 256;
  const reopened = h.open().verifier.verify(fixture.input);
  assert.equal(reopened.overall, 'UNSUPPORTED');
  assert.equal(reopened.reason, 'ORG_HISTORY_KNOWLEDGE_LIMIT');
});

for (const [name, limit] of [
  ['observations', 4096],
  ['historySemantics', 256],
])
  test(`storage ${name} capacity is aggregate and sticky across reopen`, (t) => {
    const h = harness(t),
      store = new OrganizationHistoryKnowledgeStore(h.databasePath, h.value.configuration);
    const input = {
      originalBytes: Buffer.from('opaque quota input'),
      evidenceRecord: Buffer.from('opaque ERS'),
    };
    const admitted = {
      authorityHistory: [],
      statusMaterial: [],
      certificateStatusMaterial: [],
      observations: [],
      historySemantics: [],
      originalRequired: true,
    };
    admitted[name] = Array.from({ length: limit }, (_, i) =>
      c.sha256(Buffer.from(name + i)).toString('hex'),
    );
    assert.equal(
      store.transact((row) => store.append(row, input, fixture.K, admitted)).overflow,
      false,
    );
    assert.equal(store.head().value[name].length, limit);
    admitted[name] = [c.sha256(Buffer.from('one beyond ' + name)).toString('hex')];
    assert.equal(
      store.transact((row) => store.append(row, input, fixture.K + 1, admitted)).overflow,
      true,
    );
    assert.equal(store.head().value[name].length, limit);
    store.close();
    h.value.knowledge.knowledgeTime = fixture.K + 1;
    const source = h.open();
    assert.equal(source.verifier.verify(fixture.input).reason, 'ORG_HISTORY_KNOWLEDGE_LIMIT');
  });

test('storage artifact count bound handles legacy unreferenced entries atomically', (t) => {
  const h = harness(t),
    store = new OrganizationHistoryKnowledgeStore(h.databasePath, h.value.configuration);
  const admitted = {
    authorityHistory: [],
    statusMaterial: [],
    certificateStatusMaterial: [],
    observations: [c.sha256(Buffer.from('last legacy slot')).toString('hex')],
    historySemantics: [],
    originalRequired: true,
  };
  // Isolate the count mechanism: legacy databases can contain artifact entries
  // without replay frames. Exact content/readEvidence integrity is tested above.
  const row = store.head(),
    original = c.sha256(Buffer.from('legacy original')).toString('hex'),
    record = c.sha256(Buffer.from('legacy record')).toString('hex');
  const artifacts = Array.from({ length: 1023 }, (_, i) => ({
    id: c.sha256(c.dcbor(['legacy pair', i])).toString('hex'),
    original,
    record,
  }));
  store.journal.put('organization-history-v1', 'head', { ...row.value, artifacts }, row.revision);
  const last = {
    originalBytes: Buffer.from('last pair'),
    evidenceRecord: Buffer.from('opaque ERS'),
  };
  assert.equal(
    store.transact((head) => store.append(head, last, fixture.K, admitted)).overflow,
    false,
  );
  const before = store.head().value;
  assert.equal(before.artifacts.length, 1024);
  const next = {
    originalBytes: Buffer.from('one pair beyond'),
    evidenceRecord: last.evidenceRecord,
  };
  admitted.observations = [c.sha256(Buffer.from('next legacy slot')).toString('hex')];
  const overflow = store.transact((head) => store.append(head, next, fixture.K, admitted));
  assert.equal(overflow.overflow, true);
  assert.equal(overflow.evidenceID, null);
  before.overflow = true;
  assert.deepEqual(store.head().value, before);
  assert.equal(
    store.journal.get(
      'organization-history-v1',
      'blob:' + c.sha256(next.originalBytes).toString('hex'),
    ),
    undefined,
  );
  store.close();
});

test('storage exact-content byte capacity accepts 256 MiB and atomically rejects one more byte', (t) => {
  const h = harness(t),
    store = new OrganizationHistoryKnowledgeStore(h.databasePath, h.value.configuration);
  const admitted = {
    authorityHistory: [],
    statusMaterial: [],
    certificateStatusMaterial: [],
    observations: [],
    historySemantics: [],
    originalRequired: true,
  };
  const record = Buffer.from('opaque ERS');
  for (let i = 0; i < 3; i++) {
    admitted.observations = [c.sha256(Buffer.from('content observation ' + i)).toString('hex')];
    const input = { originalBytes: Buffer.alloc(64 * 1024 * 1024, i + 1), evidenceRecord: record };
    assert.equal(
      store.transact((row) => store.append(row, input, fixture.K, admitted)).overflow,
      false,
    );
  }
  const head = store.head().value;
  const frameBytes = store.journal.get('organization-history-v1', 'blob:' + head.frames.at(-1))
    .value.length;
  const remaining = 256 * 1024 * 1024 - head.bytes - frameBytes;
  admitted.observations = [c.sha256(Buffer.from('content observation 3')).toString('hex')];
  assert(remaining > 0 && remaining <= 64 * 1024 * 1024);
  const boundary = { originalBytes: Buffer.alloc(remaining, 4), evidenceRecord: record };
  assert.equal(
    store.transact((row) => store.append(row, boundary, fixture.K, admitted)).overflow,
    false,
  );
  assert.equal(store.head().value.bytes, 256 * 1024 * 1024);
  admitted.observations = [c.sha256(Buffer.from('content observation 4')).toString('hex')];
  const overflow = { originalBytes: Buffer.from([5]), evidenceRecord: record };
  assert.equal(
    store.transact((row) => store.append(row, overflow, fixture.K, admitted)).overflow,
    true,
  );
  assert.equal(store.head().value.bytes, 256 * 1024 * 1024);
  store.close();
  assert.equal(h.open().verifier.verify(fixture.input).reason, 'ORG_HISTORY_KNOWLEDGE_LIMIT');
});

test('two already-open sources reload rather than overwrite independent negative observations', (t) => {
  const h = harness(t),
    first = h.open(),
    second = h.open();
  h.value.knowledge.statusMaterial.push(revoke());
  const a = first.verifier.verify(fixture.input);
  assert.equal(a.overall, 'INVALID');
  refresh(h.value);
  h.value.knowledge.certificateStatusMaterial = [
    fixture.certificateStatus({
      publishedAt: fixture.K,
      status: 'REVOKED',
      effectiveTime: fixture.K,
      compromiseStart: fixture.A,
    }),
  ];
  const b = second.verifier.verify(fixture.input);
  assert.equal(b.overall, 'INVALID');
  assert(b.knowledgeReceipt.revision > a.knowledgeReceipt.revision);
  first.source.close();
  second.source.close();
  refresh(h.value);
  const c = h.open().verifier.verify(fixture.input);
  assert(
    c.currentAdmissibility.checks.some(
      (v) => v.reason === 'ORG_STATUS_REVOKED' || v.reason === 'ORG_KEY_COMPROMISED',
    ),
  );
  assert(c.currentAdmissibility.checks.some((v) => v.reason === 'STATUS_REVOKED'));
  assert.equal(c.knowledgeReceipt.state, 'COMMITTED');
});

test('complete database rollback demonstrates the documented local-storage limitation', (t) => {
  const h = harness(t),
    first = h.open();
  assert.equal(first.verifier.verify(fixture.input).overall, 'VALID');
  first.source.close();
  const backup = join(h.directory, 'complete-earlier-database.sqlite');
  copyFileSync(h.databasePath, backup);
  h.value.knowledge.statusMaterial.push(revoke());
  const second = h.open();
  assert.equal(second.verifier.verify(fixture.input).overall, 'INVALID');
  second.source.close();
  copyFileSync(backup, h.databasePath);
  refresh(h.value);
  const rolledBack = h.open().verifier.verify(fixture.input);
  assert.equal(
    rolledBack.overall,
    'VALID',
    'there is no external monotonic anchor in this capability',
  );
  assert.equal(rolledBack.knowledgeReceipt.state, 'COMMITTED');
});

let childSequence = 0;
function childRun(h, knowledge, { seam = 'none', evidenceID } = {}) {
  const prefix = join(h.directory, 'process-' + ++childSequence);
  writeFileSync(
    prefix + '.cbor',
    c.dcbor({
      configuration: h.value.configuration,
      knowledge,
      ...(evidenceID ? { evidenceID } : { input: fixture.input }),
    }),
  );
  const child = spawn(
    process.execPath,
    [
      fileURLToPath(new URL('./organization-history-knowledge-child.mjs', import.meta.url)),
      prefix + '.cbor',
      h.databasePath,
      prefix + '.json',
      seam,
    ],
    { stdio: ['ignore', 'pipe', 'pipe'] },
  );
  let output = '';
  child.stdout.on('data', (bytes) => {
    output += bytes;
  });
  child.stderr.on('data', (bytes) => {
    output += bytes;
  });
  const exit = new Promise((resolve, reject) => {
    child.on('error', reject);
    child.on('exit', (code, signal) => resolve({ code, signal }));
  });
  return {
    child,
    exit,
    prefix,
    async ready() {
      for (let i = 0; i < 600; i++) {
        if (existsSync(prefix + '.json.ready')) {
          const marker = JSON.parse(readFileSync(prefix + '.json.ready', 'utf8'));
          assert.equal(marker.pid, child.pid);
          assert.notEqual(marker.pid, process.pid);
          assert.equal(marker.seam, seam);
          return marker;
        }
        if (child.exitCode !== null) assert.fail('child exited before seam: ' + output);
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      child.kill('SIGKILL');
      assert.fail('child did not reach persistence seam: ' + output);
    },
    release() {
      writeFileSync(prefix + '.json.release', 'continue');
    },
    async result() {
      const status = await exit;
      assert.equal(status.code, 0, output);
      const value = JSON.parse(readFileSync(prefix + '.json', 'utf8'));
      assert.equal(value.pid, child.pid);
      assert.notEqual(value.pid, process.pid);
      return value;
    },
  };
}

test('genuinely separate processes retain a committed incident and recover exact public originals', async (t) => {
  const h = harness(t),
    negative = copy(h.value.knowledge);
  negative.statusMaterial.push(revoke());
  const writer = childRun(h, negative);
  const first = await writer.result();
  assert.equal(first.result.overall, 'INVALID');
  assert.equal(first.result.knowledgeReceipt.state, 'COMMITTED');
  refresh(h.value);
  const reader = childRun(h, h.value.knowledge, {
    evidenceID: first.result.knowledgeReceipt.evidenceID,
  });
  const second = await reader.result();
  assert.notEqual(first.pid, second.pid);
  assert.equal(second.result.overall, 'INVALID');
  assert.equal(second.result.historicalAuthorization.overall, 'VALID');
  assert.equal(second.result.knowledgeReceipt.state, 'COMMITTED');
  assert.equal(second.originalHash, c.sha256(fixture.input.originalBytes).toString('hex'));
  assert.equal(second.evidenceRecordHash, c.sha256(fixture.input.evidenceRecord).toString('hex'));
  assert.equal(fixture.source.calls.sign, 1);
});

for (const seam of ['before-append', 'before-commit', 'after-commit'])
  test(`actual process death at ${seam} preserves the transaction boundary`, async (t) => {
    const h = harness(t),
      baseline = h.open();
    const initial = baseline.verifier.verify(fixture.input);
    assert.equal(initial.overall, 'VALID');
    baseline.source.close();
    const beforeDB = new Journal(h.databasePath),
      initialRows = beforeDB.list('organization-history-v1').length;
    beforeDB.close();
    const knowledge = copy(h.value.knowledge);
    knowledge.statusMaterial.push(revoke());
    const dying = childRun(h, knowledge, { seam });
    await dying.ready();
    assert.equal(dying.child.kill('SIGKILL'), true);
    const death = await dying.exit;
    assert(
      death.signal !== null || death.code !== 0,
      'the reached process must actually terminate',
    );
    assert.equal(existsSync(dying.prefix + '.json'), false, 'no result was exposed');
    const afterDB = new Journal(h.databasePath);
    try {
      assert.equal(
        afterDB.get('organization-history-v1', 'head').value.frames.length,
        seam === 'after-commit' ? 2 : 1,
      );
      if (seam !== 'after-commit')
        assert.equal(
          afterDB.list('organization-history-v1').length,
          initialRows,
          'no partial chunk, frame, or artifact row survives an uncommitted process death',
        );
    } finally {
      afterDB.close();
    }
    refresh(h.value);
    const recovery = await childRun(h, h.value.knowledge, {
      evidenceID: initial.knowledgeReceipt.evidenceID,
    }).result();
    assert.equal(
      recovery.result.overall,
      seam === 'after-commit' ? 'INVALID' : 'VALID',
      JSON.stringify(recovery),
    );
    assert.equal(recovery.result.knowledgeReceipt.state, 'COMMITTED');
    assert.equal(recovery.originalHash, c.sha256(fixture.input.originalBytes).toString('hex'));
    assert.equal(
      recovery.evidenceRecordHash,
      c.sha256(fixture.input.evidenceRecord).toString('hex'),
    );
    assert.equal(fixture.source.calls.sign, 1);
  });

test('overlapping writer processes reload the committed incident before returning a verdict', async (t) => {
  const h = harness(t),
    seed = h.open();
  assert.equal(seed.verifier.verify(fixture.input).overall, 'VALID');
  seed.source.close();
  const negative = copy(h.value.knowledge);
  negative.statusMaterial.push(revoke());
  const first = childRun(h, negative, { seam: 'before-commit' });
  await first.ready();
  refresh(h.value);
  const second = childRun(h, h.value.knowledge);
  await new Promise((resolve) => setTimeout(resolve, 150));
  first.release();
  const [a, b] = await Promise.all([first.result(), second.result()]);
  assert.notEqual(a.pid, b.pid);
  assert.equal(a.result.overall, 'INVALID');
  assert.equal(b.result.overall, 'INVALID');
  assert.equal(a.result.knowledgeReceipt.state, 'COMMITTED');
  assert.equal(b.result.knowledgeReceipt.state, 'COMMITTED');
  assert(b.result.knowledgeReceipt.revision > a.result.knowledgeReceipt.revision);
});

test('a locked database yields typed uncommitted INDETERMINATE and never a cached positive', async (t) => {
  const h = harness(t),
    first = h.open();
  assert.equal(first.verifier.verify(fixture.input).overall, 'VALID');
  const lock = childRun(h, h.value.knowledge, { seam: 'lock' });
  await lock.ready();
  const blocked = first.verifier.verify(fixture.input);
  assert.equal(blocked.overall, 'INDETERMINATE', JSON.stringify(blocked));
  assert.equal(blocked.knowledgeReceipt.state, 'NOT_COMMITTED');
  lock.release();
  assert.equal((await lock.exit).code, 0);
  assert.equal(first.verifier.verify(fixture.input).overall, 'VALID');
});

test('a changed artifact map cannot return another retained pair under the original evidence ID', async (t) => {
  const h = harness(t),
    first = h.open();
  const original = first.verifier.verify(fixture.input);
  assert.equal(original.overall, 'VALID');
  assert.match(original.knowledgeReceipt.evidenceID, /^[a-f0-9]{64}$/);
  const originalBytes = fixture.replaceLeaf(
    'Document',
    Buffer.from('a different retained candidate'),
  );
  const evidenceRecord = await fixture.preserve(originalBytes);
  h.value.knowledge.statusMaterial.push(revoke());
  const other = first.verifier.verify({ originalBytes, evidenceRecord });
  assert.equal(other.overall, 'INVALID');
  assert.equal(other.knowledgeReceipt.state, 'COMMITTED');
  assert.match(other.knowledgeReceipt.evidenceID, /^[a-f0-9]{64}$/);
  assert.notEqual(original.knowledgeReceipt.evidenceID, other.knowledgeReceipt.evidenceID);
  first.source.close();
  const db = new Journal(h.databasePath);
  try {
    const head = db.get('organization-history-v1', 'head');
    const a = head.value.artifacts.find((v) => v.id === original.knowledgeReceipt.evidenceID);
    const b = head.value.artifacts.find((v) => v.id === other.knowledgeReceipt.evidenceID);
    a.original = b.original;
    a.record = b.record;
    db.put('organization-history-v1', 'head', head.value, head.revision);
  } finally {
    db.close();
  }
  const reopened = h.open();
  assert.throws(() => reopened.source.readEvidence(original.knowledgeReceipt.evidenceID), {
    code: 'ORG_HISTORY_STORAGE_CORRUPT',
  });
  const invalid = reopened.verifier.verify(fixture.input);
  assert.equal(invalid.overall, 'INDETERMINATE');
  assert.equal(invalid.knowledgeReceipt.state, 'NOT_COMMITTED');
});

test('sticky capacity replays a genuine retained compromise and advances only selected K', (t) => {
  const h = harness(t);
  h.value.knowledge.statusMaterial.push(revoke());
  const first = h.open(),
    initial = first.verifier.verify(fixture.input);
  assert.equal(initial.overall, 'INVALID');
  assert.equal(initial.knowledgeReceipt.state, 'COMMITTED');
  first.source.close();
  // Inject only the sticky capacity flag. Exact capacity accounting is tested
  // separately; this test retains the genuinely authenticated replay material.
  const store = new OrganizationHistoryKnowledgeStore(h.databasePath, h.value.configuration);
  const row = store.head();
  store.journal.put(
    'organization-history-v1',
    'head',
    { ...row.value, overflow: true },
    row.revision,
  );
  const before = store.head();
  assert.equal(before.value.overflow, true);
  store.close();
  refresh(h.value);
  const reopened = h.open(),
    result = reopened.verifier.verify(fixture.input);
  assert.equal(result.overall, 'INVALID', JSON.stringify(result));
  assert.equal(result.currentAdmissibility.overall, 'INVALID');
  assert.equal(result.historicalAuthorization.overall, 'VALID');
  assert.equal(result.knowledgeReceipt.state, 'COMMITTED');
  assert.equal(result.knowledgeReceipt.evidenceID, null);
  assert(
    result.checks.some(
      (v) => v.overall === 'UNSUPPORTED' && v.reason === 'ORG_HISTORY_KNOWLEDGE_LIMIT',
    ),
  );
  assert.deepEqual(
    reopened.source.readEvidence(initial.knowledgeReceipt.evidenceID).originalBytes,
    fixture.input.originalBytes,
  );
  const after = new Journal(h.databasePath);
  try {
    const row = after.get('organization-history-v1', 'head'),
      head = row.value;
    assert.equal(head.selectedKnowledge, h.value.knowledge.knowledgeTime);
    assert.equal(head.overflow, true);
    assert.equal(result.knowledgeReceipt.revision, row.revision);
    assert(row.revision > before.revision);
    for (const field of ['frames', 'artifacts', 'observations', 'historySemantics', 'bytes'])
      assert.deepEqual(head[field], before.value[field]);
  } finally {
    after.close();
  }
  const equalKnowledge = reopened.verifier.verify(fixture.input);
  assert.equal(equalKnowledge.overall, 'INVALID');
  assert.deepEqual(equalKnowledge.knowledgeReceipt, result.knowledgeReceipt);
  h.value.knowledge.knowledgeTime--;
  const rollback = reopened.verifier.verify(fixture.input);
  assert.equal(rollback.overall, 'INVALID');
  assert.equal(rollback.reason, 'ORG_KNOWLEDGE_ROLLBACK');
  assert.equal(rollback.knowledgeReceipt.state, 'NOT_COMMITTED');
});

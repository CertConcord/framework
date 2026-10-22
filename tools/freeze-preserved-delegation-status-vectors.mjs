import assert from 'node:assert/strict';
import fs from 'node:fs';
import { resolve, join } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import * as c from '../reference/core.mjs';
import * as p from '../reference/pki.mjs';
import { readControl } from '../reference/state.mjs';
import { createERS } from '../reference/archive.mjs';
import { copy } from '../reference/organization-delegation-fixtures.mjs';
import { createIndependentOrganizationHistoryFixture } from '../reference/fixtures-history-independent.mjs';
import { assertPublicHistoryData } from '../reference/fixtures-history-durable-independent.mjs';
import {
  preservedDelegationStatusSemantics,
  assertPreservedDelegationStatusOutcome,
} from '../reference/preserved-delegation-status-semantics.mjs';
import {
  canonicalVectorJSON,
  vectorHash,
  organizationVectorProfile,
} from '../reference/organization-vector-corpus.mjs';

const rawHistory = (entries) =>
  entries.map(({ manifest, signatures, publicationProof }) => ({
    manifest: c.dcbor(manifest),
    signatures: copy(signatures),
    publicationProof: Buffer.from(publicationProof),
  }));

/** Authoring only. The result contains synthetic public bytes, never signing keys. */
export async function createPreservedDelegationStatusInputs() {
  const f = await createIndependentOrganizationHistoryFixture({ knowledgeDelay: 200 });
  try {
    const S = f.A + 20,
      Q = f.A + 30,
      deadline = f.A + 40,
      key = c.generate('ml-dsa-87');
    const identity = (notAfter = f.A + 120) => ({
      ...key,
      certificate: p.issueCertificate(
        {
          publicKey: key.publicKey,
          serial: notAfter,
          issuer: p.name('Independent historical governance'),
          subject: p.name('Preserved external delegation status'),
          profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1',
          notBefore: f.A - 60,
          notAfter,
        },
        f.root.privateKey,
      ),
    });
    const signer = identity(),
      keyHex = c.keyID(key.publicKey).toString('hex'),
      configuration = copy(f.publicSourceConfiguration);
    configuration.trust.keyDeadlines[keyHex] = deadline;
    configuration.trust.controlTrust.push({
      certificate: signer.certificate,
      organizationID: f.trust.organizationID,
      identityNamespace: f.trust.identityNamespace,
      issuerID: f.trust.issuerID,
      purpose: 'ORGANIZATION_DELEGATION_STATUS',
      objectTypes: ['GRANT', 'APPROVER_REGISTRATION', 'FINAL_AUTHORIZATION'],
    });
    const targetIndex = (type) =>
      f.originalStatusMembers.findIndex(
        (member) =>
          readControl(member.cms, 'OrganizationDelegationStatus', member.issuerCertificate)
            .objectType === type,
      );
    const makeHistory = ({
      selectedSigner = signer,
      change = (v) => v,
      originalStatusUntil,
    } = {}) => {
      const record = change({
        mode: 'CERTIFICATE',
        certificate: selectedSigner.certificate,
        roles: ['STATUS_AUTHORITY'],
        scopes: [copy(f.source.scope('ORGANIZATION_DELEGATION_STATUS'))],
        knownAt: f.A - 30,
        validFrom: f.A - 30,
        validUntil: deadline,
        status: {
          authorityID: c.keyID(key.publicKey),
          trustDomainID: f.trust.trustDomainID,
          scope: 'AUTHORITY',
          status: 'GOOD',
          publishedAt: f.A - 30,
          nextUpdate: f.A + 200,
        },
      });
      const originals = (values) =>
        copy(values).map((value) => {
          if (
            originalStatusUntil !== undefined &&
            c.equal(value.certificate, f.source.keys.status.certificate)
          )
            value.validUntil = originalStatusUntil;
          return value;
        });
      const first = f.manifest([...originals(f.initialAuthorities), record], f.A - 30),
        current = copy(record);
      current.status.publishedAt = f.K - 1;
      current.status.nextUpdate = f.K + 300;
      const latest = f.manifest([...originals(f.currentAuthorities), current], f.K - 1, first, {
        replacement: true,
      });
      return [first, latest];
    };
    const defaultHistory = makeHistory(),
      entries = [];
    for (const spec of preservedDelegationStatusSemantics) {
      const type =
          spec.id === 'preserved-approver-registration'
            ? 'APPROVER_REGISTRATION'
            : spec.id === 'preserved-final-authorization'
              ? 'FINAL_AUTHORIZATION'
              : 'GRANT',
        index = targetIndex(type),
        target = f.originalStatusMembers[index];
      assert(index >= 0);
      const entry = {
        id: spec.id,
        description: spec.id.replaceAll('-', ' '),
        configuration: copy(configuration),
        knowledge: { ...copy(f.knowledge), authorityHistory: rawHistory(defaultHistory) },
        originalBytes: Buffer.from(f.originalBytes),
        evidenceRecord: Buffer.from(f.evidenceRecord),
      };
      let selectedSigner = signer,
        changes = {},
        firstAt = Q,
        renewalAt = f.A + 50;
      switch (spec.id) {
        case 'retired-without-proof':
          // Isolate role retirement from key and certificate expiry at K.
          selectedSigner = identity(f.end);
          entry.configuration.trust.keyDeadlines[keyHex] = f.end;
          entry.configuration.trust.controlTrust.at(-1).certificate = selectedSigner.certificate;
          entry.knowledge.authorityHistory = rawHistory(makeHistory({ selectedSigner }));
          break;
        case 'proof-before-publication':
          firstAt = S - 1;
          break;
        case 'proof-at-publication':
          firstAt = S;
          break;
        case 'proof-before-key-deadline':
          firstAt = deadline - 1;
          break;
        case 'proof-at-key-deadline':
          firstAt = deadline;
          break;
        case 'proof-at-signature-algorithm-deadline':
          entry.configuration.trust.algorithmDeadlines[c.ALG[key.publicKey.asymmetricKeyType].oid] =
            Q;
          break;
        case 'proof-at-hash-deadline':
          entry.configuration.trust.hashDeadlines[p.OID.sha512] = Q;
          break;
        case 'proof-at-certificate-expiry':
          selectedSigner = identity(Q);
          entry.configuration.trust.controlTrust.at(-1).certificate = selectedSigner.certificate;
          entry.knowledge.authorityHistory = rawHistory(makeHistory({ selectedSigner }));
          break;
        case 'renewal-before-expiry':
          renewalAt = f.A + 79;
          break;
        case 'renewal-at-expiry':
          renewalAt = f.A + 80;
          break;
        case 'renewal-after-expiry':
          renewalAt = f.A + 81;
          break;
        case 'status-cross-domain':
          changes.trustDomainID = c.random();
          break;
        case 'status-cross-organization':
          changes.organizationID = c.random();
          break;
        case 'status-wrong-scope':
          changes.scope = 'AUTHORITY';
          break;
        case 'status-target-unavailable':
          changes.objectID = c.random();
          break;
        case 'status-wrong-object-hash':
          changes.objectHash = c.sha512(Buffer.from('another object'));
          break;
        case 'status-wrong-subject-key':
          changes.subjectKeyID = c.sha512(Buffer.from('another key'));
          break;
        case 'signer-object-type-not-mapped':
          entry.configuration.trust.controlTrust.at(-1).objectTypes = ['FINAL_AUTHORIZATION'];
          break;
        case 'signer-not-appointed-at-publication':
        case 'signer-retired-at-proof':
        case 'signer-wrong-role':
        case 'signer-wrong-scope':
        case 'signer-revoked-at-publication':
        case 'signer-compromised-at-proof':
        case 'signer-compromised-after-proof': {
          const history = makeHistory({
            change(value) {
              if (spec.id === 'signer-not-appointed-at-publication') value.validFrom = S + 1;
              if (spec.id === 'signer-retired-at-proof') value.validUntil = Q;
              if (spec.id === 'signer-wrong-role') value.roles = ['ISSUER'];
              if (spec.id === 'signer-wrong-scope')
                value.scopes[0].issuerID = 'other-status-issuer';
              return value;
            },
          });
          if (spec.id.includes('revoked') || spec.id.includes('compromised')) {
            const authorities = copy(history[1].manifest.authorities),
              record = authorities.find((value) => c.equal(value.certificate, signer.certificate));
            record.status.status = 'REVOKED';
            record.status.effectiveTime = spec.id.includes('revoked') ? S : f.K - 1;
            if (spec.id.includes('compromised'))
              record.status.compromiseStart = Q + (spec.id.endsWith('after-proof') ? 1 : 0);
            history[1] = f.manifest(authorities, f.K - 1, history[0], { replacement: true });
          }
          entry.knowledge.authorityHistory = rawHistory(history);
          break;
        }
        case 'missing-current-authority-coverage':
          entry.knowledge.authorityHistory = rawHistory([defaultHistory[0]]);
          break;
        case 'stale-preserved-good':
          changes.nextUpdate = f.K;
          break;
        case 'stale-retrospective-compromise':
          changes = {
            status: 'REVOKED',
            effectiveTime: S,
            compromiseStart: f.A,
            nextUpdate: S + 1,
          };
          break;
        case 'ordinary-revocation-after-document-proof':
          changes = { status: 'REVOKED', effectiveTime: f.P + 1 };
          break;
        case 'revocation-at-document-proof':
          changes = { status: 'REVOKED', effectiveTime: f.P };
          break;
        case 'compromise-followed-by-current-good':
          changes = { status: 'REVOKED', effectiveTime: S, compromiseStart: f.A };
          break;
        case 'preserved-status-critical-unknown':
          changes.critical = ['unrecognized-status-extension'];
          break;
        case 'missing-status-key-deadline':
          delete entry.configuration.trust.keyDeadlines[keyHex];
          break;
      }
      const status = (overrides = {}) =>
        f.organizationStatus(
          target,
          { publishedAt: S, nextUpdate: f.K + 99, ...changes, ...overrides },
          selectedSigner,
        );
      let member = status();
      member.evidenceRecord = await f.preserve(member.cms, { firstAt, renewalAt });
      if (spec.id === 'retired-without-proof') delete member.evidenceRecord;
      if (spec.id === 'proof-signature-tampered')
        member.evidenceRecord[member.evidenceRecord.length - 1] ^= 1;
      if (spec.id === 'proof-covers-different-cms')
        member.evidenceRecord = await f.preserve(status({ nextUpdate: f.K + 98 }).cms, {
          firstAt,
          renewalAt,
        });
      if (spec.id === 'malformed-status-proof') member.evidenceRecord = Buffer.from([1, 2, 3]);
      if (spec.id === 'cms-signer-certificate-substituted')
        member.issuerCertificate = Buffer.from(f.statusSuccessor.certificate);
      entry.knowledge.statusMaterial[index] = member;
      if (['proof-at-signature-algorithm-deadline', 'proof-at-hash-deadline'].includes(spec.id)) {
        // These global deadlines also constrain current successor statements.
        // Check the selected first proof before those independent K failures.
        entry.knowledge.statusMaterial.splice(index, 1);
        entry.knowledge.statusMaterial.unshift(member);
      }
      if (spec.id === 'same-epoch-conflict') {
        const conflict = status({ status: 'REVOKED', effectiveTime: f.P + 1 });
        conflict.evidenceRecord = await f.preserve(conflict.cms, { firstAt, renewalAt });
        entry.knowledge.statusMaterial.push(conflict);
      }
      if (spec.id === 'compromise-followed-by-current-good') {
        const body = readControl(member.cms, 'OrganizationDelegationStatus', signer.certificate);
        entry.knowledge.statusMaterial.push(
          f.organizationStatus(target, { epoch: body.epoch + 1 }),
        );
      }
      if (spec.id === 'duplicate-invalid-proof') {
        const duplicate = copy(member);
        duplicate.evidenceRecord[duplicate.evidenceRecord.length - 1] ^= 1;
        entry.knowledge.statusMaterial.push(duplicate);
      }
      if (spec.id.startsWith('original-copy-')) {
        entry.knowledge.statusMaterial = [];
        for (const original of f.originalStatusMembers)
          entry.knowledge.statusMaterial.push({
            ...copy(original),
            evidenceRecord: await f.preserve(original.cms, {
              firstAt: f.A + 10,
              renewalAt: f.A + 50,
            }),
          });
        if (spec.id === 'original-copy-invalid-proof') {
          const proof = entry.knowledge.statusMaterial[0].evidenceRecord;
          proof[proof.length - 1] ^= 1;
        }
        if (spec.id === 'original-copy-role-retired-at-package-proof') {
          entry.evidenceRecord = await f.preserve(entry.originalBytes, {
            firstAt: f.A + 20,
            renewalAt: f.A + 50,
          });
          entry.knowledge.authorityHistory = rawHistory(
            makeHistory({ originalStatusUntil: f.A + 20 }),
          );
        }
        // Original final-authorization status expires at A+30. Keep current
        // successor statements so the duplicate tests isolate proof obligations,
        // without a separate stale-status failure masking the result.
        entry.knowledge.statusMaterial.push(...copy(f.knowledge.statusMaterial));
      }
      if (spec.id === 'unpreserved-current-successor')
        entry.knowledge.statusMaterial = copy(f.knowledge.statusMaterial);
      if (spec.id.startsWith('current-successor-') || spec.id === 'proof-at-selected-knowledge') {
        const at = spec.id.endsWith('after-knowledge')
          ? f.K + 1
          : spec.id === 'proof-at-selected-knowledge'
            ? f.K
            : f.K - 1;
        // Normal publication issuance selects the synthetic clock. This unused
        // manifest is not part of the reader's authority history.
        f.manifest(f.currentAuthorities, at, f.firstManifest);
        const current = f.organizationStatus(target);
        current.evidenceRecord = await createERS(current.cms, { tsa: f.renewalTSA.issue });
        if (spec.id === 'current-successor-invalid-proof')
          current.evidenceRecord[current.evidenceRecord.length - 1] ^= 1;
        entry.knowledge.statusMaterial[index] = current;
      }
      assertPublicHistoryData(entry);
      assert(S > f.P && Q > S && deadline > Q && f.K > deadline);
      entries.push(entry);
    }
    return entries;
  } finally {
    f.close();
  }
}

/** Capture complete results only after the separately reviewable oracle passes. */
export async function freezePreservedDelegationStatusVectors({
  inputPath,
  directory,
  semanticSHA256,
}) {
  const repository = fileURLToPath(new URL('../', import.meta.url)),
    semanticsPath = 'reference/preserved-delegation-status-semantics.mjs';
  assert.equal(semanticSHA256, vectorHash(fs.readFileSync(join(repository, semanticsPath))));
  assert(!fs.existsSync(join(directory, 'manifest.json')), 'Frozen corpus already exists');
  const inputBytes = fs.readFileSync(inputPath);
  const entries = copy(
    c.decodeCBOR(inputBytes, { maxBytes: 128 * 1024 * 1024, maxItems: 1000000 }),
  );
  assert.deepEqual(
    entries.map((entry) => entry.id),
    preservedDelegationStatusSemantics.map((s) => s.id),
  );
  const sdk = await import('../reference/sdk/index.mjs');
  const outcomes = [];
  for (const entry of entries) {
    assertPublicHistoryData(entry);
    const source = sdk.createOrganizationHistorySource({
      configuration: entry.configuration,
      readKnowledge: () => entry.knowledge,
    });
    try {
      const actual = sdk.createOrganizationHistoryVerifier({ source }).verify({
        originalBytes: entry.originalBytes,
        evidenceRecord: entry.evidenceRecord,
      });
      assertPreservedDelegationStatusOutcome(entry, actual);
      outcomes.push(canonicalVectorJSON(actual));
    } finally {
      source.close();
    }
  }
  const inventory = new Map();
  const add = (bytes, extension, mediaType, encoding = 'base64') => {
    const decoded = Buffer.from(bytes),
      decodedSHA256 = vectorHash(decoded),
      path = 'files/' + decodedSHA256 + '.' + extension,
      stored = encoding === 'base64' ? Buffer.from(decoded.toString('base64') + '\n') : decoded;
    const descriptor = {
      path,
      bytes: stored.length,
      sha256: vectorHash(stored),
      mediaType,
      encoding,
      decodedBytes: decoded.length,
      decodedSHA256,
    };
    if (inventory.has(path)) assert(inventory.get(path).stored.equals(stored));
    else inventory.set(path, { descriptor, stored });
    return path;
  };
  const json = (value) => add(canonicalVectorJSON(value), 'json', 'application/json', 'utf8');
  const materialize = (value, field = '') => {
    if (Buffer.isBuffer(value)) {
      const spki = ['publicKeyDER', 'issuerPublicKeyDER'].includes(field);
      return {
        $file: add(
          value,
          spki ? 'spki.b64' : 'bin.b64',
          spki ? 'application/pkix-spki' : 'application/octet-stream',
        ),
        type: spki ? 'spki' : 'bytes',
      };
    }
    if (Array.isArray(value)) return value.map((child) => materialize(child));
    if (value && typeof value === 'object')
      return Object.fromEntries(
        Object.entries(value).map(([name, child]) => [name, materialize(child, name)]),
      );
    return value;
  };
  const cases = entries.map((entry, index) => ({
    id: entry.id,
    description: entry.description,
    originalBytes: add(entry.originalBytes, 'cbor.b64', 'application/cbor'),
    evidenceRecord: add(entry.evidenceRecord, 'ers.b64', 'application/evidence-record'),
    policy: json(materialize(entry.configuration)),
    knowledge: json(materialize(entry.knowledge)),
    expected: add(outcomes[index], 'json', 'application/json', 'utf8'),
  }));
  const paths = [
    'tools/freeze-preserved-delegation-status-vectors.mjs',
    semanticsPath,
    'reference/fixtures-history-independent.mjs',
    'reference/organization-delegation-fixtures.mjs',
    'reference/fixtures-history-durable-independent.mjs',
    'reference/organization-history.mjs',
    'reference/organization-delegation-evidence.mjs',
    'reference/status-preservation.mjs',
    'reference/organization-history-source.mjs',
    'reference/organization-history-knowledge.mjs',
    'reference/organization-vector-corpus.mjs',
    'reference/verify-organization-vectors.mjs',
    'reference/archive.mjs',
    'reference/timestamp.mjs',
    'reference/retained-authorities.mjs',
    'reference/authority-history.mjs',
    'reference/document-evidence.mjs',
    'reference/enrollment-scope.mjs',
    'reference/pki.mjs',
    'reference/core.mjs',
    'reference/state.mjs',
    'reference/verification-result.mjs',
    'reference/sdk/index.mjs',
  ];
  const provenance = json({
    schemaVersion: 1,
    baselineCommit: 'ac43db6dfd52acbac57a091cb2c9b5cc71e06244',
    baselineTree: '11c0a93e9d9cbc1e52c3fca530cc263ab6260273',
    description:
      'Synthetic public inputs and complete results. Source digests describe construction; they do not attest an executing implementation or establish authority.',
    inputSHA256: vectorHash(inputBytes),
    inputBytes: inputBytes.length,
    semanticSHA256,
    runtime: { node: process.version, openssl: process.versions.openssl },
    dependencyLock: {
      path: 'package-lock.json',
      sha256: vectorHash(fs.readFileSync(join(repository, 'package-lock.json'))),
    },
    sources: paths.map((path) => ({
      path,
      sha256: vectorHash(fs.readFileSync(join(repository, path))),
    })),
  });
  const manifest = {
    schemaVersion: 1,
    profile: organizationVectorProfile,
    description:
      'External OrganizationDelegationStatus with independent complete-CMS RFC 4998 preservation and explicit original-package and current-knowledge boundaries.',
    provenance,
    files: [...inventory.values()]
      .map((v) => v.descriptor)
      .sort((a, b) => a.path.localeCompare(b.path)),
    cases,
  };
  assert(manifest.files.length <= 512);
  fs.mkdirSync(join(directory, 'files'), { recursive: true });
  for (const [path, value] of inventory)
    fs.writeFileSync(join(directory, path), value.stored, { flag: 'wx' });
  fs.writeFileSync(join(directory, 'manifest.json'), canonicalVectorJSON(manifest), { flag: 'wx' });
  return {
    cases: cases.length,
    files: manifest.files.length,
    manifestSHA256: vectorHash(canonicalVectorJSON(manifest)),
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  assert.equal(process.argv.length, 3, 'An absent output file is required for input freezing');
  const entries = await createPreservedDelegationStatusInputs();
  const bytes = c.dcbor(entries);
  fs.writeFileSync(resolve(process.argv[2]), bytes, { flag: 'wx' });
  console.log(
    JSON.stringify({
      cases: entries.length,
      bytes: bytes.length,
      sha256: c.sha256(bytes).toString('hex'),
    }),
  );
}

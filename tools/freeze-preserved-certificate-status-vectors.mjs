import assert from 'node:assert/strict';
import fs from 'node:fs';
import { resolve, join } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import * as c from '../reference/core.mjs';
import * as p from '../reference/pki.mjs';
import { readControl } from '../reference/state.mjs';
import { createERS } from '../reference/archive.mjs';
import { copy, signOrganizationControl } from '../reference/organization-delegation-fixtures.mjs';
import { createIndependentOrganizationHistoryFixture } from '../reference/fixtures-history-independent.mjs';
import { assertPublicHistoryData } from '../reference/fixtures-history-durable-independent.mjs';
import {
  preservedCertificateStatusSemantics,
  assertPreservedCertificateStatusOutcome,
} from '../reference/preserved-certificate-status-semantics.mjs';
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

/** Authoring only. Only public, exact input bytes leave this function. */
export async function createPreservedCertificateStatusInputs() {
  const f = await createIndependentOrganizationHistoryFixture();
  try {
    const S = f.A + 20,
      Q = f.A + 30,
      deadline = f.A + 40;
    const key = c.generate('ml-dsa-87');
    const signer = {
      ...key,
      certificate: p.issueCertificate(
        {
          publicKey: key.publicKey,
          serial: 1900,
          issuer: p.name('Independent historical governance'),
          subject: p.name('Preserved external certificate status'),
          profileID: 'CERTCONCORD-EVIDENCE-SIGN-v1',
          notBefore: f.A - 60,
          notAfter: f.A + 120,
        },
        f.root.privateKey,
      ),
    };
    const keyHex = c.keyID(key.publicKey).toString('hex');
    const record = {
      mode: 'CERTIFICATE',
      certificate: signer.certificate,
      roles: ['STATUS_AUTHORITY'],
      scopes: [copy(f.source.credentialScope)],
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
    };
    const configuration = copy(f.publicSourceConfiguration);
    configuration.trust.keyDeadlines[keyHex] = deadline;
    const status = (changes = {}) =>
      f.certificateStatus(
        {
          publishedAt: S,
          nextUpdate: f.K + 299,
          ...changes,
        },
        signer,
      );
    const makeHistory = (change = (value) => value) => {
      const original = change(copy(record));
      const first = f.manifest([...f.initialAuthorities, original], f.A - 30);
      const current = copy(original);
      current.status.publishedAt = f.K - 1;
      current.status.nextUpdate = f.K + 300;
      const latest = f.manifest([...f.currentAuthorities, current], f.K - 1, first, {
        replacement: true,
      });
      return [first, latest];
    };
    const defaultHistory = makeHistory();
    const baseStatus = status();
    const baseProof = await f.preserve(baseStatus.cms, { firstAt: Q, renewalAt: f.A + 50 });
    const entries = [];
    for (const spec of preservedCertificateStatusSemantics) {
      const entry = {
        id: spec.id,
        description: spec.id.replaceAll('-', ' '),
        configuration: copy(configuration),
        knowledge: { ...copy(f.knowledge), authorityHistory: rawHistory(defaultHistory) },
        originalBytes: Buffer.from(f.originalBytes),
        evidenceRecord: Buffer.from(f.evidenceRecord),
      };
      let member = { ...copy(baseStatus), evidenceRecord: Buffer.from(baseProof) };
      let changes,
        firstAt = Q,
        milliseconds = 0,
        renewalAt = f.A + 50;
      switch (spec.id) {
        case 'ordinary-revocation-after-document-proof':
          changes = { status: 'REVOKED', effectiveTime: f.P + 1 };
          break;
        case 'revocation-at-document-proof':
          changes = { status: 'REVOKED', effectiveTime: f.P };
          break;
        case 'compromise-before-document-proof':
        case 'compromise-followed-by-current-good':
          changes = { status: 'REVOKED', effectiveTime: S, compromiseStart: f.A };
          break;
        case 'retired-without-proof':
          delete member.evidenceRecord;
          break;
        case 'proof-before-publication':
          firstAt = S - 1;
          break;
        case 'proof-at-publication':
          firstAt = S;
          break;
        case 'proof-before-protection-deadline':
          firstAt = deadline - 1;
          milliseconds = 999;
          break;
        case 'proof-at-protection-deadline':
          firstAt = deadline;
          break;
        case 'proof-after-protection-deadline':
          firstAt = deadline + 1;
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
        case 'proof-signature-tampered':
          member.evidenceRecord[member.evidenceRecord.length - 1] ^= 1;
          break;
        case 'proof-covers-different-cms':
          member.evidenceRecord = await f.preserve(status({ nextUpdate: f.K + 298 }).cms, {
            firstAt: Q,
            renewalAt,
          });
          break;
        case 'cms-signer-certificate-substituted':
          member.issuerCertificate = Buffer.from(f.certificateStatusSuccessor.certificate);
          break;
        case 'status-cross-domain':
          changes = { trustDomainID: c.random() };
          break;
        case 'status-other-certificate':
          changes = { certificateID: c.random() };
          break;
        case 'status-wrong-scope':
          changes = { scope: 'AUTHORITY' };
          break;
        case 'signer-not-appointed-at-publication':
        case 'signer-retired-at-proof':
        case 'signer-wrong-role':
        case 'signer-wrong-scope':
        case 'signer-revoked-at-publication':
        case 'signer-compromised-at-proof':
        case 'signer-compromised-after-proof': {
          const selected = makeHistory((value) => {
            if (spec.id === 'signer-not-appointed-at-publication') value.validFrom = S + 1;
            if (spec.id === 'signer-retired-at-proof') value.validUntil = Q;
            if (spec.id === 'signer-wrong-role') value.roles = ['ISSUER'];
            if (spec.id === 'signer-wrong-scope') value.scopes[0].issuerID = 'other-status-issuer';
            return value;
          });
          if (spec.id.includes('revoked') || spec.id.includes('compromised')) {
            const current = copy(selected[1].manifest.authorities);
            const authority = current.find((value) =>
              c.equal(value.certificate, signer.certificate),
            );
            authority.status.status = 'REVOKED';
            authority.status.effectiveTime = spec.id.includes('revoked') ? S : f.K - 1;
            if (spec.id.includes('compromised'))
              authority.status.compromiseStart = Q + (spec.id.endsWith('after-proof') ? 1 : 0);
            selected[1] = f.manifest(current, f.K - 1, selected[0], { replacement: true });
          }
          entry.knowledge.authorityHistory = rawHistory(selected);
          break;
        }
        case 'missing-current-authority-coverage':
          entry.knowledge.authorityHistory = rawHistory([defaultHistory[0]]);
          break;
        case 'stale-preserved-good':
          changes = { nextUpdate: f.K };
          break;
        case 'stale-retrospective-compromise':
          changes = {
            status: 'REVOKED',
            effectiveTime: S,
            compromiseStart: f.A,
            nextUpdate: S + 1,
          };
          break;
        case 'same-publication-conflict':
          changes = { status: 'REVOKED', effectiveTime: f.P + 1 };
          break;
        case 'preserved-status-critical-unknown':
          changes = { critical: ['unrecognized-status-extension'] };
          break;
        case 'missing-status-tsa-selection':
          entry.configuration.preservation.timestampAuthorities =
            entry.configuration.preservation.timestampAuthorities.slice(1);
          break;
        case 'malformed-status-proof':
          member.evidenceRecord = Buffer.from([1, 2, 3]);
          break;
        case 'missing-status-key-deadline':
          delete entry.configuration.trust.keyDeadlines[keyHex];
          break;
      }
      if (changes || firstAt !== Q || milliseconds || renewalAt !== f.A + 50) {
        member = status(changes);
        member.evidenceRecord = await f.preserve(member.cms, { firstAt, milliseconds, renewalAt });
      }
      entry.knowledge.certificateStatusMaterial = [member];
      if (spec.id === 'unpreserved-current-successor')
        entry.knowledge.certificateStatusMaterial = copy(f.knowledge.certificateStatusMaterial);
      if (spec.id.startsWith('current-successor-') || spec.id === 'proof-at-selected-knowledge') {
        const proofAt =
          spec.id === 'current-successor-proof-after-knowledge'
            ? f.K + 100
            : spec.id === 'proof-at-selected-knowledge'
              ? f.K
              : f.K - 1;
        // Select the synthetic TSA clock using the fixture's normal publication
        // operation. The discarded manifest is not part of the public history.
        f.manifest(f.currentAuthorities, proofAt, f.firstManifest);
        const current = f.certificateStatus();
        current.evidenceRecord = await createERS(current.cms, { tsa: f.renewalTSA.issue });
        if (spec.id === 'current-successor-invalid-proof')
          current.evidenceRecord[current.evidenceRecord.length - 1] ^= 1;
        entry.knowledge.certificateStatusMaterial = [current];
      }
      if (spec.id === 'missing-current-certificate-status')
        entry.knowledge.certificateStatusMaterial = [];
      if (spec.id === 'same-publication-conflict')
        entry.knowledge.certificateStatusMaterial.push({
          ...copy(baseStatus),
          evidenceRecord: baseProof,
        });
      if (spec.id === 'compromise-followed-by-current-good')
        entry.knowledge.certificateStatusMaterial.push(f.certificateStatus());
      assertPublicHistoryData(entry);
      assert.equal(
        readControl(baseStatus.cms, 'CertificateStatus', signer.certificate).publishedAt,
        S,
      );
      assert.equal(f.P, f.A + 1);
      assert(S > f.P && Q > S && deadline > Q && f.K > deadline);
      entries.push(entry);
    }
    return entries;
  } finally {
    f.close();
  }
}

/** Capture complete results only after the separately reviewable oracle passes. */
export async function freezePreservedCertificateStatusVectors({
  inputPath,
  directory,
  semanticSHA256,
}) {
  const repository = fileURLToPath(new URL('../', import.meta.url)),
    semanticsPath = 'reference/preserved-certificate-status-semantics.mjs';
  assert.equal(semanticSHA256, vectorHash(fs.readFileSync(join(repository, semanticsPath))));
  assert(!fs.existsSync(join(directory, 'manifest.json')), 'Frozen corpus already exists');
  const inputBytes = fs.readFileSync(inputPath);
  const entries = copy(
    c.decodeCBOR(inputBytes, { maxBytes: 128 * 1024 * 1024, maxItems: 1000000 }),
  );
  assert.deepEqual(
    entries.map((entry) => entry.id),
    preservedCertificateStatusSemantics.map((s) => s.id),
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
      assertPreservedCertificateStatusOutcome(entry, actual);
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
    'tools/freeze-preserved-certificate-status-vectors.mjs',
    semanticsPath,
    'reference/fixtures-history-independent.mjs',
    'reference/organization-delegation-fixtures.mjs',
    'reference/fixtures-history-durable-independent.mjs',
    'reference/organization-history.mjs',
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
      'Selected credential CertificateStatus with independent RFC 4998 preservation, public trust and explicit knowledge.',
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
  const entries = await createPreservedCertificateStatusInputs();
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

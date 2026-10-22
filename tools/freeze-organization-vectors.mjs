import assert from 'node:assert/strict';
import fs from 'node:fs';
import { resolve, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import * as c from '../reference/core.mjs';
import { readControl } from '../reference/state.mjs';
import { verifyCMS } from '../reference/pki.mjs';
import { copy } from '../reference/organization-delegation-fixtures.mjs';
import { createIndependentOrganizationHistoryFixture } from '../reference/fixtures-history-independent.mjs';
import {
  organizationHistorySemantics,
  assertOrganizationHistoryInput,
  assertOrganizationHistoryOutcome,
  assertOrganizationHistoryOriginalPairs,
} from '../reference/organization-history-vector-semantics.mjs';
import {
  canonicalVectorJSON,
  vectorHash,
  organizationVectorProfile,
  defaultOrganizationHistoryVectorDirectory,
} from '../reference/organization-vector-corpus.mjs';

const repository = fileURLToPath(new URL('../', import.meta.url));
const semanticsPath = 'reference/organization-history-vector-semantics.mjs';
const body = (member) =>
  readControl(member.cms, 'OrganizationDelegationStatus', member.issuerCertificate);
const rawHistory = (history) =>
  history.map((entry) => ({
    manifest: c.dcbor(entry.manifest),
    signatures: copy(entry.signatures),
    publicationProof: Buffer.from(entry.publicationProof),
  }));

/** Authoring only: ephemeral private keys never leave this function. */
export async function createOrganizationHistoryVectorInputs() {
  const fixture = await createIndependentOrganizationHistoryFixture();
  try {
    const entries = [];
    const statusIndex = (type = 'GRANT') =>
      fixture.originalStatusMembers.findIndex((member) => body(member).objectType === type);
    for (const spec of organizationHistorySemantics) {
      const configuration = copy(fixture.publicSourceConfiguration);
      const knowledge = {
        ...copy(fixture.knowledge),
        knowledgeTime: spec.knowledgeTime,
        authorityHistory: rawHistory(fixture.history),
      };
      let originalBytes = Buffer.from(fixture.originalBytes),
        evidenceRecord = Buffer.from(fixture.evidenceRecord);
      const replaceStatus = (changes, target = 'GRANT') => {
        const index = statusIndex(target);
        knowledge.statusMaterial[index] = fixture.organizationStatus(
          fixture.originalStatusMembers[index],
          changes,
        );
      };
      const replaceHistory = (records, options = {}) => {
        const latest = fixture.manifest(records, fixture.K - 1, fixture.firstManifest, {
          replacement: true,
          ...options,
        });
        knowledge.authorityHistory = rawHistory([fixture.firstManifest, latest]);
      };
      switch (spec.kind) {
        case 'positive':
          break;
        case 'proof-boundary':
          evidenceRecord = await fixture.preserve(originalBytes, {
            firstAt: fixture.A + spec.seconds,
            milliseconds: spec.millis,
          });
          break;
        case 'missing-original':
          originalBytes = c.dcbor({
            ...fixture.bundle,
            objects: fixture.bundle.objects.filter((leaf) => leaf.type !== spec.missing),
          });
          evidenceRecord = await fixture.preserve(originalBytes);
          break;
        case 'corrupt-approval':
        case 'corrupt-approval-missing-sim': {
          const approval = c.decodeCBOR(fixture.leaves.OrganizationApprovalSet);
          approval.approvals[0].assertion.signature[0] ^= 1;
          originalBytes = fixture.replaceLeaf('OrganizationApprovalSet', c.dcbor(approval));
          if (spec.kind === 'corrupt-approval-missing-sim') {
            const changed = c.decodeCBOR(originalBytes);
            changed.objects = changed.objects.filter((leaf) => leaf.type !== 'SIM');
            originalBytes = c.dcbor(changed);
          }
          evidenceRecord = await fixture.preserve(originalBytes);
          break;
        }
        case 'ordinary-revocation':
          replaceStatus({ status: 'REVOKED', effectiveTime: fixture.P + 1 }, spec.target);
          break;
        case 'retrospective-compromise':
          replaceStatus(
            { status: 'REVOKED', effectiveTime: fixture.K - 1, compromiseStart: fixture.P },
            spec.target,
          );
          break;
        case 'credential-compromise':
          knowledge.certificateStatusMaterial = [
            fixture.certificateStatus({
              status: 'REVOKED',
              effectiveTime: fixture.K - 1,
              compromiseStart: fixture.A,
            }),
          ];
          break;
        case 'authority-compromise': {
          const receiptCertificate = verifyCMS(fixture.leaves.ExecutionReceipt).certificate;
          replaceHistory(
            fixture.currentAuthorities.map((record) =>
              c.equal(record.certificate, receiptCertificate)
                ? {
                    ...record,
                    status: {
                      ...record.status,
                      status: 'REVOKED',
                      effectiveTime: fixture.K - 1,
                      compromiseStart: fixture.A,
                    },
                  }
                : record,
            ),
          );
          break;
        }
        case 'shared-key-target-compromise': {
          const original = fixture.originalStatusMembers.map(body);
          const final = original.find((row) => row.objectType === 'FINAL_AUTHORIZATION');
          const index = original.findIndex(
            (row) => row.objectType === 'GRANT' && c.equal(row.subjectKeyID, final.subjectKeyID),
          );
          assert(index >= 0, 'The combined case requires an actual shared grant/authorization key');
          knowledge.statusMaterial[index] = fixture.organizationStatus(
            fixture.originalStatusMembers[index],
            {
              status: 'REVOKED',
              effectiveTime: fixture.K - 1,
              compromiseStart: fixture.A,
            },
          );
          break;
        }
        case 'same-epoch-conflict':
        case 'compromise-newer-good': {
          const original = fixture.originalStatusMembers[statusIndex()];
          const epoch = spec.kind === 'same-epoch-conflict' ? 2 : 3;
          knowledge.statusMaterial.push(
            fixture.organizationStatus(original, {
              epoch,
              status: 'REVOKED',
              effectiveTime: fixture.K - 1,
              ...(spec.kind === 'compromise-newer-good' ? { compromiseStart: fixture.A } : {}),
            }),
            fixture.organizationStatus(original, { epoch: epoch + 1 }),
          );
          break;
        }
        case 'missing-current':
          if (['organization', 'both'].includes(spec.category)) knowledge.statusMaterial = [];
          if (['certificate', 'both'].includes(spec.category))
            knowledge.certificateStatusMaterial = [];
          break;
        case 'missing-current-history':
          knowledge.authorityHistory = rawHistory([fixture.firstManifest]);
          break;
        case 'status-coverage':
          break;
        case 'history-coverage':
          knowledge.statusMaterial = fixture.originalStatusMembers.map((member) =>
            fixture.organizationStatus(member, {
              publishedAt: fixture.K + 1,
              nextUpdate: fixture.K + 301,
            }),
          );
          knowledge.certificateStatusMaterial = [
            fixture.certificateStatus({ publishedAt: fixture.K + 1, nextUpdate: fixture.K + 301 }),
          ];
          break;
        case 'compromise-missing-coverage':
          replaceStatus({
            status: 'REVOKED',
            effectiveTime: fixture.K - 1,
            compromiseStart: fixture.A,
          });
          knowledge.certificateStatusMaterial = [];
          break;
        case 'late-renewal':
          evidenceRecord = await fixture.preserve(originalBytes, { renewalAt: fixture.A + 80 });
          break;
        case 'early-raw-key-cutoff': {
          const approval = c.decodeCBOR(fixture.leaves.OrganizationApprovalSet).approvals[0];
          const registration = readControl(
            approval.registrationCMS,
            'OrganizationApproverRegistration',
            approval.registrationIssuerCertificate,
          );
          configuration.trust.keyDeadlines[registration.keyID.toString('hex')] = fixture.P;
          configuration.preservation.dataValidUntil = fixture.end;
          break;
        }
        case 'wrong-original-binding':
          originalBytes = fixture.replaceLeaf(
            'Document',
            Buffer.from('A different retained organization operation'),
          );
          break;
        case 'wrong-status-target':
          replaceStatus({ objectHash: Buffer.alloc(64, 0x42) });
          break;
        case 'wrong-successor-purpose':
        case 'wrong-successor-domain':
          replaceHistory(
            fixture.currentAuthorities.map((record) =>
              c.equal(record.certificate, fixture.statusSuccessor.certificate)
                ? {
                    ...record,
                    scopes:
                      spec.kind === 'wrong-successor-purpose'
                        ? [fixture.source.scope('ORGANIZATION_FINAL_AUTHORIZATION')]
                        : record.scopes.map((scope) => ({
                            ...scope,
                            trustDomainID: Buffer.alloc(32, 0x42),
                          })),
                  }
                : record,
            ),
          );
          break;
        case 'unilateral-root-successor':
          replaceHistory(fixture.currentAuthorities, { signers: [fixture.root] });
          break;
        case 'receipt-authority-after-execution': {
          const receiptCertificate = verifyCMS(fixture.leaves.ExecutionReceipt).certificate;
          const shifted = (records) =>
            records.map((record) =>
              c.equal(record.certificate, receiptCertificate)
                ? { ...record, validFrom: fixture.P }
                : record,
            );
          const first = fixture.manifest(shifted(fixture.initialAuthorities), fixture.A - 30);
          const latest = fixture.manifest(
            shifted(fixture.currentAuthorities),
            fixture.K - 1,
            first,
            { replacement: true },
          );
          knowledge.authorityHistory = rawHistory([first, latest]);
          break;
        }
        case 'proof-before-execution':
          evidenceRecord = await fixture.preserve(originalBytes, { firstAt: fixture.A - 1 });
          break;
        default:
          throw Error('No reviewed construction for ' + spec.id);
      }
      const entry = {
        id: spec.id,
        description: spec.description,
        configuration,
        knowledge,
        originalBytes,
        evidenceRecord,
      };
      assertOrganizationHistoryInput(entry);
      entries.push(entry);
    }
    assertOrganizationHistoryOriginalPairs(entries);
    assert.equal(fixture.source.calls.sign, 1);
    return entries;
  } finally {
    fixture.close();
  }
}

/** A separate, explicit authoring operation. Never imported by offline replay. */
export async function freezeOrganizationHistoryVectors({
  directory = defaultOrganizationHistoryVectorDirectory,
  semanticSHA256,
  sdk,
} = {}) {
  const semanticBytes = fs.readFileSync(join(repository, semanticsPath));
  assert.equal(
    semanticSHA256,
    vectorHash(semanticBytes),
    'An explicit reviewed semantic source digest is required',
  );
  assert(
    !fs.existsSync(join(directory, 'manifest.json')),
    'Refuse to overwrite an existing frozen corpus',
  );
  const entries = await createOrganizationHistoryVectorInputs();
  const selectedSDK = sdk ?? (await import('../reference/sdk/index.mjs'));
  const outcomes = [];
  for (const entry of entries) {
    const source = selectedSDK.createOrganizationHistorySource({
      configuration: entry.configuration,
      readKnowledge: () => entry.knowledge,
    });
    try {
      const actual = selectedSDK
        .createOrganizationHistoryVerifier({ source })
        .verify({ originalBytes: entry.originalBytes, evidenceRecord: entry.evidenceRecord });
      assertOrganizationHistoryOutcome(entry, actual);
      // Lossless representation and independent assertions precede every capture.
      outcomes.push(canonicalVectorJSON(actual));
    } catch (error) {
      error.message = entry.id + ': ' + error.message;
      throw error;
    } finally {
      source.close();
    }
  }
  const inventory = new Map();
  const add = (bytes, extension, mediaType, encoding = 'base64') => {
    const decoded = Buffer.from(bytes),
      decodedSHA256 = vectorHash(decoded);
    const path = `files/${decodedSHA256}.${extension}`;
    const stored = encoding === 'base64' ? Buffer.from(decoded.toString('base64') + '\n') : decoded;
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
      const spki = field === 'publicKeyDER' || field === 'issuerPublicKeyDER';
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
    if (value && typeof value === 'object') {
      assert.equal(Object.getPrototypeOf(value), Object.prototype);
      assert(!Object.hasOwn(value, 'privateKey') && !Object.hasOwn(value, 'privateKeyDER'));
      return Object.fromEntries(
        Object.entries(value).map(([name, child]) => [name, materialize(child, name)]),
      );
    }
    assert(['string', 'number', 'boolean'].includes(typeof value) || value === null);
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
  const sourcePaths = [
    'tools/freeze-organization-vectors.mjs',
    semanticsPath,
    'reference/fixtures-history-independent.mjs',
    'reference/organization-delegation-fixtures.mjs',
    'reference/organization-vector-corpus.mjs',
    'reference/vector-corpus.mjs',
    'reference/verify-organization-vectors.mjs',
    'reference/organization-history.mjs',
    'reference/organization-history-source.mjs',
    'reference/organization-delegation-evidence.mjs',
    'reference/retained-authorities.mjs',
    'reference/authority-history.mjs',
    'reference/archive.mjs',
    'reference/timestamp.mjs',
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
      'Synthetic public bytes authored from the named baseline plus the separately hashed reviewed sources. These declarations and inventory hashes are not authority signatures or executing-code attestation.',
    runtime: { node: process.version, openssl: process.versions.openssl },
    dependencyLock: {
      path: 'package-lock.json',
      sha256: vectorHash(fs.readFileSync(join(repository, 'package-lock.json'))),
    },
    semanticSHA256,
    sources: sourcePaths.map((path) => ({
      path,
      sha256: vectorHash(fs.readFileSync(join(repository, path))),
    })),
    command:
      'node tools/freeze-organization-vectors.mjs --write --approved-semantic-sha256 ' +
      semanticSHA256,
  });
  const manifest = {
    schemaVersion: 1,
    profile: organizationVectorProfile,
    description:
      'Frozen synthetic original organization evidence with external public trust and explicit knowledge snapshots.',
    provenance,
    files: [...inventory.values()]
      .map(({ descriptor }) => descriptor)
      .sort((a, b) => a.path.localeCompare(b.path)),
    cases,
  };
  assert(manifest.files.length <= 512);
  fs.mkdirSync(join(directory, 'files'), { recursive: true });
  for (const [path, { stored }] of inventory)
    fs.writeFileSync(join(directory, path), stored, { flag: 'wx' });
  fs.writeFileSync(join(directory, 'manifest.json'), canonicalVectorJSON(manifest), { flag: 'wx' });
  return {
    cases: cases.length,
    files: manifest.files.length,
    manifestSHA256: vectorHash(canonicalVectorJSON(manifest)),
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === '--check-inputs') {
    console.log(
      JSON.stringify({ inputCases: (await createOrganizationHistoryVectorInputs()).length }),
    );
  } else {
    assert(
      args.length === 3 &&
        args[0] === '--write' &&
        args[1] === '--approved-semantic-sha256' &&
        /^[0-9a-f]{64}$/.test(args[2]),
      'Use --check-inputs, or --write --approved-semantic-sha256 <reviewed digest> after review',
    );
    console.log(
      JSON.stringify(await freezeOrganizationHistoryVectors({ semanticSHA256: args[2] })),
    );
  }
}

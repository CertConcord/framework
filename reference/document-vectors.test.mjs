import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, cpSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { createHash } from 'node:crypto';
import { createVerifier } from './sdk/index.mjs';
import {
  defaultVectorDirectory,
  loadVectorCorpus,
  runDocumentVectors,
  runPreservationVectors,
  runRetainedVectors,
} from './verify-vectors.mjs';

const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
function copyCorpus(t) {
  const parent = resolve(tmpdir()),
    directory = mkdtempSync(join(parent, 'certconcord-vectors-'));
  cpSync(defaultVectorDirectory, directory, { recursive: true });
  t.after(() => {
    assert(resolve(directory).startsWith(parent + sep + 'certconcord-vectors-'));
    rmSync(directory, { recursive: true });
  });
  return directory;
}
function changeManifest(directory, edit) {
  const path = join(directory, 'manifest.json'),
    manifest = JSON.parse(readFileSync(path, 'utf8'));
  edit(manifest);
  writeFileSync(path, JSON.stringify(manifest, null, 2) + '\n');
}

test('published CMS and native mdoc originals verify through the public SDK', () => {
  const results = runDocumentVectors();
  for (const format of ['cms', 'mdoc']) {
    const value = results.find(({ id }) => id === format + '-valid').actual;
    assert.equal(value.overall, 'VALID');
    assert.equal(value.coreRevision, 'draft-03');
    assert.equal(typeof value.reason, 'string');
    assert(value.profile.includes(format));
    for (const dimension of [
      'integrity',
      'issuerTrust',
      'qualification',
      'keyBinding',
      'authorization',
      'status',
      'time',
      'transparency',
    ]) {
      assert.equal(value.dimensions[dimension]?.overall, 'VALID', dimension);
    }
  }
});

test('published negative documents preserve exact typed outcomes', () => {
  const results = new Map(runDocumentVectors().map((entry) => [entry.id, entry.actual]));
  for (const format of ['cms', 'mdoc']) {
    for (const suffix of [
      'changed-commitment',
      'wrong-domain',
      'wrong-role',
      'bad-signature',
      'bad-signature-missing-time',
      'unsupported-with-bad-commitment',
    ]) {
      assert.equal(results.get(format + '-' + suffix).overall, 'INVALID', suffix);
    }
    assert.equal(results.get(format + '-missing-time').overall, 'INDETERMINATE');
    assert.equal(results.get(format + '-stale-status').overall, 'INDETERMINATE');
    assert.equal(results.get(format + '-unsupported-profile').overall, 'UNSUPPORTED');
    assert.deepEqual(results.get(format + '-unsupported-profile').dimensions, {});
    assert.equal(results.get(format + '-changed-commitment').reason, 'ECP_HASH');
    assert.equal(results.get(format + '-wrong-role').reason, 'AUTHORITY_ROLE');
  }
  assert.equal(results.get('cms-known-compromise').reason, 'ECP_STATUS_REVOKED');
});

test('published replay is offline and uses its declared knowledge time', (t) => {
  const network = t.mock.method(globalThis, 'fetch', () => {
    throw Error('Unexpected network');
  });
  const corpus = loadVectorCorpus();
  const inputs = corpus.manifest.documents.map((entry) => corpus.config(entry.trust));
  const declaredTimes = inputs.map((entry) => entry.trust.knowledgeTime);
  const bounds = inputs.flatMap((entry) =>
    entry.authorities.flatMap((authority) => [authority.validFrom, authority.validUntil]),
  );
  const clockValues = [0, 4102444800000];
  assert(clockValues[0] / 1000 < Math.min(...bounds));
  assert(clockValues[1] / 1000 > Math.max(...bounds));
  let wallClock = clockValues[0];
  t.mock.method(Date, 'now', () => wallClock);
  let previous;
  for (wallClock of clockValues) {
    const seenTimes = [];
    const documents = runDocumentVectors({
      createVerifier: (options) => {
        seenTimes.push(options.trust.knowledgeTime);
        return createVerifier(options);
      },
    });
    assert.deepEqual(seenTimes, declaredTimes);
    const actual = {
      documents: documents.map(({ id, actual }) => ({ id, actual })),
      preservation: runPreservationVectors().map(({ id, actual }) => ({ id, actual })),
      retained: runRetainedVectors().map(({ id, actual }) => ({ id, actual })),
    };
    if (previous) assert.deepEqual(actual, previous);
    previous = actual;
  }
  assert.equal(network.mock.callCount(), 0);
  for (const format of ['cms', 'mdoc']) {
    const normal = corpus.manifest.documents.find((entry) => entry.id === format + '-valid');
    const expired = corpus.manifest.documents.find(
      (entry) => entry.id === format + '-stale-status',
    );
    assert.equal(normal.bytes, expired.bytes);
    assert(
      corpus.config(normal.trust).trust.knowledgeTime <
        corpus.config(expired.trust).trust.knowledgeTime,
    );
  }
});

test('published ERS records distinguish timely missing and late renewal', () => {
  const results = new Map(runPreservationVectors().map((entry) => [entry.id, entry.actual]));
  for (const format of ['cms', 'mdoc']) {
    assert.equal(results.get(format + '-ers-original').result.timestamps, 1);
    const timely = results.get(format + '-ers-timely').result;
    assert.equal(timely.preservation, 'VALID');
    assert.equal(timely.timestamps, 3);
    assert.equal(timely.chains, 2);
    assert(timely.proofOfExistenceUpperBound < timely.latestRenewalUpperBound);
    assert.equal(results.get(format + '-ers-missing-renewal').code, 'ERS_FINAL_PROTECTION_EXPIRED');
    assert.equal(results.get(format + '-ers-missing-hash-renewal').code, 'ERS_HASH_RENEWAL_LATE');
    assert.equal(results.get(format + '-ers-late-renewal').code, 'ERS_HASH_RENEWAL_LATE');
  }
});

test('published retained lifecycle separates preservation from current admissibility', () => {
  const results = new Map(runRetainedVectors().map((entry) => [entry.id, entry.actual]));
  for (const format of ['cms', 'mdoc']) {
    const renewed = results.get(format + '-retained-renewed');
    assert.equal(renewed.overall, 'VALID');
    assert.equal(renewed.preservation.overall, 'VALID');
    assert.equal(renewed.historicalAuthorization.overall, 'VALID');
    assert.equal(renewed.currentAdmissibility.overall, 'VALID');
    assert(renewed.currentKnowledgeTime > renewed.historicalKnowledgeTime);
    const stale = results.get(format + '-retained-stale-current');
    assert.equal(stale.preservation.overall, 'VALID');
    assert.equal(stale.historicalAuthorization.overall, 'VALID');
    assert.equal(stale.currentAdmissibility.overall, 'INDETERMINATE');
    const incident = results.get(format + '-retained-known-compromise');
    assert.equal(incident.preservation.overall, 'VALID');
    assert.equal(incident.historicalAuthorization.overall, 'VALID');
    assert.deepEqual(incident.currentAdmissibility, {
      overall: 'INVALID',
      reason: 'AUTHORITY_REVOKED',
    });
    assert.equal(incident.overall, 'INVALID');
  }
});

test('published corpus inventory contains only public material and exact hashes', () => {
  const corpus = loadVectorCorpus();
  assert.equal(corpus.manifest.documents.filter((entry) => entry.id.endsWith('-valid')).length, 2);
  const secretMarker = ['PRIVATE', ' KEY'].join('');
  for (const file of corpus.manifest.files) {
    const stored = readFileSync(join(defaultVectorDirectory, file.path));
    assert(
      stored.every((byte) => byte < 128),
      file.path,
    );
    assert.equal(stored.length, file.bytes);
    assert.equal(hash(stored), file.sha256);
    const decoded = corpus.read(file.path);
    assert.equal(decoded.length, file.decodedBytes);
    assert.equal(hash(decoded), file.decodedSHA256);
    assert(!stored.toString('utf8').includes(secretMarker));
    if (file.encoding === 'utf8') {
      assert(!/"privateKey(?:DER)?"\s*:/.test(stored.toString('utf8')));
      corpus.config(file.path);
    }
  }
});

test('vector loader rejects corrupt inventories and unsafe file references', async (t) => {
  for (const [name, edit, code] of [
    [
      'traversal',
      (m) => {
        m.files[0].path = '../outside';
      },
      'VECTOR_PATH',
    ],
    [
      'bad-size',
      (m) => {
        m.files[0].bytes += 1;
      },
      'VECTOR_FILE_SIZE',
    ],
    [
      'bad-file-hash',
      (m) => {
        m.files[0].sha256 = '0'.repeat(64);
      },
      'VECTOR_FILE_HASH',
    ],
    [
      'bad-decoded-hash',
      (m) => {
        m.files[0].decodedSHA256 = '0'.repeat(64);
      },
      'VECTOR_DECODED_HASH',
    ],
    [
      'duplicate-file',
      (m) => {
        m.files.push(m.files[0]);
      },
      'VECTOR_FILE_DESCRIPTOR',
    ],
    [
      'unknown-reference',
      (m) => {
        m.documents[0].bytes = 'absent.cbor.b64';
      },
      'VECTOR_FILE_UNDECLARED',
    ],
    [
      'unknown-version',
      (m) => {
        m.schemaVersion += 1;
      },
      'VECTOR_VERSION',
    ],
    [
      'unknown-dimension',
      (m) => {
        m.documents[0].expected.dimensions.fabricated = { overall: 'VALID', reason: 'unsupported' };
      },
      'VECTOR_DIMENSION',
    ],
  ])
    await t.test(name, (caseTest) => {
      const directory = copyCorpus(caseTest);
      changeManifest(directory, edit);
      assert.throws(() => loadVectorCorpus(directory), { code });
    });
});

test('vector runner rejects an incorrect expected verdict', (t) => {
  const directory = copyCorpus(t);
  changeManifest(directory, (manifest) => {
    manifest.documents[0].expected.overall = 'INVALID';
  });
  assert.throws(
    () => runDocumentVectors({ directory }),
    (error) => {
      assert.equal(error.code, 'VECTOR_EXPECTATION_MISMATCH');
      assert.equal(error.actual.overall, 'VALID');
      assert.equal(error.expected.overall, 'INVALID');
      return true;
    },
  );
});

test('document replay uses the supplied public verifier factory', () => {
  const seen = [];
  const results = runDocumentVectors({
    createVerifier: (options) => {
      assert.deepEqual(Object.keys(options).sort(), ['format', 'trust']);
      assert(Number.isSafeInteger(options.trust.knowledgeTime));
      const verifier = createVerifier(options);
      return {
        verify(bytes) {
          assert(Buffer.isBuffer(bytes));
          seen.push(options.format);
          return verifier.verify(bytes);
        },
      };
    },
  });
  assert.equal(seen.length, loadVectorCorpus().manifest.documents.length);
  assert.equal(results.length, seen.length);
  assert(seen.includes('CMS') && seen.includes('MDOC'));
});

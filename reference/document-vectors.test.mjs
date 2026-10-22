import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, cpSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { createVerifier } from './sdk/index.mjs';
import { dcbor, decodeCBOR } from './core.mjs';
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

function replaceMaterial(directory, name, bytes) {
  const path = join(directory, name);
  let stored;
  changeManifest(directory, (manifest) => {
    const descriptor = manifest.files.find((entry) => entry.path === name);
    assert(descriptor, name);
    stored =
      descriptor.encoding === 'base64' ? Buffer.from(bytes.toString('base64') + '\n') : bytes;
    Object.assign(descriptor, {
      bytes: stored.length,
      sha256: hash(stored),
      decodedBytes: bytes.length,
      decodedSHA256: hash(bytes),
    });
  });
  writeFileSync(path, stored);
}

test('draft-06 document corpus requires its original verifier', () => {
  const legacy = resolve(defaultVectorDirectory, '..', 'document-acceptance');
  assert.equal(
    JSON.parse(readFileSync(join(legacy, 'manifest.json'), 'utf8')).profile,
    'certconcord-document-acceptance-vectors-draft-03',
  );
  assert.throws(() => loadVectorCorpus(legacy), { code: 'VECTOR_VERSION' });
});

test('schema1 document corpus requires its original verifier', () => {
  assert.throws(
    () => loadVectorCorpus(resolve(defaultVectorDirectory, '..', 'document-acceptance-mtc07')),
    { code: 'VECTOR_VERSION' },
  );
});

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

test('public timestamp status bridge preserves staleness and known revocation for CMS and mdoc', async (t) => {
  for (const format of ['cms', 'mdoc']) {
    for (const revoked of [false, true])
      await t.test(`${format}: ${revoked ? 'revoked and stale' : 'stale'}`, (caseTest) => {
        const directory = copyCorpus(caseTest);
        const corpus = loadVectorCorpus(directory);
        const entry = corpus.manifest.documents.find((value) => value.id === format + '-valid');
        const input = JSON.parse(readFileSync(join(directory, entry.trust), 'utf8'));
        input.timestampStatus.nextUpdate = input.trust.knowledgeTime;
        assert(input.timestampStatus.publishedAt < input.timestampStatus.nextUpdate);
        if (revoked) Object.assign(input.timestampStatus, { status: 'REVOKED', effectiveTime: 0 });
        replaceMaterial(directory, entry.trust, Buffer.from(JSON.stringify(input) + '\n'));
        const overall = revoked ? 'INVALID' : 'INDETERMINATE';
        const reason = revoked ? 'TIMESTAMP_STATUS_REVOKED' : 'TIMESTAMP_STATUS_STALE';
        const expected = {
          ...entry.expected,
          overall,
          reason,
          dimensions: { time: { overall, reason } },
        };
        changeManifest(directory, (manifest) => {
          manifest.documents = [{ ...entry, expected }];
        });
        const actual = runDocumentVectors({ directory })[0].actual;
        assert.equal(actual.overall, overall);
        assert.equal(actual.reason, reason);
        assert.deepEqual(actual.dimensions.time, { overall, reason });
        assert.deepEqual(loadVectorCorpus(directory).read(entry.bytes), corpus.read(entry.bytes));
      });
  }
});

test('retained ERS bridge reports missing latest governance coverage without changing original bytes', async (t) => {
  for (const format of ['cms', 'mdoc'])
    await t.test(format, (caseTest) => {
      const directory = copyCorpus(caseTest);
      const corpus = loadVectorCorpus(directory);
      const entry = corpus.manifest.retained.find(
        (value) => value.id === format + '-retained-renewed',
      );
      const original = corpus.config(entry.options);
      const encoded = JSON.parse(readFileSync(join(directory, entry.options), 'utf8'));
      const history = decodeCBOR(original.history);
      assert(history.length > 1);
      replaceMaterial(directory, encoded.history.$file, dcbor([history[0]]));
      const decision = { overall: 'INDETERMINATE', reason: 'HISTORY_KNOWLEDGE_COVERAGE' };
      changeManifest(directory, (manifest) => {
        manifest.retained = [
          {
            ...entry,
            expected: {
              ...entry.expected,
              overall: 'INDETERMINATE',
              preservation: decision,
              currentAdmissibility: decision,
            },
          },
        ];
      });
      const { actual, details } = runRetainedVectors({ directory })[0];
      assert.equal(actual.overall, 'INDETERMINATE');
      assert.deepEqual(actual.preservation, decision);
      assert.equal(actual.historicalAuthorization.overall, 'VALID');
      assert.deepEqual(actual.currentAdmissibility, decision);
      assert.equal(details.historicalKnowledgeTime, original.historicalKnowledgeTime);
      assert.equal(details.currentKnowledgeTime, original.currentKnowledgeTime);
      const retained = loadVectorCorpus(directory).config(entry.options);
      for (const name of ['originalBytes', 'currentBytes', 'evidenceRecord'])
        assert.deepEqual(retained[name], original[name], name);
    });
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

function smallCorpus(t) {
  const parent = resolve(tmpdir());
  const temporary = fs.mkdtempSync(join(parent, 'certconcord-vector-io-'));
  const directory = join(temporary, 'corpus');
  fs.mkdirSync(join(directory, 'files'), { recursive: true });
  const decoded = Buffer.from('original public bytes');
  const stored = Buffer.from(decoded.toString('base64') + '\n');
  const name = 'files/object.b64';
  const manifest = {
    schemaVersion: 1,
    profile: 'certconcord-document-acceptance-vectors-draft-03-mtc07',
    description: 'Original fixture',
    files: [
      {
        path: name,
        bytes: stored.length,
        sha256: hash(stored),
        mediaType: 'application/octet-stream',
        encoding: 'base64',
        decodedBytes: decoded.length,
        decodedSHA256: hash(decoded),
      },
    ],
    documents: [],
    preservation: [],
    retained: [],
  };
  fs.writeFileSync(join(directory, name), stored);
  fs.writeFileSync(join(directory, 'manifest.json'), JSON.stringify(manifest) + '\n');
  t.after(() => {
    assert(resolve(temporary).startsWith(parent + sep + 'certconcord-vector-io-'));
    fs.rmSync(temporary, { recursive: true });
  });
  return { directory, temporary, manifest, name, decoded, stored };
}

function mockFilesystem(t, name, implementation) {
  const replacement = t.mock.method(fs, name, implementation);
  syncBuiltinESMExports();
  t.after(() => {
    replacement.mock.restore();
    syncBuiltinESMExports();
  });
}

function fileReadBoundary(t, target, mutate) {
  const original = {
    open: fs.openSync,
    read: fs.readSync,
    readFile: fs.readFileSync,
    close: fs.closeSync,
  };
  const state = { opened: new Set(), closed: new Set(), requested: 0, returned: 0, mutated: false };
  const matches = (path) => typeof path === 'string' && resolve(path) === resolve(target);
  const change = () => {
    if (!state.mutated) {
      state.mutated = true;
      mutate?.();
    }
  };
  mockFilesystem(t, 'openSync', (path, flags, ...rest) => {
    const fd = original.open(path, flags, ...rest);
    if (
      matches(path) &&
      (flags === 'r' ||
        (typeof flags === 'number' &&
          (flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR)) === 0))
    )
      state.opened.add(fd);
    return fd;
  });
  mockFilesystem(t, 'readSync', (fd, buffer, offset, length, position) => {
    if (state.opened.has(fd)) {
      change();
      state.requested += length;
    }
    const count = original.read(fd, buffer, offset, length, position);
    if (state.opened.has(fd)) state.returned += count;
    return count;
  });
  mockFilesystem(t, 'readFileSync', (path, ...rest) => {
    if (matches(path)) change();
    const bytes = original.readFile(path, ...rest);
    if (matches(path)) state.returned += bytes.length;
    return bytes;
  });
  mockFilesystem(t, 'closeSync', (fd) => {
    if (state.opened.has(fd)) state.closed.add(fd);
    return original.close(fd);
  });
  return state;
}

test('vector loader detects replacement of a checked manifest or material', async (t) => {
  for (const kind of ['manifest', 'material'])
    await t.test(kind, (caseTest) => {
      const fixture = smallCorpus(caseTest);
      const target = join(fixture.directory, kind === 'manifest' ? 'manifest.json' : fixture.name);
      const original = fs.lstatSync;
      let replaced = false;
      mockFilesystem(caseTest, 'lstatSync', (path, ...args) => {
        const result = original(path, ...args);
        if (!replaced && resolve(path) === resolve(target)) {
          replaced = true;
          fs.renameSync(target, target + '.original');
          const replacement =
            kind === 'manifest'
              ? Buffer.from(
                  JSON.stringify({ ...fixture.manifest, description: 'Replaced fixture' }) + '\n',
                )
              : Buffer.alloc(fixture.stored.length, 65);
          fs.writeFileSync(target, replacement);
        }
        return result;
      });
      assert.throws(() => loadVectorCorpus(fixture.directory), { code: 'VECTOR_FILE_CHANGED' });
      assert.equal(replaced, true);
    });
});

test('vector loader bounds descriptor reads when a file grows', (t) => {
  const fixture = smallCorpus(t),
    target = join(fixture.directory, fixture.name);
  const boundary = fileReadBoundary(t, target, () =>
    fs.appendFileSync(target, Buffer.alloc(1024 * 1024)),
  );
  assert.throws(() => loadVectorCorpus(fixture.directory), { code: 'VECTOR_FILE_CHANGED' });
  assert.equal(boundary.mutated, true);
  assert(boundary.requested <= fixture.stored.length + 1);
  assert(boundary.returned <= fixture.stored.length + 1);
  assert.equal(boundary.opened.size, 1);
  assert.deepEqual(boundary.closed, boundary.opened);
});

test('vector loader rejects truncation during a descriptor read', (t) => {
  const fixture = smallCorpus(t),
    target = join(fixture.directory, fixture.name);
  const boundary = fileReadBoundary(t, target, () => fs.truncateSync(target, 0));
  assert.throws(() => loadVectorCorpus(fixture.directory), { code: 'VECTOR_FILE_CHANGED' });
  assert.equal(boundary.mutated, true);
  assert.equal(boundary.opened.size, 1);
  assert.deepEqual(boundary.closed, boundary.opened);
});

test('vector loader closes its descriptor after a read failure', (t) => {
  const fixture = smallCorpus(t),
    target = join(fixture.directory, fixture.name);
  const boundary = fileReadBoundary(t, target, () => {
    throw Object.assign(new Error('Read failed'), { code: 'EIO' });
  });
  assert.throws(() => loadVectorCorpus(fixture.directory), { code: 'EIO' });
  assert.equal(boundary.mutated, true);
  assert.equal(boundary.opened.size, 1);
  assert.deepEqual(boundary.closed, boundary.opened);
});

test('vector loader retains directory and escaping link rejection', async (t) => {
  await t.test('directory', (caseTest) => {
    const fixture = smallCorpus(caseTest),
      target = join(fixture.directory, fixture.name);
    fs.unlinkSync(target);
    fs.mkdirSync(target);
    assert.throws(() => loadVectorCorpus(fixture.directory), { code: 'VECTOR_FILE_TYPE' });
  });
  await t.test('escaping-directory-link', (caseTest) => {
    const fixture = smallCorpus(caseTest);
    const outside = join(fixture.temporary, 'outside');
    fs.renameSync(join(fixture.directory, 'files'), outside);
    fs.symlinkSync(outside, join(fixture.directory, 'files'), 'junction');
    assert.throws(() => loadVectorCorpus(fixture.directory), { code: 'VECTOR_PATH' });
  });
});

test('vector loader closes descriptors after successful loading', (t) => {
  const fixture = smallCorpus(t),
    target = join(fixture.directory, fixture.name);
  const boundary = fileReadBoundary(t, target);
  assert.deepEqual(loadVectorCorpus(fixture.directory).read(fixture.name), fixture.decoded);
  assert.equal(boundary.opened.size, 1);
  assert.deepEqual(boundary.closed, boundary.opened);
});

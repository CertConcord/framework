import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, basename, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  loadOrganizationHistoryVectorCorpus,
  vectorHash,
  organizationVectorProfile,
  assertLosslessVectorJSON,
} from './organization-vector-corpus.mjs';
import { runOrganizationHistoryVectors } from './verify-organization-vectors.mjs';

const json = (value) => Buffer.from(JSON.stringify(value, null, 2) + '\n');
function miniature(t) {
  const directory = fs.mkdtempSync(join(tmpdir(), 'certconcord-org-loader-'));
  t.after(() => {
    assert.equal(dirname(resolve(directory)), resolve(tmpdir()));
    assert(basename(directory).startsWith('certconcord-org-loader-'));
    fs.rmSync(directory, { recursive: true, force: true });
  });
  fs.mkdirSync(join(directory, 'files'));
  const manifest = {
    schemaVersion: 1,
    profile: organizationVectorProfile,
    description: 'Loader-only public data; no cryptographic acceptance is claimed.',
    provenance: '',
    files: [],
    cases: [],
  };
  const add = (decoded, encoding = 'utf8') => {
    const hash = vectorHash(decoded),
      path = `files/${hash}.${encoding === 'utf8' ? 'json' : 'bin.b64'}`;
    const stored = encoding === 'utf8' ? decoded : Buffer.from(decoded.toString('base64') + '\n');
    if (!manifest.files.some((file) => file.path === path))
      manifest.files.push({
        path,
        bytes: stored.length,
        sha256: vectorHash(stored),
        mediaType: encoding === 'utf8' ? 'application/json' : 'application/octet-stream',
        encoding,
        decodedBytes: decoded.length,
        decodedSHA256: hash,
      });
    fs.writeFileSync(join(directory, path), stored);
    return path;
  };
  const configuration = { schemaVersion: 1, trust: {}, retainedAuthorities: {}, preservation: {} };
  const knowledge = {
    knowledgeTime: 7,
    authorityHistory: [],
    statusMaterial: [],
    certificateStatusMaterial: [],
  };
  const expected = {
    overall: 'VALID',
    reason: 'LOADER_TEST_ONLY',
    dimensions: { time: { overall: 'VALID', reason: 'SELECTED' } },
    checks: [{ check: 'all-fields', overall: 'VALID', reason: 'EXPECTED_IS_NOT_INPUT' }],
    limits: ['A'],
    historicalAuthorization: { stateTime: 1.5 },
    protectionLedger: [{ kind: 'KEY', validUntil: 9 }],
  };
  const original = add(Buffer.from('original bytes'), 'base64');
  manifest.provenance = add(json({ description: 'Synthetic loader unit fixture only' }));
  manifest.cases.push({
    id: 'loader-case',
    description: 'Loader test',
    originalBytes: original,
    evidenceRecord: add(Buffer.from('ERS bytes'), 'base64'),
    policy: add(json(configuration)),
    knowledge: add(json(knowledge)),
    expected: add(json(expected)),
  });
  const save = () => fs.writeFileSync(join(directory, 'manifest.json'), json(manifest));
  save();
  return {
    directory,
    manifest,
    configuration,
    knowledge,
    expected,
    add,
    save,
    policy: (value) => {
      manifest.cases[0].policy = add(json(value));
      save();
    },
    expectedResult: (value) => {
      manifest.cases[0].expected = add(json(value));
      save();
    },
  };
}
const clone = (value) => JSON.parse(JSON.stringify(value));

test('organization loader returns copies and closed immutable case metadata', (t) => {
  const f = miniature(t),
    corpus = loadOrganizationHistoryVectorCorpus(f.directory);
  assert.equal(corpus.manifest.cases.length, 1);
  assert(Object.isFrozen(corpus.manifest.cases[0]));
  const original = corpus.read(corpus.manifest.cases[0].originalBytes);
  original.fill(0);
  assert.equal(corpus.input(corpus.manifest.cases[0]).originalBytes.toString(), 'original bytes');
  assert.deepEqual(corpus.input(corpus.manifest.cases[0]).knowledge, f.knowledge);
});

test('organization loader rejects malformed inventories before factory invocation', async (t) => {
  const mutations = [
    [
      'version',
      (m) => {
        m.schemaVersion = 2;
      },
      'ORG_VECTOR_VERSION',
    ],
    [
      'profile',
      (m) => {
        m.profile = 'other';
      },
      'ORG_VECTOR_VERSION',
    ],
    [
      'manifest field',
      (m) => {
        m.callback = 'execute';
      },
      'ORG_VECTOR_SCHEMA',
    ],
    [
      'empty cases',
      (m) => {
        m.cases = [];
      },
      'ORG_VECTOR_CASE_LIMIT',
    ],
    [
      'too many cases',
      (m) => {
        m.cases = Array(129).fill(m.cases[0]);
      },
      'ORG_VECTOR_CASE_LIMIT',
    ],
    [
      'duplicate case',
      (m) => {
        m.cases.push(m.cases[0]);
      },
      'ORG_VECTOR_CASE_ID',
    ],
    [
      'uppercase case',
      (m) => {
        m.cases[0].id = 'CASE';
      },
      'ORG_VECTOR_CASE_ID',
    ],
    [
      'case field',
      (m) => {
        m.cases[0].mode = 'VALID';
      },
      'ORG_VECTOR_SCHEMA',
    ],
    [
      'traversal',
      (m) => {
        m.files[0].path = '../outside';
      },
      'ORG_VECTOR_PATH',
    ],
    [
      'absolute path',
      (m) => {
        m.files[0].path = 'C:/outside';
      },
      'ORG_VECTOR_PATH',
    ],
    [
      'backslash path',
      (m) => {
        m.files[0].path = m.files[0].path.replace('/', '\\');
      },
      'ORG_VECTOR_PATH',
    ],
    [
      'dot segment',
      (m) => {
        m.files[0].path = 'files/./' + m.files[0].path.split('/')[1];
      },
      'ORG_VECTOR_PATH',
    ],
    [
      'empty segment',
      (m) => {
        m.files[0].path = m.files[0].path.replace('/', '//');
      },
      'ORG_VECTOR_PATH',
    ],
    [
      'long path',
      (m) => {
        m.files[0].path += 'a'.repeat(240);
      },
      'ORG_VECTOR_PATH',
    ],
    [
      'duplicate file',
      (m) => {
        m.files.push(m.files[0]);
      },
      'ORG_VECTOR_PATH',
    ],
    [
      'case folded path',
      (m) => {
        m.files.push({ ...m.files[0], path: m.files[0].path.toUpperCase() });
      },
      'ORG_VECTOR_PATH',
    ],
    [
      'file count',
      (m) => {
        m.files = Array(513).fill(m.files[0]);
      },
      'ORG_VECTOR_FILE_LIMIT',
    ],
    [
      'stored size limit',
      (m) => {
        m.files[0].bytes = 32 * 1024 * 1024 + 1;
      },
      'ORG_VECTOR_FILE_DESCRIPTOR',
    ],
    [
      'decoded size limit',
      (m) => {
        m.files[0].decodedBytes = 32 * 1024 * 1024 + 1;
      },
      'ORG_VECTOR_FILE_DESCRIPTOR',
    ],
    [
      'negative size',
      (m) => {
        m.files[0].bytes = -1;
      },
      'ORG_VECTOR_FILE_DESCRIPTOR',
    ],
    [
      'address mismatch',
      (m) => {
        m.files[0].decodedSHA256 = '0'.repeat(64);
      },
      'ORG_VECTOR_ADDRESS',
    ],
    [
      'missing reference',
      (m) => {
        m.cases[0].originalBytes = 'files/' + '0'.repeat(64) + '.bin.b64';
      },
      'ORG_VECTOR_FILE_UNDECLARED',
    ],
    [
      'expected binary',
      (m) => {
        m.cases[0].expected = m.cases[0].originalBytes;
      },
      'ORG_VECTOR_JSON_REFERENCE',
    ],
  ];
  for (const [name, change, code] of mutations)
    await t.test(name, (t) => {
      const f = miniature(t);
      change(f.manifest);
      f.save();
      let calls = 0;
      assert.throws(
        () =>
          runOrganizationHistoryVectors({
            directory: f.directory,
            createOrganizationHistorySource() {
              calls++;
            },
            createOrganizationHistoryVerifier() {
              calls++;
            },
          }),
        { code },
      );
      assert.equal(calls, 0);
    });
});

test('organization loader bounds both inventory totals before material reads', async (t) => {
  for (const field of ['bytes', 'decodedBytes'])
    await t.test(field, (t) => {
      const f = miniature(t);
      f.manifest.files = Array.from({ length: 5 }, (_, i) => {
        const digest = String(i + 1).repeat(64);
        return {
          path: `files/${digest}.bin.b64`,
          bytes: 1,
          sha256: digest,
          mediaType: 'application/octet-stream',
          encoding: 'base64',
          decodedBytes: 1,
          decodedSHA256: digest,
          [field]: 32 * 1024 * 1024,
        };
      });
      f.save();
      assert.throws(() => loadOrganizationHistoryVectorCorpus(f.directory), {
        code: 'ORG_VECTOR_TOTAL_SIZE',
      });
    });
});

test('organization loader rejects byte corruption and noncanonical encodings', async (t) => {
  for (const [name, mutate, code] of [
    [
      'stored size',
      (f, d) => {
        d.bytes++;
      },
      'ORG_VECTOR_FILE_SIZE',
    ],
    [
      'stored hash',
      (f, d) => {
        d.sha256 = '0'.repeat(64);
      },
      'ORG_VECTOR_FILE_HASH',
    ],
    [
      'decoded size',
      (f, d) => {
        d.decodedBytes++;
      },
      'ORG_VECTOR_DECODED_HASH',
    ],
    [
      'base64 newline',
      (f, d) => {
        const bytes = fs.readFileSync(join(f.directory, d.path)).subarray(0, -1);
        fs.writeFileSync(join(f.directory, d.path), bytes);
        d.bytes = bytes.length;
        d.sha256 = vectorHash(bytes);
      },
      'ORG_VECTOR_BASE64',
    ],
    [
      'duplicate JSON key',
      (f) => {
        f.add(Buffer.from('{\n  "x": 1,\n  "x": 2\n}\n'));
      },
      'ORG_VECTOR_JSON_CANONICAL',
    ],
    [
      'JSON whitespace',
      (f) => {
        f.add(Buffer.from('{"x":1}\n'));
      },
      'ORG_VECTOR_JSON_CANONICAL',
    ],
    [
      'invalid UTF8',
      (f) => {
        f.add(Buffer.from([0x22, 0xff, 0x22, 0x0a]));
      },
      'ORG_VECTOR_JSON',
    ],
    [
      'invalid JSON',
      (f) => {
        f.add(Buffer.from('not JSON\n'));
      },
      'ORG_VECTOR_JSON',
    ],
    [
      'nonfinite JSON',
      (f) => {
        f.add(Buffer.from('1e400\n'));
      },
      'ORG_VECTOR_JSON_VALUE',
    ],
    [
      'excess depth',
      (f) => {
        let item = 1;
        for (let i = 0; i < 70; i++) item = [item];
        f.add(json(item));
      },
      'ORG_VECTOR_JSON_DEPTH',
    ],
  ])
    await t.test(name, (t) => {
      const f = miniature(t),
        descriptor = f.manifest.files[0];
      mutate(f, descriptor);
      f.save();
      assert.throws(() => loadOrganizationHistoryVectorCorpus(f.directory), { code });
    });
});

test('organization loader accepts only bounded public data tags', async (t) => {
  for (const [name, value, code] of [
    ['unknown tag', { $module: 'file:///unsafe.mjs' }, 'ORG_VECTOR_CONFIG_FIELD'],
    [
      'unknown material type',
      { $file: 'placeholder', type: 'private' },
      'ORG_VECTOR_MATERIAL_TYPE',
    ],
    ['extra tag property', { $hex: '00', extra: 1 }, 'ORG_VECTOR_SCHEMA'],
    ['bad hex', { $hex: '0g' }, 'ORG_VECTOR_HEX'],
    ['too much hex', { $hex: 'ab'.repeat(4097) }, 'ORG_VECTOR_HEX'],
    ['bad SPKI', { $file: 'placeholder', type: 'spki' }, 'ORG_VECTOR_PUBLIC_KEY'],
    ['private key field', { privateKey: 'secret' }, 'ORG_VECTOR_CONFIG_FIELD'],
    ['private DER field', { privateKeyDER: 'secret' }, 'ORG_VECTOR_CONFIG_FIELD'],
    ['prototype field', JSON.parse('{"__proto__":{}}'), 'ORG_VECTOR_CONFIG_FIELD'],
    ['callback field', { authorityResolver: 'return true' }, 'ORG_VECTOR_CONFIG_FIELD'],
    ['verdict field', { overall: 'VALID' }, 'ORG_VECTOR_CONFIG_FIELD'],
    ['time override', { stateTime: 1 }, 'ORG_VECTOR_CONFIG_FIELD'],
    ['durable override', { databasePath: ':memory:' }, 'ORG_VECTOR_CONFIG_FIELD'],
  ])
    await t.test(name, (t) => {
      const f = miniature(t),
        changed = clone(value);
      if (changed.$file) changed.$file = f.manifest.cases[0].originalBytes;
      f.policy({ ...f.configuration, trust: changed });
      assert.throws(() => loadOrganizationHistoryVectorCorpus(f.directory), { code });
    });
});

test('organization runner compares every actual result field without expectation input', async (t) => {
  const edits = [
    [
      'overall',
      (v) => {
        v.overall = 'INVALID';
      },
    ],
    [
      'check',
      (v) => {
        v.checks[0].reason = 'CHANGED';
      },
    ],
    [
      'dimension',
      (v) => {
        v.dimensions.time.reason = 'CHANGED';
      },
    ],
    [
      'limitation',
      (v) => {
        v.limits.push('EXTRA');
      },
    ],
    [
      'fractional time',
      (v) => {
        v.historicalAuthorization.stateTime = 1;
      },
    ],
    [
      'ledger',
      (v) => {
        v.protectionLedger[0].validUntil++;
      },
    ],
    [
      'missing field',
      (v) => {
        delete v.checks;
      },
    ],
    [
      'extra field',
      (v) => {
        v.unevaluated = true;
      },
    ],
  ];
  for (const [name, edit] of edits)
    await t.test(name, (t) => {
      const f = miniature(t),
        altered = clone(f.expected);
      edit(altered);
      f.expectedResult(altered);
      let sourceCalls = 0,
        verifyCalls = 0,
        closed = 0;
      assert.throws(
        () =>
          runOrganizationHistoryVectors({
            directory: f.directory,
            createOrganizationHistorySource(options) {
              sourceCalls++;
              assert.deepEqual(Object.keys(options).sort(), ['configuration', 'readKnowledge']);
              assert.deepEqual(options.configuration, f.configuration);
              assert.deepEqual(options.readKnowledge(), f.knowledge);
              return {
                close() {
                  closed++;
                },
              };
            },
            createOrganizationHistoryVerifier(options) {
              assert.deepEqual(Object.keys(options), ['source']);
              return {
                verify(input) {
                  verifyCalls++;
                  assert.deepEqual(Object.keys(input).sort(), ['evidenceRecord', 'originalBytes']);
                  assert.equal(input.originalBytes.toString(), 'original bytes');
                  return clone(f.expected);
                },
              };
            },
          }),
        (error) => {
          assert.equal(error.code, 'ORG_VECTOR_EXPECTATION_MISMATCH');
          assert.deepEqual(error.actual, f.expected);
          assert.deepEqual(error.expected, altered);
          return true;
        },
      );
      assert.deepEqual([sourceCalls, verifyCalls, closed], [1, 1, 1]);
    });
});

test('organization complete-result validation refuses silent JSON loss', (t) => {
  let accesses = 0;
  const accessor = Object.defineProperty({}, 'value', {
    enumerable: true,
    get() {
      accesses++;
      return 1;
    },
  });
  const cycle = {};
  cycle.self = cycle;
  for (const value of [
    { field: undefined },
    { field: NaN },
    { field: Infinity },
    { field: -0 },
    { field() {} },
    { field: Symbol('lost') },
    { field: Buffer.from('bytes') },
    accessor,
    cycle,
    Object.assign([], { extra: 1 }),
    Array(1),
  ])
    assert.throws(() => assertLosslessVectorJSON(value), { code: 'ORG_VECTOR_JSON_VALUE' });
  assert.equal(accesses, 0);
  assertLosslessVectorJSON({ fraction: 1.5, checks: [], dimensions: {}, nullable: null });
});

test('organization CLI rejects extra arguments with a nonzero status', () => {
  const command = fileURLToPath(new URL('./verify-organization-vectors.mjs', import.meta.url));
  const child = spawnSync(process.execPath, [command, 'one', 'two'], { encoding: 'utf8' });
  assert.equal(child.status, 1);
  assert.equal(JSON.parse(child.stderr).error, 'ORG_VECTOR_ARGUMENTS');
});

test('organization complete-result validation rejects sparse arrays with compensating own properties', () => {
  const value = [1, , 3];
  value.extra = 'must-not-disappear';
  assert.equal(Object.getOwnPropertyNames(value).length, value.length + 1);
  assert.equal(JSON.stringify(value), '[1,null,3]');
  assert.throws(() => assertLosslessVectorJSON(value), { code: 'ORG_VECTOR_JSON_VALUE' });
  assertLosslessVectorJSON([1, 2, 3]);
});

test('organization complete-result validation rejects inherited array serialization hooks', () => {
  let calls = 0;
  class Custom extends Array {
    toJSON() {
      calls++;
      return 'replacement';
    }
  }
  const value = new Custom(1, 2, 3);
  assert.equal(JSON.stringify(value), '"replacement"');
  calls = 0;
  assert.throws(() => assertLosslessVectorJSON(value), { code: 'ORG_VECTOR_JSON_VALUE' });
  assert.equal(calls, 0);
  assertLosslessVectorJSON([1, 2, 3]);
});

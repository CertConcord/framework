import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { setImmediate as immediate } from 'node:timers/promises';
import { createOrganizationHistorySource, createOrganizationHistoryVerifier } from './sdk/index.mjs';
import { connectOrganizationHistorySource } from './organization-history-source.mjs';
import { VerificationError } from './verification-result.mjs';
import {
  defaultOrganizationHistoryVectorDirectory,
  loadOrganizationHistoryVectorCorpus,
  runOrganizationHistoryVectors,
} from './verify-organization-vectors.mjs';
import { vectorHash, canonicalVectorJSON } from './organization-vector-corpus.mjs';
import {
  organizationHistorySemantics,
  assertOrganizationHistoryOutcome,
  assertOrganizationHistoryOriginalPairs,
} from './organization-history-vector-semantics.mjs';

const cli = fileURLToPath(new URL('./verify-organization-vectors.mjs', import.meta.url));

for (const [slot, reason] of [
  ['readKnowledge', 'ORG_HISTORY_KNOWLEDGE_UNAVAILABLE'],
  ['authorityResolver', 'ORG_AUTHORITY_UNAVAILABLE'],
  ['resolveTimestamp', 'ORG_TIMESTAMP_TRUST_UNAVAILABLE'],
]) {
  test(`saved history ${slot} Promise results retain typed uncertainty and recover`, async (t) => {
    const corpus = loadOrganizationHistoryVectorCorpus();
    const entry = corpus.manifest.cases.find((value) => value.id === 'expired-issuer-scoped-successor');
    const fixture = corpus.input(entry);
    const input = { originalBytes: fixture.originalBytes, evidenceRecord: fixture.evidenceRecord };
    const original = { originalBytes: Buffer.from(input.originalBytes), evidenceRecord: Buffer.from(input.evidenceRecord) };
    const source = createOrganizationHistorySource({
      configuration: fixture.configuration,
      readKnowledge: () => fixture.knowledge,
    });
    t.after(() => source.close());
    let options;
    connectOrganizationHistorySource(source, (value) => { options = value; });
    let mode = 'synchronous', callbackCalls = 0, hookCalls = 0, thenCalls = 0;
    const callback = slot === 'resolveTimestamp' ? options.preservationPolicy[slot] : options[slot];
    const selected = (...args) => {
      const answer = callback(...args);
      if (mode === 'synchronous') return answer;
      callbackCalls++;
      const value = mode === 'rejected' || mode === 'own-then'
        ? Promise.reject(new Error('callback unavailable')) : Promise.resolve(answer);
      if (mode === 'own-then') Object.defineProperty(value, 'then', {
        get() { thenCalls++; throw new Error('own then must not be read'); },
      });
      if (mode.startsWith('constructor-') || mode.startsWith('species-')) {
        const get = () => {
          hookCalls++;
          throw mode.endsWith('-null') ? null
            : new VerificationError('CALLER_SELECTED_OUTCOME', 'UNSUPPORTED', 'authorization');
        };
        Object.defineProperty(value, 'constructor', mode.startsWith('constructor-')
          ? { get } : { value: Object.defineProperty({}, Symbol.species, { get }) });
      }
      return value;
    };
    const configured = slot === 'resolveTimestamp'
      ? { ...options, preservationPolicy: { ...options.preservationPolicy, [slot]: selected } }
      : { ...options, [slot]: selected };
    const verifier = createOrganizationHistoryVerifier(configured);
    const baseline = verifier.verify(input);
    assert.equal(baseline.overall, 'VALID');
    assert.deepEqual(baseline, corpus.expected(entry));
    mode = 'fulfilled';
    const unavailable = verifier.verify(input);
    assert.equal(unavailable.overall, 'INDETERMINATE');
    assert(unavailable.checks.some((row) => row.reason === reason && row.overall === 'INDETERMINATE'));
    for (const kind of ['fulfilled', 'rejected', 'own-then', 'constructor-null', 'constructor-typed', 'species-null', 'species-typed']) {
      await t.test(kind, async () => {
        mode = kind;
        callbackCalls = hookCalls = thenCalls = 0;
        assert.deepEqual(verifier.verify(input), unavailable);
        assert(callbackCalls > 0);
        assert.equal(hookCalls, kind.startsWith('constructor-') || kind.startsWith('species-') ? callbackCalls : 0);
        await immediate();
        assert.equal(thenCalls, 0);
        mode = 'synchronous';
        assert.deepEqual(verifier.verify(input), baseline);
        assert.deepEqual(input, original);
      });
    }
  });
}

test('schema1 organization corpora require their original verifier', () => {
  for (const name of [
    'organization-history',
    'preserved-certificate-status',
    'preserved-delegation-status',
  ])
    assert.throws(
      () =>
        loadOrganizationHistoryVectorCorpus(
          resolve(defaultOrganizationHistoryVectorDirectory, '..', name),
        ),
      { code: 'ORG_VECTOR_VERSION' },
    );
});
function copiedCorpus(t, ids) {
  const directory = fs.mkdtempSync(join(tmpdir(), 'certconcord-org-replay-'));
  t.after(() => {
    assert.equal(dirname(resolve(directory)), resolve(tmpdir()));
    assert(basename(directory).startsWith('certconcord-org-replay-'));
    fs.rmSync(directory, { recursive: true, force: true });
  });
  const corpus = join(directory, 'corpus');
  fs.cpSync(defaultOrganizationHistoryVectorDirectory, corpus, { recursive: true });
  const manifest = JSON.parse(fs.readFileSync(join(corpus, 'manifest.json')));
  if (ids) manifest.cases = manifest.cases.filter((entry) => ids.includes(entry.id));
  const save = () => fs.writeFileSync(join(corpus, 'manifest.json'), canonicalVectorJSON(manifest));
  save();
  return { directory, corpus, manifest, save };
}

test('saved organization history cases satisfy independently frozen semantics and complete results', async (t) => {
  const corpus = loadOrganizationHistoryVectorCorpus();
  assert.equal(corpus.manifest.cases.length, organizationHistorySemantics.length);
  const results = runOrganizationHistoryVectors();
  const inputs = corpus.manifest.cases.map((entry) => corpus.input(entry));
  assertOrganizationHistoryOriginalPairs(inputs);
  for (let index = 0; index < inputs.length; index++) {
    const input = inputs[index],
      result = results[index];
    await t.test(input.id, () => {
      assert.equal(result.id, input.id);
      assertOrganizationHistoryOutcome(input, result.actual);
      assert.deepEqual(result.actual, corpus.expected(corpus.manifest.cases[index]));
    });
  }
});

test('saved organization corpus retains exact public original bytes and declared provenance', () => {
  const corpus = loadOrganizationHistoryVectorCorpus();
  for (const file of corpus.manifest.files) {
    const stored = fs.readFileSync(join(corpus.directory, file.path)),
      decoded = corpus.read(file.path);
    assert.equal(stored.length, file.bytes);
    assert.equal(vectorHash(stored), file.sha256);
    assert.equal(decoded.length, file.decodedBytes);
    assert.equal(vectorHash(decoded), file.decodedSHA256);
    assert(stored.every((byte) => byte < 128));
    assert(!stored.toString().includes('PRIVATE KEY'));
  }
  const provenance = JSON.parse(corpus.read(corpus.manifest.provenance));
  assert.equal(
    provenance.semanticSHA256,
    vectorHash(
      fs.readFileSync(new URL('./organization-history-vector-semantics.mjs', import.meta.url)),
    ),
  );
  assert.equal(provenance.baselineCommit, 'ac43db6dfd52acbac57a091cb2c9b5cc71e06244');
  assert(
    provenance.sources.some(
      (source) => source.path === 'reference/organization-history-source.mjs',
    ),
  );
  assert.equal(typeof provenance.runtime.node, 'string');
  assert.equal(typeof provenance.runtime.openssl, 'string');
  // These are construction declarations, not a claim that the current runtime
  // or a later implementation has the author's exact source identity.
});

test('saved organization replay is offline and independent of wall clock and working directory', (t) => {
  const f = copiedCorpus(t, [
    'expired-issuer-scoped-successor',
    'missing-current-history',
    'late-renewal',
  ]);
  const before = new Map(
    ['manifest.json', ...f.manifest.files.map((file) => file.path)].map((path) => [
      path,
      vectorHash(fs.readFileSync(join(f.corpus, path))),
    ]),
  );
  const childPath = join(f.directory, 'offline.mjs');
  fs.writeFileSync(
    childPath,
    `
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import dgram from 'node:dgram';
import childProcess from 'node:child_process';
import { registerHooks, syncBuiltinESMExports } from 'node:module';
import { basename } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
const deny = () => { throw Error('OFFLINE_REPLAY_FORBIDDEN'); };
globalThis.fetch = deny;
net.Socket.prototype.connect = deny;
for (const [module, names] of [
  [net, ['connect', 'createConnection']], [http, ['get', 'request']], [https, ['get', 'request']],
  [dgram, ['createSocket']],
  [crypto, ['generateKey', 'generateKeySync', 'generateKeyPair', 'generateKeyPairSync', 'sign']],
  [childProcess, ['exec', 'execSync', 'execFile', 'execFileSync', 'fork', 'spawn', 'spawnSync']],
]) for (const name of names) module[name] = deny;
crypto.Sign.prototype.sign = deny;
crypto.webcrypto.subtle.sign = deny;
crypto.webcrypto.subtle.generateKey = deny;
syncBuiltinESMExports();
registerHooks({ resolve(specifier, context, nextResolve) {
  const value = nextResolve(specifier, context);
  if (value.url.startsWith('file:') && /fixture|freeze-organization-vectors|organization-history-vector-semantics/i.test(basename(fileURLToPath(value.url)))) deny();
  return value;
} });
Date.now = process.argv[4] === 'forbidden' ? deny : () => Number(process.argv[4]);
const { runOrganizationHistoryVectors } = await import(pathToFileURL(process.argv[2]));
const actual = runOrganizationHistoryVectors({ directory: process.argv[3] });
assert.equal(actual.length, 3);
console.log(JSON.stringify(actual));
`,
  );
  const outputs = [0, Date.UTC(2100, 0, 1), 'forbidden'].map((time) => {
    const child = spawnSync(process.execPath, [childPath, cli, f.corpus, String(time)], {
      cwd: f.directory,
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
    });
    assert.equal(child.status, 0, child.stderr);
    return JSON.parse(child.stdout);
  });
  assert.deepEqual(outputs[0], outputs[1]);
  assert.deepEqual(outputs[0], outputs[2]);
  for (const [path, digest] of before)
    assert.equal(vectorHash(fs.readFileSync(join(f.corpus, path))), digest);
});

test('saved organization CLI separates result mismatch from malformed corpus data', async (t) => {
  await t.test('changed expected does not change actual VALID', (t) => {
    const f = copiedCorpus(t, ['expired-issuer-scoped-successor']);
    const expected = JSON.parse(fs.readFileSync(join(f.corpus, f.manifest.cases[0].expected)));
    expected.currentAdmissibility.knowledgeTime--;
    const bytes = canonicalVectorJSON(expected),
      digest = vectorHash(bytes),
      path = `files/${digest}.json`;
    fs.writeFileSync(join(f.corpus, path), bytes);
    f.manifest.files.push({
      path,
      bytes: bytes.length,
      sha256: digest,
      mediaType: 'application/json',
      encoding: 'utf8',
      decodedBytes: bytes.length,
      decodedSHA256: digest,
    });
    f.manifest.cases[0].expected = path;
    f.save();
    const child = spawnSync(process.execPath, [cli, f.corpus], {
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
    });
    assert.equal(child.status, 1);
    const error = JSON.parse(child.stderr);
    assert.equal(error.error, 'ORG_VECTOR_EXPECTATION_MISMATCH');
    assert.equal(error.actual.overall, 'VALID');
    assert.equal(
      error.actual.currentAdmissibility.knowledgeTime,
      error.expected.currentAdmissibility.knowledgeTime + 1,
    );
  });
  await t.test('corrupted original file is a corpus error', (t) => {
    const f = copiedCorpus(t, ['expired-issuer-scoped-successor']);
    const path = join(f.corpus, f.manifest.cases[0].originalBytes),
      bytes = fs.readFileSync(path);
    bytes[0] ^= 1;
    fs.writeFileSync(path, bytes);
    const child = spawnSync(process.execPath, [cli, f.corpus], { encoding: 'utf8' });
    assert.equal(child.status, 1);
    const error = JSON.parse(child.stderr);
    assert.equal(error.error, 'ORG_VECTOR_FILE_HASH');
    assert.equal(Object.hasOwn(error, 'actual'), false);
  });
});

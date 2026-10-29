import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import koffi from 'koffi';
import { PKCS11Provider } from './pkcs11.mjs';

const vectors = JSON.parse(
  readFileSync(new URL('./vectors/pkcs11-capability.json', import.meta.url)),
);
test(
  'PKCS11 native capability admission',
  { skip: process.platform !== 'linux' && 'Linux synthetic ABI fixture' },
  async (t) => {
    const directory = mkdtempSync(join(tmpdir(), 'certconcord-pkcs11-capability-'));
    const library = join(directory, 'fixture.so');
    let fixture;
    try {
      execFileSync('cc', [
        '-shared',
        '-fPIC',
        '-std=c11',
        '-O2',
        '-o',
        library,
        fileURLToPath(new URL('./native/pkcs11-capability-fixture.c', import.meta.url)),
      ]);
      fixture = koffi.load(library);
      const configure = fixture.func('void fixture_configure(ulong mode)');
      const setMode = fixture.func('void fixture_mode(ulong mode)');
      const count = fixture.func('ulong fixture_count(void)');
      const event = fixture.func('ulong fixture_event(ulong i)');
      const trace = () => Array.from({ length: count() }, (_, i) => vectors.events[event(i)]);
      for (const vector of vectors.cases)
        await t.test(vector.name, async () => {
          configure(vector.mode);
          let provider;
          const keys =
            vector.algorithm === null
              ? new Map()
              : new Map([
                  [
                    'pinned',
                    { id: Buffer.alloc(16, 1), algorithm: vector.algorithm, publicKey: null },
                  ],
                ]);
          const construct = () =>
            (provider = new PKCS11Provider({ library, slot: 7, pin: 'synthetic-only', keys }));
          if (vector.error) {
            assert.throws(construct, (error) => error.message === vector.error);
            assert.equal(provider, undefined);
          } else {
            construct();
            assert.deepEqual(provider.cryptokiVersion, vector.version);
            assert.equal(
              provider.id,
              'pkcs11-v' + vector.version.major + '.' + vector.version.minor,
            );
            assert(Object.isFrozen(provider.cryptokiVersion));
            assert.throws(() => {
              provider.cryptokiVersion = { major: 3, minor: 2 };
            }, TypeError);
            if (vector.afterMode !== undefined) setMode(vector.afterMode);
            if (vector.operation === 'generate') {
              assert.throws(
                () =>
                  provider.generate({
                    keyRef: 'new',
                    id: Buffer.alloc(16, 2),
                    algorithm: vector.operationAlgorithm,
                  }),
                (error) => error.message === vector.operationError,
              );
            } else if (vector.operation === 'sign') {
              await assert.rejects(
                provider.sign({ keyRef: 'pinned', tbs: Buffer.from('synthetic admission only') }),
                (error) => error.message === vector.operationError,
              );
            } else if (vector.operation === 'capabilities') {
              await assert.rejects(
                provider.capabilities('pinned'),
                (error) => error.message === vector.operationError,
              );
            }
            provider.close();
            provider.close();
          }
          assert.deepEqual(trace(), vector.trace);
          assert(!trace().includes('sign'), 'The fixture never signs a message');
        });
    } finally {
      fixture?.unload();
      rmSync(directory, { recursive: true, force: true });
    }
  },
);

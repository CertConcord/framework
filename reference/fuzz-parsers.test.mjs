import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { decode as isoDecode } from './cose.mjs';
import { MdocValidationError } from './vendor/mdoc-signing/errors.mjs';
import { parseCheckpoint } from './transparency.mjs';
import { expectedRejection, fuzz } from './fuzz/parsers.mjs';

const unsignedCheckpoint = 'synthetic/log\n1\n' + Buffer.alloc(32).toString('base64') + '\n\n';
const input = (parser, bytes) => Buffer.concat([Buffer.from([parser]), Buffer.from(bytes)]);
function rejection(callback) {
  try {
    callback();
  } catch (error) {
    return error;
  }
  assert.fail('The malformed serialized input must be rejected');
}

test('Parser fuzz replay preserves rejection of legacy unsigned checkpoints', () => {
  assert.throws(() => parseCheckpoint(unsignedCheckpoint), { code: 'CHECKPOINT_SIGNATURE' });
  assert.doesNotThrow(() => fuzz(input(5, unsignedCheckpoint)));
});

test('Parser fuzz recognizes component rejection codes only for the originating parser', () => {
  const checkpointError = rejection(() => parseCheckpoint(unsignedCheckpoint));
  const cborError = rejection(() => isoDecode(Buffer.from('9f0102ff', 'hex')));
  assert(cborError instanceof MdocValidationError);
  assert.equal(cborError.code, 'CBOR_INDEFINITE');
  assert.equal(expectedRejection(checkpointError, 5), true);
  assert.equal(expectedRejection(checkpointError, 2), false);
  assert.equal(expectedRejection(checkpointError), false);
  assert.equal(expectedRejection(cborError, 2), true);
  assert.equal(expectedRejection(cborError, 5), false);
  assert.equal(expectedRejection(cborError), false);
  assert.doesNotThrow(() => fuzz(input(2, Buffer.from('9f0102ff', 'hex'))));
});

test('Parser fuzz does not suppress unknown codes, assertions, or programming errors', () => {
  for (const error of [
    new Error('CHECKPOINT_SIGNATURE'),
    Object.assign(new Error('CHECKPOINT_UNKNOWN'), { code: 'CHECKPOINT_UNKNOWN' }),
    Object.assign(new Error('unrelated failure'), { code: 'CHECKPOINT_SIGNATURE' }),
    Object.assign(new TypeError('CHECKPOINT_SIGNATURE'), { code: 'CHECKPOINT_SIGNATURE' }),
    new assert.AssertionError({ message: 'parser disagreement' }),
  ]) {
    assert.equal(expectedRejection(error, 5), false, String(error));
  }
  assert.equal(expectedRejection(new MdocValidationError('MDOC_MSO'), 2), false);
  assert.equal(expectedRejection(new MdocValidationError('CBOR_LIMIT', 'UNSUPPORTED'), 2), false);
});

test('Parser seed and replay commands cover signed and rejected unsigned checkpoint envelopes', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'certconcord-fuzz-replay-'));
  try {
    const corpus = join(directory, 'parsers');
    for (const script of ['seed.mjs', 'replay.mjs']) {
      const result = spawnSync(
        process.execPath,
        [fileURLToPath(new URL('./fuzz/' + script, import.meta.url)), corpus],
        {
          cwd: directory,
          encoding: 'utf8',
          windowsHide: true,
        },
      );
      assert.equal(result.status, 0, script + '\n' + result.stdout + result.stderr);
    }
    const checkpointSeeds = [];
    for (const name of await readdir(corpus)) {
      const bytes = await readFile(join(corpus, name));
      if (bytes[0] === 5) checkpointSeeds.push(bytes.subarray(1).toString('utf8'));
    }
    assert(
      checkpointSeeds.includes(unsignedCheckpoint),
      'Keep the rejected legacy seed as a regression',
    );
    const signed = checkpointSeeds
      .filter((note) => note !== unsignedCheckpoint)
      .map(parseCheckpoint);
    assert(signed.length > 0, 'The corpus must also exercise a supported signature envelope');
    assert.equal(signed[0].origin, 'synthetic/log');
    assert.equal(signed[0].signatures.length, 1);
    assert.equal(signed[0].signatures[0].signature.length, 64);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

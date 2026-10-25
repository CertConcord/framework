import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join, resolve, delimiter } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const here = dirname(fileURLToPath(import.meta.url));
const dependencies = JSON.parse(readFileSync(join(here, 'dependencies.json'), 'utf8'));
const expected = JSON.parse(readFileSync(join(here, 'observed.json'), 'utf8'));
if (!process.argv[2]) throw Error('Supply the directory containing the three pinned BC jars');
const dependencyDirectory = resolve(process.argv[2]);
for (const dependency of dependencies) {
  const bytes = readFileSync(join(dependencyDirectory, dependency.file));
  assert.equal(
    createHash('sha256').update(bytes).digest('hex'),
    dependency.sha256,
    dependency.file,
  );
}
const output = mkdtempSync(join(tmpdir(), 'certconcord-ers-bc186-'));
const classpath = dependencies.map(({ file }) => join(dependencyDirectory, file)).join(delimiter);
try {
  const compile = spawnSync(
    process.env.JAVAC || 'javac',
    ['-cp', classpath, '-d', output, join(here, 'ErsBc186Probe.java')],
    { encoding: 'utf8', timeout: 60000 },
  );
  assert.ifError(compile.error);
  assert.equal(compile.status, 0, compile.stderr);
  const replay = spawnSync(
    process.env.JAVA || 'java',
    [
      '-cp',
      output + delimiter + classpath,
      'ErsBc186Probe',
      resolve(here, '../../reference/vectors/cms-retirement-mtc07-rar2'),
    ],
    { encoding: 'utf8', timeout: 60000 },
  );
  assert.ifError(replay.error);
  // The compatibility probe itself must keep its failed positive expectations.
  assert.equal(replay.status, 1, replay.stderr);
  const actual = replay.stdout
    .trim()
    .split(/\r?\n/)
    .map((line) => JSON.parse(line));
  assert.equal(actual.length, expected.length);
  assert.equal(typeof actual.at(-1).javaVersion, 'string');
  for (let i = 0; i < actual.length; i++) {
    const { javaVersion: actualJava, ...actualResult } = actual[i];
    const { javaVersion: expectedJava, ...expectedResult } = expected[i];
    assert.deepEqual(actualResult, expectedResult, 'BC observation ' + i);
  }
  console.log(replay.stdout.trim());
  console.log(
    'BC 1.86 regression matched. Compatibility expectations remain 5/8; complete trust is not established.',
  );
} finally {
  rmSync(output, { recursive: true, force: true });
}

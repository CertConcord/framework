import { readFile, lstat, realpath, writeFile } from 'node:fs/promises';
import { resolve, relative, isAbsolute } from 'node:path';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { requireThat, fields } from '../core.mjs';
import { parseJSON } from '../json.mjs';

export async function validateResult(record, artifactDirectory) {
  fields(record, [
    'schemaVersion',
    'category',
    'assessor',
    'sourceCommit',
    'manifestSHA256',
    'role',
    'suite',
    'profile',
    'configurationSHA256',
    'startedAt',
    'completedAt',
    'tests',
    'artifacts',
  ]);
  requireThat(
    record.schemaVersion === 1 &&
      ['LOCAL_ADAPTER', 'EXTERNAL_EXECUTION', 'INDEPENDENT_REVIEW', 'CERTIFICATION'].includes(
        record.category,
      ),
    'ASSESSMENT_CATEGORY',
  );
  requireThat(
    typeof record.assessor === 'string' &&
      record.assessor.length > 0 &&
      /^[a-f0-9]{40}$/.test(record.sourceCommit),
    'ASSESSMENT_IDENTITY',
  );
  requireThat(
    ['ISSUER', 'WALLET', 'VERIFIER', 'CORE', 'PROVIDER'].includes(record.role),
    'ASSESSMENT_ROLE',
  );
  for (const name of ['manifestSHA256', 'configurationSHA256'])
    requireThat(/^[a-f0-9]{64}$/.test(record[name]), 'ASSESSMENT_DIGEST');
  requireThat(
    typeof record.profile === 'string' &&
      record.profile.length > 0 &&
      record.suite?.revision &&
      record.suite?.name,
    'ASSESSMENT_PROFILE',
  );
  requireThat(
    Number.isFinite(Date.parse(record.startedAt)) &&
      Date.parse(record.completedAt) >= Date.parse(record.startedAt),
    'ASSESSMENT_TIME',
  );
  requireThat(
    Array.isArray(record.tests) &&
      record.tests.length > 0 &&
      record.tests.length <= 100000 &&
      new Set(record.tests.map((t) => t.id)).size === record.tests.length &&
      record.tests.every(
        (t) =>
          typeof t.id === 'string' &&
          ['PASS', 'FAIL', 'INAPPLICABLE', 'INDETERMINATE'].includes(t.result) &&
          typeof t.artifact === 'string',
      ),
    'ASSESSMENT_TESTS',
  );
  requireThat(
    Array.isArray(record.artifacts) &&
      record.artifacts.length > 0 &&
      record.artifacts.length <= 1000,
    'ASSESSMENT_ARTIFACTS',
  );
  const base = await realpath(artifactDirectory),
    names = new Set();
  let total = 0;
  for (const artifact of record.artifacts) {
    fields(artifact, ['path', 'sha256']);
    requireThat(
      typeof artifact.path === 'string' &&
        !isAbsolute(artifact.path) &&
        !artifact.path.split(/[\\/]/).includes('..') &&
        /^[a-f0-9]{64}$/.test(artifact.sha256),
      'ASSESSMENT_ARTIFACT_PATH',
    );
    const path = resolve(base, artifact.path),
      stat = await lstat(path),
      actual = await realpath(path),
      rel = relative(base, actual);
    requireThat(
      !stat.isSymbolicLink() &&
        stat.isFile() &&
        !isAbsolute(rel) &&
        rel !== '..' &&
        !rel.startsWith('..' + (process.platform === 'win32' ? '\\' : '/')),
      'ASSESSMENT_ARTIFACT_PATH',
    );
    total += stat.size;
    requireThat(
      stat.size <= 32 * 1024 * 1024 && total <= 128 * 1024 * 1024,
      'ASSESSMENT_ARTIFACT_LIMIT',
    );
    requireThat(!names.has(artifact.path), 'ASSESSMENT_DUPLICATE');
    names.add(artifact.path);
    requireThat(
      createHash('sha256')
        .update(await readFile(actual))
        .digest('hex') === artifact.sha256,
      'ASSESSMENT_ARTIFACT_DIGEST',
    );
  }
  requireThat(
    record.tests.every((t) => names.has(t.artifact)),
    'ASSESSMENT_MISSING_ARTIFACT',
  );
  // This proves record/artifact integrity only. Authenticity and assessment authority are relying-party decisions.
  return {
    integrity: 'VALID',
    category: record.category,
    assessor: record.assessor,
    sourceCommit: record.sourceCommit,
    tests: record.tests.length,
    artifacts: names.size,
    authority: 'REQUIRES_EXTERNAL_AUTHENTICATION',
    conclusions: Object.fromEntries(
      ['PASS', 'FAIL', 'INAPPLICABLE', 'INDETERMINATE'].map((s) => [
        s,
        record.tests.filter((t) => t.result === s).length,
      ]),
    ),
  };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [file, directory] = process.argv.slice(2);
  requireThat(file && directory, 'ASSESSMENT_ARGUMENTS');
  const record = parseJSON(await readFile(file, 'utf8'), { maxBytes: 8 * 1024 * 1024 });
  console.log(JSON.stringify(await validateResult(record, directory), null, 2));
}

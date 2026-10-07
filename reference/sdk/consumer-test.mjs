import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdir, writeFile, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { runDemo } from '../demo.mjs';
import { runFoundationDemo } from '../foundation-demo.mjs';
import { runDocumentDemo } from '../document-demo.mjs';
import { dcbor, decodeCBOR } from '../core.mjs';
const cwd = resolve('.runtime/sdk-consumer');
const sdkPackage = JSON.parse(await readFile('sdk/package.json'));
assert.equal(sdkPackage.private, true);
await mkdir(cwd, { recursive: true });
await writeFile(cwd + '/package.json', JSON.stringify({ private: true, type: 'module' }));
const install = spawnSync(
  process.execPath,
  [
    process.env.npm_execpath,
    'install',
    '--offline',
    '--ignore-scripts',
    '--no-audit',
    '--no-fund',
    resolve('dist/certconcord-verifier-' + sdkPackage.version + '.tgz'),
  ],
  { cwd, encoding: 'utf8' },
);
assert.equal(install.status, 0, install.stderr);
const require = createRequire(cwd + '/package.json');
const entry = cwd + '/load.mjs';
await writeFile(entry, "export * from '@certconcord/verifier';\n");
const sdk = await import(pathToFileURL(entry));
assert.deepEqual(Object.keys(sdk).sort(), ['createVerifier', 'profiles']);
assert.throws(() => require.resolve('@certconcord/verifier/core.mjs'), /not defined|not exported/);
assert.throws(() => sdk.createVerifier({ format: 'CMS', trust: {} }), /SDK_TRUST/);
for (const [format, executionBinding, trustedTime = false] of [
  ['CMS', false],
  ['MDOC', false],
  ['CMS', true],
  ['MDOC', true],
  ['CMS', false, true],
  ['MDOC', false, true],
]) {
  const r =
    format === 'CMS'
      ? await runDemo({ executionBinding, trustedTime })
      : await runFoundationDemo({ executionBinding, trustedTime });
  const verifier = sdk.createVerifier({ format, trust: r.trust });
  const verified = verifier.verify(dcbor(r.bundle));
  assert.equal(verified.overall, 'VALID');
  assert.equal(verified.coreRevision, 'draft-03');
  for (const suffix of ['attested-v1', 'passkey-v1', 'execution-draft-02', 'attested-draft-02']) {
    const profile = 'certconcord-ecp-' + format.toLowerCase() + '-' + suffix;
    assert.equal(
      verifier.verify(dcbor({ ...r.bundle, plan: { ...r.bundle.plan, profile } })).overall,
      'UNSUPPORTED',
      profile,
    );
  }
  assert.equal(verifier.verify(dcbor({ ...r.bundle, schemaVersion: 1 })).overall, 'UNSUPPORTED');
  const changed = decodeCBOR(dcbor(r.bundle));
  changed.objects.find((object) => object.type === 'Document').payload[0] ^= 1;
  assert.equal(verifier.verify(dcbor(changed)).overall, 'INVALID');
  assert.equal(verifier.verify(Buffer.from('not evidence')).overall, 'INVALID');
  assert.equal(verifier.verify(dcbor({ ...r.bundle, extra: true })).overall, 'INVALID');
  const wrong = sdk.createVerifier({
    format,
    trust: { ...r.trust, trustDomainID: Buffer.alloc(32) },
  });
  assert.equal(wrong.verify(dcbor(r.bundle)).overall, 'INVALID');
}
const sealed = await runDocumentDemo();
assert.equal(
  sdk.createVerifier({ format: 'CMS', trust: sealed.trust }).verify(dcbor(sealed.bundle))
    .organizationAuthorization,
  'AUTHORITY_ATTESTED_OPERATION',
);
console.log(
  'SDK archive install, export boundary, trust binding, document evidence and execution plans passed',
);

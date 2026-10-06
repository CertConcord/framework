import { build } from 'esbuild';
import { mkdir, readFile, writeFile, copyFile, readdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
const dir = 'dist/sdk';
await mkdir(dir, { recursive: true });
const result = await build({
  entryPoints: ['sdk/index.mjs'],
  bundle: true,
  format: 'esm',
  platform: 'node',
  target: 'node24',
  outfile: dir + '/index.mjs',
  metafile: true,
  legalComments: 'inline',
  treeShaking: true,
});
for (const file of ['index.d.ts', 'package.json', 'README.md'])
  await copyFile('sdk/' + file, dir + '/' + file);
for (const file of ['LICENSE', 'NOTICE']) await copyFile('../' + file, dir + '/' + file);
const packages = new Map();
for (const path of Object.keys(result.metafile.inputs)) {
  const match = path.match(/^(.*?node_modules\/((?:@[^/]+\/)?[^/]+))\//);
  if (match) packages.set(match[2], match[1]);
}
if (!packages.size) throw Error('Missing bundled dependency inventory');
let notices = 'Bundled third-party software. Original licenses follow.\n';
const components = [];
for (const [name, base] of [...packages].sort(([a], [b]) => a.localeCompare(b))) {
  const p = JSON.parse(await readFile(base + '/package.json'));
  const files = (await readdir(base)).filter((f) =>
    /^(LICENSE|LICENCE|COPYING|NOTICE)(\.|$)/i.test(f),
  );
  if (!files.length) throw Error('Missing third-party license: ' + name);
  notices += '\n' + name + ' ' + p.version + '\n';
  for (const f of files) notices += '\n' + (await readFile(base + '/' + f, 'utf8'));
  const purl =
    'pkg:npm/' +
    name.split('/').map(encodeURIComponent).join('/') +
    '@' +
    encodeURIComponent(p.version);
  components.push({
    type: 'library',
    'bom-ref': purl,
    name,
    version: p.version,
    purl,
    licenses: [{ license: { id: p.license } }],
  });
}
await writeFile(dir + '/THIRD-PARTY-NOTICES.txt', notices);
const pkg = JSON.parse(await readFile('sdk/package.json'));
const root = 'pkg:npm/%40certconcord/verifier@' + pkg.version;
const identity = createHash('sha1')
  .update(Buffer.from('6ba7b8109dad11d180b400c04fd430c8', 'hex'))
  .update(root)
  .update(await readFile(dir + '/index.mjs'))
  .update(JSON.stringify(components))
  .digest()
  .subarray(0, 16);
identity[6] = (identity[6] & 15) | 80;
identity[8] = (identity[8] & 63) | 128;
const uuid = identity
  .toString('hex')
  .replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5');
const sbom = {
  $schema: 'http://cyclonedx.org/schema/bom-1.6.schema.json',
  bomFormat: 'CycloneDX',
  specVersion: '1.6',
  serialNumber: 'urn:uuid:' + uuid,
  version: 1,
  metadata: {
    component: {
      type: 'library',
      'bom-ref': root,
      name: pkg.name,
      version: pkg.version,
      licenses: [{ license: { id: 'Apache-2.0' } }],
    },
  },
  components,
  dependencies: [
    { ref: root, dependsOn: components.map((c) => c['bom-ref']) },
    ...components.map((c) => ({ ref: c['bom-ref'], dependsOn: [] })),
  ],
};
await writeFile(dir + '/sbom.cdx.json', JSON.stringify(sbom, null, 2) + '\n');
await writeFile('dist/sdk-build-meta.json', JSON.stringify(result.metafile, null, 2) + '\n');
// npm's JavaScript CLI avoids shell interpretation of paths on every supported OS.
const npm = process.env.npm_execpath;
if (!npm) throw Error('Run through npm run sdk:build');
const packed = spawnSync(
  process.execPath,
  [npm, 'pack', './' + dir, '--pack-destination', 'dist', '--json'],
  { encoding: 'utf8' },
);
if (packed.status !== 0) throw Error(packed.stderr);
const info = JSON.parse(packed.stdout)[0];
const allowed = new Set(['package.json', ...pkg.files]);
if (info.files.some((f) => !allowed.has(f.path))) throw Error('SDK_FILE_BOUNDARY');
console.log(
  JSON.stringify({
    file: 'dist/' + info.filename,
    bytes: info.size,
    bundledComponents: components.length,
    sha256: createHash('sha256')
      .update(await readFile('dist/' + info.filename))
      .digest('hex'),
  }),
);

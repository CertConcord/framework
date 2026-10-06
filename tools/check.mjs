import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { dirname, resolve, relative, extname, join } from 'node:path';
import { createManifest, repositoryRoot as root } from './manifest.mjs';
import { validateRegistry } from '../reference/governance/registry.mjs';
import { sources as sourceURLs } from '../reference/sources.mjs';
const read = (path) => readFileSync(join(root, path), 'utf8');
const json = (path) => JSON.parse(read(path));
const manifest = createManifest();
assert.deepEqual(
  manifest,
  json('draft-manifest.json'),
  'Draft manifest differs; review changes before regeneration',
);
const draft = json('draft.json'),
  workspace = json('package.json'),
  pkg = json('reference/package.json');
const lock = json('package-lock.json'),
  sdk = json('reference/sdk/package.json');
assert.equal(draft.status, 'working-draft');
assert.equal(draft.stable, false);
assert.match(draft.edition, /^draft-\d+$/);
assert.match(draft.referenceVersion, /^0\.\d+\.\d+-draft\.\d+$/);
for (const p of [workspace, pkg, sdk]) {
  assert.equal(p.version, draft.referenceVersion);
  assert.equal(p.private, true);
  assert.equal(p.license, 'Apache-2.0');
  assert(!Object.hasOwn(p, 'publishConfig'), 'Drafts must not configure registry publication');
}
assert.equal(pkg.name, '@certconcord/reference');
assert.equal(sdk.name, '@certconcord/verifier');
assert.equal(lock.version, workspace.version);
assert.equal(lock.packages.reference.version, pkg.version);
validateRegistry(json('reference/governance/registry.json'));
for (const group of ['dependencies', 'devDependencies'])
  for (const [name, version] of Object.entries(pkg[group] ?? {})) {
    assert(/^\d+\.\d+\.\d+$/.test(version), 'Unpinned dependency ' + name);
    assert.equal(lock.packages.reference[group]?.[name], version);
  }
const sources = json('reference/source-lock.json'),
  adapters = json('reference/adapter-lock.json');
const sourceIDs = new Set(sources.sources.map((s) => s.id));
assert.equal(sources.release, pkg.version);
assert.equal(sourceIDs.size, sources.sources.length);
assert.deepEqual(sourceIDs, new Set(Object.keys(sourceURLs)), 'Source registry/lock IDs differ');
for (const s of sources.sources) {
  assert(s.url.startsWith('https://'));
  assert.equal(s.url, sourceURLs[s.id], 'Source registry/lock URL differs: ' + s.id);
  assert(/^[a-f0-9]{64}$/.test(s.sha256));
  assert(s.bytes > 0);
  assert(Number.isFinite(Date.parse(s.retrievedAt ?? sources.retrievedAt)));
}
assert.equal(adapters.release, pkg.version);
assert.equal(new Set(adapters.adapters.map((a) => a.id)).size, adapters.adapters.length);
for (const a of adapters.adapters) {
  assert(a.downgradeForbidden && a.wireProfile && a.inputSemantics && a.environment);
  for (const f of [...a.modules, ...a.tests])
    assert(existsSync(join(root, 'reference', f)), 'Missing adapter file ' + f);
  for (const id of a.sources) assert(sourceIDs.has(id), 'Missing source ' + id);
}
const forbiddenPath =
  /(^|\/)(?:AGENTS\.md|CLAUDE\.md|\.codex|\.runtime|\.git|task-context|worklog|local\.properties|\.env|research)(\/|$)|\.(?:dpapi|bundle|key|p12|pfx)$/i;
const published = new Set([...manifest.files.map((f) => f.path), 'draft-manifest.json']);
for (const item of manifest.files) {
  assert(!forbiddenPath.test(item.path), 'Private publication path ' + item.path);
  const body = read(item.path);
  assert(!/\p{Script=Han}/u.test(body), 'Project content must be in English: ' + item.path);
  assert(
    !/[A-Z]:[\\/](?:Users|VeriCommons|fusionpbx|Framework)[\\/]/i.test(body),
    'Local absolute path ' + item.path,
  );
  if (extname(item.path) === '.md') {
    for (const m of body.matchAll(/!?\[[^\]]*\]\(([^)]+)\)/g)) {
      const target = m[1].replace(/^<|>$/g, '').split('#')[0];
      if (!target || /^[a-z][a-z0-9+.-]*:/i.test(target)) continue;
      const path = resolve(root, dirname(item.path), decodeURIComponent(target));
      const publicationPath = relative(root, path).replaceAll('\\', '/');
      assert(
        published.has(publicationPath) ||
          [...published].some((p) => p.startsWith(publicationPath + '/')),
        'Link targets unpublished content ' + item.path + ' -> ' + target,
      );
      assert(
        !relative(root, path).startsWith('..') && existsSync(path),
        'Broken local link ' + item.path + ' -> ' + target,
      );
    }
  }
  assert(
    !/-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/.test(body),
    'Private key ' + item.path,
  );
  assert(
    !/gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}/.test(body),
    'Credential ' + item.path,
  );
}
// New source files must be reviewed into the explicit public inventory.
const listed = new Set([...manifest.files.map((f) => f.path), 'draft-manifest.json']);
const excluded = new Set([
  '.runtime',
  '.git',
  'node_modules',
  'dist',
  'coverage',
  '.gradle',
  'build',
  'DerivedData',
  'xcuserdata',
]);
function walk(dir = '') {
  for (const entry of readdirSync(join(root, dir), { withFileTypes: true })) {
    if (excluded.has(entry.name)) continue;
    const path = dir ? dir + '/' + entry.name : entry.name;
    if (entry.isDirectory()) walk(path);
    else assert(listed.has(path), 'Unreviewed file outside publication inventory: ' + path);
  }
}
walk();
const components = json('components.lock.json').components;
assert.equal(new Set(components.map(c => c.name)).size, components.length);
for (const component of components) {
  assert(/^https:\/\/github\.com\/CertConcord\/[a-z0-9-]+$/.test(component.repository));
  assert(/^[a-f0-9]{40}$/.test(component.commit));
  for (const file of component.files) {
    assert(listed.has(file.path), 'Unpublished component snapshot');
    assert(!file.source.split('/').includes('..'));
    const hash = createHash('sha256').update(readFileSync(join(root, file.path))).digest('hex');
    assert.equal(hash, file.sha256, 'Component snapshot differs from its source pin: ' + file.path);
  }
}
const coverage = json('spec/conformance.json');
const requirements = new Set();
for (const path of [
  'spec/trust-core.md',
  'spec/document-baseline.md',
  'spec/mdoc-certificates.md',
  'spec/passkey-credentials.md',
])
  for (const m of read(path).matchAll(/CC-(?:CORE|DOC|MDOC|PASSKEY)-\d{2}/g))
    requirements.add(m[0]);
assert.deepEqual(
  new Set(coverage.requirements.map((r) => r.id)),
  requirements,
  'Requirement coverage inventory differs',
);
assert.equal(coverage.requirements.length, requirements.size);
for (const r of coverage.requirements) {
  assert(['partial', 'planned'].includes(r.coverage));
  assert(r.gap.length > 0, 'Missing draft limitation ' + r.id);
  for (const t of r.tests) {
    assert(listed.has(t.file));
    assert(read(t.file).includes(t.name), 'Missing named test ' + r.id + ': ' + t.name);
  }
}
assert(
  !existsSync(join(root, '.github/workflows/release.yml')),
  'Retired release workflow present',
);
console.log(
  'Draft integrity: ' +
    manifest.files.length +
    ' files; ' +
    requirements.size +
    ' requirements; ' +
    adapters.adapters.length +
    ' adapters; ' +
    sources.sources.length +
    ' source pins',
);

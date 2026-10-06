import { readFileSync, writeFileSync, lstatSync } from 'node:fs';
import { join, resolve, dirname, relative, isAbsolute } from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
export const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export function publicationFiles(root = repositoryRoot) {
  const files = JSON.parse(readFileSync(join(root, 'publication-files.json'), 'utf8'));
  if (!Array.isArray(files) || new Set(files).size !== files.length)
    throw Error('Invalid publication allowlist');
  for (const file of files) {
    if (
      typeof file !== 'string' ||
      file.includes('\\') ||
      isAbsolute(file) ||
      file.split('/').some((p) => !p || p === '.' || p === '..') ||
      file === 'draft-manifest.json'
    )
      throw Error('Invalid publication path');
    const full = resolve(root, file);
    if (relative(root, full).startsWith('..')) throw Error('Publication path outside root');
    for (let p = full; p !== resolve(root); p = dirname(p))
      if (lstatSync(p).isSymbolicLink()) throw Error('Publication symlink: ' + file);
    if (!lstatSync(full).isFile()) throw Error('Publication entry is not a file: ' + file);
  }
  return files.sort();
}
export function createManifest(root = repositoryRoot) {
  const draft = JSON.parse(readFileSync(join(root, 'draft.json'), 'utf8'));
  return {
    draft: draft.edition,
    referenceVersion: draft.referenceVersion,
    algorithm: 'SHA-256',
    files: publicationFiles(root).map((path) => {
      const bytes = readFileSync(join(root, path));
      return {
        path,
        bytes: bytes.length,
        sha256: createHash('sha256').update(bytes).digest('hex'),
      };
    }),
  };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (!process.argv.includes('--write'))
    throw Error('Use --write after reviewing the publication allowlist');
  const manifest = createManifest();
  writeFileSync(
    join(repositoryRoot, 'draft-manifest.json'),
    JSON.stringify(manifest, null, 2) + '\n',
  );
  console.log('Draft manifest: ' + manifest.files.length + ' files');
}

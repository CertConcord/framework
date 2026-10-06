import { open, writeFile, realpath } from 'node:fs/promises';
import { constants } from 'node:fs';
import { resolve, relative, isAbsolute } from 'node:path';
import { parseJSON } from '../json.mjs';
import {
  byteDigest,
  digest,
  validateRegistry,
  openRegister,
  checkContribution,
  checkMark,
} from './registry.mjs';

async function bytes(path) {
  const limit = 4 * 1024 * 1024;
  const file = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const s = await file.stat();
    if (!s.isFile() || s.size > limit) throw Error('GOVERNANCE_FILE_LIMIT');
    const buffer = Buffer.alloc(limit + 1);
    let total = 0;
    for (;;) {
      const { bytesRead } = await file.read(buffer, total, buffer.length - total, total);
      total += bytesRead;
      if (total > limit) throw Error('GOVERNANCE_FILE_LIMIT');
      if (bytesRead === 0) return buffer.subarray(0, total);
    }
  } finally {
    await file.close();
  }
}
const json = async (path) =>
  parseJSON((await bytes(path)).toString('utf8'), { maxBytes: 4 * 1024 * 1024 });
const [command, ...args] = process.argv.slice(2);
let result;
if (command === 'validate' && args.length === 1) result = validateRegistry(await json(args[0]));
else if (['contribution', 'finalize'].includes(command) && args.length === 3) {
  result = checkContribution(openRegister(await bytes(args[1]), args[2]), await json(args[0]), {
    final: command === 'finalize',
  });
} else if (command === 'mark' && args.length === 5) {
  result = await checkMark(
    openRegister(await bytes(args[3]), args[4]),
    args[0],
    await json(args[1]),
    args[2],
  );
} else if (command === 'snapshot' && args.length === 3) {
  const selection = await json(args[0]),
    base = await realpath(args[1]);
  if (
    selection.name !== 'CertConcord' ||
    typeof selection.edition !== 'string' ||
    !/^[a-f0-9]{40}$/.test(selection.sourceCommit) ||
    !Array.isArray(selection.requiredPortions) ||
    selection.requiredPortions.length < 1 ||
    selection.requiredPortions.length > 1000
  )
    throw Error('SPECIFICATION_SELECTION');
  for (const field of ['roles', 'profiles', 'adapters'])
    if (
      !Array.isArray(selection[field]) ||
      selection[field].some((s) => typeof s !== 'string') ||
      new Set(selection[field]).size !== selection[field].length
    )
      throw Error('SPECIFICATION_SCOPE');
  const framework = selection.framework,
    composition = selection.composition;
  if (
    !framework ||
    !composition ||
    [
      framework.edition,
      framework.document,
      composition.id,
      composition.specification,
      composition.conformance,
    ].some((s) => typeof s !== 'string' || !s.length || s.length > 512)
  )
    throw Error('SPECIFICATION_COMPOSITION');
  const required = [framework.document, composition.specification, composition.conformance];
  if (composition.id === 'certconcord-governed-draft-02') {
    if (
      framework.edition !== 'draft-02' ||
      framework.document !== 'spec/architecture.md' ||
      composition.specification !== 'spec/bindings/DTI-draft-02.md' ||
      composition.conformance !== 'spec/conformance.md'
    )
      throw Error('SPECIFICATION_COMPOSITION');
    required.push('spec/bindings/COMMON-draft-02.md');
  }
  if (
    !selection.roles.length ||
    required.some((path) => !selection.requiredPortions.some((p) => p.path === path))
  )
    throw Error('SPECIFICATION_REQUIRED_PORTIONS');
  const names = new Set(),
    files = [];
  for (const portion of selection.requiredPortions) {
    if (
      typeof portion.path !== 'string' ||
      isAbsolute(portion.path) ||
      portion.path.split(/[\\/]/).includes('..') ||
      names.has(portion.path) ||
      !Array.isArray(portion.sections) ||
      portion.sections.length < 1 ||
      portion.sections.some((s) => typeof s !== 'string' || !s.length)
    )
      throw Error('SPECIFICATION_PORTION');
    const path = resolve(base, portion.path),
      actual = await realpath(path),
      rel = relative(base, actual);
    if (
      isAbsolute(rel) ||
      rel === '..' ||
      rel.startsWith('..' + (process.platform === 'win32' ? '\\' : '/'))
    )
      throw Error('SPECIFICATION_PATH');
    const content = await bytes(path);
    names.add(portion.path);
    files.push({
      path: portion.path,
      sections: portion.sections,
      bytes: content.length,
      sha256: byteDigest(content),
    });
  }
  result = {
    ...selection,
    requiredPortions: files.sort((a, b) => a.path.localeCompare(b.path, 'en')),
  };
  await writeFile(args[2], JSON.stringify(result, null, 2) + '\n', { flag: 'wx' });
  result = {
    snapshotDigest: digest(result),
    file: args[2],
    authority: 'REQUIRES_SCOPE_REVIEW_AND_EXECUTED_AGREEMENT',
  };
} else
  throw Error(
    'Usage: validate REGISTRY | contribution|finalize SUBMISSION REGISTRY TRUSTED_SHA256 | mark GRANT REPORT ARTIFACTS REGISTRY TRUSTED_SHA256 | snapshot SELECTION SOURCE_ROOT OUTPUT',
  );
console.log(JSON.stringify(result, null, 2));

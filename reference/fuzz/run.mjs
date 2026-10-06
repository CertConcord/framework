import { spawn } from 'node:child_process';
import { mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const target = process.argv[2] ?? 'parsers',
  seconds = Number(process.argv[3] ?? 30);
if (
  !['parsers', 'containers', 'documents'].includes(target) ||
  !Number.isInteger(seconds) ||
  seconds < 1 ||
  seconds > 3600
)
  throw Error('FUZZ_PARAMETERS');
const corpus = resolve('.runtime/fuzz-corpus/' + target),
  artifacts = resolve('.runtime/fuzz-artifacts') + '/';
await mkdir(corpus, { recursive: true });
await mkdir(artifacts, { recursive: true });
const args = [
  require.resolve('@jazzer.js/core/dist/cli.js'),
  resolve('fuzz/' + target + '.mjs'),
  corpus,
  ...(target === 'parsers' ? ['--sync'] : []),
  '--',
  '-max_total_time=' + seconds,
  '-max_len=65536',
  '-timeout=5',
  '-rss_limit_mb=2048',
  '-artifact_prefix=' + artifacts,
];
const child = spawn(process.execPath, args, {
  stdio: 'inherit',
  windowsHide: true,
  cwd: artifacts,
});
child.on('error', (e) => {
  throw e;
});
child.on('exit', (code) => {
  process.exitCode = code ?? 1;
});

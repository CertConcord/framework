import { readdir, readFile } from 'node:fs/promises';
import { fuzz } from './parsers.mjs';
const dir = process.argv[2] ?? '.runtime/fuzz-corpus/parsers';
let count = 0;
for (const name of await readdir(dir)) {
  fuzz(await readFile(dir + '/' + name));
  count++;
}
console.log('Parser corpus replay: ' + count);

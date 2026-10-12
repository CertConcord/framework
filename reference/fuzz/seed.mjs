import { mkdir, writeFile } from 'node:fs/promises';
import { dcbor, seq, integer, octet } from '../core.mjs';
import { encode, Tag } from '../cose.mjs';
import { encodeProof } from '../mtc.mjs';
const dir = process.argv[2] ?? '.runtime/fuzz-corpus/parsers';
await mkdir(dir, { recursive: true });
const unsignedCheckpoint = 'synthetic/log\n1\n' + Buffer.alloc(32).toString('base64') + '\n\n';
const seeds = [
  [0, dcbor({ a: 1, bytes: Buffer.from('synthetic'), nested: [true, null, -1, 2n ** 63n] })],
  [0, Buffer.from('a2616101616102', 'hex')],
  [0, Buffer.from('9f0102ff', 'hex')],
  [0, Buffer.from('a2616901695f5f70726f746f5f5f717171717171710300007171717171717100', 'hex')],
  [1, seq(integer(1), octet(Buffer.from('synthetic')))],
  [2, encode(new Tag(24, Buffer.from('a10126', 'hex')))],
  [3, encodeProof({ start: 0, end: 1, inclusion: [], signatures: [] })],
  [4, Buffer.from('null')],
  [
    4,
    Buffer.from(
      JSON.stringify({
        type: 'webauthn.get',
        origin: 'https://verifier.example',
        challenge: Buffer.alloc(32).toString('base64url'),
      }),
    ),
  ],
  // Retain the old unsigned envelope: the current component must reject it.
  [5, Buffer.from(unsignedCheckpoint)],
  [6, Buffer.from('{"a":1,"a":2}')],
  [6, Buffer.from('{"nested":[true,null,{"a":"b"}]}')],
  // Shape-only parser fixture: a key hint plus a 64-byte signature. This is not
  // an authenticated checkpoint and is never used by a log verifier.
  [
    5,
    Buffer.from(
      unsignedCheckpoint + '— synthetic/log ' + Buffer.alloc(68).toString('base64') + '\n',
    ),
  ],
  [2, Buffer.from('9f0102ff', 'hex')],
  [2, Buffer.from('a2616101616102', 'hex')],
];
for (const [i, [type, bytes]] of seeds.entries())
  await writeFile(dir + '/' + i, Buffer.concat([Buffer.from([type]), bytes]));
console.log('Synthetic parser seeds: ' + seeds.length);
await mkdir('.runtime/fuzz-corpus/documents', { recursive: true });
await writeFile(
  '.runtime/fuzz-corpus/documents/pdf-timeout-regression',
  Buffer.from('wiIiLg==', 'base64'),
);
await mkdir('.runtime/fuzz-corpus/containers', { recursive: true });
await writeFile(
  '.runtime/fuzz-corpus/containers/cms-version-regression',
  Buffer.from('CwAZAgsAAAAgedY=', 'base64'),
);

import assert from 'node:assert/strict';
import { readFileSync, writeSync } from 'node:fs';
import { dcbor, decodeCBOR, sha512 } from './core.mjs';
import { Journal } from './state.mjs';
import { ArchivePublicationStore } from './retained-authorities.mjs';

const [path, snapshot, mode] = process.argv.slice(2);
if (mode === 'exit-before-publication') {
  process.exitCode = 23;
} else {
  assert.equal(mode, 'publish');
  const publication = decodeCBOR(readFileSync(snapshot));
  const journal = new Journal(path);
  const expected = decodeCBOR(dcbor({ digest: sha512(dcbor(publication)), publication }));
  const store = new ArchivePublicationStore(journal, {
    validatePublication: () => ({ overall: 'VALID' }),
    crash: (point) => {
      if (point !== 'after-publication-before-commit') return;
      assert.equal(journal.depth, 1);
      assert.deepEqual(journal.get('archive-publication', publication.archiveID), {
        revision: 1,
        value: expected,
      });
      writeSync(
        1,
        JSON.stringify({
          event: 'publication-pending',
          point,
          pid: process.pid,
          archiveID: publication.archiveID,
          digest: expected.digest.toString('hex'),
          revision: 1,
          transactionDepth: journal.depth,
        }) + '\n',
      );
      // Stay inside the uncommitted transaction until the parent forcibly kills this process.
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0);
      assert.fail('The crash boundary must never return');
    },
  });
  store.publish(publication);
  assert.fail('Publication must not return from the crash child');
}

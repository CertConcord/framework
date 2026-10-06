import { PostgresJournal } from './postgres.mjs';
import { IndexedMerkleLog } from './merkle.mjs';
const config = JSON.parse(process.env.CERTCONCORD_TEST_DB);
const j = new PostgresJournal(config),
  mode = process.argv[2];
try {
  if (mode === 'nonce') {
    try {
      j.consumeNonce('test', process.argv[3]);
      process.stdout.write('CONSUMED');
    } catch (e) {
      if (e.code !== 'NONCE_EXPIRED_OR_REPLAY') throw e;
      process.stdout.write('REPLAY');
    }
  } else if (mode === 'append') {
    const log = new IndexedMerkleLog(j, 'race');
    for (let i = 0; i < 12; i++)
      log.append(Buffer.from(process.argv[3] + ':' + i), process.argv[3] + ':' + i);
    process.stdout.write('APPENDED');
  } else if (mode === 'crash') {
    j.transaction(() => {
      j.put('crash', 'uncommitted', { value: 1 });
      process.exit(0);
    });
  } else throw Error('WORKER_MODE');
} finally {
  j.close();
}

import { readFileSync, writeFileSync, appendFileSync, writeSync } from 'node:fs';
import * as c from './core.mjs';
import { OrganizationDelegationApplication } from './organization-delegation.mjs';
import { createOrganizationFixture } from './organization-delegation-fixtures.mjs';

const [mode, snapshotPath, journalPath, candidatePath, effectPath] = process.argv.slice(2);
const f = createOrganizationFixture({ snapshot: readFileSync(snapshotPath), path: journalPath });
function stopAt(seam) {
  writeSync(1, JSON.stringify({ seam }) + '\n');
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0);
}
if (mode === 'approval-transaction') {
  const put = f.journal.put;
  f.journal.put = function (namespace, id, value, revision) {
    const result = put.call(this, namespace, id, value, revision);
    if (namespace === 'organization-delegation-counter') stopAt('counter-written-before-commit');
    return result;
  };
} else if (mode === 'after-signature') {
  f.hooks.beforeSign = () => appendFileSync(effectPath, 'document-sign\n');
  f.hooks.afterSign = ({ signature }) => {
    writeFileSync(candidatePath, signature);
    stopAt('document-signed-before-completion');
  };
} else throw new Error('Unknown crash fixture mode');

const app = new OrganizationDelegationApplication(f.applicationOptions);
if (mode === 'approval-transaction') {
  const retained = app.getOperationResult({ operationID: f.operationID });
  const result = app.approve({
    operationID: f.operationID,
    personID: f.persons[0].body.personID,
    ...f.assertion(retained.record.request, 0, { counter: 7 }),
  });
  throw new Error('Crash seam not reached: ' + c.dcbor(result).toString('hex'));
} else {
  const result = await app.execute({ operationID: f.operationID });
  throw new Error('Crash seam not reached: ' + JSON.stringify(result));
}

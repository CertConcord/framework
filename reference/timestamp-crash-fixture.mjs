import { readFileSync, writeFileSync } from 'node:fs';
import { createPrivateKey } from 'node:crypto';
import { decodeCBOR, dcbor, sign } from './core.mjs';
import { createAuthorityResolver } from './authority-history.mjs';
import { Journal } from './state.mjs';
import { TimestampService, TimestampClient } from './timestamp-service.mjs';

const [configurationPath, mode] = process.argv.slice(2);
const config = decodeCBOR(readFileSync(configurationPath));
const journal = new Journal(config.journalPath);
config.context.policy.authorityResolver = createAuthorityResolver({
  trustDomainID: config.context.policy.scope.trustDomainID,
  authorities: config.authorities,
});
const persistThenStop = (value) => {
  writeFileSync(config.externalResultPath, dcbor(value), { flush: true });
  process.kill(process.pid, 'SIGKILL');
};
if (mode === 'sign') {
  const privateKey = createPrivateKey({ key: config.privateKeyDER, format: 'der', type: 'pkcs8' });
  const service = new TimestampService({
    journal,
    serviceID: 'crash-service',
    certificate: config.certificate,
    certificates: config.certificates,
    policyOID: config.policyOID,
    signer: {
      publicKeyDER: config.publicKeyDER,
      sign: async (tbs, metadata) => {
        persistThenStop({
          signature: sign(tbs, privateKey),
          tbs,
          serial: metadata.serial.toString(),
        });
        throw Error('process termination did not stop signing');
      },
    },
    clock: { read: async () => config.reading },
    readContext: async () => config.context,
  });
  await service.issue({ operationID: config.operationID, requestDER: config.requestDER });
} else if (mode === 'send') {
  const client = new TimestampClient({
    journal,
    clientID: 'crash-client',
    readContext: async () => config.context,
    send: async (requestDER) => {
      persistThenStop({ requestDER, responseDER: config.responseDER });
      throw Error('process termination did not stop dispatch');
    },
  });
  await client.request({ operationID: config.operationID, requestDER: config.requestDER });
} else throw Error('unknown crash fixture mode');

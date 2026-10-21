import { createPrivateKey, createPublicKey } from 'node:crypto';
import { appendFileSync } from 'node:fs';
import { createServer } from 'node:http';
import * as c from './core.mjs';
import { Journal } from './state.mjs';
import { RemoteCryptoKeyService, SoftwareProvider } from './providers.mjs';
import { exampleAuthorityResolver } from './example-authorities.mjs';
import { parseJSON } from './json.mjs';
import { readBody, sendJSON } from './transport.mjs';

async function pauseAt(stage, value) {
  await new Promise((resolve, reject) =>
    process.send({ event: 'paused', stage, value }, (error) => (error ? reject(error) : resolve())),
  );
  await new Promise(() => {});
}

// Synthetic private material arrives over IPC and is never written to a fixture file.
process.once('message', async (configuration) => {
  const { journalPath, effectsPath, certificate, trustDomainID, token, at, mode } = configuration,
    privateKey = createPrivateKey({ key: configuration.privateKey, format: 'der', type: 'pkcs8' }),
    publicKey = createPublicKey(privateKey),
    provider = new SoftwareProvider(new Map([['document-key', { privateKey, publicKey }]])),
    journal = new Journal(journalPath),
    sign = provider.sign.bind(provider);
  provider.sign = async (input) => {
    appendFileSync(effectsPath, input.operationID + '\n');
    const signature = await sign(input);
    if (mode === 'after-sign') await pauseAt('after-sign', c.b64u(signature));
    return signature;
  };
  const service = new RemoteCryptoKeyService({
      provider,
      journal,
      permitCertificate: certificate,
      audience: 'test-gateway',
      authorityResolver: exampleAuthorityResolver({
        trustDomainID,
        at,
        authorities: [{ certificate, roles: ['PERMIT_AUTHORITY'] }],
      }),
      authorize: async ({ permit, keyRef }) =>
        permit.proofMode === 'HUMAN_WEBAUTHN' && keyRef === 'document-key',
      // Hold the synthetic admission time fixed so restart latency cannot expire the permit.
      clock: () => at,
    }),
    server = createServer(async (req, res) => {
      try {
        c.requireThat(req.headers.authorization === 'Bearer ' + token, 'AUTH');
        const data = parseJSON((await readBody(req)).toString('utf8')),
          path = req.url.split('/').at(-1),
          result = await service.handle(path, data);
        if (path === 'sign' && mode === 'after-commit') await pauseAt('after-commit', result);
        sendJSON(res, 200, result);
      } catch (error) {
        sendJSON(res, 400, { error: error.code ?? 'INVALID_REQUEST' });
      }
    });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  process.send({
    event: 'ready',
    pid: process.pid,
    url: 'http://127.0.0.1:' + server.address().port,
  });
});

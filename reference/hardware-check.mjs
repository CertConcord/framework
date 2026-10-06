import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { random, verify, requireThat } from './core.mjs';
import { PKCS11Provider } from './pkcs11.mjs';

// This command initializes only a new isolated SoftHSM fixture, never a configured production token.
const root = resolve('.runtime');
mkdirSync(root, { recursive: true });
const directory = mkdtempSync(join(root, 'softhsm-')),
  tokens = join(directory, 'tokens');
mkdirSync(tokens);
const config = join(directory, 'softhsm2.conf');
writeFileSync(
  config,
  'directories.tokendir = ' +
    tokens +
    '\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n',
);
process.env.SOFTHSM2_CONF = config;
const pin = random(12).toString('hex'),
  soPin = random(12).toString('hex'),
  output = execFileSync(
    'softhsm2-util',
    ['--init-token', '--free', '--label', 'RRA isolated fixture', '--so-pin', soPin, '--pin', pin],
    { encoding: 'utf8' },
  ),
  match = /reassigned to slot (\d+)/.exec(output);
requireThat(match, 'SOFTHSM_SLOT');
const library = process.env.PKCS11_LIBRARY ?? '/usr/lib/softhsm/libsofthsm2.so',
  provider = new PKCS11Provider({ library, slot: Number(match[1]), pin });
try {
  const publicKey = provider.generate({
      keyRef: 'certconcord-fixture-ec',
      id: random(20),
      algorithm: 'ec',
    }),
    tbs = Buffer.from('RRA PKCS11 real token mechanism test'),
    signature = await provider.sign({ keyRef: 'certconcord-fixture-ec', tbs });
  requireThat(verify(tbs, signature, publicKey), 'PKCS11_TEST_SIGNATURE');
  const capability = await provider.capabilities('certconcord-fixture-ec');
  requireThat(capability.exportable === false, 'PKCS11_TEST_EXPORT');
  console.log(
    'PKCS11 ES256: key generation, SPKI pin, non-exportable attribute, actual C_Sign and independent verification passed.',
  );
} finally {
  provider.close();
}

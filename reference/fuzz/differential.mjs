import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { generate, sha256 } from '../core.mjs';
import { issueCertificate, name, signCMS, verifyCMS, parseCertificate } from '../pki.mjs';

const executable = process.env.OPENSSL_BIN ?? 'openssl';
const version = spawnSync(executable, ['version'], { encoding: 'utf8' });
assert.equal(version.status, 0, 'Independent OpenSSL is required');
const dir = resolve('.runtime/differential');
await mkdir(dir, { recursive: true });
const key = generate(),
  certificate = issueCertificate(
    {
      publicKey: key.publicKey,
      subject: name('Synthetic differential subject'),
      issuer: name('Synthetic differential issuer'),
      serial: 1,
    },
    key.privateKey,
  ),
  message = Buffer.from('Synthetic differential CMS content.'),
  cms = signCMS({ content: message, certificate }, key.privateKey);
const rows = [];
for (let i = 0; i <= 160; i++) {
  const bytes = Buffer.from(cms);
  if (i) {
    const selector = sha256(Buffer.from('certconcord-differential-v1:' + i));
    bytes[selector.readUInt32BE(0) % bytes.length] ^= selector[4] || 1;
  }
  let accepted = false;
  try {
    verifyCMS(bytes);
    accepted = true;
  } catch {}
  await writeFile(dir + '/input.der', bytes);
  const independent = spawnSync(
    executable,
    [
      'cms',
      '-verify',
      '-noverify',
      '-binary',
      '-inform',
      'DER',
      '-in',
      dir + '/input.der',
      '-out',
      dir + '/content.bin',
    ],
    { timeout: 5000, windowsHide: true, encoding: 'utf8' },
  );
  assert(!independent.error, 'OpenSSL timeout or launch failure');
  // RRA's CMS subset can be stricter, but must not accept a signature OpenSSL rejects.
  if (accepted)
    assert.equal(independent.status, 0, 'RRA accepted CMS rejected by OpenSSL, mutation ' + i);
  if (!i) assert(accepted && independent.status === 0, 'Valid baseline must be accepted by both');
  rows.push({
    mutation: i,
    sha256: sha256(bytes).toString('hex'),
    certconcordAccepted: accepted,
    opensslAccepted: independent.status === 0,
  });
}
await writeFile(
  dir + '/results.json',
  JSON.stringify(
    { synthetic: true, seed: 'certconcord-differential-v1', openssl: version.stdout.trim(), cases: rows },
    null,
    2,
  ) + '\n',
);
console.log(
  JSON.stringify({
    cases: rows.length,
    certconcordAccepted: rows.filter((x) => x.certconcordAccepted).length,
    independentRejections: rows.filter((x) => !x.opensslAccepted).length,
  }),
);

import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createPublicKey } from 'node:crypto';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import {
  readPublicCommand,
  readPublicResponse,
  certifyCommand,
  certifyResponse,
} from './tpm-wire.mjs';
import { verifyTPMCertify } from './key-attestation.mjs';

// An isolated software TPM validates command and attestation interoperability.
// The process never connects to a host TPM or imports this fixture into an issuer.
c.requireThat(process.platform === 'linux', 'LINUX_SIMULATOR_REQUIRED');
const directory = mkdtempSync('/tmp/certconcord-tpm-'),
  socket = join(directory, 'tpm'),
  state = join(directory, 'state');
mkdirSync(state);
const simulator = spawn(
  'swtpm',
  [
    'socket',
    '--tpm2',
    '--tpmstate',
    'dir=' + state,
    '--ctrl',
    'type=unixio,path=' + socket + '.ctrl',
    '--server',
    'type=unixio,path=' + socket,
    '--flags',
    'not-need-init,startup-clear',
  ],
  { stdio: ['ignore', 'pipe', 'pipe'] },
);
let diagnostics = '',
  spawnError;
simulator.stderr.on('data', (chunk) => {
  diagnostics += chunk.toString();
});
simulator.on('error', (error) => {
  spawnError = error;
});
const env = { ...process.env, TPM2TOOLS_TCTI: 'swtpm:path=' + socket };
const run = (name, args, input) =>
  execFileSync(name, args, { cwd: directory, env, input, maxBuffer: 1024 * 1024, timeout: 10000 });
try {
  for (let attempt = 0; !existsSync(socket) && !spawnError && attempt < 100; attempt++)
    await new Promise((resolve) => setTimeout(resolve, 50));
  if (spawnError) throw spawnError;
  c.requireThat(existsSync(socket), 'SIMULATOR_START: ' + diagnostics);
  run('tpm2_createprimary', ['-Q', '-C', 'o', '-G', 'ecc', '-g', 'sha256', '-c', 'primary.ctx']);
  run('tpm2_evictcontrol', ['-Q', '-C', 'o', '-c', 'primary.ctx', '0x81000001']);
  run('tpm2_flushcontext', ['-t']);
  const base = 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign';
  for (const [name, handle, attributes] of [
    ['ak', '0x81000002', base + '|restricted'],
    ['holder', '0x81000003', base],
  ]) {
    run('tpm2_create', [
      '-Q',
      '-C',
      '0x81000001',
      '-G',
      'ecc:ecdsa-sha256:null',
      '-g',
      'sha256',
      '-a',
      attributes,
      '-u',
      name + '.pub',
      '-r',
      name + '.priv',
    ]);
    run('tpm2_load', [
      '-Q',
      '-C',
      '0x81000001',
      '-u',
      name + '.pub',
      '-r',
      name + '.priv',
      '-c',
      name + '.ctx',
    ]);
    run('tpm2_evictcontrol', ['-Q', '-C', 'o', '-c', name + '.ctx', handle]);
    run('tpm2_flushcontext', ['-t']);
    run('tpm2_readpublic', [
      '-Q',
      '-c',
      handle,
      '-f',
      'pem',
      '-o',
      name + '.pem',
      '-q',
      name + '.name',
    ]);
  }
  const raw = (command) => run('tpm2_send', [], command),
    holderPublicKey = createPublicKey(readFileSync(join(directory, 'holder.pem'))),
    akPublicKey = createPublicKey(readFileSync(join(directory, 'ak.pem'))),
    challenge = c.b64u(c.random()),
    pub = readPublicResponse(raw(readPublicCommand(0x81000003))),
    result = certifyResponse(
      raw(
        certifyCommand({
          objectHandle: 0x81000003,
          akHandle: 0x81000002,
          qualifyingData: c.sha256(Buffer.from(challenge, 'utf8')),
        }),
      ),
    ),
    evidence = {
      format: 'tpm2-certify',
      akID: 'isolated-simulator-AK',
      pubArea: pub.pubArea,
      ...result,
    },
    policy = {
      authorizedAKs: new Map([
        [
          'isolated-simulator-AK',
          {
            publicKey: akPublicKey,
            qualifiedName: readFileSync(join(directory, 'ak.name')),
            status: 'ACTIVE',
            notBefore: c.now() - 60,
            expiresAt: c.now() + 3600,
            enrollmentMethod: 'AUDITED_HARDWARE_CEREMONY',
            restrictedSigning: true,
            fixedTPM: true,
            fixedParent: true,
            sensitiveDataOrigin: true,
            enrollmentEvidenceHash: c.H('SyntheticSimulatorAKEnrollment', {
              publicKey: c.spki(akPublicKey),
            }),
          },
        ],
      ]),
      akStatus: () => ({
        status: 'GOOD',
        checkedAt: c.now(),
        nextUpdate: c.now() + 3600,
        evidenceHash: c.H('SyntheticSimulatorStatus', {}),
      }),
    };
  assert.equal(verifyTPMCertify(evidence, { holderPublicKey, challenge, policy }).boundary, 'TPM2');
  assert.throws(
    () => verifyTPMCertify(evidence, { holderPublicKey, challenge: c.b64u(c.random()), policy }),
    /CHALLENGE/,
  );
  assert.throws(
    () =>
      verifyTPMCertify(evidence, {
        holderPublicKey: c.generate('ec').publicKey,
        challenge,
        policy,
      }),
    /SUBJECT_KEY/,
  );
  writeFileSync(
    join(directory, 'certify-response.bin'),
    Buffer.concat([result.certInfo, result.signature]),
  );
  console.log(
    'TPM 2.0 simulator: real ReadPublic/Certify, restricted AK signature, exact key/Name/challenge and substitution rejection passed.',
  );
} finally {
  simulator.kill('SIGTERM');
  if (simulator.exitCode === null && !spawnError)
    await new Promise((resolve) => simulator.once('exit', resolve));
}

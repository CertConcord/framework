import test from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import {
  readPublicCommand,
  readPublicResponse,
  certifyCommand,
  certifyResponse,
  u16,
  u32,
  tpm2b,
} from './tpm-wire.mjs';
import { tpmFixture } from './attestation-fixtures.mjs';
import { verifyTPMCertify } from './key-attestation.mjs';
test('TPM commands use separate object and AK authorization handles with two PW sessions', () => {
  assert.equal(readPublicCommand(0x81000001).toString('hex'), '80010000000e0000017381000001');
  const b = certifyCommand({
    objectHandle: 0x81000001,
    akHandle: 0x81000002,
    qualifyingData: Buffer.alloc(32, 0x55),
  });
  assert.equal(b.length, 78);
  assert.equal(b.readUInt32BE(2), b.length);
  assert.equal(b.subarray(0, 22).toString('hex'), '80020000004e00000148810000018100000200000012');
  assert.equal(b.subarray(22, 40).toString('hex'), '400000090000000000400000090000000000');
  assert.equal(b.subarray(40).toString('hex'), '0020' + '55'.repeat(32) + '0018000b');
});
test('TPM response framing reaches independent attestation checks and rejects malformed framing', () => {
  const key = c.generate('ec'),
    challenge = c.b64u(c.random()),
    fixture = tpmFixture(key.publicKey, challenge);
  const packet = (tag, parameters, auth = Buffer.alloc(0)) =>
    Buffer.concat([u16(tag), u32(10 + parameters.length + auth.length), u32(0), parameters, auth]);
  const pub = packet(
    0x8001,
    Buffer.concat([
      tpm2b(fixture.evidence.pubArea),
      tpm2b(Buffer.concat([u16(11), c.sha256(fixture.evidence.pubArea)])),
      tpm2b(Buffer.alloc(34)),
    ]),
  );
  const parameters = Buffer.concat([tpm2b(fixture.evidence.certInfo), fixture.evidence.signature]);
  const cert = packet(
    0x8002,
    Buffer.concat([u32(parameters.length), parameters]),
    Buffer.alloc(10),
  );
  const decoded = { ...fixture.evidence, ...readPublicResponse(pub), ...certifyResponse(cert) };
  assert.equal(
    verifyTPMCertify(decoded, {
      holderPublicKey: key.publicKey,
      challenge,
      policy: fixture.policy.formats['tpm2-certify'],
    }).boundary,
    'TPM2',
  );
  for (const position of [0, 5, 9, cert.length - 1]) {
    const bad = Buffer.from(cert);
    bad[position] ^= 2;
    assert.throws(() => certifyResponse(bad), /TPM/);
  }
  assert.throws(() => readPublicResponse(Buffer.concat([pub, Buffer.from([0])])), /SIZE/);
});

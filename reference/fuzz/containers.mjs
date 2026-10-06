import assert from 'node:assert/strict';
import { compactVerify } from 'jose';
import { generate, sign, verify, dcbor, decodeCBOR } from '../core.mjs';
import { name, issueCertificate, signCMS, verifyCMS } from '../pki.mjs';
import { sign1, verify1 } from '../cose.mjs';
import { signJWS, verifyJWS } from '../jose.mjs';
import { encryptCMS, decryptCMS } from '../protection.mjs';
import { executionFixture } from './execution-fixture.mjs';
import { verifyExecutionEvidence } from '../execution-binding.mjs';
const execution = await executionFixture();
verifyExecutionEvidence(execution.input, execution.trust);
const document = Buffer.from('Synthetic document for mutation testing.'),
  key = generate('ec'),
  pq = generate(),
  certificate = issueCertificate(
    {
      publicKey: pq.publicKey,
      subject: name('Synthetic signer'),
      issuer: name('Synthetic signer'),
      serial: 1,
    },
    pq.privateKey,
  ),
  cms = signCMS({ content: document, certificate }, pq.privateKey),
  cose = sign1(document, key.privateKey),
  jwt = signJWS(
    { iss: 'https://issuer.example', aud: 'https://verifier.example', synthetic: true },
    key.privateKey,
  ),
  kem = generate('ml-kem-768'),
  ski = Buffer.alloc(32, 7),
  encrypted = encryptCMS(document, [{ publicKey: kem.publicKey, subjectKeyIdentifier: ski }]);
function changed(bytes, data) {
  const result = Buffer.from(bytes);
  const at = data.readUInt16BE(1) % result.length;
  result[at] ^= data[3] || 1;
  return result;
}
// Each mutation changes an authenticated field while preserving its surrounding object shape.
// Rejection is expected; acceptance must satisfy independently checked original bindings.
export async function fuzz(data) {
  if (data.length < 4) return;
  switch (data[0] % 6) {
    case 0: {
      const bad = changed(document, data);
      let accepted;
      try {
        accepted = verifyCMS(cms, { content: bad, expectedCertificate: certificate });
      } catch {
        return;
      }
      assert.fail('CMS accepted substituted detached/embedded content');
      break;
    }
    case 1: {
      const bad = [...cose];
      bad[3] = changed(cose[3], data);
      try {
        verify1(bad, key.publicKey);
      } catch {
        return;
      }
      assert.fail('COSE accepted mutated signature');
      break;
    }
    case 2: {
      const parts = jwt.split('.');
      parts[2] = changed(Buffer.from(parts[2], 'base64url'), data).toString('base64url');
      const bad = parts.join('.');
      let ours = false,
        external = false;
      try {
        verifyJWS(bad, key.publicKey);
        ours = true;
      } catch {}
      try {
        await compactVerify(bad, key.publicKey, { algorithms: ['ES256'] });
        external = true;
      } catch {}
      assert.equal(ours, external, 'JOSE disagreement');
      assert.equal(ours, false, 'JOSE accepted mutation');
      break;
    }
    case 3: {
      // Mutate the AEAD tail, beyond KEM and recipient metadata.
      const bad = Buffer.from(encrypted);
      bad[bad.length - 1 - (data[1] % 16)] ^= data[3] || 1;
      try {
        decryptCMS(bad, { privateKey: kem.privateKey, subjectKeyIdentifier: ski });
      } catch {
        return;
      }
      assert.fail('KEM/CMS accepted unauthenticated plaintext');
      break;
    }
    case 4: {
      const sig = sign(document, key.privateKey);
      assert.equal(
        verify(changed(document, data), sig, key.publicKey),
        false,
        'ECDSA accepted altered document',
      );
      break;
    }
    case 5: {
      const input = { ...execution.input };
      const field = ['permit', 'receipt', 'binding', 'tbs', 'sim'][(data[4] ?? 0) % 5];
      if (field === 'binding') input.evidence = { binding: changed(input.evidence.binding, data) };
      else if (field === 'sim') {
        input.sim = decodeCBOR(dcbor(input.sim));
        input.sim.transactionID = changed(input.sim.transactionID, data);
      } else input[field] = changed(input[field], data);
      assert.throws(() => verifyExecutionEvidence(input, execution.trust));
      break;
    }
  }
}

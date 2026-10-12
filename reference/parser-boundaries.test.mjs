import test from 'node:test';
import assert from 'node:assert/strict';
import { clientData } from './webauthn.mjs';
import { ProtocolError } from './core.mjs';
import { fuzz } from './fuzz/parsers.mjs';

test('WebAuthn client data rejects JSON values that are not objects with a protocol error', () => {
  const context = { type: 'webauthn.get', origin: 'https://verifier.example', challenge: Buffer.alloc(32) };
  for (const value of ['null', '[]', 'false', '12', '"text"'])
    assert.throws(() => clientData(Buffer.from(value), context), (error) => error instanceof ProtocolError);
  assert.doesNotThrow(() => fuzz(Buffer.from('C251bGw=', 'base64')));
});

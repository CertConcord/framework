import { generate, random, b64u, sha256, sign } from './core.mjs';

// Generates a software WebAuthn fixture for command-line protocol examples.
export function exampleAssertion({ challenge, origin, rpID, keyID, subjectID }) {
  const passkey = generate('ec'),
    credentialID = random(),
    counter = Buffer.alloc(4);
  counter.writeUInt32BE(1);
  const client = Buffer.from(
    JSON.stringify({
      type: 'webauthn.get',
      challenge: b64u(challenge),
      origin,
      crossOrigin: false,
    }),
  );
  const auth = Buffer.concat([sha256(Buffer.from(rpID)), Buffer.from([5]), counter]);
  return {
    registration: {
      credentialID,
      publicKey: passkey.publicKey,
      counter: 0,
      backupEligible: false,
      active: true,
      keyID,
      subjectID,
      origin,
      rpID,
    },
    assertion: {
      id: b64u(credentialID),
      rawId: b64u(credentialID),
      type: 'public-key',
      response: {
        clientDataJSON: b64u(client),
        authenticatorData: b64u(auth),
        signature: b64u(sign(Buffer.concat([auth, sha256(client)]), passkey.privateKey)),
      },
    },
  };
}

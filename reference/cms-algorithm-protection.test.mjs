import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { verify } from 'node:crypto';
import * as c from './core.mjs';
import * as api from './cades.mjs';
import * as pades from './pades.mjs';
import { inspectAdESSignature } from './ades-cms.mjs';
import { TimestampResponseVerifier } from './timestamp-service.mjs';
import { encodeTimestampResponse } from './timestamp-protocol.mjs';
import { applicationFixture } from './timestamp-application-fixtures.mjs';
import { O, fixture, attr, cmsView, resign, rewriteCMS, decision } from './cades-fixtures.mjs';
import {
  padesFixture,
  independentTimestamp,
  replaceCMS,
  independentApproval,
  pdfSignatures,
  decision as pdfDecision,
} from './pades-fixtures.mjs';

const registered = '1.2.840.113549.1.9.16.2.52';
const legacy = '1.2.840.113549.1.9.52';
let f, pdfFixture, timestampFixture, original;
before(() => {
  f = fixture();
  pdfFixture = padesFixture();
  timestampFixture = applicationFixture();
  original = {
    CADES: f.baseCMS(api),
    SMIME: f.baseCMS(api, { detached: false }),
    RFC3161: f.token({
      hashOID: O.sha256,
      imprint: Buffer.alloc(32, 0x61),
      nonce: 41n,
      policy: O.policy,
    }),
  };
});
after(() => {
  f?.close();
  pdfFixture?.close();
  timestampFixture?.close();
});

function protection(kind) {
  const digest = c.seq(
    c.oid(kind === 'wrong digest' ? O.sha512 : O.sha256),
    ...(kind === 'digest NULL' ? [c.der(5, Buffer.alloc(0))] : []),
    ...(kind === 'digest parameters' ? [c.integer(1)] : []),
  );
  const signature = c.der(
    kind === 'MAC choice' ? 0xa2 : 0xa1,
    Buffer.concat([
      c.oid(kind === 'wrong signature' ? '1.2.840.10045.4.3.3' : O.es256),
      ...(kind === 'signature parameters' ? [c.der(5, Buffer.alloc(0))] : []),
    ]),
  );
  if (kind === 'wrong value') return c.octet(Buffer.alloc(0));
  return c.seq(
    digest,
    ...(kind === 'missing signature' ? [] : [signature]),
    ...(kind === 'both choices' ? [c.der(0xa2, c.oid(O.es256))] : []),
  );
}
function key(profile) {
  return profile === 'RFC3161' ? f.tsa : f.signer;
}
function signed(profile, additional) {
  const attrs = cmsView(original[profile]).signed.map((n) => n.raw);
  return resign(original[profile], [...attrs, ...additional], key(profile).privateKey);
}
function inspect(profile, cms, overall, reason) {
  const view = cmsView(cms);
  assert.equal(
    verify(
      'sha256',
      c.set(...view.signed.map((n) => n.raw)),
      key(profile).publicKey,
      view.signature,
    ),
    true,
  );
  const before = Buffer.from(cms);
  const result = inspectAdESSignature(cms, {
    profile,
    ...(profile === 'CADES' ? { content: f.content } : {}),
  });
  assert.equal(result.overall, overall);
  assert.equal(result.reason, reason);
  assert.deepEqual(cms, before);
  assert(Object.isFrozen(result));
  if (profile === 'CADES') {
    const full = decision(api, f, cms);
    assert.equal(full.overall, overall);
    assert.equal(full.reason, reason);
  }
  return result;
}
const cases = [
  ['matching', 'VALID', 'CADES_VALID'],
  ['digest NULL', 'VALID', 'CADES_VALID'],
  ['wrong digest', 'INVALID', 'CADES_ALGORITHM_PROTECTION_BINDING'],
  ['wrong signature', 'INVALID', 'CADES_ALGORITHM_PROTECTION_BINDING'],
  ['signature parameters', 'INVALID', 'CADES_ALGORITHM_PROTECTION_BINDING'],
  ['digest parameters', 'INVALID', 'CADES_HASH_PARAMETERS'],
  ['MAC choice', 'INVALID', 'CADES_ALGORITHM_PROTECTION_ENCODING'],
  ['both choices', 'INVALID', 'CADES_ALGORITHM_PROTECTION_ENCODING'],
  ['missing signature', 'INVALID', 'CADES_ALGORITHM_PROTECTION_ENCODING'],
  ['wrong value', 'INVALID', 'CADES_ALGORITHM_PROTECTION_ENCODING'],
  ['unsigned', 'INVALID', 'CADES_ATTRIBUTE_LOCATION'],
  ['duplicate', 'INVALID', 'CADES_DUPLICATE_SIGNED_ATTRIBUTE'],
  ['multiple values', 'INVALID', 'CADES_SIGNED_ATTRIBUTE_VALUES'],
];
for (const profile of ['CADES', 'SMIME', 'RFC3161']) {
  for (const [label, id] of [
    ['registered', registered],
    ['legacy', legacy],
  ]) {
    for (const [kind, overall, reason] of cases)
      test(profile + ' ' + label + ' algorithm protection: ' + kind, () => {
        const value = protection(kind);
        const attribute = attr(
          id,
          value,
          ...(kind === 'multiple values' ? [protection('wrong digest')] : []),
        );
        const cms =
          kind === 'unsigned'
            ? rewriteCMS(original[profile], { unsigned: [attribute] })
            : signed(profile, [attribute, ...(kind === 'duplicate' ? [attribute] : [])]);
        inspect(profile, cms, overall, reason);
      });
  }
  for (const bad of ['neither', 'registered', 'legacy', 'both'])
    test(profile + ' checks both distinct algorithm-protection OIDs: ' + bad, () => {
      const attributes = [
        attr(
          registered,
          protection(['registered', 'both'].includes(bad) ? 'wrong digest' : 'matching'),
        ),
        attr(legacy, protection(['legacy', 'both'].includes(bad) ? 'wrong signature' : 'matching')),
      ];
      const result = inspect(
        profile,
        signed(profile, attributes),
        bad === 'neither' ? 'VALID' : 'INVALID',
        bad === 'neither' ? 'CADES_VALID' : 'CADES_ALGORITHM_PROTECTION_BINDING',
      );
      if (bad === 'neither') {
        assert.deepEqual(
          result.parsed.signed
            .filter((a) => [registered, legacy].includes(a.id))
            .map((a) => a.id)
            .sort(),
          [registered, legacy].sort(),
        );
      }
    });
  for (const [signedID, unsignedID] of [
    [registered, legacy],
    [legacy, registered],
  ])
    test(profile + ' signed ' + signedID + ' cannot hide unsigned ' + unsignedID, () => {
      const cms = rewriteCMS(signed(profile, [attr(signedID, protection('matching'))]), {
        unsigned: [attr(unsignedID, protection('matching'))],
      });
      inspect(profile, cms, 'INVALID', 'CADES_ATTRIBUTE_LOCATION');
    });
  test(profile + ' unrelated OID is not an algorithm-protection alias', () => {
    inspect(
      profile,
      signed(profile, [attr(registered + '0', protection('wrong digest'))]),
      'VALID',
      'CADES_VALID',
    );
  });
}
for (const [label, id] of [
  ['registered', registered],
  ['legacy', legacy],
]) {
  for (const location of ['signed', 'unsigned'])
    test(
      'PAdES approval rejects ' + label + ' algorithm protection in ' + location + ' attributes',
      async () => {
        const attribute = attr(id, protection('matching'));
        const pdf = independentApproval(pdfFixture, {
          cmsOptions:
            location === 'signed' ? { additionalSigned: [attribute] } : { unsigned: [attribute] },
        }).pdf;
        const view = cmsView(pdfSignatures(pdf)[0].cms);
        assert.equal(
          verify(
            'sha256',
            c.set(...view.signed.map((n) => n.raw)),
            pdfFixture.signer.publicKey,
            view.signature,
          ),
          true,
        );
        const result = await pdfDecision(pades, pdfFixture, pdf, 'B');
        assert.equal(result.overall, 'INVALID');
        assert.equal(
          result.reason,
          location === 'signed' ? 'PADES_ATTRIBUTE_FORBIDDEN' : 'CADES_ATTRIBUTE_LOCATION',
        );
      },
    );
}

for (const [label, id] of [
  ['registered', registered],
  ['legacy', legacy],
]) {
  for (const kind of ['matching', 'wrong digest', 'unsigned']) {
    test(
      'PAdES document timestamp checks ' + label + ' algorithm protection: ' + kind,
      async () => {
        const base = independentApproval(pdfFixture).pdf;
        const timestamped = independentTimestamp(pdfFixture, base).pdf;
        const attribute = attr(id, protection(kind));
        const pdf = replaceCMS(timestamped, 1, (raw) =>
          kind === 'unsigned'
            ? rewriteCMS(raw, { unsigned: [attribute] })
            : resign(
                raw,
                [...cmsView(raw).signed.map((n) => n.raw), attribute],
                pdfFixture.tsa.privateKey,
              ),
        );
        const view = cmsView(pdfSignatures(pdf)[1].cms);
        assert.equal(
          verify(
            'sha256',
            c.set(...view.signed.map((n) => n.raw)),
            pdfFixture.tsa.publicKey,
            view.signature,
          ),
          true,
        );
        const result = await pdfDecision(pades, pdfFixture, pdf, 'T');
        assert.equal(result.overall, kind === 'matching' ? 'VALID' : 'INVALID');
        if (kind !== 'matching')
          assert.equal(
            result.reason,
            kind === 'unsigned' ? 'CADES_ATTRIBUTE_LOCATION' : 'CADES_ALGORITHM_PROTECTION_BINDING',
          );
      },
    );
    test(
      'timestamp service retains its allowlist for ' + label + ' algorithm protection: ' + kind,
      async () => {
        const requestDER = timestampFixture.request({ certReq: true });
        let tokenDER = timestampFixture.token(requestDER, {
          extraSigned: kind === 'unsigned' ? [] : [attr(id, protection(kind))],
        });
        if (kind === 'unsigned')
          tokenDER = rewriteCMS(tokenDER, { unsigned: [attr(id, protection(kind))] });
        const view = cmsView(tokenDER);
        assert.equal(
          verify(
            'sha256',
            c.set(...view.signed.map((n) => n.raw)),
            timestampFixture.tsa.publicKey,
            view.signature,
          ),
          true,
        );
        const responseDER = encodeTimestampResponse({ status: 0, tokenDER });
        const result = await new TimestampResponseVerifier({
          readContext: async () => timestampFixture.context(),
        }).verify({ requestDER, responseDER });
        assert.equal(result.overall, kind === 'matching' ? 'UNSUPPORTED' : 'INVALID');
        assert.equal(
          result.reason,
          kind === 'matching'
            ? 'TSP_ATTRIBUTE_UNSUPPORTED'
            : kind === 'unsigned'
              ? 'CADES_ATTRIBUTE_LOCATION'
              : 'CADES_ALGORITHM_PROTECTION_BINDING',
        );
      },
    );
  }
}

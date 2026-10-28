import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as c from './core.mjs';
import * as api from './cades.mjs';
import * as pdf from './pades.mjs';
import { validateCAdESMaterial, validateSmimeMaterial } from './cades-validation.mjs';
import { fixture, epoch } from './cades-fixtures.mjs';
import { padesFixture } from './pades-fixtures.mjs';
import { smimeMaterialFixture, SIGNING, ENCRYPTION } from './smime-material-fixtures.mjs';

let f, hold, clear;
before(() => {
  f = fixture({ signerNotAfter: epoch + 1000 });
  hold = f.crl({
    number: 1,
    thisUpdate: epoch + 20,
    nextUpdate: epoch + 100,
    entries: [{ revokedAt: epoch + 10, reason: 6 }],
    utcTime: true,
  });
  clear = f.crl({ number: 2, thisUpdate: epoch + 50, nextUpdate: epoch + 100, utcTime: true });
});
after(() => f?.close());
const policy = (changes = {}) => f.policy({ currentMaterial: undefined, ...changes });
const run = (changes = {}) =>
  validateCAdESMaterial({
    certificate: f.signer.der,
    certificates: [f.root.der, f.signer.der],
    crls: [hold, clear],
    purpose: 'SIGNER',
    stateTime: epoch + 60,
    knowledgeTime: epoch + 80,
    policy: policy(),
    ...changes,
  });
function expected(result, overall, reason) {
  assert.equal(result.overall, overall, JSON.stringify(result.checks));
  if (reason) assert.equal(result.reason, reason);
  return result;
}
const unsupported = (result) =>
  expected(result, 'UNSUPPORTED', 'CADES_CRL_HOLD_RELEASE_UNSUPPORTED');
function retained(result) {
  expected(result, 'INVALID', 'CADES_CERTIFICATE_REVOKED');
  assert(!result.checks.some((v) => v.reason === 'CADES_CRL_HOLD_RELEASE_UNSUPPORTED'));
}
const clearCRL = (changes = {}) =>
  f.crl({ number: 2, thisUpdate: epoch + 50, nextUpdate: epoch + 100, utcTime: true, ...changes });

test('a complete current snapshot without retained hold evidence keeps its existing result', () => {
  expected(run({ crls: [clear] }), 'VALID');
  retained(run({ crls: [hold] }));
});
for (const reversed of [false, true])
  test(
    'authenticated hold omission has an unsupported transition independent of input order: ' +
      reversed,
    () => {
      const result = unsupported(run({ crls: reversed ? [clear, hold] : [hold, clear] }));
      assert.deepEqual(result.usedCRLs, [clear]);
    },
  );
test('later-known old hold is compared with the admitted current positive snapshot', () =>
  unsupported(run({ crls: [clear], knownCRLs: [hold] })));
test('clearing snapshot at the evaluated state time identifies the boundary', () =>
  unsupported(run({ stateTime: epoch + 50 })));
test('a clearing snapshot does not establish an earlier release instant', () =>
  retained(run({ stateTime: epoch + 49 })));
test('a protected positive snapshot can identify the boundary within its evidence domain', () =>
  unsupported(run({ evidenceTime: epoch + 70 })));
test('later-known-only clearing CRL cannot enlarge historical positive evidence', () =>
  retained(run({ crls: [hold], knownCRLs: [clear], evidenceTime: epoch + 70 })));
test('external current clearing CRL cannot enlarge historical positive evidence', () =>
  retained(
    run({
      crls: [hold],
      evidenceTime: epoch + 70,
      policy: policy({ currentMaterial: { crls: [clear] } }),
    }),
  ));
test('a historical hold remains applicable before a protected clearing snapshot', () =>
  retained(run({ stateTime: epoch + 30, evidenceTime: epoch + 70 })));

for (const [name, changes] of [
  ['unknown', { thisUpdate: epoch + 90, nextUpdate: epoch + 150 }],
  ['later than state', { thisUpdate: epoch + 70 }],
  ['stale', { nextUpdate: epoch + 75 }],
  ['lower number', { number: 0 }],
  ['same number', { number: 1 }],
  ['same publication time', { thisUpdate: epoch + 20 }],
  ['earlier publication time', { thisUpdate: epoch + 15 }],
  ['after certificate expiry', { thisUpdate: epoch + 1100, nextUpdate: epoch + 1300 }],
])
  test('a ' + name + ' clearing CRL does not replace the hold result', () =>
    retained(
      run({
        crls: [hold, clearCRL(changes)],
        ...(name === 'after certificate expiry' ? { knowledgeTime: epoch + 1200 } : {}),
      }),
    ),
  );

test('known CRL number conflict preserves the negative result', () => {
  const fork = clearCRL({ thisUpdate: epoch + 51 });
  const result = run({ crls: [hold, clear, fork] });
  retained(result);
  assert(result.checks.some((v) => v.reason === 'CADES_CRL_CONFLICT'));
});
test('unprotected clearing snapshot after root cutoff cannot replace a protected hold', () => {
  const selected = policy();
  selected.keyDeadlines[c.keyID(f.root.publicKey).toString('hex')] = epoch + 75;
  retained(run({ crls: [hold], knownCRLs: [clear], evidenceTime: epoch + 70, policy: selected }));
});
test('denied clearing CRL authority cannot reclassify an authenticated hold', () => {
  const resolver = f.authorities();
  const result = run({
    policy: policy({
      authorityResolver: (q) =>
        q.role === 'STATUS_AUTHORITY' && q.stateTime === epoch + 50
          ? { overall: 'INDETERMINATE', reason: 'CLEARING_AUTHORITY_UNAVAILABLE' }
          : resolver(q),
    }),
  });
  retained(result);
});
test('unproven hold authenticity does not become an unsupported transition', () => {
  const resolver = f.authorities();
  const result = run({
    policy: policy({
      authorityResolver: (q) =>
        q.role === 'STATUS_AUTHORITY' && q.stateTime === epoch + 20
          ? { overall: 'INDETERMINATE', reason: 'HOLD_AUTHORITY_UNAVAILABLE' }
          : resolver(q),
    }),
  });
  expected(result, 'INDETERMINATE', 'HOLD_AUTHORITY_UNAVAILABLE');
});
for (const reason of [0, 1, 2, 3, 4, 5, 9, 10])
  test('a later omission cannot reclassify permanent reason ' + reason, () => {
    const permanent = f.crl({
      number: 1,
      thisUpdate: epoch + 20,
      nextUpdate: epoch + 100,
      entries: [{ revokedAt: epoch + 10, reason }],
      utcTime: true,
    });
    retained(run({ crls: [permanent, clear] }));
  });
test('a permanent negative still wins when an earlier hold has an unselected transition', () => {
  const permanent = f.crl({
    number: 0,
    thisUpdate: epoch + 15,
    nextUpdate: epoch + 100,
    entries: [{ revokedAt: epoch + 10, reason: 1 }],
    utcTime: true,
  });
  const result = run({ crls: [permanent, hold, clear] });
  expected(result, 'INVALID', 'CADES_CERTIFICATE_REVOKED');
});
test('a later applicable hold is not cleared by an older absent snapshot', () => {
  const later = f.crl({
    number: 3,
    thisUpdate: epoch + 55,
    nextUpdate: epoch + 100,
    entries: [{ revokedAt: epoch + 52, reason: 6 }],
    utcTime: true,
  });
  retained(run({ crls: [hold, clear, later] }));
});
test('a bad clearing signature keeps its established INVALID outcome', () => {
  const bad = Buffer.from(clear);
  bad[bad.length - 1] ^= 1;
  expected(run({ crls: [hold, bad] }), 'INVALID', 'CADES_CRL_SIGNATURE');
});
test('TSA holds retain their existing revocation and independent signature-proof rules', () => {
  const tsaHold = f.crl({
    number: 1,
    thisUpdate: epoch + 20,
    nextUpdate: epoch + 100,
    entries: [{ serial: f.tsa.cert.serial, revokedAt: epoch + 10, reason: 6 }],
    utcTime: true,
  });
  const options = { certificate: f.tsa.der, purpose: 'TSA', crls: [tsaHold, clear] };
  retained(run(options));
  expected(run({ ...options, stateTime: epoch + 5 }), 'INDETERMINATE', 'CADES_TSA_REVOKED_NO_POE');
  expected(run({ ...options, stateTime: epoch + 5, signatureEvidenceTime: epoch + 9 }), 'VALID');
});
test('public CAdES reports the boundary without accepting or losing a bad content signature', () => {
  const cms = f.baseCMS(api, { signingTime: epoch + 60 });
  const options = {
    content: f.content,
    minimumLevel: 'B',
    validationTime: epoch + 60,
    knowledgeTime: epoch + 80,
    policy: f.policy({
      currentMaterial: { certificates: [f.root.der, f.signer.der], crls: [hold, clear] },
    }),
  };
  unsupported(api.verifyCAdES(cms, options));
  expected(
    api.verifyCAdES(cms, { ...options, content: Buffer.from('different bytes') }),
    'INVALID',
  );
});
test('public PAdES retains the shared unsupported result without a missing-POE downgrade', async () => {
  const p = padesFixture({ signerNotAfter: epoch + 1000 });
  try {
    const before = p.crl({
      number: 1,
      thisUpdate: epoch + 20,
      nextUpdate: epoch + 100,
      entries: [{ reason: 6, revokedAt: epoch + 10 }],
    });
    const after = p.crl({ number: 2, thisUpdate: epoch + 50, nextUpdate: epoch + 100 });
    const signed = await p.sign(pdf, { signingTime: epoch + 60 });
    const options = {
      minimumLevel: 'B',
      validationTime: epoch + 60,
      knowledgeTime: epoch + 80,
      policy: p.policy({
        currentMaterial: { certificates: [p.root.der, p.signer.der], crls: [before, after] },
      }),
    };
    unsupported(await pdf.verifyPAdES(signed, options));
    expected(
      await pdf.verifyPAdES(signed, {
        ...options,
        policy: p.policy({
          currentMaterial: { certificates: [p.root.der, p.signer.der], crls: [after] },
        }),
      }),
      'VALID',
    );
  } finally {
    p.close();
  }
});
for (const purpose of [SIGNING, ENCRYPTION])
  test('current S/MIME ' + purpose + ' admission preserves the unsupported boundary', () => {
    const m = smimeMaterialFixture();
    try {
      const leaf = purpose === SIGNING ? m.signer : m.recipient;
      const before = m.crl({
        number: 1,
        thisUpdate: epoch + 20,
        nextUpdate: epoch + 100,
        entries: [{ serial: leaf.cert.serial, reason: 6, revokedAt: epoch + 10 }],
      });
      const after = m.crl({ number: 2, thisUpdate: epoch + 50, nextUpdate: epoch + 100 });
      const options = m.options(leaf, {
        purpose,
        knowledgeTime: epoch + 80,
        crls: [before, after],
      });
      const result = unsupported(validateSmimeMaterial(options));
      assert.deepEqual(result.ordinaryTimeCheckIndexes, []);
      expected(validateSmimeMaterial({ ...options, crls: [after] }), 'VALID');
    } finally {
      m.close();
    }
  });

test('a snapshot preceding a scheduled hold does not establish its later release', () => {
  const scheduled = f.crl({
    number: 1,
    thisUpdate: epoch + 20,
    nextUpdate: epoch + 100,
    entries: [{ revokedAt: epoch + 55, reason: 6 }],
    utcTime: true,
  });
  retained(run({ crls: [scheduled, clear] }));
});
test('unprotected hold and clearing snapshot after root cutoff remain indeterminate', () => {
  const selected = policy();
  selected.keyDeadlines[c.keyID(f.root.publicKey).toString('hex')] = epoch + 75;
  expected(run({ policy: selected }), 'INDETERMINATE', 'CADES_CRL_AUTHENTICITY_UNPROVEN');
});
test('both exact CRLs protected before root cutoff can identify the unsupported boundary', () => {
  const selected = policy();
  selected.keyDeadlines[c.keyID(f.root.publicKey).toString('hex')] = epoch + 75;
  unsupported(run({ evidenceTime: epoch + 70, policy: selected }));
});

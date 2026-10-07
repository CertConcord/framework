import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import * as c from './core.mjs';
import * as cades from './cades.mjs';
import * as pades from './pades.mjs';
import { validateCAdESMaterial } from './cades-validation.mjs';
import { epoch, fixture, expectOverall, cmsView, rewriteCMS } from './cades-fixtures.mjs';
import {
  independentApproval,
  independentTimestamp,
  independentDSS,
  replaceCMS,
} from './pades-fixtures.mjs';
import { revokedTSAStatus } from './timestamp-revocation-fixtures.mjs';

let f, good, baseCMS, basePDF;
before(() => {
  f = fixture({ signerNotAfter: epoch + 1000, tsaNotAfter: epoch + 1000 });
  good = f.material().crls[0];
  baseCMS = f.augment(cades, f.baseCMS(cades), 'T', { at: epoch + 20 }).cms;
  basePDF = independentTimestamp(f, independentApproval(f).pdf, { at: epoch + 20 }).pdf;
});
after(() => f?.close());

const policy = (status, changes = {}) =>
  f.policy({ currentMaterial: f.material(status), ...changes });
const material = (status, changes = {}) =>
  validateCAdESMaterial({
    certificate: f.tsa.der,
    certificates: f.material().certificates,
    crls: [good],
    knownCRLs: [status],
    purpose: 'TSA',
    stateTime: epoch + 20,
    knowledgeTime: epoch + 80,
    policy: policy(good),
    ...changes,
  });
function noIndependentPOE(result) {
  expectOverall(result, 'INDETERMINATE');
  assert.equal(result.reason, 'CADES_TSA_REVOKED_NO_POE');
}

test('absent and explicit zero CRL reasons are distinct, normal OpenSSL-verified CRLs', () => {
  const absent = revokedTSAStatus(f),
    zero = revokedTSAStatus(f, { reason: 0 });
  assert.notDeepEqual(absent, zero);
  for (const [name, raw] of [
    ['absent', absent],
    ['zero', zero],
  ]) {
    const filename = f.file(`tsa-${name}.crl`);
    writeFileSync(filename, raw);
    f.run('crl', '-inform', 'DER', '-in', filename, '-CAfile', f.root.pemFile, '-verify', '-noout');
  }
});

for (const reason of [undefined, 1, 2]) {
  const name = reason === undefined ? 'absent reasonCode' : `reasonCode ${reason}`;
  test(`TSA ${name} cannot use its claimed early token time to bypass known revocation`, () => {
    noIndependentPOE(material(revokedTSAStatus(f, { reason })));
  });
  test(`TSA ${name} can use an independent token POE strictly before revocation`, () => {
    expectOverall(
      material(revokedTSAStatus(f, { reason }), { signatureEvidenceTime: epoch + 30 }),
      'VALID',
    );
  });
}
for (const reason of [0, 3, 4, 5])
  test(`explicit non-compromise TSA reasonCode ${reason} preserves an earlier token`, () => {
    expectOverall(material(revokedTSAStatus(f, { reason })), 'VALID');
  });

test('material POE without token POE cannot repair absent TSA revocation reason', () => {
  noIndependentPOE(material(revokedTSAStatus(f), { evidenceTime: epoch + 30 }));
});
test('independent token POE may precede revocation while material POE follows it', () => {
  expectOverall(
    material(revokedTSAStatus(f, { reason: 1 }), {
      signatureEvidenceTime: epoch + 30,
      evidenceTime: epoch + 60,
    }),
    'VALID',
  );
});
for (const [name, signatureEvidenceTime] of [
  ['non-finite', Number.NaN],
  ['after actual knowledge time', epoch + 81],
  ['before the token state time', epoch + 19],
])
  test(`independent token POE ${name} is not an admissible helper time`, () => {
    const result = material(revokedTSAStatus(f, { reason: 1 }), { signatureEvidenceTime });
    expectOverall(result, 'INVALID');
    assert.equal(result.reason, 'CADES_VALIDATION_TIME');
  });
for (const offset of [50, 60])
  test(`independent token POE at +${offset} is not before the +50 compromise cutoff`, () => {
    noIndependentPOE(
      material(revokedTSAStatus(f, { reason: 1 }), { signatureEvidenceTime: epoch + offset }),
    );
  });
test('an authenticated effective revocation before token time stays known INVALID despite later POE', () => {
  const result = material(revokedTSAStatus(f, { reason: 1, invalidityDate: epoch + 10 }), {
    signatureEvidenceTime: epoch + 30,
  });
  expectOverall(result, 'INVALID');
  assert.equal(result.reason, 'CADES_CERTIFICATE_REVOKED');
});
test('non-compromise reason does not preserve tokens at the revocation instant', () => {
  expectOverall(material(revokedTSAStatus(f, { reason: 0 }), { stateTime: epoch + 50 }), 'INVALID');
});
test('TSA unknown-reason semantics do not reinterpret an ordinary signer revocation', () => {
  const status = f.crl({
    number: 2,
    thisUpdate: epoch + 60,
    entries: [{ revokedAt: epoch + 50, reason: 1 }],
  });
  expectOverall(material(status, { certificate: f.signer.der, purpose: 'SIGNER' }), 'VALID');
});
for (const thisUpdate of [epoch + 25, epoch + 60])
  test(`unprotected CRL published at +${thisUpdate - epoch} after loss of current root authenticity is not a revocation fact`, () => {
    const selected = policy(good);
    selected.keyDeadlines[c.keyID(f.root.publicKey).toString('hex')] = epoch + 40;
    const result = material(revokedTSAStatus(f, { reason: 1, revokedAt: epoch + 5, thisUpdate }), {
      evidenceTime: epoch + 30,
      signatureEvidenceTime: epoch + 30,
      policy: selected,
    });
    expectOverall(result, 'INDETERMINATE');
    assert.equal(result.reason, 'CADES_CRL_AUTHENTICITY_UNPROVEN');
  });

function document(format, independentPOE) {
  if (independentPOE === undefined) return format === 'CAdES' ? baseCMS : basePDF;
  if (format === 'CAdES') {
    const lt = f.augment(cades, baseCMS, 'LT', {
      at: epoch + 25,
      validationMaterial: f.material(good),
    }).cms;
    return f.augment(cades, lt, 'LTA', {
      at: epoch + independentPOE,
      authority: f.successor,
      validationMaterial: f.material(good),
    }).cms;
  }
  return independentTimestamp(f, independentDSS(basePDF, f.material(good)), {
    at: epoch + independentPOE,
    tokenOptions: { authority: f.successor },
  }).pdf;
}
async function verifyDocument(format, bytes, status) {
  const options = {
    // This matrix tests trust in the old timestamp. Later-discovered current
    // CRLs are external evidence here, not a claim of complete embedded LT/A.
    minimumLevel: 'T',
    validationTime: epoch + 40,
    knowledgeTime: epoch + 80,
    policy: policy(status),
  };
  return format === 'CAdES'
    ? cades.verifyCAdES(bytes, { ...options, content: f.content })
    : pades.verifyPAdES(bytes, options);
}

for (const format of ['CAdES', 'PAdES']) {
  test(`${format} known bad CMS signature outranks uncertain revoked TSA token proof`, async () => {
    const badMath = (raw) => {
      const signature = Buffer.from(cmsView(raw).signature);
      signature[signature.length - 1] ^= 1;
      return rewriteCMS(raw, { signature });
    };
    const bytes = format === 'CAdES' ? badMath(baseCMS) : replaceCMS(basePDF, 0, badMath);
    const result = await verifyDocument(format, bytes, revokedTSAStatus(f, { reason: 1 }));
    expectOverall(result, 'INVALID');
    assert.equal(result.reason, 'CADES_SIGNATURE_INVALID');
  });
  for (const reason of [undefined, 1]) {
    const name = reason === undefined ? 'absent' : 'keyCompromise';
    test(`${format} public verification rejects a self-dated token after late-known ${name} TSA revocation`, async () => {
      noIndependentPOE(
        await verifyDocument(format, document(format), revokedTSAStatus(f, { reason })),
      );
    });
    test(`${format} independent successor covers the exact older token before ${name} revocation`, async () => {
      const bytes = document(format, 30);
      const result = await verifyDocument(format, bytes, revokedTSAStatus(f, { reason }));
      expectOverall(result, 'VALID');
      assert.equal(result.stateTime, epoch + 20);
      assert.equal(result.preservationTime, epoch + 30);
    });
  }
  test(`${format} explicit zero TSA reason preserves an earlier timestamp without a successor`, async () => {
    expectOverall(
      await verifyDocument(format, document(format), revokedTSAStatus(f, { reason: 0 })),
      'VALID',
    );
  });
  test(`${format} a successor after compromise cannot retroactively authenticate the older token`, async () => {
    noIndependentPOE(
      await verifyDocument(format, document(format, 60), revokedTSAStatus(f, { reason: 1 })),
    );
  });
}

test('PAdES keeps the earliest independent token POE when validation material arrives under a later proof', async () => {
  const tokenProof = independentTimestamp(f, basePDF, {
    at: epoch + 30,
    tokenOptions: { authority: f.successor },
  }).pdf;
  const materialProof = independentTimestamp(f, independentDSS(tokenProof, f.material(good)), {
    at: epoch + 60,
    tokenOptions: { authority: f.successor },
  }).pdf;
  const result = await verifyDocument('PAdES', materialProof, revokedTSAStatus(f, { reason: 1 }));
  expectOverall(result, 'VALID');
  assert.equal(result.stateTime, epoch + 20);
  assert.equal(result.preservationTime, epoch + 60);
});

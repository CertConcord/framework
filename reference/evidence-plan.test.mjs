import test from 'node:test';
import assert from 'node:assert/strict';
import { H, dcbor, decodeCBOR, random } from './core.mjs';
import { evidenceLeaf, createEvidencePackage, verifyEvidencePackage } from './evidence-plan.mjs';
import { createSignaturePackage } from './evidence.mjs';
import { createMdocSignaturePackage } from './signer-mdoc.mjs';

const copy = (value) => decodeCBOR(dcbor(value));
const fixture = () =>
  createEvidencePackage('synthetic-flat-plan', [
    evidenceLeaf('Document', Buffer.from('Approved document bytes')),
    evidenceLeaf('OperationPermit', Buffer.from('Opaque authenticated permit')),
  ]);

test('a flat plan binds every leaf type and payload after serialization', () => {
  const bundle = copy(fixture());
  assert.equal(
    verifyEvidencePackage(bundle, {
      requiredTypes: ['Document', 'OperationPermit'],
    }).closure,
    'COMPLETE',
  );
  for (const mutation of [
    (leaf) => {
      leaf.payload[0] ^= 1;
    },
    (leaf) => {
      leaf.type = 'SubstitutedDocument';
    },
  ]) {
    const changed = copy(bundle);
    mutation(changed.objects[0]);
    assert.throws(() => verifyEvidencePackage(changed), { code: 'ECP_HASH' });
  }
});

test('a known invalid leaf takes precedence over a missing plan or unsupported schema', () => {
  for (const change of [
    (bundle) => {
      delete bundle.plan;
    },
    (bundle) => {
      bundle.schemaVersion = 3;
    },
    (bundle) => {
      bundle.plan.schemaVersion = 3;
    },
  ]) {
    const bundle = fixture();
    bundle.objects[0].payload[0] ^= 1;
    change(bundle);
    assert.throws(() => verifyEvidencePackage(bundle), { code: 'ECP_HASH' });
  }
});

test('flat evidence rejects graph fields at every level', () => {
  for (const [level, field, value] of [
    ['bundle', 'root', random(64)],
    ['plan', 'dependencies', []],
    ['plan', 'links', []],
    ['leaf', 'version', 1],
    ['leaf', 'dependencies', []],
    ['leaf', 'links', []],
  ]) {
    const bundle = fixture(),
      target = level === 'bundle' ? bundle : level === 'plan' ? bundle.plan : bundle.objects[0];
    target[field] = value;
    assert.throws(
      () => verifyEvidencePackage(bundle),
      { code: 'UNKNOWN_FIELD' },
      level + '.' + field,
    );
  }
});

test('nested verification plans and independent activation leaves are forbidden even with valid commitments', () => {
  for (const type of ['VerificationPlan', 'ActivationContext']) {
    const bundle = fixture(),
      payload = dcbor({ schemaVersion: 2 }),
      leaf = { id: H('EvidenceLeaf', { type, payload }), type, payload };
    bundle.objects.push(leaf);
    bundle.plan.objects[type] = leaf.id;
    assert.throws(() => verifyEvidencePackage(bundle), { code: 'ECP_LEAF_SHAPE' }, type);
    assert.throws(() => evidenceLeaf(type, payload), { code: 'ECP_LEAF_TYPE' }, type);
  }
});

test('duplicate leaves and repeated plan references cannot create ambiguous evidence', () => {
  const duplicateLeaf = fixture();
  duplicateLeaf.objects.push(copy(duplicateLeaf.objects[0]));
  assert.throws(() => verifyEvidencePackage(duplicateLeaf), { code: 'ECP_DUPLICATE' });
  const duplicateReference = fixture();
  duplicateReference.plan.objects.OperationPermit = duplicateReference.plan.objects.Document;
  assert.throws(() => verifyEvidencePackage(duplicateReference), { code: 'ECP_DUPLICATE' });
});

test('missing, unreferenced and substituted leaf references are distinct rejections', () => {
  const missing = fixture();
  missing.objects.pop();
  assert.throws(() => verifyEvidencePackage(missing), { code: 'ECP_MISSING_OBJECT' });
  const missingPlan = fixture();
  delete missingPlan.plan;
  assert.throws(() => verifyEvidencePackage(missingPlan), { code: 'ECP_MISSING_OBJECT' });
  const unreferenced = fixture();
  delete unreferenced.plan.objects.Document;
  assert.throws(() => verifyEvidencePackage(unreferenced), { code: 'ECP_UNREACHABLE_OBJECT' });
  const substituted = fixture();
  substituted.plan.objects.Document = random(64);
  assert.throws(() => verifyEvidencePackage(substituted), { code: 'ECP_PLAN_OBJECT' });
  assert.throws(
    () =>
      verifyEvidencePackage(fixture(), {
        requiredTypes: ['Document'],
      }),
    { code: 'ECP_PLAN' },
  );
});

test('legacy and future package schemas never gain acceptance as the selected flat format', () => {
  for (const schemaVersion of [1, 3]) {
    const bundle = fixture();
    bundle.schemaVersion = schemaVersion;
    assert.throws(() => verifyEvidencePackage(bundle), { code: 'ECP_UNSUPPORTED_SCHEMA' });
  }
  const bundle = fixture();
  bundle.plan.schemaVersion = 3;
  assert.throws(() => verifyEvidencePackage(bundle), { code: 'ECP_UNSUPPORTED_SCHEMA' });
});

test('flat evidence limits bound both leaf count and payload bytes', () => {
  const bundle = fixture();
  assert.throws(() => verifyEvidencePackage(bundle, { maxBytes: 1 }), { code: 'ECP_SIZE' });
  const leaves = Array.from({ length: 129 }, (_, i) =>
    evidenceLeaf('Evidence' + i, Buffer.alloc(0)),
  );
  assert.throws(() => createEvidencePackage('synthetic-flat-plan', leaves), { code: 'ECP_SHAPE' });
});

test('both document package constructors explicitly reject a separate activation input', () => {
  for (const create of [createSignaturePackage, createMdocSignaturePackage])
    for (const activation of [undefined, {}, { operationID: random() }])
      assert.throws(() => create({ activation }), { code: 'ECP_DUPLICATE_ACTIVATION' });
});

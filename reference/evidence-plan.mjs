import { H, b64u, equal, fields, requireThat } from './core.mjs';

const forbiddenTypes = new Set(['VerificationPlan', 'ActivationContext']);
const validType = (type) =>
  typeof type === 'string' && type.length > 0 && type.length <= 128 && !forbiddenTypes.has(type);

export function evidenceLeaf(type, payload) {
  requireThat(validType(type) && Buffer.isBuffer(payload), 'ECP_LEAF_TYPE');
  const bytes = Buffer.from(payload);
  return { id: H('EvidenceLeaf', { type, payload: bytes }), type, payload: bytes };
}

export function createEvidencePackage(profile, objects) {
  const bundle = {
    schemaVersion: 2,
    plan: {
      schemaVersion: 2,
      profile,
      objects: Object.fromEntries(objects.map((o) => [o.type, o.id])),
    },
    objects,
  };
  verifyEvidencePackage(bundle);
  return bundle;
}

// The plan references every leaf exactly once. No nested plans or graph links are admitted.
export function verifyEvidencePackage(bundle, { requiredTypes, maxBytes = 64 * 1024 * 1024 } = {}) {
  requireThat(
    bundle && Number.isSafeInteger(bundle.schemaVersion) && bundle.schemaVersion > 0,
    'ECP_SCHEMA',
  );
  requireThat(bundle.schemaVersion !== 1, 'ECP_UNSUPPORTED_SCHEMA');
  fields(bundle, ['schemaVersion', 'objects'], ['plan']);
  requireThat(Array.isArray(bundle.objects) && bundle.objects.length <= 128, 'ECP_SHAPE');
  const leaves = new Map(),
    ids = new Set();
  let size = 0;
  for (const leaf of bundle.objects) {
    fields(leaf, ['id', 'type', 'payload']);
    requireThat(
      validType(leaf.type) &&
        Buffer.isBuffer(leaf.id) &&
        leaf.id.length === 64 &&
        Buffer.isBuffer(leaf.payload),
      'ECP_LEAF_SHAPE',
    );
    size += leaf.payload.length;
    requireThat(size <= maxBytes, 'ECP_SIZE');
    requireThat(
      equal(leaf.id, H('EvidenceLeaf', { type: leaf.type, payload: leaf.payload })),
      'ECP_HASH',
    );
    requireThat(!leaves.has(leaf.type) && !ids.has(b64u(leaf.id)), 'ECP_DUPLICATE');
    leaves.set(leaf.type, leaf);
    ids.add(b64u(leaf.id));
  }
  requireThat(Object.hasOwn(bundle, 'plan'), 'ECP_MISSING_OBJECT');
  const plan = bundle.plan;
  fields(plan, ['schemaVersion', 'profile', 'objects']);
  requireThat(
    Number.isSafeInteger(plan.schemaVersion) &&
      plan.schemaVersion > 0 &&
      typeof plan.profile === 'string' &&
      plan.profile.length > 0 &&
      plan.profile.length <= 256 &&
      plan.objects &&
      typeof plan.objects === 'object' &&
      !Array.isArray(plan.objects) &&
      !Buffer.isBuffer(plan.objects),
    'ECP_PLAN',
  );
  const entries = Object.entries(plan.objects);
  requireThat(
    entries.length <= 128 &&
      entries.every(([type, id]) => validType(type) && Buffer.isBuffer(id) && id.length === 64),
    'ECP_PLAN',
  );
  requireThat(new Set(entries.map(([, id]) => b64u(id))).size === entries.length, 'ECP_DUPLICATE');
  for (const leaf of leaves.values()) {
    requireThat(Object.hasOwn(plan.objects, leaf.type), 'ECP_UNREACHABLE_OBJECT');
    requireThat(equal(plan.objects[leaf.type], leaf.id), 'ECP_PLAN_OBJECT');
  }
  if (requiredTypes)
    requireThat(
      entries.every(([type]) => requiredTypes.includes(type)),
      'ECP_PLAN',
    );
  requireThat(
    entries.every(([type]) => leaves.has(type)) &&
      (!requiredTypes || requiredTypes.every((type) => Object.hasOwn(plan.objects, type))),
    'ECP_MISSING_OBJECT',
  );
  requireThat(bundle.schemaVersion === 2 && plan.schemaVersion === 2, 'ECP_UNSUPPORTED_SCHEMA');
  return {
    plan,
    values: Object.fromEntries([...leaves].map(([type, leaf]) => [type, leaf.payload])),
    closure: 'COMPLETE',
  };
}

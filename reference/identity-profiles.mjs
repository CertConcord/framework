import { H, requireThat } from './core.mjs';

// Admission schemas describe disclosed claims. Issuance schemas may require more fields.
const text = Object.freeze({ type: 'string', maxLength: 150 });
export const identityProfiles = Object.freeze({
  mdl: {
    id: 'iso-mdl-2021',
    docType: 'org.iso.18013.5.1.mDL',
    namespace: 'org.iso.18013.5.1',
    namespaces: {
      'org.iso.18013.5.1': {
        family_name: text,
        given_name: text,
        age_over_18: { type: 'boolean' },
      },
    },
  },
  photoid: {
    id: 'iso-photoid-multipaz-0.100.0',
    docType: 'org.iso.23220.photoid.1',
    namespace: 'org.iso.23220.1',
    namespaces: {
      'org.iso.23220.1': { family_name: text, given_name: text },
      'org.iso.23220.photoid.1': { person_id: text },
    },
  },
  pid: {
    id: 'eudi-pid-arf-1.4.0',
    docType: 'eu.europa.ec.eudi.pid.1',
    namespace: 'eu.europa.ec.eudi.pid.1',
    certificateProfile: 'EUDI_PID_ARF_1_4',
    namespaces: {
      'eu.europa.ec.eudi.pid.1': {
        family_name: text,
        given_name: text,
        age_over_18: { type: 'boolean' },
      },
    },
  },
  custom: {
    id: 'example-identity-v1',
    docType: 'org.example.identity.1',
    namespace: 'org.example.identity.1',
    namespaces: {
      'org.example.identity.1': { family_name: text, given_name: text },
      'org.example.membership.1': { member_id: text },
    },
  },
});

export function normalizeIdentityProfile(profile) {
  requireThat(
    profile &&
      typeof profile.docType === 'string' &&
      profile.docType.length > 0 &&
      profile.docType.length <= 256,
    'IDENTITY_PROFILE',
  );
  const namespaces = profile.namespaces ?? {
    [profile.namespace]: Object.fromEntries(
      (profile.allowedClaims ?? []).map((name) => [name, { type: 'any' }]),
    ),
  };
  const entries = Object.entries(namespaces);
  requireThat(
    entries.length > 0 && entries.length <= 16 && entries.some(([ns]) => ns === profile.namespace),
    'IDENTITY_NAMESPACES',
  );
  for (const [ns, fields] of entries) {
    requireThat(
      ns.length > 0 &&
        ns.length <= 256 &&
        ns !== 'undefined' &&
        fields &&
        typeof fields === 'object',
      'IDENTITY_NAMESPACE',
    );
    const attributes = Object.entries(fields);
    requireThat(attributes.length > 0 && attributes.length <= 128, 'IDENTITY_SCHEMA');
    for (const [name, rule] of attributes) {
      requireThat(
        name.length > 0 &&
          name.length <= 128 &&
          ['any', 'string', 'boolean', 'uint', 'bytes'].includes(rule?.type),
        'IDENTITY_SCHEMA_TYPE',
      );
      if (rule.maxLength !== undefined)
        requireThat(
          Number.isSafeInteger(rule.maxLength) && rule.maxLength > 0 && rule.maxLength <= 65536,
          'IDENTITY_SCHEMA_LENGTH',
        );
    }
  }
  return {
    id: profile.id ?? 'configured-identity-profile',
    docType: profile.docType,
    namespace: profile.namespace,
    namespaces,
    certificateProfile: profile.certificateProfile ?? 'ISO_MDOC',
    statusMode: profile.statusMode ?? 'UNCONFIGURED',
    maxCredentialLifetime: profile.maxCredentialLifetime ?? 0,
  };
}

export function identityProfileHash(profile) {
  return H('IdentityAdmissionProfile', normalizeIdentityProfile(profile));
}

export function identityClaimPaths(profile, claims) {
  const p = normalizeIdentityProfile(profile);
  requireThat(
    Array.isArray(claims) && claims.length > 0 && claims.length <= 128,
    'IDENTITY_CLAIM_POLICY',
  );
  const seen = new Set();
  return claims.map((claim) => {
    const path = typeof claim === 'string' ? [p.namespace, claim] : claim;
    requireThat(
      Array.isArray(path) &&
        path.length === 2 &&
        path.every((v) => typeof v === 'string') &&
        Object.hasOwn(p.namespaces, path[0]) &&
        Object.hasOwn(p.namespaces[path[0]], path[1]),
      'IDENTITY_CLAIM_POLICY',
    );
    const id = JSON.stringify(path);
    requireThat(!seen.has(id), 'IDENTITY_DUPLICATE_CLAIM');
    seen.add(id);
    return [...path];
  });
}

export function requestedNamespaces(paths) {
  const result = new Map();
  for (const [ns, name] of paths) {
    if (!result.has(ns)) result.set(ns, []);
    requireThat(!result.get(ns).includes(name), 'IDENTITY_DUPLICATE_CLAIM');
    result.get(ns).push(name);
  }
  return result;
}

export function validateIdentityClaims(profile, claims, paths) {
  const p = normalizeIdentityProfile(profile),
    requested = requestedNamespaces(identityClaimPaths(profile, paths));
  requireThat(claims instanceof Map && claims.size === requested.size, 'IDENTITY_DISCLOSURE_SCOPE');
  for (const [ns, names] of requested) {
    const values = claims.get(ns);
    requireThat(values instanceof Map && values.size === names.length, 'IDENTITY_DISCLOSURE_SCOPE');
    for (const name of names) {
      requireThat(values.has(name), 'IDENTITY_CLAIM_MISSING');
      const value = values.get(name),
        rule = p.namespaces[ns][name];
      requireThat(
        rule.type === 'any' ||
          (rule.type === 'string' && typeof value === 'string') ||
          (rule.type === 'boolean' && typeof value === 'boolean') ||
          (rule.type === 'uint' &&
            ((Number.isSafeInteger(value) && value >= 0) ||
              (typeof value === 'bigint' && value >= 0n))) ||
          (rule.type === 'bytes' && Buffer.isBuffer(value)),
        'IDENTITY_CLAIM_TYPE',
      );
      if (rule.maxLength !== undefined)
        requireThat(
          (typeof value === 'string' ? [...value].length : value.length) <= rule.maxLength,
          'IDENTITY_CLAIM_LENGTH',
        );
    }
  }
  return Object.fromEntries([...claims].map(([ns, values]) => [ns, Object.fromEntries(values)]));
}

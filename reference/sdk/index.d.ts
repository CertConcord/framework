import type { KeyObject, X509Certificate } from 'node:crypto';
export const profiles: readonly ['CMS', 'MDOC'];
export interface EvidenceLeaf {
  id: Buffer;
  type: string;
  payload: Buffer;
}
export interface VerificationPlan {
  schemaVersion: 2;
  profile: string;
  objects: Record<string, Buffer>;
}
export interface EvidencePackage {
  schemaVersion: 2;
  plan: VerificationPlan;
  objects: EvidenceLeaf[];
}
export interface SignaturePolicy {
  schemaVersion: 1;
  allowedProfiles: string[];
  allowedOrigins: string[];
  rpID: string;
  audience: string;
  maxActivationLifetime: number;
  requireTrustedTime: boolean;
  documentEvidence?: {
    profile: 'certconcord-document-evidence-draft-03';
    organizationAuthorization: boolean;
  };
  [field: string]: unknown;
}
export interface MTCTrust {
  caID: string;
  caPublicKey: KeyObject;
  members: { id: string; operatorID: string; publicKey: KeyObject }[];
  threshold: number;
  policyHash: Buffer;
  rtmHash: Buffer;
  membershipEpoch: number;
  [field: string]: unknown;
}
export interface LogSigner {
  name: string;
  publicKey: KeyObject;
  scheme: string;
  operatorID?: string;
}
export interface IssuanceScope {
  trustDomainID: Buffer;
  issuerID: string;
  issuerKeyID: Buffer;
  representation: 'X509' | 'MTC' | 'MDOC';
}
export interface AuthorityQuery {
  certificate?: Buffer;
  publicKeyDER?: Buffer;
  role: string;
  scope: {
    trustDomainID: Buffer;
    profileID?: string;
    issuerID?: string;
    representation?: 'X509' | 'MTC' | 'MDOC';
    purpose?: string;
  };
  stateTime: number;
  knowledgeTime: number;
}
export interface AuthorityDecision {
  overall: 'VALID' | 'INVALID' | 'INDETERMINATE' | 'UNSUPPORTED';
  reason: string;
  [field: string]: unknown;
}
export interface CommonTrust {
  trustDomainID: Buffer;
  issuanceScope: IssuanceScope;
  authorityResolver: (query: AuthorityQuery) => AuthorityDecision;
  expectedPolicy: SignaturePolicy;
  permitCertificate: Buffer;
  receiptCertificate: Buffer;
  knowledgeTime?: number;
  raCertificate: Buffer;
  organizationAuthorities?: {
    organizationID: Buffer;
    certificate: Buffer;
    statusCertificate: Buffer;
  }[];
  timestamp?: {
    certificate: Buffer;
    issuerKey: KeyObject;
    policy: string;
    signatureProfile?: 'CERTCONCORD-PQ' | 'EXTERNAL-RFC3161';
    status: (input: {
      certificate: Buffer;
      genTime: number;
      stateTime: number;
      knowledgeTime: number;
    }) => boolean | AuthorityDecision;
  };
  passkeyStatus?: (binding: unknown, time: { at: number; knowledgeTime: number }) => boolean;
  executionBindingCertificate?: Buffer;
  executionStatus?: (binding: unknown, time: { at: number; knowledgeTime: number }) => boolean;
}
export type CMSTrust = CommonTrust & { statusCertificate: Buffer; issuerCertificate?: Buffer } & (
    { mtc: MTCTrust; issuerPublicKey?: never } | { issuerPublicKey: KeyObject; mtc?: never }
  );
export interface MdocTrust extends CommonTrust {
  issuerCertificate: Buffer;
  issuerPublicKey: KeyObject;
  issuerRoots: X509Certificate[];
  sealCertificate: Buffer;
  statusURI: string;
  credentialLogTrust: { log: LogSigner; members: LogSigner[]; threshold: number };
  docType?: string;
  certificateProfile?: string;
}
export type VerificationOutcome = 'VALID' | 'INVALID' | 'INDETERMINATE' | 'UNSUPPORTED';
export type VerificationDimension =
  | 'integrity'
  | 'issuerTrust'
  | 'qualification'
  | 'keyBinding'
  | 'authorization'
  | 'status'
  | 'time'
  | 'transparency';
export interface VerificationDimensionResult {
  readonly overall: VerificationOutcome;
  readonly reason: string;
}
export interface VerificationResult {
  readonly overall: VerificationOutcome;
  readonly coreRevision: 'draft-03';
  /** The parsed candidate plan label; this field does not imply acceptance. */
  readonly profile: string | null;
  readonly reason: string;
  /** Omitted dimensions were not established by the checks that completed. */
  readonly dimensions: Readonly<
    Partial<Record<VerificationDimension, VerificationDimensionResult>>
  >;
  [detail: string]: unknown;
}
export function createVerifier(
  options: ({ format: 'CMS'; trust: CMSTrust } | { format: 'MDOC'; trust: MdocTrust }) & {
    maxBytes?: number;
  },
): Readonly<{ verify(bytes: Uint8Array): Readonly<VerificationResult> }>;

export interface OrganizationHistoryMaterial {
  cms: Buffer;
  issuerCertificate: Buffer;
}
export interface OrganizationHistoryKnowledge {
  /** Latest authenticated relying-party knowledge; monotonic within this verifier instance. */
  knowledgeTime: number;
  /** Cumulative evidence must retain applicable incidents and same-epoch conflicts. */
  statusMaterial: OrganizationHistoryMaterial[];
  certificateStatusMaterial: OrganizationHistoryMaterial[];
}
export interface OrganizationHistoryTrust {
  trustDomainID: Buffer;
  organizationID: Buffer;
  issuerID: string;
  identityNamespace: string;
  policy: SignaturePolicy;
  controlTrust: {
    purpose: string;
    issuerID: string;
    organizationID: Buffer;
    identityNamespace: string;
    certificate: Buffer;
    objectTypes: ('GRANT' | 'APPROVER_REGISTRATION' | 'FINAL_AUTHORIZATION')[];
  }[];
  credentialTrust: {
    certificate: Buffer;
    registrationAuthorization: Buffer;
    issuerCertificate: Buffer;
    raCertificate: Buffer;
    statusCertificate: Buffer;
    issuanceScope: IssuanceScope;
  };
  algorithmDeadlines: Record<string, number>;
  hashDeadlines: Record<string, number>;
  keyDeadlines: Record<string, number>;
}
export interface OrganizationHistoryTimestampTrust {
  certificate: Buffer;
  issuerKey: KeyObject;
  policy: string;
  validUntil: number;
  revokedAt?: number;
  signatureProfile?: 'CERTCONCORD-PQ' | 'EXTERNAL-RFC3161';
  status: (query: {
    certificate: Buffer;
    genTime: number;
    stateTime: number;
    knowledgeTime: number;
  }) => boolean | AuthorityDecision;
}
export interface OrganizationHistoryView extends VerificationResult {
  readonly scope: 'AS_KNOWN_AT_PROOF_TIME' | 'HISTORICAL_EVIDENCE_UNDER_CURRENT_KNOWLEDGE';
  readonly stateTime: number | null;
  readonly knowledgeTime: number | null;
}
export interface OrganizationHistoryResult extends VerificationResult {
  readonly purpose: 'RETAINED_EVIDENCE_VERIFICATION';
  readonly operationTime: number | null;
  /** Exact first complete-package PoE upper bound, including fractional accuracy. */
  readonly proofOfExistenceUpperBound: number | null;
  readonly knowledgeTime: number | null;
  readonly historicalAuthorization: OrganizationHistoryView;
  readonly currentAdmissibility: OrganizationHistoryView;
  readonly preservation: VerificationResult;
  readonly originalProtectionDeadline?: number;
  readonly limitations: readonly string[];
}
export interface OrganizationHistoryTimestampPin {
  certificate: Buffer;
  /** Exact canonical public SPKI DER; private keys and KeyObject values are not accepted. */
  issuerPublicKeyDER: Buffer;
  policy: string;
  validUntil: number;
  revokedAt?: number;
  signatureProfile: 'CERTCONCORD-PQ' | 'EXTERNAL-RFC3161';
}
export interface OrganizationHistorySourceConfiguration {
  schemaVersion: 1;
  trust: OrganizationHistoryTrust;
  retainedAuthorities: {
    governance: {
      roots: { publicKeyDER: Buffer; validFrom: number; validUntil: number }[];
      threshold: number;
    };
    algorithmDeadlines: Record<string, number>;
    publication: {
      format: 'RFC3161';
      timestampAuthorities: (OrganizationHistoryTimestampPin & {
        validFrom: number;
        knowledgeValidUntil: number;
      })[];
      hashValidUntil: Record<string, number>;
    };
  };
  preservation: {
    hashValidUntil: Record<string, number>;
    dataValidUntil?: number;
    timestampAuthorities: OrganizationHistoryTimestampPin[];
  };
}
export interface OrganizationHistorySourceKnowledge extends OrganizationHistoryKnowledge {
  authorityHistory: {
    /** Exact deterministic-CBOR RTM body, with no JSON reconstruction. */
    manifest: Buffer;
    signatures: { keyID: Buffer; signature: Buffer }[];
    publicationProof: Buffer;
  }[];
}
declare const organizationHistorySource: unique symbol;
export interface OrganizationHistorySource {
  readonly [organizationHistorySource]: true;
  close(): void;
  /** Memory sources do not retain exact artifacts. This never returns an authorization. */
  readEvidence(evidenceID: string): undefined;
}
/** Bounded public-data adapter. Its reader supplies material, never decisions or outcomes. */
export function createOrganizationHistorySource(options: {
  configuration: OrganizationHistorySourceConfiguration;
  readKnowledge: () => OrganizationHistorySourceKnowledge;
}): OrganizationHistorySource;
export function createOrganizationHistoryVerifier(options: {
  source: OrganizationHistorySource;
}): Readonly<{
  verify(input: {
    originalBytes: Buffer;
    evidenceRecord: Buffer;
  }): Readonly<OrganizationHistoryResult>;
}>;
/** Offline evidence verification; it grants no current execution or recovery permission. */
export function createOrganizationHistoryVerifier(options: {
  trust: OrganizationHistoryTrust;
  authorityResolver: (query: AuthorityQuery) => AuthorityDecision;
  readKnowledge: () => OrganizationHistoryKnowledge;
  preservationPolicy: {
    hashValidUntil: Record<string, number>;
    /** Optional tightening bound; it can never extend derived original protection. */
    dataValidUntil?: number;
    resolveTimestamp: (token: Buffer) => OrganizationHistoryTimestampTrust;
  };
}): Readonly<{
  verify(input: {
    originalBytes: Buffer;
    evidenceRecord: Buffer;
  }): Readonly<OrganizationHistoryResult>;
}>;

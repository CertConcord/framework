import type { KeyObject, X509Certificate } from 'node:crypto';
export const profiles: readonly ['CMS', 'MDOC'];
export interface SignaturePolicy {
  schemaVersion: 1;
  allowedProfiles: string[];
  allowedOrigins: string[];
  rpID: string;
  audience: string;
  maxActivationLifetime: number;
  requireTrustedTime: boolean;
  documentEvidence?: {
    profile: 'certconcord-document-evidence-draft-02';
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
export interface CommonTrust {
  trustDomainID: Buffer;
  expectedPolicy: SignaturePolicy;
  permitCertificate: Buffer;
  receiptCertificate: Buffer;
  knowledgeTime?: number;
  raCertificate?: Buffer;
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
    }) => boolean;
  };
  passkeyStatus?: (binding: unknown, time: { at: number; knowledgeTime: number }) => boolean;
  executionBindingCertificate?: Buffer;
  executionStatus?: (binding: unknown, time: { at: number; knowledgeTime: number }) => boolean;
}
export type CMSTrust = CommonTrust & { statusCertificate: Buffer } & (
    | { mtc: MTCTrust; issuerPublicKey?: never }
    | { issuerPublicKey: KeyObject; mtc?: never }
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
export interface VerificationResult {
  overall: 'VALID' | 'INVALID' | 'INDETERMINATE' | 'UNSUPPORTED';
  coreRevision: 'draft-02';
  profile?: string;
  reason?: string;
  [dimension: string]: unknown;
}
export function createVerifier(
  options: ({ format: 'CMS'; trust: CMSTrust } | { format: 'MDOC'; trust: MdocTrust }) & {
    maxBytes?: number;
  },
): Readonly<{ verify(bytes: Uint8Array): Readonly<VerificationResult> }>;

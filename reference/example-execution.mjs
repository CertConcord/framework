import { H, keyID, now } from './core.mjs';
import { parseCertificate } from './pki.mjs';
import {
  EXECUTION_BINDING_PROFILE,
  ExecutionBindingGateway,
  issueExecutionBinding,
} from './execution-binding.mjs';

export const exampleExecutionPolicy = () => ({
  profile: EXECUTION_BINDING_PROFILE,
  providerID: 'synthetic-broker',
  maxLeaseSeconds: 300,
});

// Synthetic exchanges combine control roles; deployment admission uses governed authority pins.
export function exampleExecutionGateway({ publicKey, policy, trustDomainID, ...options }) {
  const issuedAt = now();
  const binding = issueExecutionBinding(
    {
      schemaVersion: 1,
      profile: EXECUTION_BINDING_PROFILE,
      trustDomainID,
      providerID: policy.executionBinding.providerID,
      epoch: 1,
      status: 'ACTIVE',
      keyID: keyID(publicKey),
      permitKeyID: keyID(parseCertificate(options.permitCertificate).publicKey),
      receiptKeyID: keyID(parseCertificate(options.receiptCertificate).publicKey),
      policyHash: H('SignaturePolicy', policy),
      audience: policy.audience,
      enforcement: 'BROKER_ENFORCED',
      issuedAt,
      expiresAt: issuedAt + 300,
    },
    { certificate: options.receiptCertificate, privateKey: options.receiptKey },
  );
  return new ExecutionBindingGateway({
    ...options,
    policy,
    trustDomainID,
    binding,
    bindingCertificate: options.receiptCertificate,
  });
}

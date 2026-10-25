# Retention horizon clarification for MTC signed artifacts

Target: [draft-ietf-plants-mtc-deploy-use-cases-00, section 3.5.5](https://www.ietf.org/archive/id/draft-ietf-plants-mtc-deploy-use-cases-00.txt). Status: proposed informative clarification, not submitted.

The WG draft retains the signed-artifact analysis from individual draft-gray-plants-mtc-deploy-use-cases-01. Its existing minimum for batch tree-head retention and continued access after CA retirement should be preserved. The additional question is how a deployment assigns responsibility when the application needs longer validation.

For example, a signing certificate expires in 2030, but a document signed while it was authorized must remain verifiable through 2045. Assume that by 2030 the archive has already satisfied the minimum retention duration based on the maximum certificate validity period in its batch. Stopping retention then would still leave the application without required evidence for 2031-2045. The certificate expiry date alone does not establish when the upstream minimum has been satisfied. Continued access to batch tree heads alone does not supply the document profile's historical status, authority and time evidence. A positive deployment declares the 2045 horizon, names the parties retaining those inputs, and arranges retrieval and any necessary protection renewal throughout that period. Certificate expiry alone is not evidence that an already preserved signature became invalid.

Proposed addition:

> For signed artifacts whose intended validation horizon extends beyond signing-certificate validity, a deployment needs an explicit retention period and responsible archive parties. Retained verification inputs include certificate/proof material and the authority, status and time evidence required by the selected application. Certificate expiry alone does not terminate that responsibility. Issuer retirement needs a continuity arrangement for those inputs.

This addition is informative deployment guidance. Exact container augmentation, policy decisions and preservation algorithms belong to application profiles, including the accompanying document-validation draft. It does not propose another MTC certificate type or make every artifact deployment use one trust framework. The code-signing SigningReceipt establishes certificate inclusion in a batch; it is not evidence of a later document-signing operation.

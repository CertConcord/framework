# Retention horizon clarification for MTC signed artifacts

Target: draft-gray-plants-mtc-deploy-use-cases-01, signed-artifact deployment analysis and archival obligations in section 3.5. Status: proposed clarification, not submitted.

The minimum archive horizon associated with certificate validity does not state what a document application needs when validation continues after certificate expiry. The distinction affects standalone evidence distribution, issuer retirement and who retains historical status and operator authority.

Proposed addition:

> For signed artifacts whose intended validation horizon extends beyond signing-certificate validity, a deployment needs an explicit retention period and responsible archive parties. Retained verification inputs include certificate/proof material and the authority, status and time evidence required by the selected application. Certificate expiry alone does not terminate that responsibility. Issuer retirement needs a continuity arrangement for those inputs.

This addition is informative deployment guidance. Exact container augmentation, policy decisions and preservation algorithms belong to application profiles, including the accompanying document-validation draft. It does not propose another MTC certificate type or make every artifact deployment use one trust framework.

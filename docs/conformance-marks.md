# Conformance mark policy — draft reference

No CertConcord conformance mark, certification program or active mark grant is established by draft 02. The following retained administrative rules describe how an explicitly established future designation would need to be scoped and evidenced. The empty register does not award a mark, and the historical CertConcord label is not an active CertConcord designation.

## Eligibility and authorization

Only an implementation that passes every applicable requirement in its declared scope may receive or use a designated mark. Passing tests is necessary; use additionally requires an active, explicit grant by the recorded mark holder or authorized administrator. Local test results, repository ownership and publication of a reference implementation do not automatically award a mark.

A grant binds all of the following:

- Exact mark, holder, grantee and authenticated grant instrument.
- Implementation name and version, source revision or reproducible build identity, configuration digest and evaluated environment.
- Specification snapshot, roles, profiles, adapters, algorithms, custody levels and evidence plans in scope.
- A versioned assessment plan mapping every applicable normative requirement to evidence; every mandatory test has a passing result.
- Assessor authority, report/artifact digests, assessment date, validity period and an explicit administrative decision.

The [conformance requirements](../spec/bindings/CONFORMANCE-draft-02.md) determine applicability. A narrowly scoped component mark must display that scope next to the mark; it must not imply complete trust-domain conformance. An extension or experimental draft may only appear in a designation whose registered scope explicitly includes that draft. Passing an OIDF, EUDI or platform-specific assessment supports its stated scope and cannot independently grant a CertConcord or CertConcord mark.

## Assessment and decision

The administrator approves the plan and eligible assessor before evaluating the report. Mandatory requirements cannot be omitted, marked inapplicable or overridden by a test-count total. Unsupported, indeterminate and failed required results are non-passing. The administrator verifies report authenticity and artifact integrity, resolves applicable non-test review requirements and signs the scoped grant only after a passing decision.

[Assessment import](../reference/interop/import-result.mjs) checks report and artifact integrity. The [mark validator](../reference/governance/README.md) additionally binds the approved plan, assessor, implementation, report and grant to a trusted register, verifies every required result and checks time and lifecycle state. Neither utility independently establishes the legal identity of an assessor or rights holder; those are authenticated during registration.

## Use, changes and lifecycle

Authorized display includes a link to the grant record, implementation version, scope and validity period. The mark may not be altered or used as an organizational endorsement, legal-signature qualification, security warranty or claim about unassessed features. Accurate self-descriptions such as support for a named profile remain distinct from a designated conformance mark.

A material change to protocol behavior, dependencies affecting assurance, custody, trust policy, deployment or enabled profiles requires reassessment before use for the changed configuration. Renewal requires current evidence and a new grant period. A verified regression, misrepresentation, security incident affecting the evaluated scope or expired evidence may cause suspension pending review; failure to remedy may cause revocation. Expired, suspended and revoked grants do not authorize display for current products. Historical assessment records remain available with their dates and state.

The administrator records reasons, notifies the grantee through its registered contact and provides an appeal reviewed by a person uninvolved in the original disputed decision. Corrections and lifecycle transitions are appended with references to the preceding record; historical evidence is preserved. An appeal does not reinstate a suspended mark unless an explicit decision does so.

## Separation from implementation rights

Implementation, modification and distribution rights come from the applicable copyright and patent instruments. Implementers need no conformance-mark grant to exercise those rights or to make accurate technical compatibility statements. Mark administration cannot narrow Apache-2.0, CC BY 4.0, CC0 or an executed OWFa commitment. [Trademark policy](../TRADEMARKS.md) governs general VeriCommons branding separately.

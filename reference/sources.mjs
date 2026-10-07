import { readFile, writeFile, rename, rm } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { sha256 } from './core.mjs';
const arf3 =
  'https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/c64f2cbb19aee37c571c58af66d359c4d5be29c8/docs/';
export const sources = {
  c2spCheckpoint:
    'https://raw.githubusercontent.com/C2SP/C2SP/a29318317776ae8a0e65ff45cfe450fd935a1aca/tlog-checkpoint.md',
  rfc9360: 'https://www.rfc-editor.org/rfc/rfc9360.txt',
  wg10WorkingDraft:
    'https://raw.githubusercontent.com/ISOWG10/ISO-18013/b250e7a64f99e22ceed10d2a5799bed38ee89f85/Working%20Documents/Working%20Draft%20ISO_IEC_18013-5_second-edition_CD_ballot_resolution_v4.pdf',
  mtcDeploymentUseCases:
    'https://www.ietf.org/archive/id/draft-gray-plants-mtc-deploy-use-cases-01.txt',
  cades:
    'https://www.etsi.org/deliver/etsi_EN/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf',
  cadesERS:
    'https://www.etsi.org/deliver/etsi_ts/119100_119199/11912203/01.02.01_60/ts_11912203v010201p.pdf',
  cryptoSuites:
    'https://www.etsi.org/deliver/etsi_ts/119300_119399/119312/02.01.01_60/ts_119312v020101p.pdf',
  pades:
    'https://www.etsi.org/deliver/etsi_EN/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf',
  jades:
    'https://www.etsi.org/deliver/etsi_TS/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf',
  adesValidation:
    'https://www.etsi.org/deliver/etsi_EN/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf',
  fcafProvider:
    'https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-doc-functional-conformance-assessment/2b223b56be0d0a073ee0cdc9db1d7fd31d9529a1/docs/fcaf/suts/wallet_solution/attestation_provider/test-cases.md',
  fcafRP:
    'https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-doc-functional-conformance-assessment/2b223b56be0d0a073ee0cdc9db1d7fd31d9529a1/docs/fcaf/suts/wallet_solution/relying_party/test-cases.md',
  fcafICS:
    'https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-doc-functional-conformance-assessment/2b223b56be0d0a073ee0cdc9db1d7fd31d9529a1/docs/fcaf/ics.md',
  fcafIndex:
    'https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-doc-functional-conformance-assessment/2b223b56be0d0a073ee0cdc9db1d7fd31d9529a1/docs/fcaf/index.md',
  'oidf-VCIIssuerTestPlan':
    'https://raw.githubusercontent.com/openid-certification/conformance-suite/949724883989f9f067ea728c7c13cacc18bbd81f/src/main/java/net/openid/conformance/vci10issuer/VCIIssuerTestPlan.java',
  'oidf-VCIIssuerTestPlanHaip':
    'https://raw.githubusercontent.com/openid-certification/conformance-suite/949724883989f9f067ea728c7c13cacc18bbd81f/src/main/java/net/openid/conformance/vci10issuer/VCIIssuerTestPlanHaip.java',
  'oidf-VCIWalletTestPlan':
    'https://raw.githubusercontent.com/openid-certification/conformance-suite/949724883989f9f067ea728c7c13cacc18bbd81f/src/main/java/net/openid/conformance/vci10wallet/VCIWalletTestPlan.java',
  'oidf-VCIWalletTestPlanHaip':
    'https://raw.githubusercontent.com/openid-certification/conformance-suite/949724883989f9f067ea728c7c13cacc18bbd81f/src/main/java/net/openid/conformance/vci10wallet/VCIWalletTestPlanHaip.java',
  'oidf-VP1FinalVerifierTestPlan':
    'https://raw.githubusercontent.com/openid-certification/conformance-suite/949724883989f9f067ea728c7c13cacc18bbd81f/src/main/java/net/openid/conformance/vp1finalverifier/VP1FinalVerifierTestPlan.java',
  'oidf-VP1FinalVerifierTestPlanHaip':
    'https://raw.githubusercontent.com/openid-certification/conformance-suite/949724883989f9f067ea728c7c13cacc18bbd81f/src/main/java/net/openid/conformance/vp1finalverifier/VP1FinalVerifierTestPlanHaip.java',
  'oidf-VP1FinalWalletTestPlan':
    'https://raw.githubusercontent.com/openid-certification/conformance-suite/949724883989f9f067ea728c7c13cacc18bbd81f/src/main/java/net/openid/conformance/vp1finalwallet/VP1FinalWalletTestPlan.java',
  'oidf-VP1FinalWalletTestPlanHaip':
    'https://raw.githubusercontent.com/openid-certification/conformance-suite/949724883989f9f067ea728c7c13cacc18bbd81f/src/main/java/net/openid/conformance/vp1finalwallet/VP1FinalWalletTestPlanHaip.java',
  postgres18: 'https://www.postgresql.org/docs/18/warm-standby.html',
  jazzer4:
    'https://raw.githubusercontent.com/CodeIntelligenceTesting/jazzer.js/v4.0.0/docs/fuzz-targets.md',
  webauthn4: 'https://www.w3.org/TR/2026/WD-webauthn-4-20260915/',
  eudiFunctions3: arf3 + 'main/02-eudi-wallet-functionalities.md',
  eudiRoles3: arf3 + 'main/03-roles-within-the-eudi-wallet-ecosystem.md',
  eudiArchitecture3: arf3 + 'main/04-high-level-architecture.md',
  eudiData3: arf3 + 'main/05-data-model-and-data-exchange-protocols.md',
  eudiTrust3: arf3 + 'main/06-trust-model.md',
  eudiConformance3: arf3 + 'main/07-wallet-solution-certification-and-risk-management.md',
  eudiRequirements3: arf3 + 'annexes/annex-2/annex-2.02-high-level-requirements-by-topic.md',
  eudiPIDReference3: arf3 + 'annexes/annex-3/annex-3.01-pid-rulebook.md',
  eudiWUAReference3: arf3 + 'technical-specifications/ts3-wallet-unit-attestation.md',
  eudiPeerReference3: arf3 + 'technical-specifications/ts9-wallet-to-wallet-interactions.md',
  eudiLicense3:
    'https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/c64f2cbb19aee37c571c58af66d359c4d5be29c8/LICENCE',
  nobleCurves24:
    'https://raw.githubusercontent.com/paulmillr/noble-curves/656c4364dffa44c64aa0c49914b8000b278b67a9/README.md',
  yubicoARKGPreview:
    'https://raw.githubusercontent.com/YubicoLabs/build-with-us/b6fd13109a62936072d8ef84102262560507fb61/quickstart/ios/ARKGPreviewSign/ARKGQuickstart/ARKG/ARKG.swift',
  arkgP256:
    'https://raw.githubusercontent.com/Yubico/arkg-rfc/8ddd04d27ef7ea479d372c7b8bdfecfdad0d1e1c/draft-bradleylundberg-cfrg-arkg.md',
  arkgDraft: 'https://www.ietf.org/archive/id/draft-bradleylundberg-cfrg-arkg-11.txt',
  coseSplitSigning: 'https://www.ietf.org/archive/id/draft-ietf-cose-split-signing-algs-01.txt',
  webKitRemoteKeys:
    'https://raw.githubusercontent.com/WebKit/explainers/6ce73fa4f91bbe7fb1990b6c1e7276c8dbd12609/remote-cryptokeys/README.md',
  webauthnPR2078:
    'https://raw.githubusercontent.com/w3c/webauthn/28e878d6b31130a3621c0eb793529a65bf3dc162/index.bs',
  rawSigningV5:
    'https://raw.githubusercontent.com/yubicolabs/webauthn-sign-extension/812b911a2a5d737d2ebdb91ead8bfd78f8277710/index.bs',
  rawSigningV4: 'https://yubicolabs.github.io/webauthn-sign-extension/4/',
  passSignRFC:
    'https://raw.githubusercontent.com/codedpills/pass-sign/4ae5a3d077040632b0885947b63329ba99413fb3/docs/research/deliverables/doc-6-rfc-draft-v0.1.md',
  passSignProposal:
    'https://raw.githubusercontent.com/codedpills/pass-sign/4ae5a3d077040632b0885947b63329ba99413fb3/docs/research/deliverables/doc-5-protocol-proposal.md',
  mtc: 'https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-06.txt',
  mtcEditor:
    'https://raw.githubusercontent.com/ietf-plants-wg/merkle-tree-certs/44b1c0b8c54669a35e8d9e96f0e55bb3cab67757/draft-ietf-plants-merkle-tree-certs.md',
  webauthn: 'https://www.w3.org/TR/2026/REC-webauthn-3-20260825/',
  rawSigning:
    'https://raw.githubusercontent.com/w3c/webauthn/9d88b7681b10926a41fd18b78e206a01804ed855/explainers/raw-signing-extension.md',
  oid4vci: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html',
  oid4vp: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html',
  haip: 'https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html',
  oid4vp11:
    'https://raw.githubusercontent.com/openid/OpenID4VP/003e1b39e3244a2f293905dd503e7fd19f9434df/1.1/openid-4-verifiable-presentations-1_1.md',
  oid4vci11:
    'https://raw.githubusercontent.com/openid/OpenID4VCI/ebd8b70ae54ab97eaabf23a6648378a0a0729572/1.1/openid-4-verifiable-credential-issuance-1_1.md',
  haip11:
    'https://raw.githubusercontent.com/openid/OpenID4VC-HAIP/aac5372e4aa735667cd066ce4975904b27d120b4/1.1/openid4vc-high-assurance-interoperability-profile-1_1.md',
  joseHPKE: 'https://www.ietf.org/archive/id/draft-ietf-jose-hpke-encrypt-22.txt',
  oauthFirstParty: 'https://www.ietf.org/archive/id/draft-ietf-oauth-first-party-apps-04.txt',
  c2spMirror:
    'https://raw.githubusercontent.com/C2SP/C2SP/625d8db08a0f196540e40f0a2256332275492f78/tlog-mirror.md',
  c2spWitness:
    'https://raw.githubusercontent.com/C2SP/C2SP/a29318317776ae8a0e65ff45cfe450fd935a1aca/tlog-witness.md',
  c2spCosignature:
    'https://raw.githubusercontent.com/C2SP/C2SP/a29318317776ae8a0e65ff45cfe450fd935a1aca/tlog-cosignature.md',
  c2spNote:
    'https://raw.githubusercontent.com/C2SP/C2SP/a29318317776ae8a0e65ff45cfe450fd935a1aca/signed-note.md',
  c2spTiles:
    'https://raw.githubusercontent.com/C2SP/C2SP/a29318317776ae8a0e65ff45cfe450fd935a1aca/tlog-tiles.md',
  pkcs11:
    'https://raw.githubusercontent.com/oasis-tcs/pkcs11/6edf334c5b324626c95e82b0cb9737eaaa37a340/published/3-02/pkcs11t.h',
  openssl365:
    'https://github.com/openssl/openssl/releases/download/openssl-3.6.5/openssl-3.6.5.tar.gz',
  cscDataModel: 'https://cloudsignatureconsortium.org/wp-content/uploads/2025/10/csc-dm.pdf',
  csc: 'https://cloudsignatureconsortium.org/wp-content/uploads/2025/11/csc-api.pdf',
  androidAttestation: 'https://source.android.com/docs/security/features/keystore/attestation',
  androidKeyTrust: 'https://developer.android.com/privacy-and-security/security-key-attestation',
  androidVCIKeyProof:
    'https://developer.android.com/identity/digital-credentials/credential-issuer/keystore-attestation',
  appleManagedAttestation: 'https://support.apple.com/en-ca/guide/security/sec8a37b4cb2/web',
  appleAttestationValidation:
    'https://developer.apple.com/tutorials/data/documentation/devicemanagement/validating-a-managed-device-attestation-attestation.json',
  appleACMEPayload:
    'https://developer.apple.com/tutorials/data/documentation/devicemanagement/acmecertificate.json',
  acmeDeviceAttestation: 'https://www.ietf.org/archive/id/draft-ietf-acme-device-attest-10.txt',
  microsoftTBS:
    'https://learn.microsoft.com/en-us/windows/win32/api/tbs/nf-tbs-tbsip_submit_command',
  tpmCertify: 'https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_certify.1/',
  acmeProfiles: 'https://www.ietf.org/archive/id/draft-ietf-acme-profiles-02.txt',
  sdJWTVC: 'https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-19.txt',
  tokenStatusList: 'https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.txt',
  digitalCredentialsAPI: 'https://www.w3.org/TR/2026/WD-digital-credentials-20260904/',
  multipazMdoc:
    'https://raw.githubusercontent.com/openwallet-foundation/multipaz/0.100.0/multipaz/src/commonMain/kotlin/org/multipaz/mdoc/util/MdocUtil.kt',
  multipazAnnexC:
    'https://raw.githubusercontent.com/openwallet-foundation/multipaz/0.100.0/multipaz/src/commonMain/kotlin/org/multipaz/verification/VerificationUtil.kt',
  multipazPhotoID:
    'https://raw.githubusercontent.com/openwallet-foundation/multipaz/0.100.0/multipaz-doctypes/src/commonMain/kotlin/org/multipaz/documenttype/knowntypes/PhotoID.kt',
  eudiARF14:
    'https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/v1.4.0/docs/arf.md',
  eudiPID14:
    'https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/v1.4.0/docs/annexes/annex-3/annex-3.01-pid-rulebook.md',
  eudiRequirements14:
    'https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/v1.4.0/docs/annexes/annex-2/annex-2-high-level-requirements.md',
  appleIdentityServices: 'https://developer.apple.com/documentation/identitydocumentservices.md',
  appleIdentityProvider:
    'https://developer.apple.com/documentation/identitydocumentservices/implenting-as-an-identity-document-provider.md',
  appleIdentityWeb:
    'https://developer.apple.com/documentation/identitydocumentservices/requesting-a-mobile-document-on-the-web.md',
  appleIdentityEntitlement:
    'https://developer.apple.com/tutorials/data/documentation/bundleresources/entitlements/com.apple.developer.identity-document-services.document-provider.mobile-document-types.json',
  appleIdentityRegistration:
    'https://developer.apple.com/documentation/identitydocumentservices/mobiledocumentregistration.md',
  appleIdentityContext:
    'https://developer.apple.com/documentation/identitydocumentservicesui/iso18013mobiledocumentrequestcontext.md',
  appleIdentityDocumentRequest:
    'https://developer.apple.com/documentation/identitydocumentservices/iso18013mobiledocumentrequest/documentrequest.md',
  appleIdentityElementInfo:
    'https://developer.apple.com/documentation/identitydocumentservices/iso18013mobiledocumentrequest/elementinfo.md',
  appleIdentityRequestType:
    'https://developer.apple.com/documentation/identitydocumentservices/identitydocumentwebpresentmentrawrequest/requesttype-swift.enum.md',
  appleDigitalID:
    'https://developer.apple.com/documentation/identitydocumentservices/verifying-a-mobile-document-from-a-passport.md',
  ...Object.fromEntries(
    [
      5280, 5652, 5869, 3394, 5649, 8949, 9052, 9629, 9881, 9882, 9883, 9935, 9936, 3161, 5816,
      5035, 4998, 6283, 8555, 9901, 9449, 9964, 9180, 6960, 2986, 9810, 7797, 7515, 7516, 7518,
      7638, 6211,
    ].map((n) => ['rfc' + n, `https://www.rfc-editor.org/rfc/rfc${n}.txt`]),
  ),
};
// Maintenance command. Runtime never downloads specifications or silently changes adapters.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [command, ...ids] = process.argv.slice(2);
  if (command !== '--refresh') throw Error('Usage: node sources.mjs --refresh [sourceID ...]');
  const selected = ids.length ? ids : Object.keys(sources);
  if (new Set(selected).size !== selected.length) throw Error('Duplicate source ID');
  for (const id of selected)
    if (!Object.hasOwn(sources, id)) throw Error(`Unknown source ID: ${id}`);
  const lockURL = new URL('./source-lock.json', import.meta.url);
  const lock = JSON.parse(await readFile(lockURL, 'utf8'));
  const pkg = JSON.parse(await readFile(new URL('./package.json', import.meta.url), 'utf8'));
  const entries = new Map(lock.sources.map((entry) => [entry.id, entry]));
  for (const id of selected) {
    const url = sources[id];
    const res = await fetch(url, { signal: AbortSignal.timeout(30000) });
    if (!res.ok) throw Error(`${id}: HTTP ${res.status}`);
    const body = Buffer.from(await res.arrayBuffer());
    if (!body.length) throw Error(`${id}: empty source`);
    entries.set(id, {
      id,
      url,
      sha256: sha256(body).toString('hex'),
      bytes: body.length,
      retrievedAt: new Date().toISOString(),
    });
    console.log(id, body.length);
  }
  const temporaryURL = new URL(`./source-lock.json.${process.pid}.tmp`, import.meta.url);
  try {
    await writeFile(
      temporaryURL,
      JSON.stringify({ ...lock, release: pkg.version, sources: [...entries.values()] }, null, 2) +
        '\n',
      { flag: 'wx' },
    );
    await rename(temporaryURL, lockURL);
  } finally {
    await rm(temporaryURL, { force: true });
  }
}

import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.time.Instant;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.tsp.*;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.ers.*;

/** Fixed-input compatibility probe. Token signature checks do not establish TSA trust. */
public class ErsBc186Probe {
    static DigestCalculatorProvider digests;
    static String hex(byte[] b) { return HexFormat.of().formatHex(b); }
    static byte[] hash(String alg, byte[]... parts) throws Exception {
        MessageDigest md = MessageDigest.getInstance(alg);
        for (byte[] p : parts) md.update(p);
        return md.digest();
    }
    static byte[] read(Path corpus, String sha, String suffix) throws Exception {
        byte[] b = Base64.getMimeDecoder().decode(Files.readString(corpus.resolve("files/" + sha + suffix)));
        if (!hex(hash("SHA-256", b)).equals(sha)) throw new IllegalStateException("input hash mismatch");
        return b;
    }
    static EvidenceRecord parse(byte[] b) throws Exception {
        return EvidenceRecord.getInstance(ASN1Primitive.fromByteArray(b));
    }
    static byte[] prefix(EvidenceRecord record, int stamps) throws Exception {
        ArchiveTimeStamp[] ats = record.getArchiveTimeStampSequence().getArchiveTimeStampChains()[0].getArchiveTimestamps();
        ArchiveTimeStampChain chain = new ArchiveTimeStampChain(Arrays.copyOf(ats, stamps));
        return new EvidenceRecord(new AlgorithmIdentifier[]{ats[0].getDigestAlgorithmIdentifier()}, null, null,
            new ArchiveTimeStampSequence(chain)).getEncoded("DER");
    }
    static String quote(String s) { return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r") + "\""; }
    static int caseResult(String id, byte[] data, byte[] record, boolean expectedPresence, int expectedValidSignatures) throws Exception {
        boolean present = false; String error = "", phase = "construct", tokenParsingError = ""; int valid = 0; int total = 0;
        List<String> tokenResults = new ArrayList<>();
        try {
            ERSEvidenceRecord parsed = new ERSEvidenceRecord(record, digests);
            phase = "validate-present";
            parsed.validatePresent(new ERSByteData(data), Date.from(Instant.ofEpochSecond(1792627202)));
            phase = "complete";
            present = true;
        } catch (Exception e) { error = e.getClass().getSimpleName() + ": " + e.getMessage(); }
        try {
            for (ArchiveTimeStampChain chain : parse(record).getArchiveTimeStampSequence().getArchiveTimeStampChains()) {
                for (ArchiveTimeStamp ats : chain.getArchiveTimestamps()) {
                    total++;
                    boolean signatureValid = false, constraintsValid = false; String tokenError = "";
                    try {
                        TimeStampToken token = new TimeStampToken(ats.getTimeStamp());
                        Collection<X509CertificateHolder> certs = token.getCertificates().getMatches(token.getSID());
                        if (certs.size() != 1) throw new IllegalStateException("ambiguous TSA signer");
                        var verifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certs.iterator().next());
                        signatureValid = token.isSignatureValid(verifier);
                        token.validate(verifier);
                        constraintsValid = true;
                        valid++;
                    } catch (Exception e) { tokenError = e.getClass().getSimpleName() + ": " + e.getMessage(); }
                    tokenResults.add("{\"index\":" + total + ",\"signatureValid\":" + signatureValid + ",\"constraintsValid\":" + constraintsValid + ",\"error\":" + quote(tokenError) + "}");
                }
            }
        } catch (Exception e) { tokenParsingError = e.getClass().getSimpleName() + ": " + e.getMessage(); }
        boolean matched = present == expectedPresence && valid == expectedValidSignatures;
        System.out.println("{\"case\":" + quote(id) + ",\"dataSHA256\":" + quote(hex(hash("SHA-256", data)))
            + ",\"recordSHA256\":" + quote(hex(hash("SHA-256", record))) + ",\"expectedPresence\":" + expectedPresence
            + ",\"presence\":" + present + ",\"presencePhase\":" + quote(phase) + ",\"presenceError\":" + quote(error) + ",\"expectedValidTokenSignatures\":" + expectedValidSignatures
            + ",\"validTokenSignatures\":" + valid + ",\"totalTokens\":" + total + ",\"tokenResults\":[" + String.join(",", tokenResults) + "],\"tokenParsingError\":" + quote(tokenParsingError) + ",\"compatibilityExpectationMatched\":" + matched + "}");
        return matched ? 1 : 0;
    }
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        if (!Security.getProvider("BC").getVersionStr().equals("1.86")) throw new IllegalStateException("BC 1.86 required");
        digests = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
        Path corpus = Path.of(args[0]);
        byte[] original = read(corpus, "09e93450939c93b3dce9daa2ab8f278a357701b46d2d93f0c4fba3c9a0839133", ".cbor.b64");
        byte[] timely = read(corpus, "148c25cb9fb9c16846eb14ece6bc8927bdf442444d7ff76168b680236b343050", ".der.b64");
        byte[] initial = read(corpus, "456167c872b5e60e7ed55e199924cf460bea3dd4fb6e91cca80c8f009b219040", ".der.b64");
        byte[] late = read(corpus, "6a3851994afc0cf36df9ae9668c7ed04b54426fe47deec89d148cfb4086b3230", ".der.b64");
        EvidenceRecord er = parse(timely);
        if (!Arrays.equals(initial, prefix(er, 1))) throw new IllegalStateException("initial control differs from recorded prefix");
        byte[] timestampOnly = prefix(er, 2), corrupt = timely.clone(), changed = original.clone();
        corrupt[corrupt.length - 1] ^= 1; changed[changed.length - 1] ^= 1;
        int matched = 0;
        matched += caseResult("initial", original, initial, true, 1);
        matched += caseResult("timestamp-only", original, timestampOnly, true, 2);
        matched += caseResult("timely-hash-renewal", original, timely, true, 3);
        matched += caseResult("late-hash-renewal", original, late, true, 3);
        matched += caseResult("corrupt-final-signature", original, corrupt, true, 2);
        matched += caseResult("changed-original-initial", changed, initial, false, 1);
        matched += caseResult("truncated-record", original, Arrays.copyOf(timely, timely.length - 1), false, 0);
        matched += caseResult("changed-original-renewed", changed, timely, false, 3);
        ArchiveTimeStampChain[] chains = er.getArchiveTimeStampSequence().getArchiveTimeStampChains();
        byte[] previous = new ArchiveTimeStampSequence(chains[0]).getEncoded("DER");
        byte[] d = hash("SHA-512", original), h = hash("SHA-512", previous);
        byte[] sorted = Arrays.compareUnsigned(d, h) < 0 ? hash("SHA-512", d, h) : hash("SHA-512", h, d);
        byte[] bc = new ERSByteData(original).getHash(digests.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512)), h);
        byte[] observed = new TimeStampToken(chains[1].getArchiveTimestamps()[0].getTimeStamp()).getTimeStampInfo().getMessageImprintDigest();
        System.out.println("{\"diagnostic\":true,\"dataSHA512\":" + quote(hex(d)) + ",\"previousSequenceSHA512\":" + quote(hex(h))
            + ",\"sortedPairSHA512\":" + quote(hex(sorted)) + ",\"dataThenChainSHA512\":" + quote(hex(hash("SHA-512", d, h)))
            + ",\"bcERSByteDataHash\":" + quote(hex(bc)) + ",\"observedImprint\":" + quote(hex(observed)) + "}");
        System.out.println("{\"cases\":8,\"compatibilityExpectationsMatched\":" + matched + ",\"bcVersion\":\"1.86\",\"javaVersion\":" + quote(System.getProperty("java.version")) + ",\"completeTrustEstablished\":false}");
        if (matched != 8) System.exit(1);
    }
}

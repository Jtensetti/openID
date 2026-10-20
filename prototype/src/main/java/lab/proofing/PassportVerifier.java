package lab.proofing;

import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.time.*;
import java.util.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jmrtd.lds.SODFile;
import org.jmrtd.lds.icao.DG1File;
import org.jmrtd.lds.icao.DG2File;

/** Passive authentication of SOD, DG1 and DG2 against an operator-provided CSCA. */
public final class PassportVerifier {
  public record Identity(String givenNames, String familyName, String birthDateMrz, String nationality,
      String issuingState, String documentNumber, String documentExpires) {}
  public record Result(byte[] portrait, String mimeType, LocalDate expires, Identity identity) {
    public Result { portrait = portrait.clone(); }
    @Override public byte[] portrait() { return portrait.clone(); }
  }
  public static final class Rejected extends Exception {
    Rejected() { super("Passport verification failed"); }
  }
  private static final Provider BC = new BouncyCastleProvider();
  private final Set<TrustAnchor> anchors;
  private final Clock clock;
  public PassportVerifier(Set<X509Certificate> trustedCscas, Clock clock) {
    if (trustedCscas.isEmpty()) throw new IllegalArgumentException("Operator-provisioned CSCA trust is required");
    var set = new HashSet<TrustAnchor>();
    for (var certificate : trustedCscas) {
      if (certificate.getBasicConstraints() < 0 || certificate.getKeyUsage() == null || !certificate.getKeyUsage()[5])
        throw new IllegalArgumentException("CSCA must be a certificate-signing CA");
      set.add(new TrustAnchor(certificate, null));
    }
    anchors = Set.copyOf(set); this.clock = clock;
  }
  public Result verify(byte[] sodBytes, byte[] dg1Bytes, byte[] dg2Bytes) throws Rejected {
    try {
      bounded(sodBytes, 65536); bounded(dg1Bytes, 4096); bounded(dg2Bytes, 2_000_000);
      // BC rejects trailing ASN.1 objects. SOD is the application-23 wrapper around CMS.
      var wrapper = ASN1TaggedObject.getInstance(ASN1Primitive.fromByteArray(sodBytes));
      if (!wrapper.hasTag(BERTags.APPLICATION, 23)) throw new Rejected();
      var cms = new CMSSignedData(wrapper.getExplicitBaseObject().getEncoded());
      if (!"2.23.136.1.1.1".equals(cms.getSignedContentTypeOID()) || cms.getSignerInfos().size() != 1) throw new Rejected();
      var signer = cms.getSignerInfos().getSigners().iterator().next();
      if (!Set.of("2.16.840.1.101.3.4.2.1", "2.16.840.1.101.3.4.2.2", "2.16.840.1.101.3.4.2.3").contains(signer.getDigestAlgOID())) throw new Rejected();
      var candidates = cms.getCertificates().getMatches(signer.getSID());
      if (candidates.size() != 1) throw new Rejected();
      var certificate = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().setProvider(BC)
          .getCertificate((org.bouncycastle.cert.X509CertificateHolder)candidates.iterator().next());
      if (certificate.getBasicConstraints() >= 0 || certificate.getKeyUsage() == null || !certificate.getKeyUsage()[0]) throw new Rejected();
      // Deliberately direct DSC -> provisioned CSCA only. No AIA, network fetch or embedded trust root.
      var parameters = new PKIXParameters(anchors);
      parameters.setDate(Date.from(clock.instant())); parameters.setRevocationEnabled(false);
      var path = CertificateFactory.getInstance("X.509").generateCertPath(List.of(certificate));
      var validation = (PKIXCertPathValidatorResult)CertPathValidator.getInstance("PKIX").validate(path, parameters);
      validation.getTrustAnchor().getTrustedCert().checkValidity(Date.from(clock.instant()));
      if (!signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(certificate))) throw new Rejected();
      var sod = new SODFile(new ByteArrayInputStream(sodBytes));
      if (!Set.of("SHA-256", "SHA-384", "SHA-512", "SHA256", "SHA384", "SHA512").contains(sod.getDigestAlgorithm())) throw new Rejected();
      var digest = MessageDigest.getInstance(sod.getDigestAlgorithm());
      var hashes = sod.getDataGroupHashes();
      if (!hashes.containsKey(1) || !hashes.containsKey(2) ||
          !MessageDigest.isEqual(hashes.get(1), digest.digest(dg1Bytes)) ||
          !MessageDigest.isEqual(hashes.get(2), digest.digest(dg2Bytes))) throw new Rejected();
      // Parse identity/portrait only after authenticating their exact encoded data groups.
      var dg1Input = new ByteArrayInputStream(dg1Bytes);
      var mrz = new DG1File(dg1Input).getMRZInfo();
      if (dg1Input.available() != 0 || mrz.getDocumentType() != 3 || !mrz.getDocumentCode().startsWith("P")) throw new Rejected();
      var date = mrz.getDateOfExpiry();
      if (!date.matches("[0-9]{6}")) throw new Rejected();
      var expiry = LocalDate.of(2000 + Integer.parseInt(date.substring(0, 2)), Integer.parseInt(date.substring(2, 4)), Integer.parseInt(date.substring(4, 6)));
      var today = LocalDate.now(clock);
      if (expiry.isBefore(today) || expiry.isAfter(today.plusYears(20))) throw new Rejected();
      var dg2Input = new ByteArrayInputStream(dg2Bytes);
      var faces = new DG2File(dg2Input).getFaceInfos();
      if (dg2Input.available() != 0 || faces.size() != 1 || faces.getFirst().getFaceImageInfos().size() != 1) throw new Rejected();
      var portrait = faces.getFirst().getFaceImageInfos().getFirst();
      byte[] image = portrait.getImageInputStream().readNBytes(2_000_001);
      bounded(image, 2_000_000);
      if (!Set.of("image/jpeg", "image/jp2").contains(portrait.getMimeType())) throw new Rejected();
      String birth = mrz.getDateOfBirth();
      if (!birth.matches("[0-9]{6}")) throw new Rejected();
      // MRZ does not encode the century. Validate month/day without assigning one.
      LocalDate.of(2000, Integer.parseInt(birth.substring(2, 4)), Integer.parseInt(birth.substring(4, 6)));
      var identity = new Identity(name(mrz.getSecondaryIdentifier()), name(mrz.getPrimaryIdentifier()), birth,
          mrz.getNationality(), mrz.getIssuingState(), mrz.getDocumentNumber(), expiry.toString());
      if (identity.familyName().isEmpty() && identity.givenNames().isEmpty()) throw new Rejected();
      return new Result(image, portrait.getMimeType(), expiry, identity);
    } catch (Exception e) { throw new Rejected(); } // No untrusted document contents in logs/errors.
  }
  private static String name(String value) throws Rejected {
    String normalized = value.replace('<', ' ').strip().replaceAll(" +", " ");
    if (!normalized.matches("[A-Z ]{0,44}")) throw new Rejected();
    return normalized;
  }
  private static void bounded(byte[] bytes, int max) throws Rejected {
    if (bytes == null || bytes.length == 0 || bytes.length > max) throw new Rejected();
  }
}

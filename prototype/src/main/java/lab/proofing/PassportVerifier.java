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
      String issuingState, String documentNumber, String documentExpires, String passportPersonalNumber) {
    public Identity(String givenNames, String familyName, String birthDateMrz, String nationality,
        String issuingState, String documentNumber, String documentExpires) {
      this(givenNames, familyName, birthDateMrz, nationality, issuingState, documentNumber, documentExpires, null);
    }
  }
  /** {@code revocation}: CHECKED_CRL when a current, CSCA-signed CRL was consulted; otherwise NOT_CHECKED. */
  public record Result(byte[] portrait, String mimeType, LocalDate expires, Identity identity,
      String revocation, long revocationValidUntil) {
    public Result { portrait = portrait.clone(); }
    public Result(byte[] portrait, String mimeType, LocalDate expires, Identity identity) { this(portrait, mimeType, expires, identity, "NOT_CHECKED", 0); }
    @Override public byte[] portrait() { return portrait.clone(); }
  }
  public static final class Rejected extends Exception {
    private final String stage;
    Rejected() { this("DOCUMENT"); }
    Rejected(String stage) { super("Passport verification failed"); this.stage = stage; }
    public String stage() { return stage; }
  }
  private static final Provider BC = new BouncyCastleProvider();
  /** Parse operator-provisioned anchors with explicit EC parameter support. */
  public static Set<X509Certificate> loadTrust(InputStream stream) throws CertificateException {
    var certificates = new HashSet<X509Certificate>();
    for (var certificate : CertificateFactory.getInstance("X.509", BC).generateCertificates(stream))
      certificates.add((X509Certificate)certificate);
    return Set.copyOf(certificates);
  }
  /** Operator-provisioned CRLs, e.g. Polismyndigheten's SWE.crl from cert.polisen.se/CSCA. */
  public static List<X509CRL> loadCrls(InputStream stream) throws CertificateException, CRLException {
    var crls = new ArrayList<X509CRL>();
    for (var crl : CertificateFactory.getInstance("X.509", BC).generateCRLs(stream)) crls.add((X509CRL)crl);
    return List.copyOf(crls);
  }
  private final Set<TrustAnchor> anchors;
  private final List<X509CRL> crls;
  private final Clock clock;
  public PassportVerifier(Set<X509Certificate> trustedCscas, Clock clock) { this(trustedCscas, List.of(), clock); }
  /**
   * With CRLs, revocation is checked and fails closed: every document signer must be covered by a current CRL
   * signed by its CSCA. Without CRLs, revocation is not checked and the result says so.
   */
  public PassportVerifier(Set<X509Certificate> trustedCscas, List<X509CRL> crls, Clock clock) {
    if (trustedCscas.isEmpty()) throw new IllegalArgumentException("Operator-provisioned CSCA trust is required");
    var set = new HashSet<TrustAnchor>();
    for (var certificate : trustedCscas) {
      if (certificate.getBasicConstraints() < 0 || certificate.getKeyUsage() == null || !certificate.getKeyUsage()[5])
        throw new IllegalArgumentException("CSCA must be a certificate-signing CA");
      set.add(new TrustAnchor(certificate, null));
    }
    anchors = Set.copyOf(set); this.clock = clock;
    for (var crl : crls) {
      // This verifier supports complete direct CRLs only, never a partial view
      // which could omit a revoked signer. Reject unknown critical semantics.
      if (crl.hasUnsupportedCriticalExtension() || crl.getExtensionValue("2.5.29.27") != null
          || crl.getExtensionValue("2.5.29.28") != null)
        throw new IllegalArgumentException("Complete direct CRL required");
      // Each CRL must be signed by a provisioned CSCA; an unrelated CRL is a configuration error, not an ignore.
      boolean signed = trustedCscas.stream().anyMatch(ca -> {
        if (!ca.getSubjectX500Principal().equals(crl.getIssuerX500Principal())
            || ca.getKeyUsage().length <= 6 || !ca.getKeyUsage()[6]) return false;
        try { crl.verify(ca.getPublicKey(), BC); return true; } catch (GeneralSecurityException e) { return false; }
      });
      if (!signed) throw new IllegalArgumentException("CRL must be signed by a provisioned CSCA");
    }
    this.crls = List.copyOf(crls);
  }
  private record Revocation(String status, long validUntil) {}
  private Revocation revocation(X509Certificate documentSigner, X509Certificate anchor) throws Rejected {
    if (crls.isEmpty()) return new Revocation("NOT_CHECKED", 0);
    Date now = Date.from(clock.instant());
    long validUntil = 0;
    for (var crl : crls) {
      // ICAO 9303-12: the CSCA's current key signs one CRL for all document signers under its name, also those
      // issued with an earlier CSCA key. Each CRL was verified against a provisioned CSCA at construction.
      if (!crl.getIssuerX500Principal().equals(documentSigner.getIssuerX500Principal())) continue;
      if (crl.isRevoked(documentSigner) || crl.isRevoked(anchor)) throw new Rejected("REVOKED");
      if (!crl.getThisUpdate().after(now) && crl.getNextUpdate() != null && crl.getNextUpdate().after(now))
        validUntil = Math.max(validUntil, crl.getNextUpdate().toInstant().getEpochSecond());
    }
    if (validUntil == 0) throw new Rejected("REVOCATION_STATUS");
    validUntil = Math.min(validUntil, documentSigner.getNotAfter().toInstant().getEpochSecond());
    validUntil = Math.min(validUntil, anchor.getNotAfter().toInstant().getEpochSecond());
    return new Revocation("CHECKED_CRL", validUntil);
  }
  public Result verify(byte[] sodBytes, byte[] dg1Bytes, byte[] dg2Bytes) throws Rejected {
    String stage = "FORMAT";
    try {
      bounded(sodBytes, 65536); bounded(dg1Bytes, 4096); bounded(dg2Bytes, 2_000_000);
      // BC rejects trailing ASN.1 objects. SOD is the application-23 wrapper around CMS.
      var wrapper = ASN1TaggedObject.getInstance(ASN1Primitive.fromByteArray(sodBytes));
      if (!wrapper.hasTag(BERTags.APPLICATION, 23)) throw new Rejected();
      var cms = new CMSSignedData(wrapper.getExplicitBaseObject().getEncoded());
      if (!"2.23.136.1.1.1".equals(cms.getSignedContentTypeOID()) || cms.getSignerInfos().size() != 1) throw new Rejected();
      stage = "SIGNER";
      var signer = cms.getSignerInfos().getSigners().iterator().next();
      if (!Set.of("2.16.840.1.101.3.4.2.1", "2.16.840.1.101.3.4.2.2", "2.16.840.1.101.3.4.2.3").contains(signer.getDigestAlgOID())) throw new Rejected();
      var candidates = cms.getCertificates().getMatches(signer.getSID());
      if (candidates.size() != 1) throw new Rejected();
      var certificate = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().setProvider(BC)
          .getCertificate((org.bouncycastle.cert.X509CertificateHolder)candidates.iterator().next());
      if (certificate.getBasicConstraints() >= 0 || certificate.getKeyUsage() == null || !certificate.getKeyUsage()[0]) throw new Rejected();
      // Deliberately direct DSC -> provisioned CSCA only. No AIA, network fetch or embedded trust root.
      stage = "TRUST_CHAIN";
      var parameters = new PKIXParameters(anchors);
      parameters.setDate(Date.from(clock.instant())); parameters.setRevocationEnabled(false);
      var path = CertificateFactory.getInstance("X.509", BC).generateCertPath(List.of(certificate));
      var validation = (PKIXCertPathValidatorResult)CertPathValidator.getInstance("PKIX", BC).validate(path, parameters);
      validation.getTrustAnchor().getTrustedCert().checkValidity(Date.from(clock.instant()));
      stage = "REVOCATION_STATUS";
      var revocation = revocation(certificate, validation.getTrustAnchor().getTrustedCert());
      stage = "SIGNATURE";
      if (!signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(certificate))) throw new Rejected();
      stage = "DATA_HASHES";
      var sod = new SODFile(new ByteArrayInputStream(sodBytes));
      if (!Set.of("SHA-256", "SHA-384", "SHA-512", "SHA256", "SHA384", "SHA512").contains(sod.getDigestAlgorithm())) throw new Rejected();
      var digest = MessageDigest.getInstance(sod.getDigestAlgorithm());
      var hashes = sod.getDataGroupHashes();
      if (!hashes.containsKey(1) || !hashes.containsKey(2) ||
          !MessageDigest.isEqual(hashes.get(1), digest.digest(dg1Bytes)) ||
          !MessageDigest.isEqual(hashes.get(2), digest.digest(dg2Bytes))) throw new Rejected();
      // Parse identity/portrait only after authenticating their exact encoded data groups.
      stage = "IDENTITY_FORMAT";
      var dg1Input = new ByteArrayInputStream(dg1Bytes);
      var mrz = new DG1File(dg1Input).getMRZInfo();
      if (dg1Input.available() != 0 || mrz.getDocumentType() != 3 || !mrz.getDocumentCode().startsWith("P")) throw new Rejected();
      stage = "DOCUMENT_DATE";
      var date = mrz.getDateOfExpiry();
      if (!date.matches("[0-9]{6}")) throw new Rejected();
      var expiry = LocalDate.of(2000 + Integer.parseInt(date.substring(0, 2)), Integer.parseInt(date.substring(2, 4)), Integer.parseInt(date.substring(4, 6)));
      var today = LocalDate.now(clock);
      if (expiry.isBefore(today) || expiry.isAfter(today.plusYears(20))) throw new Rejected();
      stage = "PORTRAIT_FORMAT";
      var dg2Input = new ByteArrayInputStream(dg2Bytes);
      var faces = new DG2File(dg2Input).getFaceInfos();
      if (dg2Input.available() != 0 || faces.size() != 1 || faces.getFirst().getFaceImageInfos().size() != 1) throw new Rejected();
      var portrait = faces.getFirst().getFaceImageInfos().getFirst();
      byte[] image = portrait.getImageInputStream().readNBytes(2_000_001);
      bounded(image, 2_000_000);
      if (!Set.of("image/jpeg", "image/jp2").contains(portrait.getMimeType())) throw new Rejected();
      stage = "IDENTITY_FORMAT";
      String birth = mrz.getDateOfBirth();
      if (!birth.matches("[0-9]{6}")) throw new Rejected();
      // MRZ does not encode the century. Validate month/day without assigning one.
      LocalDate.of(2000 + Integer.parseInt(birth.substring(0, 2)), Integer.parseInt(birth.substring(2, 4)), Integer.parseInt(birth.substring(4, 6)));
      var identity = new Identity(name(mrz.getSecondaryIdentifier()), name(mrz.getPrimaryIdentifier()), birth,
          mrz.getNationality(), mrz.getIssuingState(), mrz.getDocumentNumber(), expiry.toString(), personalNumber(mrz));
      if (identity.familyName().isEmpty() && identity.givenNames().isEmpty()) throw new Rejected();
      return new Result(image, portrait.getMimeType(), expiry, identity, revocation.status(), revocation.validUntil());
    } catch (Rejected e) { throw "REVOKED".equals(e.stage()) ? e : new Rejected(stage); }
    catch (Exception e) { throw new Rejected(stage); } // No untrusted document contents in logs/errors.
  }
  /** Signed DG1 only. Preserve the supplied century (or its absence); not a registry check. */
  private static String personalNumber(org.jmrtd.lds.icao.MRZInfo mrz) throws Rejected {
    if (!"SWE".equals(mrz.getIssuingState())) return null;
    String value = mrz.getPersonalNumber();
    if (value == null) return null;
    value = value.replaceFirst("<+$", "");
    if (value.isEmpty()) return null;
    if (!value.matches("(?:[0-9]{10}|[0-9]{12})")) throw new Rejected("PERSONAL_NUMBER_FORMAT");
    String shortValue = value.substring(value.length() - 10);
    int year = value.length() == 12 ? Integer.parseInt(value.substring(0, 4)) : 2000 + Integer.parseInt(shortValue.substring(0, 2));
    if (year < 1) throw new Rejected("PERSONAL_NUMBER_FORMAT");
    int day = Integer.parseInt(shortValue.substring(4, 6));
    // Coordination numbers use day + 60. This does not establish their registry status.
    if (day > 60) day -= 60;
    try { LocalDate.of(year, Integer.parseInt(shortValue.substring(2, 4)), day); }
    catch (java.time.DateTimeException e) { throw new Rejected("PERSONAL_NUMBER_FORMAT"); }
    int sum = 0;
    for (int i = 0; i < 10; i++) {
      int product = (shortValue.charAt(i) - '0') * (i % 2 == 0 ? 2 : 1);
      sum += product / 10 + product % 10;
    }
    if (sum % 10 != 0) throw new Rejected("PERSONAL_NUMBER_FORMAT");
    return value;
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

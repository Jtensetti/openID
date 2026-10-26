package lab.signing;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.spec.ECGenParameterSpec;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.*;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.*;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.ess.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.*;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.*;

/**
 * PAdES-B-B signatures for the account service's signature test. The signing certificate is issued on demand to the
 * person in a verified SAML assertion, like a Sweden Connect central signing service. The issuing CA is created per
 * process and is NOT trusted by anyone: this is a test profile, not a qualified or advanced production signature.
 */
public final class PadesSigner {
  private static final Provider BC = new BouncyCastleProvider();
  /** Private test policy OID (UUID arc); tells validators that the certificate is a test certificate. */
  public static final String TEST_POLICY = "2.25.214329817396745329813218939481256397201";
  private final KeyPair authorityKey;
  private final X509Certificate authority;
  private final Clock clock;

  public record Signer(String displayName, String subject, String birthDateMrz) {
    public Signer {
      if (displayName == null || !displayName.matches("[A-Z ]{1,64}") || subject == null || !subject.matches("[a-f0-9]{64}")
          || birthDateMrz == null || !birthDateMrz.matches("[0-9]{6}")) throw new IllegalArgumentException("Verified signer required");
    }
  }
  public record Signed(byte[] pdf, X509Certificate signer, X509Certificate authority, String documentSha256, String signedSha256, Instant time) {
    public Signed { pdf = pdf.clone(); }
    @Override public byte[] pdf() { return pdf.clone(); }
  }

  public PadesSigner(Clock clock) throws GeneralSecurityException {
    this.clock = clock;
    try {
      authorityKey = ecKey();
      Instant now = clock.instant();
      var name = new X500Name("CN=openID TEST underskrifts-CA (ej betrodd),O=openID testmiljö,C=SE");
      var b = new JcaX509v3CertificateBuilder(name, serial(), Date.from(now.minusSeconds(60)), Date.from(now.plus(Duration.ofDays(30))), name, authorityKey.getPublic());
      b.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
      b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
      b.addExtension(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(authorityKey.getPublic()));
      authority = new JcaX509CertificateConverter().setProvider(BC).getCertificate(b.build(
          new JcaContentSignerBuilder("SHA256withECDSA").setProvider(BC).build(authorityKey.getPrivate())));
    } catch (Exception e) { throw new GeneralSecurityException("Test CA unavailable", e); }
  }
  public X509Certificate authority() { return authority; }

  /** A one-page synthetic agreement. The text says what it is; nothing in it is legally binding. */
  public static byte[] demoDocument(String reference, Instant created) throws IOException { return demoDocument(reference, created, false); }
  /** {@code highValue}: a larger commitment, for which the service requires the security code. */
  public static byte[] demoDocument(String reference, Instant created, boolean highValue) throws IOException {
    try (var document = new PDDocument(); var out = new ByteArrayOutputStream()) {
      var page = new PDPage(PDRectangle.A4); document.addPage(page);
      var info = document.getDocumentInformation();
      String title = highValue ? "Lånelöfte 250 000 kr" : "Avtal om provtjänst";
      info.setTitle(title + " " + reference); info.setAuthor("openID testmiljö"); info.setCreator("openID kontotjänst");
      var created_ = GregorianCalendar.from(created.atZone(ZoneId.of("Europe/Stockholm"))); info.setCreationDate(created_);
      PDFont bold = new PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD), regular = new PDType1Font(Standard14Fonts.FontName.HELVETICA);
      String date = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").format(created.atZone(ZoneId.of("Europe/Stockholm")));
      try (var c = new PDPageContentStream(document, page)) {
        float y = 780;
        y = line(c, bold, 22, 60, y, title);
        y = line(c, regular, 11, 60, y - 6, "Dokument " + reference + " · skapat " + date);
        y -= 24;
        String[] body = highValue ? new String[]{
            "1. Parter. openID testbank (”Banken”) lämnar ett lånelöfte till den person",
            "som skriver under med openID (”Låntagaren”).",
            "",
            "2. Belopp. Lånelöftet avser högst 250 000 kr och gäller i 30 dagar.",
            "",
            "3. Säkerhet. Ett åtagande av den här storleken kräver underskrift med",
            "säkerhetskod (6 siffror), inte bara Face ID.",
            "",
            "4. Giltighet. Dokumentet är ett demonstrationsdokument utan rättslig verkan.",
            "Underskriften kommer från en test-CA som inte är betrodd.",
        } : new String[]{
            "1. Parter. Detta avtal ingås mellan openID kontotjänst (”Tjänsten”) och den",
            "person som skriver under med openID (”Användaren”).",
            "",
            "2. Syfte. Användaren godkänner att prova Tjänsten under testperioden och att",
            "Tjänsten behandlar namn, födelsedatum och passfoto för att visa underskriften.",
            "",
            "3. Giltighet. Avtalet är ett demonstrationsdokument utan rättslig verkan.",
            "Det används för att visa en federerad underskrift enligt Sweden Connects",
            "tekniska ramverk (SignMessage, signMessageDigest och SAD).",
            "",
            "4. Underskrift. Ett synligt kvitto läggs in tillsammans med en PAdES-signatur.",
            "Äktheten kontrolleras med den digitala signaturen, inte med kvittots utseende.",
            "Certifikatet kommer från en test-CA och får inte användas för rättshandlingar.",
        };
        for (String text : body) y = line(c, regular, 12, 60, y, text);
        y -= 30;
        y = line(c, bold, 12, 60, y, "Underskrifter");
        line(c, regular, 11, 60, y - 2, "Kvittot visas nedan efter underskrift. Kontrollera även den digitala signaturen.");
      }
      SignatureAppearance.reserve(document, page);
      document.save(out);
      return out.toByteArray();
    }
  }
  private static float line(PDPageContentStream c, PDFont font, float size, float x, float y, String text) throws IOException {
    if (!text.isEmpty()) { c.beginText(); c.setFont(font, size); c.newLineAtOffset(x, y); c.showText(text); c.endText(); }
    return y - size * 1.45f;
  }

  public Signed sign(byte[] pdf, Signer signer, String signRequestId) throws Exception {
    if (pdf.length == 0 || pdf.length > 2_000_000) throw new IllegalArgumentException("Document size");
    if (signRequestId == null || !signRequestId.matches("[A-Za-z0-9_-]{1,64}")) throw new IllegalArgumentException("Signature reference");
    Instant now = clock.instant();
    authority.checkValidity(Date.from(now));
    // One key and certificate per signature, as in a central signing service; never a login or TLS key.
    KeyPair key = ecKey();
    var subject = new X500NameBuilder(BCStyle.INSTANCE)
        .addRDN(BCStyle.C, "SE").addRDN(BCStyle.SERIALNUMBER, signer.subject().substring(0, 32))
        .addRDN(BCStyle.OU, "TESTCERTIFIKAT - ej for rattshandlingar").addRDN(BCStyle.CN, signer.displayName()).build();
    var b = new JcaX509v3CertificateBuilder(authority, serial(), Date.from(now.minusSeconds(1)), Date.from(now.plus(Duration.ofDays(30))), subject, key.getPublic());
    b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
    b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.nonRepudiation));
    var ext = new JcaX509ExtensionUtils();
    b.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(key.getPublic()));
    b.addExtension(Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(authority));
    b.addExtension(Extension.certificatePolicies, false, new CertificatePolicies(new PolicyInformation(new ASN1ObjectIdentifier(TEST_POLICY))));
    X509Certificate certificate = new JcaX509CertificateConverter().setProvider(BC).getCertificate(b.build(
        new JcaContentSignerBuilder("SHA256withECDSA").setProvider(BC).build(authorityKey.getPrivate())));

    try (var document = Loader.loadPDF(pdf); var out = new ByteArrayOutputStream()) {
      var field = SignatureAppearance.reservedField(document);
      var signature = new PDSignature();
      signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
      signature.setSubFilter(PDSignature.SUBFILTER_ETSI_CADES_DETACHED);
      signature.setName(signer.displayName());
      signature.setReason("Underskrift med openID (test) · begäran " + signRequestId);
      signature.setLocation("openID testmiljö");
      signature.setSignDate(GregorianCalendar.from(now.atZone(ZoneOffset.UTC)));
      var options = new SignatureOptions(); options.setPreferredSignatureSize(12000);
      field.setValue(signature);
      document.addSignature(signature, options);
      if (field.getSignature() == null || field.getSignature().getCOSObject() != signature.getCOSObject())
        throw new GeneralSecurityException("Signature field binding failed");
      SignatureAppearance.draw(document, field, signer.displayName(), now, signRequestId, sha256Hex(pdf));
      var external = document.saveIncrementalForExternalSigning(out);
      byte[] content = external.getContent().readAllBytes();
      external.setSignature(cms(content, certificate, key.getPrivate()));
      options.close();
      byte[] signed = out.toByteArray();
      verify(signed, authority, signer, now);
      return new Signed(signed, certificate, authority, sha256Hex(pdf), sha256Hex(signed), now);
    }
  }

  /** CAdES-detached for PAdES baseline: content type, message digest and signingCertificateV2; no signing-time. */
  private byte[] cms(byte[] content, X509Certificate certificate, PrivateKey key) throws Exception {
    var attributes = new Hashtable<ASN1ObjectIdentifier, Attribute>();
    attributes.put(PKCSObjectIdentifiers.id_aa_signingCertificateV2, new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2,
        new DERSet(new SigningCertificateV2(new ESSCertIDv2(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()))))));
    CMSAttributeTableGenerator signed = parameters -> {
      var table = new DefaultSignedAttributeTableGenerator(new AttributeTable(attributes)).getAttributes(parameters);
      return table.remove(CMSAttributes.signingTime);
    };
    var info = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build())
        .setSignedAttributeGenerator(signed)
        .build(new JcaContentSignerBuilder("SHA256withECDSA").setProvider(BC).build(key), certificate);
    var generator = new CMSSignedDataGenerator();
    generator.addSignerInfoGenerator(info);
    generator.addCertificates(new JcaCertStore(List.of(certificate, authority)));
    // PAdES (EN 319 142-1) requires DER; Bouncy Castle's default encoding is BER with indefinite lengths.
    return generator.generate(new CMSProcessableByteArray(content), false).getEncoded(ASN1Encoding.DER);
  }

  /** Validation of this test profile: one signature over the whole file, the expected signer and the given CA. */
  public static void verify(byte[] pdf, X509Certificate trustedAuthority, Signer expected, Instant at) throws Exception {
    try (var document = Loader.loadPDF(pdf)) {
      var signatures = document.getSignatureDictionaries();
      if (signatures.size() != 1) throw new GeneralSecurityException("One signature required");
      var signature = signatures.getFirst();
      if (!PDSignature.SUBFILTER_ETSI_CADES_DETACHED.getName().equals(signature.getSubFilter())) throw new GeneralSecurityException("PAdES subfilter required");
      int[] range = signature.getByteRange();
      // The signature must cover the whole file except its own placeholder: no unsigned appended revision.
      if (range.length != 4 || range[0] != 0 || range[2] <= range[1] || (long) range[2] + range[3] != pdf.length)
        throw new GeneralSecurityException("Signature does not cover the document");
      byte[] covered = new byte[range[1] + range[3]];
      System.arraycopy(pdf, range[0], covered, 0, range[1]);
      System.arraycopy(pdf, range[2], covered, range[1], range[3]);
      // /Contents is a zero-padded placeholder: one DER object, then only padding.
      byte[] contents = signature.getContents(pdf), der;
      try (var in = new ASN1InputStream(contents)) { der = in.readObject().getEncoded(ASN1Encoding.DER); }
      if (der.length > contents.length || !Arrays.equals(der, Arrays.copyOf(contents, der.length))) throw new GeneralSecurityException("DER encoding required");
      for (int i = der.length; i < contents.length; i++) if (contents[i] != 0) throw new GeneralSecurityException("Data after signature");
      var cms = new CMSSignedData(new CMSProcessableByteArray(covered), der);
      if (cms.getSignerInfos().size() != 1) throw new GeneralSecurityException("Single signer required");
      var info = cms.getSignerInfos().getSigners().iterator().next();
      var matches = cms.getCertificates().getMatches(info.getSID());
      if (matches.size() != 1) throw new GeneralSecurityException("Ambiguous signer");
      var cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate((org.bouncycastle.cert.X509CertificateHolder) matches.iterator().next());
      var name = new X500Name(cert.getSubjectX500Principal().getName());
      if (!expected.displayName().equals(text(name, BCStyle.CN)) || !expected.subject().substring(0, 32).equals(text(name, BCStyle.SERIALNUMBER))
          || cert.getBasicConstraints() != -1 || cert.getKeyUsage() == null || !cert.getKeyUsage()[1])
        throw new GeneralSecurityException("Signer mismatch");
      if (info.getSignedAttributes().get(CMSAttributes.signingTime) != null) throw new GeneralSecurityException("PAdES baseline forbids signing-time");
      var essAttribute = info.getSignedAttributes().get(PKCSObjectIdentifiers.id_aa_signingCertificateV2);
      if (essAttribute == null) throw new GeneralSecurityException("Missing certificate binding");
      var ess = SigningCertificateV2.getInstance(essAttribute.getAttrValues().getObjectAt(0)).getCerts();
      if (ess.length != 1 || !MessageDigest.isEqual(ess[0].getCertHash(), MessageDigest.getInstance("SHA-256").digest(cert.getEncoded())))
        throw new GeneralSecurityException("Certificate binding mismatch");
      if (!info.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert))) throw new GeneralSecurityException("Invalid signature");
      var parameters = new PKIXParameters(Set.of(new TrustAnchor(trustedAuthority, null)));
      parameters.setDate(Date.from(at));
      parameters.setRevocationEnabled(false); // The test CA publishes no revocation status; never production validation.
      CertPathValidator.getInstance("PKIX").validate(CertificateFactory.getInstance("X.509").generateCertPath(List.of(cert)), parameters);
    }
  }
  private static String text(X500Name name, ASN1ObjectIdentifier type) {
    var rdns = name.getRDNs(type);
    return rdns.length == 1 ? IETFUtils.valueToString(rdns[0].getFirst().getValue()) : null;
  }
  public static String sha256Hex(byte[] value) {
    try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value)); }
    catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
  }
  public static String pem(X509Certificate certificate) throws CertificateEncodingException {
    return "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(certificate.getEncoded())
        + "\n-----END CERTIFICATE-----\n";
  }
  private static KeyPair ecKey() throws GeneralSecurityException {
    var generator = KeyPairGenerator.getInstance("EC"); generator.initialize(new ECGenParameterSpec("secp256r1")); return generator.generateKeyPair();
  }
  private static BigInteger serial() { return new BigInteger(159, new SecureRandom()).add(BigInteger.ONE); }
}

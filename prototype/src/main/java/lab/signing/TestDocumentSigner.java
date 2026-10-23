package lab.signing;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.time.*;
import java.util.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.ess.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.*;

/** Disposable, synthetic-only CMS signing. Not a Sweden Connect SignService or a qualified service. */
public final class TestDocumentSigner {
  private static final Provider BC = new BouncyCastleProvider();
  private final KeyPair authorityKey;
  private final X509Certificate authority;
  private final Clock clock;

  public record Signed(byte[] cms, X509Certificate signer, X509Certificate authority) {
    public Signed { cms = cms.clone(); }
    @Override public byte[] cms() { return cms.clone(); }
  }

  public TestDocumentSigner(Clock clock) throws Exception {
    this.clock = clock;
    authorityKey = key();
    Instant now = clock.instant();
    var name = new X500Name("CN=SYNTHETIC-ONLY document test CA");
    var b = new JcaX509v3CertificateBuilder(name, serial(), Date.from(now.minusSeconds(60)),
        Date.from(now.plusSeconds(86400)), name, authorityKey.getPublic());
    b.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, new BasicConstraints(0));
    b.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
    var ext = new JcaX509ExtensionUtils();
    b.addExtension(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(authorityKey.getPublic()));
    authority = new JcaX509CertificateConverter().setProvider(BC).getCertificate(b.build(
        new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(authorityKey.getPrivate())));
  }

  public Signed sign(byte[] document, String identity) throws Exception {
    requireIdentity(identity);
    if (document.length == 0 || document.length > 16384) throw new IllegalArgumentException("Document size");
    Instant now = clock.instant();
    authority.checkValidity(Date.from(now));
    // One disposable signature key per operation. No authentication/TLS key is reused.
    KeyPair signingKey = key();
    var b = new JcaX509v3CertificateBuilder(authority, serial(), Date.from(now.minusSeconds(1)),
        Date.from(now.plusSeconds(600)), new X500Name("CN=" + identity), signingKey.getPublic());
    b.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, new BasicConstraints(false));
    b.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));
    var ext = new JcaX509ExtensionUtils();
    b.addExtension(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(signingKey.getPublic()));
    b.addExtension(org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(authority));
    X509Certificate cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(b.build(
        new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(authorityKey.getPrivate())));
    var attributes = new Hashtable<ASN1ObjectIdentifier, Attribute>();
    attributes.put(PKCSObjectIdentifiers.id_aa_signingCertificateV2, new Attribute(
        PKCSObjectIdentifiers.id_aa_signingCertificateV2,
        new DERSet(new SigningCertificateV2(new ESSCertIDv2(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()))))));
    attributes.put(CMSAttributes.signingTime, new Attribute(CMSAttributes.signingTime, new DERSet(new org.bouncycastle.asn1.cms.Time(Date.from(now)))));
    var info = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(BC).build())
        .setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(attributes)))
        .build(new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(signingKey.getPrivate()), cert);
    var generator = new CMSSignedDataGenerator();
    generator.addSignerInfoGenerator(info);
    generator.addCertificates(new JcaCertStore(List.of(cert, authority)));
    byte[] cms = generator.generate(new CMSProcessableByteArray(document), false).getEncoded();
    verify(document, cms, authority, identity, now);
    return new Signed(cms, cert, authority);
  }

  /** Narrow validation of this test format, with an explicitly supplied trust anchor and expected signer. */
  public static void verify(byte[] document, byte[] encoded, X509Certificate trustedAuthority,
      String expectedIdentity, Instant at) throws Exception {
    requireIdentity(expectedIdentity);
    var cms = new CMSSignedData(new CMSProcessableByteArray(document), encoded);
    if (!new CMSSignedData(encoded).isDetachedSignature() || cms.getSignerInfos().size() != 1)
      throw new GeneralSecurityException("Detached single signature required");
    var signer = cms.getSignerInfos().getSigners().iterator().next();
    var certificates = cms.getCertificates().getMatches(signer.getSID());
    if (certificates.size() != 1) throw new GeneralSecurityException("Ambiguous signer");
    var holder = (org.bouncycastle.cert.X509CertificateHolder) certificates.iterator().next();
    var cert = new JcaX509CertificateConverter().setProvider(BC).getCertificate(holder);
    if (!cert.getSubjectX500Principal().equals(new javax.security.auth.x500.X500Principal("CN=" + expectedIdentity))
        || cert.getBasicConstraints() != -1 || cert.getKeyUsage() == null || !cert.getKeyUsage()[0]
        || !"2.16.840.1.101.3.4.2.1".equals(signer.getDigestAlgOID())
        || !Set.of("1.2.840.113549.1.1.1", "1.2.840.113549.1.1.11").contains(signer.getEncryptionAlgOID()))
      throw new GeneralSecurityException("Signer or algorithm mismatch");
    cert.checkValidity(Date.from(at)); trustedAuthority.checkValidity(Date.from(at));
    var path = CertificateFactory.getInstance("X.509").generateCertPath(List.of(cert));
    var parameters = new PKIXParameters(Set.of(new TrustAnchor(trustedAuthority, null)));
    parameters.setDate(Date.from(at));
    // This disposable CA has no revocation service. Never interpret this as production PKI validation.
    parameters.setRevocationEnabled(false);
    CertPathValidator.getInstance("PKIX").validate(path, parameters);
    var attr = signer.getSignedAttributes().get(PKCSObjectIdentifiers.id_aa_signingCertificateV2);
    if (attr == null || signer.getSignedAttributes().getAll(PKCSObjectIdentifiers.id_aa_signingCertificateV2).size() != 1
        || attr.getAttrValues().size() != 1) throw new GeneralSecurityException("Missing certificate binding");
    var ess = SigningCertificateV2.getInstance(attr.getAttrValues().getObjectAt(0)).getCerts();
    if (ess.length != 1 || !"2.16.840.1.101.3.4.2.1".equals(ess[0].getHashAlgorithm().getAlgorithm().getId())
        || !MessageDigest.isEqual(ess[0].getCertHash(), MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()))
        || !signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(cert)))
      throw new GeneralSecurityException("Invalid document signature");
  }

  public static String pem(X509Certificate certificate) throws CertificateEncodingException {
    return "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(certificate.getEncoded())
        + "\n-----END CERTIFICATE-----\n";
  }
  private static void requireIdentity(String identity) {
    if (identity == null || !identity.matches("SYNTHETIC-[a-z]{1,32}")) throw new IllegalArgumentException("Synthetic signer required");
  }
  private static KeyPair key() throws GeneralSecurityException {
    var generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(3072); return generator.generateKeyPair();
  }
  private static BigInteger serial() { return new BigInteger(159, new SecureRandom()).add(BigInteger.ONE); }
}

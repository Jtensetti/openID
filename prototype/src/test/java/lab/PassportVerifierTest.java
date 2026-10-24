package lab;

import lab.proofing.PassportVerifier;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.*;
import java.util.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.jmrtd.lds.*;
import org.jmrtd.lds.icao.*;
import org.jmrtd.lds.iso19794.*;
import net.sf.scuba.data.Gender;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

class PassportVerifierTest {
  static final Instant NOW = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
  static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
  KeyPair caKey, signerKey;
  X509Certificate ca, signer;
  byte[] sod, dg1, dg2;
  byte[] image;
  PassportVerifier verifier;
  @BeforeEach void setup() throws Exception {
    var picture = new java.awt.image.BufferedImage(32, 32, java.awt.image.BufferedImage.TYPE_INT_RGB);
    var output = new ByteArrayOutputStream(); javax.imageio.ImageIO.write(picture, "jpeg", output); image = output.toByteArray();
    caKey = key(); signerKey = key();
    ca = certificate(caKey, "CN=SYNTHETIC-CSCA", caKey, "CN=SYNTHETIC-CSCA", true);
    signer = certificate(signerKey, "CN=SYNTHETIC-DSC", caKey, "CN=SYNTHETIC-CSCA", false);
    dg1 = dg1("301019");
    var face = new FaceImageInfo(Gender.UNSPECIFIED, FaceImageInfo.EyeColor.UNSPECIFIED, 0, 0, 0,
        new int[]{0,0,0}, new int[]{0,0,0}, 0, 0, 0, 0, 0, new FaceImageInfo.FeaturePoint[0],
        10, 10, new ByteArrayInputStream(image), image.length, FaceImageInfo.IMAGE_DATA_TYPE_JPEG);
    dg2 = DG2File.createISO19794DG2File(List.of(new FaceInfo(List.of(face)))).getEncoded();
    sod = sign("SHA-256", "SHA256withECDSA");
    verifier = new PassportVerifier(Set.of(ca), CLOCK);
  }
  static KeyPair key() throws Exception { var g = KeyPairGenerator.getInstance("EC"); g.initialize(256); return g.generateKeyPair(); }
  static X509Certificate certificate(KeyPair subject, String name, KeyPair issuer, String issuerName, boolean root) throws Exception {
    var builder = new JcaX509v3CertificateBuilder(new X500Name(issuerName), new BigInteger(96, new SecureRandom()),
        Date.from(NOW.minusSeconds(86400)), Date.from(NOW.plusSeconds(86400)), new X500Name(name), subject.getPublic());
    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(root));
    builder.addExtension(Extension.keyUsage, true, new KeyUsage(root ? KeyUsage.keyCertSign : KeyUsage.digitalSignature));
    return new JcaX509CertificateConverter().getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(issuer.getPrivate())));
  }
  byte[] dg1(String expiry) {
    return new DG1File(MRZInfo.createTD3MRZInfo("P", "UTO", "SYNTHETIC", "ALICE", "TEST00001", "UTO", "900101", Gender.UNSPECIFIED, expiry, "")).getEncoded();
  }
  // Reserved SPAR test identity, testfall-foer-personsoekning-i-kundtestmiljoen_v8.pdf §3.1.
  byte[] numberedDg1(String issuer, String number) {
    return new DG1File(MRZInfo.createTD3MRZInfo("P", issuer, "SYNTHETIC", "ALICE", "TEST00001", issuer,
        "570413", Gender.UNSPECIFIED, "301019", number)).getEncoded();
  }
  @ParameterizedTest @ValueSource(strings={"195704133106", "5704133106"})
  void extractsSwedishNumberOnlyFromAuthenticatedDg1WithoutInferringCentury(String number) throws Exception {
    dg1 = numberedDg1("SWE", number); sod = sign("SHA-256", "SHA256withECDSA");
    assertEquals(number, verifier.verify(sod, dg1, dg2).identity().passportPersonalNumber());
    var other = key(); var untrusted = certificate(other,"CN=SYNTHETIC-CSCA",other,"CN=SYNTHETIC-CSCA",true);
    assertThrows(PassportVerifier.Rejected.class, () -> new PassportVerifier(Set.of(untrusted), CLOCK).verify(sod,dg1,dg2));
    byte[] changed = numberedDg1("SWE", "195704133107");
    assertEquals("DATA_HASHES", assertThrows(PassportVerifier.Rejected.class,
        () -> verifier.verify(sod, changed, dg2)).stage());
  }
  @ParameterizedTest @ValueSource(strings={"", "<<<<<<<<<<<<<<"})
  void missingSwedishOptionalNumberDoesNotInventAnIdentity(String number) throws Exception {
    dg1 = numberedDg1("SWE", number); sod = sign("SHA-256", "SHA256withECDSA");
    assertNull(verifier.verify(sod,dg1,dg2).identity().passportPersonalNumber());
  }
  @ParameterizedTest @ValueSource(strings={"195704133107", "19570413310", "195713133106", "195704003106", "1957<4133106", "ABCDEFGHIJKL"})
  void rejectsMalformedSwedishNumberEvenWithValidSignature(String number) throws Exception {
    dg1 = numberedDg1("SWE", number); sod = sign("SHA-256", "SHA256withECDSA");
    assertThrows(PassportVerifier.Rejected.class, () -> verifier.verify(sod,dg1,dg2));
  }
  @Test void foreignOptionalFieldIsNotTreatedAsSwedishNumber() throws Exception {
    dg1 = numberedDg1("UTO", "195704133106"); sod = sign("SHA-256", "SHA256withECDSA");
    assertNull(verifier.verify(sod,dg1,dg2).identity().passportPersonalNumber());
  }
  byte[] sign(String hash, String signature) throws Exception {
    var digest = MessageDigest.getInstance(hash);
    return new SODFile(hash, signature, Map.of(1,digest.digest(dg1),2,digest.digest(dg2)), signerKey.getPrivate(), signer).getEncoded();
  }
  @Test void verifiesRealCmsPkixHashesAndExtractsOnlySignedPortrait() throws Exception {
    var result = verifier.verify(sod,dg1,dg2);
    assertArrayEquals(image,result.portrait()); assertEquals(LocalDate.of(2030,10,19),result.expires());
    assertEquals(new PassportVerifier.Identity("ALICE", "SYNTHETIC", "900101", "UTO", "UTO", "TEST00001", "2030-10-19"), result.identity());
    byte[] copy = result.portrait(); copy[0]=0; assertArrayEquals(image,result.portrait());
    String export = System.getProperty("proofing.fixtureDirectory");
    if (export != null) {
      var directory = java.nio.file.Path.of(export); java.nio.file.Files.createDirectories(directory);
      java.nio.file.Files.write(directory.resolve("csca.der"),ca.getEncoded());
      java.nio.file.Files.write(directory.resolve("portrait.jpg"),image);
      for (var entry : Map.of("sod",sod,"dg1",dg1,"dg2",dg2).entrySet())
        java.nio.file.Files.write(directory.resolve(entry.getKey()+".bin"),entry.getValue());
    }
  }
  @ParameterizedTest @ValueSource(strings={"SHA-256","SHA-384","SHA-512"})
  void acceptsSupportedModernDigests(String algorithm) throws Exception {
    assertNotNull(verifier.verify(sign(algorithm,"SHA512withECDSA"),dg1,dg2));
  }
  @ParameterizedTest @ValueSource(ints={0,1,2}) void rejectsChangedSignedData(int index) {
    byte[][] parts = {sod,dg1,dg2}; parts[index][parts[index].length-1] ^= 1;
    assertThrows(PassportVerifier.Rejected.class,()->verifier.verify(parts[0],parts[1],parts[2]));
  }
  @Test void rejectsUntrustedSignerEvenWithValidSignature() throws Exception {
    var other = key(); var untrusted = certificate(other,"CN=SYNTHETIC-CSCA",other,"CN=SYNTHETIC-CSCA",true);
    assertThrows(PassportVerifier.Rejected.class,()->new PassportVerifier(Set.of(untrusted),CLOCK).verify(sod,dg1,dg2));
  }
  @Test void rejectsDocumentExpiryEvenWhenSignatureIsValid() throws Exception {
    dg1=dg1("251019"); sod=sign("SHA-256","SHA256withECDSA");
    assertThrows(PassportVerifier.Rejected.class,()->verifier.verify(sod,dg1,dg2));
  }
  @Test void rejectsExpiredCertificates() {
    assertThrows(PassportVerifier.Rejected.class,()->new PassportVerifier(Set.of(ca),Clock.offset(CLOCK,Duration.ofDays(2))).verify(sod,dg1,dg2));
  }
  @Test void rejectsWeakDigest() throws Exception {
    sod=sign("SHA-1","SHA1withECDSA"); assertThrows(PassportVerifier.Rejected.class,()->verifier.verify(sod,dg1,dg2));
  }
  java.security.cert.X509CRL crl(KeyPair issuer, String issuerName, Instant thisUpdate, Instant nextUpdate, X509Certificate... revoked) throws Exception {
    var builder = new org.bouncycastle.cert.X509v2CRLBuilder(new X500Name(issuerName), Date.from(thisUpdate));
    builder.setNextUpdate(Date.from(nextUpdate));
    for (var certificate : revoked) builder.addCRLEntry(certificate.getSerialNumber(), Date.from(thisUpdate), CRLReason.keyCompromise);
    return new org.bouncycastle.cert.jcajce.JcaX509CRLConverter().getCRL(builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(issuer.getPrivate())));
  }
  @Test void currentCscaCrlIsCheckedAndReported() throws Exception {
    var current = crl(caKey, "CN=SYNTHETIC-CSCA", NOW.minusSeconds(3600), NOW.plusSeconds(86400 * 90));
    assertEquals("CHECKED_CRL", new PassportVerifier(Set.of(ca), List.of(current), CLOCK).verify(sod, dg1, dg2).revocation());
    assertEquals("NOT_CHECKED", verifier.verify(sod, dg1, dg2).revocation());
  }
  @Test void revokedDocumentSignerIsRejectedEvenWithValidSignature() throws Exception {
    var revoked = crl(caKey, "CN=SYNTHETIC-CSCA", NOW.minusSeconds(3600), NOW.plusSeconds(86400), signer);
    assertEquals("REVOKED", assertThrows(PassportVerifier.Rejected.class,
        () -> new PassportVerifier(Set.of(ca), List.of(revoked), CLOCK).verify(sod, dg1, dg2)).stage());
  }
  @Test void staleOrMissingRevocationStatusFailsClosed() throws Exception {
    var stale = crl(caKey, "CN=SYNTHETIC-CSCA", NOW.minusSeconds(86400 * 100), NOW.minusSeconds(60));
    var future = crl(caKey, "CN=SYNTHETIC-CSCA", NOW.plusSeconds(3600), NOW.plusSeconds(86400));
    for (var crl : List.of(stale, future))
      assertEquals("REVOCATION_STATUS", assertThrows(PassportVerifier.Rejected.class,
          () -> new PassportVerifier(Set.of(ca), List.of(crl), CLOCK).verify(sod, dg1, dg2)).stage());
    // A second trusted CSCA with a CRL does not cover a document signer of the first.
    var otherKey = key(); var other = certificate(otherKey, "CN=OTHER-CSCA", otherKey, "CN=OTHER-CSCA", true);
    var otherCrl = crl(otherKey, "CN=OTHER-CSCA", NOW.minusSeconds(60), NOW.plusSeconds(86400));
    assertEquals("REVOCATION_STATUS", assertThrows(PassportVerifier.Rejected.class,
        () -> new PassportVerifier(Set.of(ca, other), List.of(otherCrl), CLOCK).verify(sod, dg1, dg2)).stage());
  }
  @Test void crlFromRolledOverCscaKeyCoversSignersOfTheEarlierKey() throws Exception {
    // Same CSCA name, new key (as Polismyndigheten's v2 keys): the current key signs the CRL for all signers.
    var newKey = key(); var renewed = certificate(newKey, "CN=SYNTHETIC-CSCA", newKey, "CN=SYNTHETIC-CSCA", true);
    var current = crl(newKey, "CN=SYNTHETIC-CSCA", NOW.minusSeconds(60), NOW.plusSeconds(86400));
    assertEquals("CHECKED_CRL", new PassportVerifier(Set.of(ca, renewed), List.of(current), CLOCK).verify(sod, dg1, dg2).revocation());
    var revoked = crl(newKey, "CN=SYNTHETIC-CSCA", NOW.minusSeconds(60), NOW.plusSeconds(86400), signer);
    assertEquals("REVOKED", assertThrows(PassportVerifier.Rejected.class,
        () -> new PassportVerifier(Set.of(ca, renewed), List.of(revoked), CLOCK).verify(sod, dg1, dg2)).stage());
  }
  @Test void crlNotSignedByProvisionedCscaIsAConfigurationError() throws Exception {
    var otherKey = key();
    var forged = crl(otherKey, "CN=SYNTHETIC-CSCA", NOW.minusSeconds(60), NOW.plusSeconds(86400));
    assertThrows(IllegalArgumentException.class, () -> new PassportVerifier(Set.of(ca), List.of(forged), CLOCK));
  }
  @Test void rejectsEmptyTrustOrDscAsTrustAnchor() {
    assertThrows(IllegalArgumentException.class,()->new PassportVerifier(Set.of(),CLOCK));
    assertThrows(IllegalArgumentException.class,()->new PassportVerifier(Set.of(signer),CLOCK));
  }
  @Test void rejectsOversizeAndTrailingAsn1() {
    assertThrows(PassportVerifier.Rejected.class,()->verifier.verify(sod,dg1,new byte[2_000_001]));
    assertThrows(PassportVerifier.Rejected.class,()->verifier.verify(Arrays.copyOf(sod,sod.length+1),dg1,dg2));
  }
  @Test void rejectsDifferentPassportPortrait() throws Exception {
    byte[] other = dg2.clone(); other[other.length-3]^=1;
    assertThrows(PassportVerifier.Rejected.class,()->verifier.verify(sod,dg1,other));
  }
  @Test void acceptsExplicitEcParametersInProvisionedTrustAndRejectsUntrustedChain() throws Exception {
    var bc = new org.bouncycastle.jce.provider.BouncyCastleProvider();
    var named = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("brainpoolP512r1");
    var explicit = new org.bouncycastle.jce.spec.ECParameterSpec(named.getCurve(), named.getG(), named.getN(), named.getH());
    var generator = KeyPairGenerator.getInstance("EC", bc); generator.initialize(explicit);
    var rootKey = generator.generateKeyPair();
    var rootName = new X500Name("CN=SYNTHETIC-EXPLICIT-CSCA");
    var rootBuilder = new JcaX509v3CertificateBuilder(rootName, BigInteger.ONE,
        Date.from(NOW.minusSeconds(86400)), Date.from(NOW.plusSeconds(86400)), rootName, rootKey.getPublic());
    rootBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
    rootBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));
    var root = new JcaX509CertificateConverter().setProvider(bc).getCertificate(rootBuilder.build(
        new JcaContentSignerBuilder("SHA512withECDSA").setProvider(bc).build(rootKey.getPrivate())));
    var loaded = PassportVerifier.loadTrust(new ByteArrayInputStream(root.getEncoded()));
    assertEquals(1, loaded.size());
    var leafBuilder = new JcaX509v3CertificateBuilder(rootName, BigInteger.TWO,
        Date.from(NOW.minusSeconds(86400)), Date.from(NOW.plusSeconds(86400)), new X500Name("CN=SYNTHETIC-DSC"), signerKey.getPublic());
    leafBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
    leafBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
    signer = new JcaX509CertificateConverter().setProvider(bc).getCertificate(leafBuilder.build(
        new JcaContentSignerBuilder("SHA512withECDSA").setProvider(bc).build(rootKey.getPrivate())));
    sod = sign("SHA-256", "SHA256withECDSA");
    assertNotNull(new PassportVerifier(loaded, CLOCK).verify(sod, dg1, dg2));
    assertThrows(PassportVerifier.Rejected.class, () -> verifier.verify(sod, dg1, dg2));
    var tampered = dg2.clone(); tampered[tampered.length - 1] ^= 1;
    assertThrows(PassportVerifier.Rejected.class, () -> new PassportVerifier(loaded, CLOCK).verify(sod, dg1, tampered));
  }

}

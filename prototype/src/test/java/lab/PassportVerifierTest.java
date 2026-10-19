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
  static final Instant NOW = Instant.parse("2026-10-19T12:00:00Z");
  static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
  KeyPair caKey, signerKey;
  X509Certificate ca, signer;
  byte[] sod, dg1, dg2;
  final byte[] image = new byte[]{(byte)0xff,(byte)0xd8,1,2,3,(byte)0xff,(byte)0xd9};
  PassportVerifier verifier;
  @BeforeEach void setup() throws Exception {
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
  byte[] sign(String hash, String signature) throws Exception {
    var digest = MessageDigest.getInstance(hash);
    return new SODFile(hash, signature, Map.of(1,digest.digest(dg1),2,digest.digest(dg2)), signerKey.getPrivate(), signer).getEncoded();
  }
  @Test void verifiesRealCmsPkixHashesAndExtractsOnlySignedPortrait() throws Exception {
    var result = verifier.verify(sod,dg1,dg2);
    assertArrayEquals(image,result.portrait()); assertEquals(LocalDate.of(2030,10,19),result.expires());
    byte[] copy = result.portrait(); copy[0]=0; assertArrayEquals(image,result.portrait());
    String export = System.getProperty("proofing.fixtureDirectory");
    if (export != null) {
      var directory = java.nio.file.Path.of(export); java.nio.file.Files.createDirectories(directory);
      java.nio.file.Files.write(directory.resolve("csca.der"),ca.getEncoded());
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
}

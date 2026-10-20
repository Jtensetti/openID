package lab.proofing;

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
import org.jmrtd.*;
import org.jmrtd.lds.*;
import org.jmrtd.lds.icao.*;
import org.jmrtd.lds.iso19794.*;
import net.sf.scuba.data.Gender;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

class ChipAuthenticationTest {
  KeyPair chipKey, signerKey;
  X509Certificate ca, signer;
  byte[] dg1, dg2, dg14, sod;
  PassportVerifier verifier;
  @BeforeEach void setup() throws Exception {
    var generator = KeyPairGenerator.getInstance("EC"); generator.initialize(256);
    var caKey = generator.generateKeyPair(); signerKey = generator.generateKeyPair(); chipKey = generator.generateKeyPair();
    ca = certificate(caKey, "CSCA", caKey, "CSCA", true);
    signer = certificate(signerKey, "DSC", caKey, "CSCA", false);
    verifier = new PassportVerifier(Set.of(ca), Clock.systemUTC());
    dg1 = new DG1File(MRZInfo.createTD3MRZInfo("P", "UTO", "SYNTHETIC", "ALICE", "TEST00001", "UTO", "900101", Gender.UNSPECIFIED, "301019", "")).getEncoded();
    var face = new FaceImageInfo(Gender.UNSPECIFIED, FaceImageInfo.EyeColor.UNSPECIFIED, 0, 0, 0,
        new int[]{0,0,0}, new int[]{0,0,0}, 0, 0, 0, 0, 0, new FaceImageInfo.FeaturePoint[0],
        1, 1, new ByteArrayInputStream(new byte[]{1,2,3}), 3, FaceImageInfo.IMAGE_DATA_TYPE_JPEG);
    dg2 = DG2File.createISO19794DG2File(List.of(new FaceInfo(List.of(face)))).getEncoded();
    dg14 = group(SoftwarePassportChip.CA, 1, chipKey, BigInteger.ONE);
    sod = sign();
  }
  static X509Certificate certificate(KeyPair key, String subject, KeyPair issuer, String issuerName, boolean root) throws Exception {
    var now = Instant.now();
    var builder = new JcaX509v3CertificateBuilder(new X500Name("CN=SYNTHETIC-"+issuerName), new BigInteger(96, new SecureRandom()),
        Date.from(now.minusSeconds(86400)), Date.from(now.plusSeconds(86400)), new X500Name("CN=SYNTHETIC-"+subject), key.getPublic());
    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(root));
    builder.addExtension(Extension.keyUsage, true, new KeyUsage(root ? KeyUsage.keyCertSign : KeyUsage.digitalSignature));
    return new JcaX509CertificateConverter().getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(issuer.getPrivate())));
  }
  byte[] group(String oid, int version, KeyPair key, BigInteger id) {
    return new DG14File(List.of(new ChipAuthenticationInfo(oid, version, BigInteger.ONE),
        new ChipAuthenticationPublicKeyInfo(key.getPublic(), id))).getEncoded();
  }
  byte[] sign() throws Exception {
    var hash = MessageDigest.getInstance("SHA-256");
    return new SODFile("SHA-256", "SHA256withECDSA", Map.of(1,hash.digest(dg1),2,hash.digest(dg2),14,hash.digest(dg14)), signerKey.getPrivate(), signer).getEncoded();
  }
  ChipAuthentication.Document document() throws Exception { return ChipAuthentication.verifyDocument(verifier,sod,dg1,dg2,dg14); }
  SoftwarePassportChip chip() { return new SoftwarePassportChip(chipKey, dg14, new BACKey("TEST00001","900101","301019")); }
  void authenticate(SoftwarePassportChip chip) throws Exception {
    var service = new PassportService(chip,256,223,false,true);
    try { ChipAuthentication.authenticate(service,document()); } finally { service.close(); }
  }
  @Test void fullPaceCaAndFreshMacCheckedRead() throws Exception {
    var first = chip(); authenticate(first);
    var second = chip(); authenticate(second);
    assertEquals(2,first.proofs.size()); assertEquals(2,second.proofs.size());
    assertFalse(Arrays.equals(first.proofs.getFirst(),second.proofs.getFirst()));
  }
  @Test void rejectsCopiedDataWithoutChipPrivateKey() throws Exception {
    var generator = KeyPairGenerator.getInstance("EC"); generator.initialize(256);
    var copy = new SoftwarePassportChip(generator.generateKeyPair(),dg14,new BACKey("TEST00001","900101","301019"));
    assertThrows(Exception.class,()->authenticate(copy));
  }
  @Test void rejectsReplayFromEarlierKeyAgreement() throws Exception {
    var first = chip(); authenticate(first); var second = chip(); second.replay = first.proofs;
    assertThrows(Exception.class,()->authenticate(second));
  }
  @Test void rejectsTamperedMac() { var chip=chip(); chip.corruptMac=true; assertThrows(Exception.class,()->authenticate(chip)); }
  @Test void rejectsBareSuccessStatus() { var chip=chip(); chip.bareSuccess=true; assertThrows(Exception.class,()->authenticate(chip)); }
  @Test void rejectsValidMacForDifferentDocument() { var chip=chip(); chip.wrongData=true; assertThrows(Exception.class,()->authenticate(chip)); }
  @Test void doesNotDowngradeWhenPaceFails() { var chip=chip(); chip.rejectPace=true; assertThrows(Exception.class,()->authenticate(chip)); assertTrue(chip.proofs.isEmpty()); }
  @Test void rejectsChangedDg14BeforeContactingChip() { dg14[dg14.length-1]^=1; assertThrows(Exception.class,this::document); }
  @Test void rejectsMissingSignedDg14() throws Exception {
    var hash=MessageDigest.getInstance("SHA-256");
    sod=new SODFile("SHA-256","SHA256withECDSA",Map.of(1,hash.digest(dg1),2,hash.digest(dg2)),signerKey.getPrivate(),signer).getEncoded();
    assertThrows(Exception.class,this::document);
  }
  @Test void rejectsUnsupportedCaVersionAndMismatchedKeyId() throws Exception {
    dg14=group(SoftwarePassportChip.CA,2,chipKey,BigInteger.ONE);sod=sign();assertThrows(Exception.class,this::document);
    dg14=group(SoftwarePassportChip.CA,1,chipKey,BigInteger.TWO);sod=sign();assertThrows(Exception.class,this::document);
    dg14=group(SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC,1,chipKey,BigInteger.ONE);sod=sign();assertThrows(Exception.class,this::document);
  }
  @Test void refusesDisabledMacVerification() throws Exception {
    var service=new PassportService(chip(),256,223,false,false);
    assertThrows(Exception.class,()->ChipAuthentication.authenticate(service,document()));
  }
  @Test void commandLineDrivesChipWithoutExportingSessionKeys(@org.junit.jupiter.api.io.TempDir java.nio.file.Path directory) throws Exception {
    var trust = directory.resolve("csca.der"); java.nio.file.Files.write(trust,ca.getEncoded());
    String classpath = System.getProperty("surefire.test.class.path",System.getProperty("java.class.path"));
    var process = new ProcessBuilder(System.getProperty("java.home")+"/bin/java","-cp",classpath,
        "lab.Lab","authenticate-chip",trust.toString()).redirectError(ProcessBuilder.Redirect.DISCARD).start();
    var timeout = Thread.startVirtualThread(()->{
      try { Thread.sleep(15_000); process.destroyForcibly(); } catch (InterruptedException ignored) { }
    });
    try (var input = new BufferedInputStream(process.getInputStream());
         var output = new PrintWriter(process.getOutputStream(),true)) {
      var data = new HashMap<String,String>();
      for (var part : Map.of("sod",sod,"dg1",dg1,"dg2",dg2,"dg14",dg14).entrySet())
        data.put(part.getKey(),Base64.getEncoder().encodeToString(part.getValue()));
      output.println(ChipCommand.JSON.writeValueAsString(data));
      var peer = chip(); peer.open(); int count = 0;
      for (;;) {
        var message = ChipCommand.line(input,8192);
        if (message.path("type").asText().equals("verified")) {
          assertEquals(1,message.size()); break;
        }
        assertTrue(ChipCommand.fields(message,Set.of("type","sequence","command")));
        assertEquals("command",message.path("type").asText()); assertEquals(count++,message.path("sequence").asInt());
        assertTrue(count<128);
        var reply = peer.transmit(new net.sf.scuba.smartcards.CommandAPDU(Base64.getDecoder().decode(message.path("command").asText())));
        output.println(ChipCommand.JSON.writeValueAsString(Map.of("sequence",count-1,"response",Base64.getEncoder().encodeToString(reply.getBytes()))));
      }
      assertTrue(count>8); assertTrue(process.waitFor(2,java.util.concurrent.TimeUnit.SECONDS)); assertEquals(0,process.exitValue());
    } finally { timeout.interrupt(); process.destroyForcibly(); }
  }
}

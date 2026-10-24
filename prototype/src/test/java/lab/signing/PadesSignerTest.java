package lab.signing;

import java.nio.charset.StandardCharsets;
import java.time.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class PadesSignerTest {
  private static final PadesSigner.Signer ALICE = new PadesSigner.Signer("ALICE SYNTHETIC", "a".repeat(64), "900101");

  @Test void signsWholeDocumentForVerifiedSigner() throws Exception {
    var signer = new PadesSigner(Clock.systemUTC());
    byte[] document = PadesSigner.demoDocument("OID-123456", Instant.now());
    var signed = signer.sign(document, ALICE, "request-1");
    String pdf = new String(signed.pdf(), StandardCharsets.ISO_8859_1);
    assertTrue(pdf.startsWith("%PDF-") && pdf.contains("/ETSI.CAdES.detached") && pdf.contains("/ByteRange"));
    // Incremental update: the original revision is kept byte for byte.
    assertArrayEquals(document, java.util.Arrays.copyOf(signed.pdf(), document.length));
    assertEquals(PadesSigner.sha256Hex(document), signed.documentSha256());
    PadesSigner.verify(signed.pdf(), signer.authority(), ALICE, Instant.now());
    assertTrue(signed.signer().getSubjectX500Principal().getName().contains("CN=ALICE SYNTHETIC"));
  }

  /** Independent check with OpenSSL when it is installed: same bytes, DER CMS, valid signature. */
  @Test void openSslAcceptsTheSignature() throws Exception {
    var openssl = java.nio.file.Path.of("/usr/bin/openssl");
    org.junit.jupiter.api.Assumptions.assumeTrue(java.nio.file.Files.isExecutable(openssl));
    var signed = new PadesSigner(Clock.systemUTC()).sign(PadesSigner.demoDocument("OID-123456", Instant.now()), ALICE, "request-1").pdf();
    String text = new String(signed, StandardCharsets.ISO_8859_1);
    var m = java.util.regex.Pattern.compile("/ByteRange\\s*\\[\\s*(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)").matcher(text);
    assertTrue(m.find());
    int a = Integer.parseInt(m.group(1)), b = Integer.parseInt(m.group(2)), c = Integer.parseInt(m.group(3)), d = Integer.parseInt(m.group(4));
    var dir = java.nio.file.Files.createTempDirectory("pades");
    try {
      var covered = java.io.ByteArrayOutputStream.class.getDeclaredConstructor().newInstance();
      covered.write(signed, a, b); covered.write(signed, c, d);
      java.nio.file.Files.write(dir.resolve("covered.bin"), covered.toByteArray());
      byte[] hex = java.util.HexFormat.of().parseHex(text.substring(a + b + 1, c - 1));
      try (var in = new org.bouncycastle.asn1.ASN1InputStream(hex)) {
        java.nio.file.Files.write(dir.resolve("sig.der"), java.util.Arrays.copyOf(hex, in.readObject().getEncoded("DER").length));
      }
      var process = new ProcessBuilder(openssl.toString(), "cms", "-verify", "-binary", "-inform", "DER", "-in", dir.resolve("sig.der").toString(),
          "-content", dir.resolve("covered.bin").toString(), "-noverify", "-out", "/dev/null").redirectErrorStream(true).start();
      String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
      assertEquals(0, process.waitFor(), output);
    } finally {
      try (var files = java.nio.file.Files.list(dir)) { for (var f : files.toList()) java.nio.file.Files.delete(f); }
      java.nio.file.Files.delete(dir);
    }
  }

  @Test void rejectsChangedFileWrongSignerAndOtherCa() throws Exception {
    var signer = new PadesSigner(Clock.systemUTC());
    var signed = signer.sign(PadesSigner.demoDocument("OID-123456", Instant.now()), ALICE, "request-1").pdf();
    byte[] changed = signed.clone();
    changed[200] ^= 1; // Inside the signed original revision.
    assertThrows(Exception.class, () -> PadesSigner.verify(changed, signer.authority(), ALICE, Instant.now()));
    byte[] appended = java.util.Arrays.copyOf(signed, signed.length + 10);
    assertThrows(Exception.class, () -> PadesSigner.verify(appended, signer.authority(), ALICE, Instant.now()));
    var bob = new PadesSigner.Signer("BOB SYNTHETIC", "a".repeat(64), "900101");
    assertThrows(Exception.class, () -> PadesSigner.verify(signed, signer.authority(), bob, Instant.now()));
    var other = new PadesSigner(Clock.systemUTC());
    assertThrows(Exception.class, () -> PadesSigner.verify(signed, other.authority(), ALICE, Instant.now()));
  }

  @Test void refusesUnverifiedSigner() {
    assertThrows(IllegalArgumentException.class, () -> new PadesSigner.Signer("alice", "a".repeat(64), "900101"));
    assertThrows(IllegalArgumentException.class, () -> new PadesSigner.Signer("ALICE", "short", "900101"));
  }
}

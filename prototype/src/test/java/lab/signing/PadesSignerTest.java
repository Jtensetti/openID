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
    String evidence = System.getProperty("pades.evidence.dir");
    if (evidence != null) {
      var directory = java.nio.file.Path.of(evidence); java.nio.file.Files.createDirectories(directory);
      java.nio.file.Files.write(directory.resolve("underskriftskvitto-exempel.pdf"), signed.pdf());
      java.nio.file.Files.write(directory.resolve("original.pdf"), document);
      java.nio.file.Files.writeString(directory.resolve("test-ca.pem"), PadesSigner.pem(signer.authority()));
    }
  }

  @Test void visibleReceiptIsTheSignedFieldAndRendersOnThePage() throws Exception {
    for (boolean highValue : new boolean[]{false, true}) {
      var signer = new PadesSigner(Clock.systemUTC());
      byte[] original = PadesSigner.demoDocument("OID-123456", Instant.now(), highValue);
      var signed = signer.sign(original, ALICE, "request-1");
      try (var pdf = org.apache.pdfbox.Loader.loadPDF(signed.pdf());
           var unsigned = org.apache.pdfbox.Loader.loadPDF(original)) {
        var form = pdf.getDocumentCatalog().getAcroForm();
        assertFalse(form.getNeedAppearances());
        assertEquals(1, form.getFields().size());
        var field = (org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField) form.getField(SignatureAppearance.FIELD);
        assertEquals(pdf.getSignatureDictionaries().getFirst().getCOSObject(), field.getSignature().getCOSObject());
        var widget = field.getWidgets().getFirst();
        assertTrue(widget.isPrinted());
        assertTrue(pdf.getPage(0).getAnnotations().stream().anyMatch(a -> a.getCOSObject().equals(widget.getCOSObject())));
        assertEquals(475, widget.getRectangle().getWidth());
        assertEquals(275, widget.getRectangle().getHeight());
        var appearance = widget.getNormalAppearanceStream();
        assertNotNull(appearance);
        String content = new org.apache.pdfbox.pdfparser.PDFStreamParser(appearance).parse().stream()
            .filter(org.apache.pdfbox.cos.COSString.class::isInstance).map(org.apache.pdfbox.cos.COSString.class::cast)
            .map(org.apache.pdfbox.cos.COSString::getString).collect(java.util.stream.Collectors.joining("\n"));
        assertTrue(content.contains("ALICE SYNTHETIC"));
        assertTrue(content.contains("TESTUNDERSKRIFT"));
        assertTrue(content.contains(PadesSigner.sha256Hex(original)));
        // Rendering, not only a populated /V: the visible field must paint ink in the reserved area.
        var before = new org.apache.pdfbox.rendering.PDFRenderer(unsigned).renderImage(0);
        var after = new org.apache.pdfbox.rendering.PDFRenderer(pdf).renderImage(0);
        int y = (int) pdf.getPage(0).getMediaBox().getHeight() - 320;
        assertNotEquals(before.getRGB(70, y), after.getRGB(70, y));
      }
      PadesSigner.verify(signed.pdf(), signer.authority(), ALICE, Instant.now());
    }
  }

  @Test void changingOrCopyingTheAppearanceCannotProvideAValidSignature() throws Exception {
    var signer = new PadesSigner(Clock.systemUTC());
    var signed = signer.sign(PadesSigner.demoDocument("OID-123456", Instant.now()), ALICE, "request-1");
    byte[] changed;
    try (var pdf = org.apache.pdfbox.Loader.loadPDF(signed.pdf()); var out = new java.io.ByteArrayOutputStream()) {
      var field = pdf.getSignatureFields().getFirst();
      var appearance = field.getWidgets().getFirst().getNormalAppearanceStream();
      try (var stream = appearance.getCOSObject().createOutputStream()) {
        stream.write("BT /F1 12 Tf 18 150 Td (BOB SYNTHETIC) Tj ET".getBytes(StandardCharsets.US_ASCII));
      }
      pdf.saveIncremental(out); changed = out.toByteArray();
    }
    assertThrows(Exception.class, () -> PadesSigner.verify(changed, signer.authority(), ALICE, Instant.now()));
    // A raster copy can look identical, but contains no signed byte range or signer certificate.
    try (var source = org.apache.pdfbox.Loader.loadPDF(signed.pdf());
         var copy = new org.apache.pdfbox.pdmodel.PDDocument(); var out = new java.io.ByteArrayOutputStream()) {
      var page = new org.apache.pdfbox.pdmodel.PDPage(org.apache.pdfbox.pdmodel.common.PDRectangle.A4); copy.addPage(page);
      var image = org.apache.pdfbox.pdmodel.graphics.image.LosslessFactory.createFromImage(copy,
          new org.apache.pdfbox.rendering.PDFRenderer(source).renderImage(0));
      try (var canvas = new org.apache.pdfbox.pdmodel.PDPageContentStream(copy, page)) {
        canvas.drawImage(image, 0, 0, page.getMediaBox().getWidth(), page.getMediaBox().getHeight());
      }
      copy.save(out);
      assertThrows(Exception.class, () -> PadesSigner.verify(out.toByteArray(), signer.authority(), ALICE, Instant.now()));
    }
  }

  @Test void longSignerAndReferenceFitAndArbitraryPdfIsRefused() throws Exception {
    var signer = new PadesSigner(Clock.systemUTC());
    var longName = new PadesSigner.Signer("W".repeat(64), "a".repeat(64), "900101");
    var result = signer.sign(PadesSigner.demoDocument("OID-123456", Instant.now()), longName, "W".repeat(64));
    PadesSigner.verify(result.pdf(), signer.authority(), longName, Instant.now());
    String evidence = System.getProperty("pades.evidence.dir");
    if (evidence != null) java.nio.file.Files.write(java.nio.file.Path.of(evidence, "long-name.pdf"), result.pdf());
    try (var pdf = new org.apache.pdfbox.pdmodel.PDDocument(); var out = new java.io.ByteArrayOutputStream()) {
      pdf.addPage(new org.apache.pdfbox.pdmodel.PDPage()); pdf.save(out);
      assertThrows(Exception.class, () -> signer.sign(out.toByteArray(), ALICE, "request-1"));
    }
    assertThrows(IllegalArgumentException.class, () -> signer.sign(new byte[]{1}, ALICE, "injected\nreference"));
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
    assertThrows(IllegalArgumentException.class, () -> new PadesSigner.Signer("W".repeat(65), "a".repeat(64), "900101"));
  }
}

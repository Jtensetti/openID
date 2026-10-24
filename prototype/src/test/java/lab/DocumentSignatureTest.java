package lab;

import lab.signing.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DocumentSignatureTest {
  final Instant now = Instant.now();
  final byte[] document = "SYNTHETIC testdokument\nSamma bytes: åäö\n".getBytes(StandardCharsets.UTF_8);
  TestDocumentSigner.Signed signed, other;
  @BeforeAll void sign() throws Exception {
    signed = new TestDocumentSigner(Clock.fixed(now, ZoneOffset.UTC)).sign(document, "SYNTHETIC-alice");
    other = new TestDocumentSigner(Clock.fixed(now, ZoneOffset.UTC)).sign(document, "SYNTHETIC-bob");
  }
  @Test void detachedSignatureVerifiesExactBytesAndExpectedSigner() throws Exception {
    TestDocumentSigner.verify(document, signed.cms(), signed.authority(), "SYNTHETIC-alice", now);
  }
  @Test void changedContentAndLineEndingsAreRejected() {
    for (byte[] changed : new byte[][]{"different".getBytes(StandardCharsets.UTF_8),
        new String(document, StandardCharsets.UTF_8).replace("\n", "\r\n").getBytes(StandardCharsets.UTF_8)})
      assertThrows(Exception.class, () -> TestDocumentSigner.verify(changed, signed.cms(), signed.authority(), "SYNTHETIC-alice", now));
  }
  @Test void wrongSignerAndUntrustedCertificateAreRejected() {
    assertThrows(Exception.class, () -> TestDocumentSigner.verify(document, signed.cms(), signed.authority(), "SYNTHETIC-bob", now));
    assertThrows(Exception.class, () -> TestDocumentSigner.verify(document, signed.cms(), other.authority(), "SYNTHETIC-alice", now));
  }
  @Test void expiredAndNotYetValidCertificateAreRejected() {
    for (Instant at : new Instant[]{now.minusSeconds(120), now.plusSeconds(700)})
      assertThrows(Exception.class, () -> TestDocumentSigner.verify(document, signed.cms(), signed.authority(), "SYNTHETIC-alice", at));
  }
  @Test void alteredAndTruncatedSignatureAreRejected() {
    byte[] altered = signed.cms(); altered[altered.length - 1] ^= 1;
    assertThrows(Exception.class, () -> TestDocumentSigner.verify(document, altered, signed.authority(), "SYNTHETIC-alice", now));
    assertThrows(Exception.class, () -> TestDocumentSigner.verify(document, new byte[]{1, 2, 3}, signed.authority(), "SYNTHETIC-alice", now));
  }
  @Test void realIdentityAndEmptyDocumentAreNotAcceptedByTestSigner() throws Exception {
    var signer = new TestDocumentSigner(Clock.fixed(now, ZoneOffset.UTC));
    assertThrows(IllegalArgumentException.class, () -> signer.sign(document, "Alice"));
    assertThrows(IllegalArgumentException.class, () -> signer.sign(new byte[0], "SYNTHETIC-alice"));
  }
}

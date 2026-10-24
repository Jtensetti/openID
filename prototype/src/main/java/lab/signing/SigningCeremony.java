package lab.signing;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;
import java.util.zip.*;
import lab.SyntheticRegistry;

/** In-memory, single-use signing transactions for the synthetic WebAuthn lab only. */
public final class SigningCeremony {
  public static final String INTENT = "Jag vill skriva under detta testdokument";
  public static final String VERSION = "synthetic-text-v1";
  public static final class Transaction {
    private final String id, credential, identity, text, digest;
    private final Instant expires;
    private final Long revocationVersion;
    private boolean consumed;
    private Transaction(String credential, String identity, Instant expires, Long revocationVersion) throws Exception {
      this.id = UUID.randomUUID().toString(); this.credential = credential; this.identity = identity;
      this.expires = expires; this.revocationVersion = revocationVersion;
      // Exact UTF-8/LF bytes are displayed and signed; no HTML, uploads, conversion or Unicode normalization.
      text = "ENDAST SYNTHETISKT TEST - INGET AVTAL\n\nDokumentversion: " + VERSION + "\nTransaktion: " + id
          + "\nUndertecknare: " + identity + "\n\nJag provar elektronisk underskrift i openID-labben.\n"
          + "Detta test skapar inga ekonomiska eller andra förpliktelser.\n";
      digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes()));
    }
    public String id() { return id; }
    public String credential() { return credential; }
    public String identity() { return identity; }
    public String text() { return text; }
    public String digest() { return digest; }
    public Instant expires() { return expires; }
    public String flow() { return "document-signature:" + id + ":" + digest; }
    public byte[] bytes() { return text.getBytes(StandardCharsets.UTF_8); }
  }
  public record Result(byte[] archive, Instant expires) {
    public Result { archive = archive.clone(); }
    @Override public byte[] archive() { return archive.clone(); }
  }
  private final SyntheticRegistry registry;
  private final Clock clock;
  private final TestDocumentSigner signer;
  public SigningCeremony(SyntheticRegistry registry, Clock clock) throws Exception {
    this.registry = registry; this.clock = clock; signer = new TestDocumentSigner(clock);
  }
  public Transaction begin(String credential) throws Exception {
    synchronized (registry) {
      var entry = registry.authorize(credential);
      return new Transaction(credential, entry.identity(), clock.instant().plusSeconds(60), registry.revocationVersions().get(entry.identity()));
    }
  }
  public void check(Transaction tx, String id, String digest) {
    synchronized (registry) {
      if (tx == null || tx.consumed || !tx.id.equals(id) || !tx.digest.equals(digest) || !tx.expires.isAfter(clock.instant())
          || !registry.activeIdentity(tx.identity, tx.revocationVersion)) throw new IllegalStateException("Signing request unavailable");
      registry.authorize(tx.credential);
    }
  }
  public void cancel(Transaction tx) { synchronized (registry) { if (tx != null) tx.consumed = true; } }

  /** The controller must first verify a fresh WebAuthn assertion bound to tx.flow(). */
  public Result finish(Transaction tx, String verifiedCredential, String id, String digest) throws Exception {
    synchronized (registry) {
      try {
        check(tx, id, digest);
        if (!tx.credential.equals(verifiedCredential)) throw new IllegalStateException("Wrong signer");
      } finally { if (tx != null) tx.consumed = true; }
      var signed = signer.sign(tx.bytes(), tx.identity);
      var manifest = new LinkedHashMap<String, Object>();
      manifest.put("schema", "openid-synthetic-signature-v1");
      manifest.put("transaction", tx.id); manifest.put("documentVersion", VERSION);
      manifest.put("documentSha256", tx.digest); manifest.put("signer", tx.identity);
      manifest.put("intent", INTENT); manifest.put("createdAt", clock.instant().toString());
      manifest.put("format", "detached CMS with signingCertificateV2; test profile");
      manifest.put("proofing", "SIMULATED"); manifest.put("approval", "fresh WebAuthn with user verification; server-observed");
      manifest.put("qualification", "NOT ASSESSED; not qualified; no Digg approval");
      manifest.put("limitations", List.of("disposable test CA", "no OCSP/CRL", "no trusted timestamp", "no long-term validation", "manifest is unsigned; validate CMS and original bytes"));
      var bytes = new ByteArrayOutputStream();
      try (var zip = new ZipOutputStream(bytes, StandardCharsets.UTF_8)) {
        add(zip, "document.txt", tx.bytes()); add(zip, "document.p7s", signed.cms());
        add(zip, "signer.crt", TestDocumentSigner.pem(signed.signer()).getBytes(StandardCharsets.US_ASCII));
        add(zip, "test-ca.crt", TestDocumentSigner.pem(signed.authority()).getBytes(StandardCharsets.US_ASCII));
        add(zip, "evidence.json", new com.fasterxml.jackson.databind.ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsBytes(manifest));
      }
      return new Result(bytes.toByteArray(), clock.instant().plusSeconds(300));
    }
  }
  private static void add(ZipOutputStream zip, String name, byte[] bytes) throws IOException {
    zip.putNextEntry(new ZipEntry(name)); zip.write(bytes); zip.closeEntry();
  }
}

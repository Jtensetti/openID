package lab;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;

/** One-time generation of disposable, dedicated keys and pinned public Sandbox trust material. */
public final class SandboxKeys {
  private SandboxKeys() {}

  public static void initialize(Path directory) throws Exception {
    TestKeys.initialize(directory); // Refuses overwrite; separate from every phone pilot and production key.
    SandboxConfig.initializeTrust(directory);
    Path file = directory.resolve("federation.p12");
    String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
    var command = List.of(keytool, "-genkeypair", "-alias", "federation", "-keyalg", "RSA",
        "-keysize", "3072", "-sigalg", "SHA256withRSA", "-validity", "30",
        "-dname", "CN=SYNTHETIC-SANDBOX-federation", "-storetype", "PKCS12",
        "-keystore", file.toString(), "-storepass", TestKeys.PASSWORD,
        "-keypass", TestKeys.PASSWORD);
    Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
    process.getInputStream().transferTo(java.io.OutputStream.nullOutputStream());
    if (process.waitFor() != 0) throw new IllegalStateException("Could not generate disposable Sandbox federation key");
    try { Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------")); }
    catch (UnsupportedOperationException ignored) { /* Windows uses the account ACL. */ }
    validate(directory);
  }

  public static void validate(Path directory) throws Exception {
    SandboxConfig.validateTrust(directory);
    KeyStore store = KeyStore.getInstance("PKCS12");
    try (var input = Files.newInputStream(directory.resolve("federation.p12"))) {
      store.load(input, TestKeys.PASSWORD.toCharArray());
    }
    X509Certificate cert = (X509Certificate) store.getCertificate("federation");
    if (cert == null || !cert.getSubjectX500Principal().getName().contains("CN=SYNTHETIC-SANDBOX-federation")
        || !"RSA".equals(cert.getPublicKey().getAlgorithm()))
      throw new IllegalStateException("Only disposable Sandbox federation keys are permitted");
    cert.checkValidity();
  }
}

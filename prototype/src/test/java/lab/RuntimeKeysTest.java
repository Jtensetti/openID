package lab;

import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import se.swedenconnect.spring.authnserver.oidc.keys.SigningKey;
import static org.junit.jupiter.api.Assertions.*;

class RuntimeKeysTest {
  @TempDir static Path fixture;
  @TempDir Path work;
  static final String PASSWORD = "R".repeat(43);

  @BeforeAll static void generate() throws Exception {
    for (String alias : List.of("tls", "idp", "sp", "encryption")) {
      var arguments = new ArrayList<>(List.of(Path.of(System.getProperty("java.home"), "bin", "keytool").toString(),
          "-genkeypair", "-alias", alias, "-keyalg", "RSA", "-keysize", "3072", "-sigalg", "SHA256withRSA",
          "-validity", "2", "-dname", "CN=Generated-runtime-test-" + alias, "-storetype", "PKCS12",
          "-keystore", fixture.resolve(alias + ".p12").toString(), "-storepass", PASSWORD, "-keypass", PASSWORD));
      if (alias.equals("tls")) arguments.addAll(List.of("-ext", "SAN=DNS:localhost,IP:127.0.0.1", "-ext", "EKU=serverAuth"));
      var process = new ProcessBuilder(arguments).redirectErrorStream(true).start();
      process.getInputStream().transferTo(java.io.OutputStream.nullOutputStream());
      assertEquals(0, process.waitFor());
      var store = java.security.KeyStore.getInstance("PKCS12");
      try (var stream = Files.newInputStream(fixture.resolve(alias + ".p12"))) { store.load(stream, PASSWORD.toCharArray()); }
      Files.write(fixture.resolve(alias + ".crt"), store.getCertificate(alias).getEncoded());
    }
  }

  Path prepare(String role) throws Exception {
    Path root = work.resolve(UUID.randomUUID().toString()); Files.createDirectory(root);
    Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"));
    String peer = role.equals("idp") ? "sp" : "idp";
    for (String alias : role.equals("idp") ? List.of("tls", role, "encryption") : List.of("tls", role)) {
      Files.copy(fixture.resolve(alias + ".p12"), root.resolve(alias + ".p12"));
      Files.writeString(root.resolve(alias + ".password"), PASSWORD + "\n");
    }
    Files.copy(fixture.resolve(peer + ".crt"), root.resolve(peer + ".crt"));
    if (role.equals("idp")) Files.writeString(root.resolve("subject-secret"), "S".repeat(43) + "\n");
    else Files.copy(fixture.resolve("encryption.crt"), root.resolve("idp-encryption.crt"));
    try (var files = Files.list(root)) {
      for (Path file : files.toList()) Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
    }
    return root.toRealPath();
  }

  @Test void eachRoleHasOnlyItsOwnPrivateCredential() throws Exception {
    for (String role : List.of("idp", "sp")) {
      var keys = new RuntimeKeys(prepare(role), role);
      String peer = role.equals("idp") ? "sp" : "idp";
      assertNotNull(keys.credential(role).getPrivateKey()); assertNotNull(keys.certificate(peer));
      assertThrows(IllegalArgumentException.class, () -> keys.credential(peer));
      assertThrows(IllegalArgumentException.class, () -> keys.storePath(peer));
      assertThrows(IllegalArgumentException.class, () -> keys.password(peer));
      if (role.equals("idp")) assertNotNull(keys.credential("encryption").getPrivateKey());
      else assertThrows(IllegalArgumentException.class, () -> keys.credential("encryption"));
      assertNotNull(keys.encryptionCertificate());
      assertNotNull(keys.sslContext());
    }
  }
  @Test void publicIssuerJwkMatchesLibraryWithoutIssuerPrivateKey() throws Exception {
    var issuer = new RuntimeKeys(prepare("idp"), "idp");
    var recipient = new RuntimeKeys(prepare("sp"), "sp");
    var expected = SigningKey.activeDefault(issuer.credential("idp")).getPublicJwk();
    var actual = PilotOidcClient.publicIssuerKey(recipient);
    assertEquals(expected.getKeyID(), actual.getKeyID());
    assertEquals(expected.computeThumbprint(), actual.computeThumbprint()); assertFalse(actual.isPrivate());
  }
  @Test void recipientStartsAndDeniesUnavailableRegistryWithoutIssuerPrivateKey() throws Exception {
    var keys = new RuntimeKeys(prepare("sp"), "sp");
    se.swedenconnect.opensaml.OpenSAMLInitializer.getInstance().initialize(
        new se.swedenconnect.opensaml.OpenSAMLSecurityDefaultsConfig(new LabSecurityConfiguration()),
        new se.swedenconnect.opensaml.OpenSAMLSecurityExtensionConfig());
    int port = FlowTest.freePort();
    var bridge = new lab.phone.PhoneBridge(work.resolve("missing.sock"), "https://sp.example.test/sp");
    try (var service = new RelyingParty(keys, "https://idp.example.test", "https://sp.example.test", null, bridge, port);
         var socket = (javax.net.ssl.SSLSocket) keys.sslContext().getSocketFactory().createSocket("localhost", port)) {
      socket.setSoTimeout(5000);
      var parameters = socket.getSSLParameters(); parameters.setEndpointIdentificationAlgorithm("HTTPS");
      socket.setSSLParameters(parameters);
      socket.getOutputStream().write("GET /health/ready HTTP/1.1\r\nHost: sp.example.test\r\nConnection: close\r\n\r\n"
          .getBytes(java.nio.charset.StandardCharsets.US_ASCII));
      String status = new java.io.BufferedReader(new java.io.InputStreamReader(socket.getInputStream())).readLine();
      assertTrue(status.contains("503"), status);
    }
  }
  @Test void subjectSecretSurvivesRestart() throws Exception {
    Path root = prepare("idp");
    assertEquals(new RuntimeKeys(root, "idp").subjectSecret(), new RuntimeKeys(root, "idp").subjectSecret());
    var recipient = new RuntimeKeys(prepare("sp"), "sp");
    assertThrows(IllegalArgumentException.class, recipient::subjectSecret);
  }
  @Test void issuerBootsWithRuntimeStoreAndOnlyPublicRecipientCertificate() throws Exception {
    var keys = new RuntimeKeys(prepare("idp"), "idp");
    var origins = new PilotOrigins("https://idp.example.test", "https://sp.example.test");
    var bridge = new lab.phone.PhoneBridge(work.resolve("absent.sock"), origins.sp() + "/sp");
    int idpPort = FlowTest.freePort(), spPort = FlowTest.freePort();
    while (spPort == idpPort) spPort = FlowTest.freePort();
    Path state = Files.createDirectory(work.resolve("metadata")).toRealPath();
    Files.setPosixFilePermissions(state, PosixFilePermissions.fromString("rwx------"));
    try (var service = Lab.runtimeIdp(keys, bridge, origins, new RuntimeFederation(false), state, idpPort, spPort);
         var socket = (javax.net.ssl.SSLSocket) keys.sslContext().getSocketFactory().createSocket("localhost", idpPort)) {
      socket.setSoTimeout(5000);
      var parameters = socket.getSSLParameters(); parameters.setEndpointIdentificationAlgorithm("HTTPS");
      socket.setSSLParameters(parameters);
      socket.getOutputStream().write("GET /saml2/metadata HTTP/1.1\r\nHost: idp.example.test\r\nConnection: close\r\n\r\n"
          .getBytes(java.nio.charset.StandardCharsets.US_ASCII));
      String reply = new String(socket.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
      assertTrue(reply.startsWith("HTTP/1.1 200"), reply.substring(0, Math.min(200, reply.length())));
      assertTrue(reply.contains(origins.idp() + "/idp"));
      assertTrue(reply.contains(Base64.getEncoder().encodeToString(keys.certificate("encryption").getEncoded())));
      assertFalse(Files.exists(keys.directory().resolve("sp.p12")));
      assertFalse(Files.exists(keys.directory().resolve("idp-metadata.xml")));
      assertTrue(Files.exists(state.resolve("idp-metadata.xml")));
    }
  }
  @Test void copiedPeerPrivateStoreStopsStart() throws Exception {
    Path root = prepare("sp"); Files.copy(fixture.resolve("idp.p12"), root.resolve("idp.p12"));
    assertThrows(IllegalArgumentException.class, () -> new RuntimeKeys(root, "sp"));
  }
  @Test void missingPasswordDoesNotFallBackToLab() throws Exception {
    Path root = prepare("sp"); Files.delete(root.resolve("sp.password"));
    assertThrows(IllegalArgumentException.class, () -> new RuntimeKeys(root, "sp"));
  }
  @Test void labMarkerStopsRuntime() throws Exception {
    Path root = prepare("idp"); Files.writeString(root.resolve("SYNTHETIC-LAB-ONLY"), "Disposable test keys\n");
    assertThrows(IllegalArgumentException.class, () -> new RuntimeKeys(root, "idp"));
  }
  @Test void wrongPasswordStopsStart() throws Exception {
    Path root = prepare("idp"); Files.writeString(root.resolve("idp.password"), "W".repeat(43));
    assertThrows(Exception.class, () -> new RuntimeKeys(root, "idp"));
  }
  @Test void sharedPermissionsStopStart() throws Exception {
    Path root = prepare("sp"); Files.setPosixFilePermissions(root.resolve("sp.p12"), PosixFilePermissions.fromString("rw-r-----"));
    assertThrows(IllegalArgumentException.class, () -> new RuntimeKeys(root, "sp"));
  }
  @Test void symlinkCannotSupplyPrivateKey() throws Exception {
    Path root = prepare("sp"); Files.delete(root.resolve("sp.p12"));
    Files.createSymbolicLink(root.resolve("sp.p12"), fixture.resolve("sp.p12"));
    assertThrows(IllegalArgumentException.class, () -> new RuntimeKeys(root, "sp"));
  }
  @Test void issuerAndRecipientCannotShareKey() throws Exception {
    Path root = prepare("sp"); Files.copy(fixture.resolve("sp.crt"), root.resolve("idp.crt"), StandardCopyOption.REPLACE_EXISTING);
    assertThrows(IllegalArgumentException.class, () -> new RuntimeKeys(root, "sp"));
  }
  @Test void recipientCannotHaveIssuerEncryptionPrivateKeyOrOmitPublicKey() throws Exception {
    Path root = prepare("sp");
    Files.delete(root.resolve("idp-encryption.crt"));
    assertThrows(IllegalArgumentException.class, () -> new RuntimeKeys(root, "sp"));
    Path recipient = prepare("sp"); Files.copy(fixture.resolve("encryption.p12"), recipient.resolve("encryption.p12"));
    assertThrows(IllegalArgumentException.class, () -> new RuntimeKeys(recipient, "sp"));
  }
  @Test void issuerSigningKeyCannotAlsoBeThePublicEncryptionKey() throws Exception {
    Path root = prepare("sp"); Files.copy(fixture.resolve("idp.crt"), root.resolve("idp-encryption.crt"), StandardCopyOption.REPLACE_EXISTING);
    assertThrows(IllegalArgumentException.class, () -> new RuntimeKeys(root, "sp"));
  }
  @Test void runtimeSandboxPinsPackagedAnchorAndSeparatesMetadataFromKeys() throws Exception {
    var keys = new RuntimeKeys(prepare("idp"), "idp");
    var properties = new HashMap<String, Object>();
    Path state = work.resolve("metadata").toAbsolutePath();
    SwedenConnectSandbox.apply(properties, keys, "https://idp.example.test", state);
    assertEquals("classpath:/sandbox/saml-metadata-signing.crt", properties.get("authn-server.saml.metadata-providers[2].validation-certificate"));
    assertEquals(state.resolve("sandbox-sp-metadata-backup.xml").toUri().toString(), properties.get("authn-server.saml.metadata-providers[2].backup-location"));
    assertEquals(false, properties.get("authn-server.saml.metadata-providers[2].skip-hostname-verification"));
    assertEquals(keys.storePath("encryption").toUri().toString(), properties.get("credential.bundles.jks.issuer-encryption.store.location"));
    assertFalse(properties.toString().contains("loa3"));
  }
  @Test void metadataCannotWriteIntoKeysOrSharedDirectory() throws Exception {
    var keys = new RuntimeKeys(prepare("idp"), "idp");
    var origins = new PilotOrigins("https://idp.example.test", "https://sp.example.test");
    var bridge = new lab.phone.PhoneBridge(work.resolve("absent.sock"), origins.sp() + "/sp");
    assertThrows(IllegalArgumentException.class, () -> Lab.runtimeIdp(keys, bridge, origins, new RuntimeFederation(false), keys.directory()));
    Path state = Files.createDirectory(work.resolve("shared")).toRealPath();
    Files.setPosixFilePermissions(state, PosixFilePermissions.fromString("rwxr-xr-x"));
    assertThrows(IllegalArgumentException.class, () -> Lab.runtimeIdp(keys, bridge, origins, new RuntimeFederation(false), state));
  }
}

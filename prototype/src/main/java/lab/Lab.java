package lab;

import java.nio.file.*;
import java.util.*;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.*;
import se.swedenconnect.opensaml.*;
import se.swedenconnect.opensaml.sweid.xmlsec.config.SwedishEidSecurityConfiguration;

/** Command-line entry point for local SAML and passport tools. */
public final class Lab implements AutoCloseable {
  public final TestKeys keys;
  public final String idpBase, spBase;
  public final SyntheticRegistry registry;
  public final RelyingParty sp;
  private final ConfigurableApplicationContext idp;

  public Lab(Path keyDirectory, int idpPort, int spPort, SyntheticRegistry registry) throws Exception {
    this(keyDirectory, idpPort, spPort, registry, false);
  }
  public Lab(Path keyDirectory, int idpPort, int spPort, SyntheticRegistry registry, boolean webAuthn) throws Exception {
    this(keyDirectory, idpPort, spPort, registry, webAuthn, null, true);
  }
  public Lab(Path keyDirectory, int idpPort, int spPort, SyntheticRegistry registry, boolean webAuthn,
      lab.phone.PhoneBridge phone, boolean startSp) throws Exception {
    this(keyDirectory, idpPort, spPort, registry, webAuthn, phone, startSp, null);
  }
  public Lab(Path keyDirectory, int idpPort, int spPort, SyntheticRegistry registry, boolean webAuthn,
      lab.phone.PhoneBridge phone, boolean startSp, PilotOrigins origins) throws Exception {
    if (origins != null && (phone == null || webAuthn)) throw new IllegalArgumentException("Private phone pilot only");
    if (idpPort < 1024 || spPort < 1024 || idpPort > 65535 || spPort > 65535 || idpPort == spPort)
      throw new IllegalArgumentException("Two distinct unprivileged loopback ports are required");
    keys = new TestKeys(keyDirectory); this.registry = registry;
    String host = webAuthn || phone != null ? "localhost" : "127.0.0.1";
    idpBase = origins == null ? "https://" + host + ":" + idpPort : origins.idp();
    spBase = origins == null ? "https://" + host + ":" + spPort : origins.sp();
    if (!webAuthn && !registry.passkeys().isEmpty()) throw new IllegalStateException("Passkey state requires start-web; no downgrade to simulated approval");
    OpenSAMLInitializer.getInstance().initialize(new OpenSAMLSecurityDefaultsConfig(new LabSecurityConfiguration()), new OpenSAMLSecurityExtensionConfig());
    Path metadata = keys.directory().resolve("sp-metadata.xml");
    Files.writeString(metadata, Metadata.sp(keys, spBase, phone != null));
    Path signMetadata = keys.directory().resolve("sign-metadata.xml");
    if (phone != null) Files.writeString(signMetadata, Metadata.signService(keys, spBase));
    Map<String, Object> p = new HashMap<>();
    p.put("spring.config.location", "classpath:/application.properties");
    p.put("spring.main.banner-mode", "off");
    p.put("server.address", "127.0.0.1"); p.put("server.port", idpPort);
    p.put("server.ssl.enabled", true); p.put("server.ssl.key-store", keys.directory().resolve("tls.p12").toUri().toString());
    p.put("server.ssl.key-store-password", TestKeys.PASSWORD); p.put("server.ssl.key-store-type", "PKCS12");
    p.put("server.ssl.key-alias", "tls"); p.put("server.ssl.enabled-protocols", "TLSv1.3,TLSv1.2");
    p.put("server.servlet.session.cookie.name", "__Host-lab-idp"); p.put("server.servlet.session.cookie.secure", true);
    p.put("server.servlet.session.cookie.http-only", true); p.put("server.servlet.session.cookie.same-site", "strict");
    p.put("server.servlet.session.timeout", "5m"); p.put("server.forward-headers-strategy", "none");
    p.put("server.servlet.session.tracking-modes", "cookie");
    p.put("server.tomcat.max-http-form-post-size", "128KB"); p.put("server.error.include-message", "never");
    p.put("authn-server.base-url", idpBase); p.put("authn-server.sso.enabled", false);
    p.put("authn-server.saml.enabled", true); p.put("authn-server.oidc.enabled", origins != null);
    if (origins != null) PilotOidc.configure(p, keys, idpBase, spBase);
    p.put("authn-server.saml.entity-id", idpBase + "/idp"); p.put("authn-server.saml.requires-signed-requests", true);
    p.put("authn-server.saml.max-message-age", "60s"); p.put("authn-server.saml.clock-skew", "0s");
    p.put("authn-server.saml.assertions.encrypt", true); p.put("authn-server.saml.assertions.not-after", "30s");
    p.put("authn-server.saml.metadata-providers[0].location", metadata.toUri().toString());
    if (phone != null) p.put("authn-server.saml.metadata-providers[1].location", signMetadata.toUri().toString());
    p.put("authn-server.saml.credentials.default-credential.bundle", "lab-idp");
    p.put("credential.bundles.jks.lab-idp.key.alias", "idp");
    p.put("credential.bundles.jks.lab-idp.key.key-password", TestKeys.PASSWORD);
    p.put("credential.bundles.jks.lab-idp.store.location", keys.directory().resolve("idp.p12").toUri().toString());
    p.put("credential.bundles.jks.lab-idp.store.password", TestKeys.PASSWORD);
    p.put("credential.bundles.jks.lab-idp.store.type", "PKCS12");
    p.put("authn-server.subject-identifier.secret", UUID.randomUUID().toString());
    p.put("authn-server.saml.metadata.ui-info.display-names.sv", phone == null ? "SIMULERAD e-id-labb" : "openID");
    p.put("lab.idp-base", idpBase); p.put("lab.sp-base", spBase);
    p.put("lab.webauthn", webAuthn);
    p.put("lab.phone", phone != null);
    StandardEnvironment env = new StandardEnvironment();
    // Security settings cannot be replaced with production metadata, keys or a public bind through environment/CLI.
    env.getPropertySources().remove(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);
    env.getPropertySources().remove(StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME);
    env.getPropertySources().addFirst(new MapPropertySource("isolated-lab", p));
    SpringApplication app = new SpringApplication(lab.idp.IdpApplication.class);
    app.setEnvironment(env); app.setAddCommandLineProperties(false);
    app.addInitializers(c -> c.getBeanFactory().registerSingleton("syntheticRegistry", registry));
    if (phone != null) app.addInitializers(c -> c.getBeanFactory().registerSingleton("phoneBridge", phone));
    idp = app.run();
    try { sp = startSp ? new RelyingParty(keys, idpBase, spBase, registry, phone, spPort) : null; }
    catch (Exception e) { idp.close(); throw e; }
  }
  @Override public void close() {
    try { if (sp != null) sp.close(); idp.close(); }
    finally { try { registry.close(); } catch (Exception e) { throw new IllegalStateException("Could not close persistent registry"); } }
  }
  public static void main(String[] args) throws Exception {
    if (args.length == 2 && args[0].equals("check-crls")) { lab.proofing.CrlCommand.run(args[1]); return; }
    if ((args.length == 2 || args.length == 3) && args[0].equals("verify-passport")) { lab.proofing.PassportCommand.run(args[1], args.length == 3 ? args[2] : null); return; }
    if (args.length == 2 && args[0].equals("authenticate-chip")) { lab.proofing.ChipCommand.run(args[1]); return; }
    if (args.length == 2 && args[0].equals("phone-init")) { TestKeys.initialize(Path.of(args[1])); return; }
    if ((args.length == 3 || args.length == 4) && Set.of("phone-idp", "phone-sp").contains(args[0])) {
      var origins = args.length == 4 ? PilotOrigins.read(Path.of(args[3])) : null;
      String idpOrigin = origins == null ? "https://localhost:8443" : origins.idp();
      String spOrigin = origins == null ? "https://localhost:8444" : origins.sp();
      var bridge = new lab.phone.PhoneBridge(Path.of(args[2]), spOrigin+"/sp");
      AutoCloseable service;
      if (args[0].equals("phone-idp")) service = new Lab(Path.of(args[1]), origins == null ? 8443 : 9443, origins == null ? 8444 : 9444,
          new SyntheticRegistry(java.time.Clock.systemUTC()), false, bridge, false, origins);
      else {
        OpenSAMLInitializer.getInstance().initialize(new OpenSAMLSecurityDefaultsConfig(new LabSecurityConfiguration()), new OpenSAMLSecurityExtensionConfig());
        service = new RelyingParty(new TestKeys(Path.of(args[1])), idpOrigin, spOrigin, null, bridge, origins == null ? 8444 : 9444);
      }
      Runtime.getRuntime().addShutdownHook(new Thread(() -> { try { service.close(); } catch (Exception ignored) {} }));
      System.out.println(args[0]+" ready; service: "+spOrigin); return;
    }
    if (args.length == 2 && args[0].equals("init")) {
      TestKeys.initialize(Path.of(args[1])); SyntheticRegistry.initialize(Path.of(args[1])); return;
    }
    if (args.length == 3 && args[0].equals("restore")) { SyntheticRegistry.restore(Path.of(args[1]), Path.of(args[2])); return; }
    if (args.length >= 2 && Set.of("audit", "report", "backup", "revoke").contains(args[0])) {
      if ((args[0].equals("audit") && args.length != 2) || (!args[0].equals("audit") && args.length != 3)) throw new IllegalArgumentException("Invalid command arguments");
      try (var registry = SyntheticRegistry.open(Path.of(args[1]), java.time.Clock.systemUTC())) {
        switch (args[0]) {
          case "backup" -> registry.backup(Path.of(args[2]));
          case "revoke" -> registry.revoke(args[2]);
          case "audit" -> System.out.println(new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(registry.audit()));
          case "report" -> System.out.println(new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(
              OfflineReport.reconcile(java.time.YearMonth.parse(args[2]), registry.outcomes())));
          default -> throw new IllegalStateException();
        }
      }
      return;
    }
    if (args.length != 2 || !Set.of("start", "start-web").contains(args[0])) throw new IllegalArgumentException("Usage: init|start|start-web|audit <directory>; report|backup|revoke <directory> <value>; restore <backup> <new-directory>");
    var registry = SyntheticRegistry.open(Path.of(args[1]), java.time.Clock.systemUTC());
    Lab lab;
    try { lab = new Lab(Path.of(args[1]), 8443, 8444, registry, args[0].equals("start-web")); }
    catch (Exception e) { registry.close(); throw e; }
    Runtime.getRuntime().addShutdownHook(new Thread(lab::close));
    System.out.println("SYNTHETIC LAB ONLY — start at " + lab.spBase + " — no Digg approval, no real proofing");
  }
}

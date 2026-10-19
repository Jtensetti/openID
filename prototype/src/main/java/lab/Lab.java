package lab;

import java.nio.file.*;
import java.util.*;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.*;
import se.swedenconnect.opensaml.*;
import se.swedenconnect.opensaml.sweid.xmlsec.config.SwedishEidSecurityConfiguration;

/** Two loopback HTTPS listeners in one disposable JVM. No external federation or production configuration. */
public final class Lab implements AutoCloseable {
  public final TestKeys keys;
  public final String idpBase, spBase;
  public final SyntheticRegistry registry;
  public final RelyingParty sp;
  private final ConfigurableApplicationContext idp;

  public Lab(Path keyDirectory, int idpPort, int spPort, SyntheticRegistry registry) throws Exception {
    if (idpPort < 1024 || spPort < 1024 || idpPort > 65535 || spPort > 65535 || idpPort == spPort)
      throw new IllegalArgumentException("Two distinct unprivileged loopback ports are required");
    keys = new TestKeys(keyDirectory); this.registry = registry;
    idpBase = "https://127.0.0.1:" + idpPort; spBase = "https://127.0.0.1:" + spPort;
    OpenSAMLInitializer.getInstance().initialize(new OpenSAMLSecurityDefaultsConfig(new LabSecurityConfiguration()), new OpenSAMLSecurityExtensionConfig());
    Path metadata = keys.directory().resolve("sp-metadata.xml");
    Files.writeString(metadata, Metadata.sp(keys, spBase));
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
    p.put("server.tomcat.max-http-form-post-size", "128KB"); p.put("server.error.include-message", "never");
    p.put("authn-server.base-url", idpBase); p.put("authn-server.sso.enabled", false);
    p.put("authn-server.saml.enabled", true); p.put("authn-server.oidc.enabled", false);
    p.put("authn-server.saml.entity-id", idpBase + "/idp"); p.put("authn-server.saml.requires-signed-requests", true);
    p.put("authn-server.saml.max-message-age", "60s"); p.put("authn-server.saml.clock-skew", "0s");
    p.put("authn-server.saml.assertions.encrypt", true); p.put("authn-server.saml.assertions.not-after", "30s");
    p.put("authn-server.saml.metadata-providers[0].location", metadata.toUri().toString());
    p.put("authn-server.saml.credentials.default-credential.bundle", "lab-idp");
    p.put("credential.bundles.jks.lab-idp.key.alias", "idp");
    p.put("credential.bundles.jks.lab-idp.key.key-password", TestKeys.PASSWORD);
    p.put("credential.bundles.jks.lab-idp.store.location", keys.directory().resolve("idp.p12").toUri().toString());
    p.put("credential.bundles.jks.lab-idp.store.password", TestKeys.PASSWORD);
    p.put("credential.bundles.jks.lab-idp.store.type", "PKCS12");
    p.put("authn-server.subject-identifier.secret", UUID.randomUUID().toString());
    p.put("authn-server.saml.metadata.ui-info.display-names.sv", "SIMULERAD e-id-labb");
    p.put("lab.idp-base", idpBase); p.put("lab.sp-base", spBase);
    StandardEnvironment env = new StandardEnvironment();
    // Security settings cannot be replaced with production metadata, keys or a public bind through environment/CLI.
    env.getPropertySources().remove(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);
    env.getPropertySources().remove(StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME);
    env.getPropertySources().addFirst(new MapPropertySource("isolated-lab", p));
    SpringApplication app = new SpringApplication(lab.idp.IdpApplication.class);
    app.setEnvironment(env); app.setAddCommandLineProperties(false);
    app.addInitializers(c -> c.getBeanFactory().registerSingleton("syntheticRegistry", registry));
    idp = app.run();
    try { sp = new RelyingParty(keys, idpBase, spBase, registry); }
    catch (Exception e) { idp.close(); throw e; }
  }
  @Override public void close() { sp.close(); idp.close(); }
  public static void main(String[] args) throws Exception {
    if (args.length == 2 && args[0].equals("init")) { TestKeys.initialize(Path.of(args[1])); return; }
    if (args.length != 2 || !args[0].equals("start")) throw new IllegalArgumentException("Usage: init|start <disposable-key-directory>");
    Lab lab = new Lab(Path.of(args[1]), 8443, 8444, SyntheticRegistry.fixtures());
    Runtime.getRuntime().addShutdownHook(new Thread(lab::close));
    System.out.println("SYNTHETIC LAB ONLY — start at " + lab.spBase + " — no Digg approval, no real proofing");
  }
}

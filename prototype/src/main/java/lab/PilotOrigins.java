package lab;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import com.fasterxml.jackson.databind.ObjectMapper;

/** Explicit private-beta origins; listeners remain on loopback behind the TLS ingress. */
public record PilotOrigins(String idp, String sp) {
  public PilotOrigins {
    validate(idp); validate(sp);
    if (idp.equals(sp)) throw new IllegalArgumentException("Distinct origins required");
  }
  private static void validate(String value) {
    var u = URI.create(value);
    if (!"https".equals(u.getScheme()) || u.getHost() == null || u.getUserInfo() != null
        || u.getPort() != -1 || !u.getRawPath().isEmpty() || u.getQuery() != null || u.getFragment() != null
        || !u.getHost().matches("[a-z0-9]+(?:[.-][a-z0-9]+)*\\.[a-z]{2,}"))
      throw new IllegalArgumentException("Canonical HTTPS DNS origin required");
  }
  public static PilotOrigins read(Path path) throws Exception {
    var data = new ObjectMapper().readTree(Files.readString(path));
    var names = new java.util.HashSet<String>(); data.fieldNames().forEachRemaining(names::add);
    if (!names.equals(Set.of("idp", "sp")) || !data.get("idp").isTextual() || !data.get("sp").isTextual())
      throw new IllegalArgumentException("Origin configuration fields");
    return new PilotOrigins(data.get("idp").textValue(), data.get("sp").textValue());
  }
}

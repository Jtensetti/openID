package lab;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.*;
import java.util.Set;

/** Explicit federation environment; neither mode grants an assurance level. */
public record RuntimeFederation(boolean sandbox) {
  public static RuntimeFederation read(Path input) throws Exception {
    Path path = input.toAbsolutePath().normalize();
    if (!input.isAbsolute() || !path.equals(path.toRealPath())
        || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
        || Files.getPosixFilePermissions(path).stream().anyMatch(p -> p == java.nio.file.attribute.PosixFilePermission.GROUP_WRITE
            || p == java.nio.file.attribute.PosixFilePermission.OTHERS_WRITE))
      throw new IllegalArgumentException("Protected regular federation configuration required");
    byte[] raw;
    try (var stream = Files.newInputStream(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
      raw = stream.readNBytes(4097);
    }
    if (raw.length == 0 || raw.length > 4096) throw new IllegalArgumentException("Federation configuration size");
    var value = new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
        .enable(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_TRAILING_TOKENS).readTree(raw);
    if (value == null || !value.isObject()) throw new IllegalArgumentException("Federation configuration object required");
    var fields = new java.util.HashSet<String>(); value.fieldNames().forEachRemaining(fields::add);
    if (!fields.equals(Set.of("version", "profile")) || !value.get("version").isInt()
        || value.get("version").intValue() != 1 || !value.get("profile").isTextual())
      throw new IllegalArgumentException("Federation configuration fields");
    return switch (value.get("profile").textValue()) {
      case "private" -> new RuntimeFederation(false);
      case "sweden-connect-sandbox" -> new RuntimeFederation(true);
      default -> throw new IllegalArgumentException("Unsupported federation profile");
    };
  }
}

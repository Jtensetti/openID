package lab;

import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class RuntimeFederationTest {
  @TempDir Path temporary;

  Path configuration(String json) throws Exception {
    Path path = temporary.resolve("federation.json");
    Files.writeString(path, json); Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-r--r--"));
    return path.toRealPath();
  }
  @Test void environmentIsAnExplicitChoiceWithoutOtherSettings() throws Exception {
    assertFalse(RuntimeFederation.read(configuration("{\"version\":1,\"profile\":\"private\"}")).sandbox());
    assertTrue(RuntimeFederation.read(configuration("{\"version\":1,\"profile\":\"sweden-connect-sandbox\"}")).sandbox());
    for (String value : new String[]{"{}", "null", "[]", "", "{\"version\":true,\"profile\":\"private\"}",
        "{\"version\":1,\"profile\":\"production\"}", "{\"version\":1,\"profile\":\"private\",\"profile\":\"sweden-connect-sandbox\"}",
        "{\"version\":1,\"profile\":\"private\",\"url\":\"https://attacker.invalid\"}", "{\"version\":1,\"profile\":\"private\"} {}"}) {
      Path path = configuration(value); assertThrows(Exception.class, () -> RuntimeFederation.read(path), value);
    }
  }
  @Test void sharedWritableLinkedMissingOrOversizeConfigurationCannotEnableFederation() throws Exception {
    Path path = configuration("{\"version\":1,\"profile\":\"private\"}");
    Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-rw-r--"));
    assertThrows(IllegalArgumentException.class, () -> RuntimeFederation.read(path));
    Path link = temporary.resolve("link.json").toAbsolutePath(); Files.createSymbolicLink(link, path);
    assertThrows(IllegalArgumentException.class, () -> RuntimeFederation.read(link));
    assertThrows(Exception.class, () -> RuntimeFederation.read(temporary.resolve("missing.json").toAbsolutePath()));
    Path large = configuration(" ".repeat(4097));
    assertThrows(IllegalArgumentException.class, () -> RuntimeFederation.read(large));
  }
}

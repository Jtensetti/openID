package lab;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class PilotOriginsTest {
  @Test void originsAreFixedCanonicalAndDistinct() {
    assertEquals("https://idp.example.org", new PilotOrigins("https://idp.example.org", "https://sp.example.org").idp());
    for (String bad : new String[]{"http://idp.example.org", "https://user@idp.example.org", "https://idp.example.org/", "https://idp.example.org:443", "https://idp.example.org?x=1", "https://idp.example.org#x", "https://localhost", "https://127.0.0.1"})
      assertThrows(IllegalArgumentException.class, () -> new PilotOrigins(bad, "https://sp.example.org"), bad);
    assertThrows(IllegalArgumentException.class, () -> new PilotOrigins("https://same.example.org", "https://same.example.org"));
  }
}

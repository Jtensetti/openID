package lab.phone;

import java.util.Map;

/** The three Sweden Connect Sandbox clients permitted to request app approval. */
public final class SandboxRelyingParties {
  private SandboxRelyingParties() {}
  public static final Map<String, String> NAMES = Map.of(
      "https://testclient.sandbox.swedenconnect.se/testsp1", "Sweden Connect Test-SP 1",
      "https://testclient.sandbox.swedenconnect.se/testsp2", "Sweden Connect Test-SP 2",
      "https://testclient.sandbox.swedenconnect.se/test-signservice1", "Sweden Connect Test – underskrift");
  public static boolean requestsPersonalNumber(String requester) {
    return NAMES.containsKey(requester) && !requester.endsWith("/testsp2");
  }
  public static String purpose(boolean signing, String requester) {
    String attributes = requestsPersonalNumber(requester) ? "förnamn, efternamn och personnummer från passet" : "förnamn och efternamn";
    return (signing ? "Skriv under testtexten och dela " : "Logga in och dela ") + attributes + " med Sweden Connects testtjänst";
  }
}

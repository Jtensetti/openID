package lab.proofing;

import java.nio.file.*;
import java.security.cert.*;
import java.time.Clock;
import java.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;

/** Private stdin/stdout integration: no document bytes or identity fields on command lines/logs. */
public final class PassportCommand {
  public static void run(String trustFile) throws Exception {
    var json = new ObjectMapper().enable(com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    try {
      var anchors = new HashSet<X509Certificate>();
      try (var stream = Files.newInputStream(Path.of(trustFile))) {
        for (var c : CertificateFactory.getInstance("X.509").generateCertificates(stream)) anchors.add((X509Certificate)c);
      }
      byte[] input = System.in.readNBytes(3_000_001);
      if (input.length > 3_000_000) throw new IllegalArgumentException();
      var request = json.readTree(input);
      if (request == null || request.size() != 3) throw new IllegalArgumentException();
      var decoder = Base64.getDecoder();
      var result = new PassportVerifier(anchors, Clock.systemUTC()).verify(decoder.decode(request.required("sod").asText()),
          decoder.decode(request.required("dg1").asText()), decoder.decode(request.required("dg2").asText()));
      System.out.println(json.writeValueAsString(Map.of("passiveAuthentication", true,
          "portrait", Base64.getEncoder().encodeToString(result.portrait()), "mimeType", result.mimeType(),
          "chipAuthentication", "NOT_PERFORMED", "revocation", "NOT_CHECKED")));
    } catch (Exception e) {
      System.out.println("{\"passiveAuthentication\":false,\"error\":\"VERIFICATION_FAILED\"}");
      System.exit(2);
    }
  }
}

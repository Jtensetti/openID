package lab.proofing;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.cert.*;
import java.time.Clock;
import java.util.*;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import com.fasterxml.jackson.databind.ObjectMapper;

/** Validate an operator-supplied CRL update without reading a passport or fetching trust. */
public final class CrlCommand {
  public static final int MAX_BYTES = 5_000_000;
  private record Entry(BigInteger number, long issued, long expires, String digest) {}
  private static String digest(byte[] bytes) throws Exception {
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
  }
  private static Map<String, Entry> inspect(byte[] bytes, Set<X509Certificate> trust, Clock clock,
      boolean current) throws Exception {
    if (bytes.length == 0 || bytes.length > MAX_BYTES) throw new IllegalArgumentException();
    var crls = PassportVerifier.loadCrls(new ByteArrayInputStream(bytes));
    if (crls.isEmpty() || crls.size() > 32) throw new IllegalArgumentException();
    // Share the passport verifier's scope, key-usage and signature validation.
    new PassportVerifier(trust, crls, clock);
    var result = new HashMap<String, Entry>();
    long now = clock.instant().getEpochSecond();
    for (var crl : crls) {
      byte[] extension = crl.getExtensionValue("2.5.29.20");
      if (extension == null || crl.getNextUpdate() == null
          || (crl.getCriticalExtensionOIDs() != null && crl.getCriticalExtensionOIDs().contains("2.5.29.20")))
        throw new IllegalArgumentException();
      var number = ASN1Integer.getInstance(ASN1OctetString.getInstance(extension).getOctets()).getValue();
      if (number.signum() < 0 || number.toByteArray().length > 20) throw new IllegalArgumentException();
      long issued = crl.getThisUpdate().toInstant().getEpochSecond();
      long expires = crl.getNextUpdate().toInstant().getEpochSecond();
      if (issued > now || expires <= issued || (current && expires <= now)) throw new IllegalArgumentException();
      var entry = new Entry(number, issued, expires, digest(crl.getEncoded()));
      // One complete list per issuer prevents ambiguous versions in a bundle.
      if (result.put(digest(crl.getIssuerX500Principal().getEncoded()), entry) != null) throw new IllegalArgumentException();
    }
    return Map.copyOf(result);
  }
  public static Map<String, Object> validate(byte[] candidate, byte[] previous,
      Set<X509Certificate> trust, Clock clock) throws Exception {
    var next = inspect(candidate, trust, clock, true);
    if (previous != null) {
      var old = inspect(previous, trust, clock, false);
      for (var item : old.entrySet()) {
        var before = item.getValue(); var after = next.get(item.getKey());
        if (after == null) throw new IllegalArgumentException(); // no silent loss of issuer coverage
        if (before.digest().equals(after.digest())) continue;
        if (after.number().compareTo(before.number()) <= 0 || after.issued() < before.issued())
          throw new IllegalArgumentException();
      }
    }
    return Map.of("status", "VERIFIED", "sha256", digest(candidate), "issuers", next.size(),
        "validUntil", next.values().stream().mapToLong(Entry::expires).min().orElseThrow());
  }
  public static void run(String trustFile) throws Exception {
    var json = new ObjectMapper().enable(com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    try {
      Set<X509Certificate> trust;
      try (var stream = Files.newInputStream(Path.of(trustFile))) { trust = PassportVerifier.loadTrust(stream); }
      byte[] input = System.in.readNBytes(14_000_001);
      if (input.length > 14_000_000) throw new IllegalArgumentException();
      var request = json.readTree(input);
      if (request == null || !request.isObject() || !request.has("candidate")
          || request.size() != (request.has("previous") ? 2 : 1)
          || !request.get("candidate").isTextual()
          || (request.has("previous") && !request.get("previous").isTextual())) throw new IllegalArgumentException();
      var decoder = Base64.getDecoder();
      System.out.println(json.writeValueAsString(validate(decoder.decode(request.get("candidate").textValue()),
          request.has("previous") ? decoder.decode(request.get("previous").textValue()) : null, trust, Clock.systemUTC())));
    } catch (Exception e) {
      // Never echo supplied files, certificate subjects, paths or library exceptions.
      System.out.println("{\"status\":\"REJECTED\",\"error\":\"CRL_UPDATE_REJECTED\"}");
      System.exit(2);
    }
  }
}

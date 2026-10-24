package lab.phone;

import com.fasterxml.jackson.databind.*;
import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;

/** One bounded exchange with the local credential registry. */
public final class PhoneBridge {
  public static final String SERVICE = "openID kontotjänst";
  public static final String PURPOSE = "Logga in och dela namn, födelsedatum enligt passet och passfoto";
  public static final String SIGN_PURPOSE = "Skriv under och dela namn, födelsedatum enligt passet och passfoto";
  public static final int SIGN_MESSAGE_LIMIT = 400;
  /** {@code signMessage} is the exact plain text shown in the app, or {@code null} for a login. */
  public record Pending(String id, String secret, String binding, long expiresAt, String code, String signMessage) {
    public Pending(String id, String secret, String binding, long expiresAt, String code) { this(id, secret, binding, expiresAt, code, null); }
    public boolean signing() { return signMessage != null; }
    @Override public String toString() { return "Phone approval"; }
  }
  /** A consumed approval. A signing approval names the SHA-256 of the exact text the holder signed. */
  public record Approved(PhoneIdentity identity, String signMessageSha256) {
    @Override public String toString() { return "Phone approval result"; }
  }
  private static final ObjectMapper JSON = new ObjectMapper().enable(com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
  private final Path socket;
  private final String audience;
  public PhoneBridge(Path socket, String audience) { this.socket = socket.toAbsolutePath(); this.audience = audience; }

  public Pending start(String binding) { return start(binding, null); }
  public Pending start(String binding, String signMessage) {
    if (signMessage != null) requireSignMessage(signMessage);
    var result = call(signMessage == null ? Map.of("operation", "start", "binding", binding)
        : Map.of("operation", "start", "binding", binding, "signMessage", signMessage));
    String id = text(result, "id"), secret = text(result, "secret"), code = text(result, "code");
    long expires = result.path("expiresAt").asLong();
    if (!id.matches("[a-f0-9]{64}") || !secret.matches("[A-Za-z0-9_-]{43}") || !code.matches("[0-9]{6}") ||
        !SERVICE.equals(text(result, "relyingParty")) || !(signMessage == null ? PURPOSE : SIGN_PURPOSE).equals(text(result, "purpose")) ||
        (signMessage == null ? result.has("signMessage") : !signMessage.equals(text(result, "signMessage"))) ||
        expires <= Instant.now().getEpochSecond() || expires > Instant.now().getEpochSecond()+120) throw rejected();
    return new Pending(id, secret, binding, expires, code, signMessage);
  }
  /** Same rules as the registry: bounded plain text without control or bidirectional override characters. */
  public static String requireSignMessage(String value) {
    if (value == null || value.isEmpty() || !value.equals(value.strip()) || value.codePointCount(0, value.length()) > SIGN_MESSAGE_LIMIT
        || value.chars().filter(c -> c == '\n').count() > 12
        || value.codePoints().anyMatch(c -> (c < 32 && c != '\n') || (c >= 127 && c < 160) || c == 0x2028 || c == 0x2029
            || (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069) || c == 0xfeff))
      throw new IllegalArgumentException("Sign message cannot be displayed");
    return value;
  }
  public static String sha256(String value) {
    try { return HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
    catch (java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
  }
  public JsonNode exchange(String operation, Pending pending) {
    return call(Map.of("operation", operation, "id", pending.id(), "secret", pending.secret(), "binding", pending.binding()));
  }
  public PhoneIdentity consume(Pending pending) { return approve(pending).identity(); }
  public Approved approve(Pending pending) {
    var result = exchange("consume", pending);
    if (!"AUTHENTICATED".equals(text(result, "state"))) throw rejected();
    var identity = result.path("identity");
    String digest = null;
    if (pending.signing()) {
      digest = text(result, "signMessageSha256");
      if (!java.security.MessageDigest.isEqual(digest.getBytes(StandardCharsets.US_ASCII), sha256(pending.signMessage()).getBytes(StandardCharsets.US_ASCII)))
        throw rejected();
    } else if (result.has("signMessageSha256")) throw rejected();
    return new Approved(new PhoneIdentity(text(result, "subject"), text(result, "credentialId"), text(result, "version"),
        text(identity, "displayName"), text(identity, "birthDateMrz"), text(identity, "portraitJpeg")), digest);
  }
  public boolean active(PhoneIdentity identity) {
    try {
      var result = call(Map.of("operation", "check", "credentialId", identity.credential(), "subject", identity.subject(), "version", identity.version()));
      return "ACTIVE".equals(text(result, "state")) && result.path("expiresAt").asLong() > Instant.now().getEpochSecond();
    } catch (IllegalStateException e) { return false; }
  }
  public boolean ready() {
    try { return "READY".equals(text(call(Map.of("operation", "health")), "state")); }
    catch (IllegalStateException e) { return false; }
  }
  private JsonNode call(Map<String, String> parameters) {
    try (var channel = SocketChannel.open(StandardProtocolFamily.UNIX); var selector = Selector.open()) {
      channel.configureBlocking(false);
      channel.connect(UnixDomainSocketAddress.of(socket));
      channel.register(selector, SelectionKey.OP_CONNECT);
      long deadline = System.nanoTime()+5_000_000_000L;
      while (!channel.finishConnect()) await(selector, deadline);
      var request = new HashMap<>(parameters); request.put("audience", audience);
      var input = ByteBuffer.wrap((JSON.writeValueAsString(request)+"\n").getBytes(StandardCharsets.UTF_8));
      channel.keyFor(selector).interestOps(SelectionKey.OP_WRITE);
      while (input.hasRemaining()) if (channel.write(input) == 0) await(selector, deadline);
      channel.keyFor(selector).interestOps(SelectionKey.OP_READ);
      var output = new ByteArrayOutputStream(); var buffer = ByteBuffer.allocate(4096);
      boolean done = false;
      while (!done) {
        int count = channel.read(buffer);
        if (count < 0) throw rejected();
        if (count == 0) { await(selector, deadline); continue; }
        buffer.flip();
        while (buffer.hasRemaining()) {
          byte value = buffer.get();
          if (value == '\n') { if (buffer.hasRemaining()) throw rejected(); done = true; break; }
          output.write(value);
          if (output.size() > 100_000) throw rejected();
        }
        buffer.clear();
        if (System.nanoTime() >= deadline) throw rejected();
      }
      var response = JSON.readTree(output.toByteArray());
      if (!response.path("ok").isBoolean() || !response.path("ok").asBoolean() || !response.path("result").isObject()) throw rejected();
      return response.get("result");
    } catch (Exception e) { throw rejected(); }
  }
  private static void await(Selector selector, long deadline) throws IOException {
    long remaining = deadline-System.nanoTime();
    if (remaining <= 0) throw rejected();
    selector.select(Math.max(1, remaining/1_000_000)); selector.selectedKeys().clear();
  }
  public static String text(JsonNode node, String key) {
    if (!node.path(key).isTextual()) throw rejected();
    return node.get(key).textValue();
  }
  private static IllegalStateException rejected() { return new IllegalStateException("Credential registry unavailable or request rejected"); }
}

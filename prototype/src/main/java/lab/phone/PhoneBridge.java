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
  public record Pending(String id, String secret, String binding, long expiresAt, String code) {
    @Override public String toString() { return "Phone approval"; }
  }
  private static final ObjectMapper JSON = new ObjectMapper().enable(com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
  private final Path socket;
  private final String audience;
  public PhoneBridge(Path socket, String audience) { this.socket = socket.toAbsolutePath(); this.audience = audience; }

  public Pending start(String binding) {
    var result = call(Map.of("operation", "start", "binding", binding));
    String id = text(result, "id"), secret = text(result, "secret"), code = text(result, "code");
    long expires = result.path("expiresAt").asLong();
    if (!id.matches("[a-f0-9]{64}") || !secret.matches("[A-Za-z0-9_-]{43}") || !code.matches("[0-9]{6}") ||
        !SERVICE.equals(text(result, "relyingParty")) || !PURPOSE.equals(text(result, "purpose")) ||
        expires <= Instant.now().getEpochSecond() || expires > Instant.now().getEpochSecond()+120) throw rejected();
    return new Pending(id, secret, binding, expires, code);
  }
  public JsonNode exchange(String operation, Pending pending) {
    return call(Map.of("operation", operation, "id", pending.id(), "secret", pending.secret(), "binding", pending.binding()));
  }
  public PhoneIdentity consume(Pending pending) {
    var result = exchange("consume", pending);
    if (!"AUTHENTICATED".equals(text(result, "state"))) throw rejected();
    var identity = result.path("identity");
    return new PhoneIdentity(text(result, "subject"), text(result, "credentialId"), text(result, "version"),
        text(identity, "displayName"), text(identity, "birthDateMrz"), text(identity, "portraitJpeg"));
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

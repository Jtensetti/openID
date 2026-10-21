package lab.proofing;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.*;
import java.nio.file.*;
import java.security.cert.*;
import java.time.Clock;
import java.util.*;
import net.sf.scuba.smartcards.*;
import org.jmrtd.PassportService;

/** Private, bounded JSON-line transport. Only APDUs leave the server process. */
public final class ChipCommand {
  static final ObjectMapper JSON = new ObjectMapper()
      .enable(com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION);

  public static void run(String trustFile) {
    try (var input = new BufferedInputStream(System.in)) {
      var anchors = new HashSet<X509Certificate>();
      try (var stream = Files.newInputStream(Path.of(trustFile))) {
        anchors.addAll(PassportVerifier.loadTrust(stream));
      }
      var request = line(input, 3_000_000);
      if (!fields(request, Set.of("sod", "dg1", "dg2", "dg14"))) throw new IOException();
      var document = ChipAuthentication.verifyDocument(new PassportVerifier(anchors, Clock.systemUTC()),
          decode(request, "sod", 65536), decode(request, "dg1", 4096),
          decode(request, "dg2", 2_000_000), decode(request, "dg14", 16384));
      var transport = new Relay(input, System.out);
      var service = new PassportService(transport, 256, 223, false, true);
      try { ChipAuthentication.authenticate(service, document); }
      finally { service.close(); }
      System.out.println("{\"type\":\"verified\"}");
    } catch (Exception e) {
      System.out.println("{\"type\":\"rejected\"}");
      System.exit(2);
    }
  }

  static boolean fields(JsonNode value, Set<String> names) {
    if (value == null || !value.isObject() || value.size() != names.size()) return false;
    for (String name : names) if (!value.has(name)) return false;
    return true;
  }
  static byte[] decode(JsonNode value, String field, int limit) throws IOException {
    if (!value.path(field).isTextual()) throw new IOException();
    byte[] result = Base64.getDecoder().decode(value.path(field).textValue());
    if (result.length == 0 || result.length > limit) throw new IOException();
    return result;
  }
  static JsonNode line(InputStream input, int limit) throws IOException {
    var result = new ByteArrayOutputStream();
    for (int b; (b = input.read()) != -1;) {
      if (b == '\n') return JSON.readTree(result.toByteArray());
      if (result.size() == limit) throw new IOException();
      result.write(b);
    }
    throw new EOFException();
  }

  static final class Relay extends CardService {
    private final InputStream input;
    private final PrintStream output;
    private int sequence;
    private boolean open;
    Relay(InputStream input, PrintStream output) { this.input = input; this.output = output; }
    @Override public void open() { open = true; }
    @Override public boolean isOpen() { return open; }
    @Override public void close() { open = false; }
    @Override public byte[] getATR() { return new byte[0]; }
    @Override public boolean isConnectionLost(Exception e) { return true; }
    @Override public boolean isExtendedAPDULengthSupported() { return false; }
    @Override public ResponseAPDU transmit(CommandAPDU command) throws CardServiceException {
      try {
        if (!open || sequence >= 128 || command.getBytes().length > 4096
            || !Set.of(0x00, 0x0C, 0x10, 0x1C).contains(command.getCLA())
            || !Set.of(0xA4, 0xB0, 0x22, 0x86, 0xC0).contains(command.getINS())) throw new IOException();
        output.println(JSON.writeValueAsString(Map.of("type", "command", "sequence", sequence,
            "command", Base64.getEncoder().encodeToString(command.getBytes()))));
        output.flush();
        var reply = line(input, 8192);
        if (!fields(reply, Set.of("sequence", "response")) || !reply.path("sequence").isInt()
            || reply.path("sequence").intValue() != sequence++) throw new IOException();
        byte[] response = decode(reply, "response", 4096);
        if (response.length < 2) throw new IOException();
        return new ResponseAPDU(response);
      } catch (Exception e) { throw new CardServiceException("Chip exchange rejected"); }
    }
  }
}

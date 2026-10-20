import com.sun.net.httpserver.HttpServer;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.*;

/** Health endpoints for the sealed deployment. */
public final class SealedEnvironment implements AutoCloseable {
  private final HttpServer server;
  private final ExecutorService executor = new ThreadPoolExecutor(2, 4, 30, TimeUnit.SECONDS,
      new ArrayBlockingQueue<>(32), new ThreadPoolExecutor.AbortPolicy());
  static final String SEALED = "{\"environment\":\"production\",\"status\":\"SEALED\",\"eidIssuanceEnabled\":false}";

  public SealedEnvironment(int port) throws Exception {
    server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 32);
    server.setExecutor(executor);
    server.createContext("/", x -> {
      try {
        boolean live = x.getRequestMethod().equals("GET") && x.getRequestURI().toString().equals("/health/live");
        var h = x.getResponseHeaders();
        h.set("Content-Type", "application/json; charset=utf-8"); h.set("Cache-Control", "no-store");
        h.set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
        h.set("X-Content-Type-Options", "nosniff"); h.set("Referrer-Policy", "no-referrer");
        h.set("Connection", "close");
        byte[] body = SEALED.getBytes(StandardCharsets.UTF_8);
        // Liveness is process health only. Readiness and all identity routes remain 503.
        if (x.getRequestMethod().equals("HEAD")) x.sendResponseHeaders(503, -1);
        else { x.sendResponseHeaders(live ? 200 : 503, body.length); x.getResponseBody().write(body); }
      } finally { x.close(); }
    });
    server.start();
  }
  @Override public void close() { server.stop(1); executor.shutdownNow(); }
  public static void main(String[] args) throws Exception {
    String raw = System.getenv().getOrDefault("PORT", "8080");
    if (!raw.matches("[0-9]{4,5}")) throw new IllegalArgumentException("Invalid unprivileged PORT");
    int port = Integer.parseInt(raw);
    if (port < 1024 || port > 65535) throw new IllegalArgumentException("Invalid unprivileged PORT");
    if (args.length != 1 || !(args[0].equals("serve") || args[0].equals("probe"))) throw new IllegalArgumentException("Usage: serve|probe");
    if (args[0].equals("probe")) {
      try (var client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).followRedirects(HttpClient.Redirect.NEVER).build()) {
        var response = client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/health/live"))
            .timeout(Duration.ofSeconds(3)).GET().build(), HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200 || !response.body().equals(SEALED)) throw new IllegalStateException("Health check failed");
        for (String path : new String[]{"/health/ready", "/login", "/saml2/post/authn"}) {
          var blocked = client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
              .timeout(Duration.ofSeconds(3)).GET().build(), HttpResponse.BodyHandlers.ofString());
          if (blocked.statusCode() != 503 || !blocked.body().equals(SEALED)) throw new IllegalStateException("Sealed route check failed");
        }
      }
      return;
    }
    var app = new SealedEnvironment(port);
    Runtime.getRuntime().addShutdownHook(new Thread(app::close));
    System.out.println("openID production infrastructure: SEALED; no identity issuance or authentication");
  }
}

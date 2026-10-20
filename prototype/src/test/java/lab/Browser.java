package lab;

import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import javax.net.ssl.SSLContext;
import org.jsoup.Jsoup;

/** Small HTTP browser: real TLS, cookies, redirects and form posts; no trust-all TLS. */
final class Browser {
  final CookieManager cookies = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
  final HttpClient client;
  final Lab lab;
  Browser(Lab lab) throws Exception {
    this.lab = lab;
    client = HttpClient.newBuilder().sslContext(lab.keys.sslContext()).cookieHandler(cookies).followRedirects(HttpClient.Redirect.NEVER).build();
  }
  HttpResponse<String> get(String url) throws Exception { return client.send(HttpRequest.newBuilder(URI.create(url)).GET().build(), HttpResponse.BodyHandlers.ofString()); }
  HttpResponse<String> post(String url, Map<String, String> form, String origin) throws Exception {
    var b = HttpRequest.newBuilder(URI.create(url)).header("Content-Type", "application/x-www-form-urlencoded");
    if (origin != null) b.header("Origin", origin);
    String body = form.entrySet().stream().map(e -> enc(e.getKey()) + "=" + enc(e.getValue())).collect(java.util.stream.Collectors.joining("&"));
    return client.send(b.POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
  }
  HttpResponse<String> follow(HttpResponse<String> response) throws Exception {
    for (int i = 0; i < 10 && response.statusCode() / 100 == 3; i++) {
      URI next = response.uri().resolve(response.headers().firstValue("Location").orElseThrow());
      if (!(next.toString().startsWith(lab.idpBase + "/") || next.toString().startsWith(lab.spBase + "/"))) throw new AssertionError("External redirect: " + next);
      response = get(next.toString());
    }
    return response;
  }
  HttpResponse<String> start() throws Exception { return follow(get(lab.spBase + "/login")); }
  HttpResponse<String> approve(HttpResponse<String> page, Map<String, String> changes) throws Exception {
    var form = hidden(page.body());
    form.put("action", "approve"); form.put("credential", "TEST-CREDENTIAL-alice"); form.put("simulatedProofing", "acknowledged"); form.putAll(changes);
    return follow(post(lab.idpBase + "/lab", form, lab.idpBase));
  }
  HttpResponse<String> receive(HttpResponse<String> response) throws Exception {
    return follow(post(lab.spBase + "/acs", hidden(response.body()), lab.idpBase));
  }
  static Map<String, String> hidden(String html) {
    Map<String, String> m = new HashMap<>();
    Jsoup.parse(html).select("input[type=hidden][name]").forEach(e -> m.put(e.attr("name"), e.attr("value")));
    return m;
  }
  static String enc(String s) { return URLEncoder.encode(s, StandardCharsets.UTF_8); }
}

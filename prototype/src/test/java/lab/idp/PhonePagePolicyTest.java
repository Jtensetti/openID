package lab.idp;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import static org.junit.jupiter.api.Assertions.*;

class PhonePagePolicyTest {
  @Test void phoneResponseAllowsOnlyConfiguredOidcReturnAndRetainsOtherRestrictions() throws Exception {
    var filter = new IdpApplication().labBoundary(null, "https://idp.example.test", "https://sp.example.test", true).getFilter();
    for (String route : new String[]{"/phone", "/phone/complete", "/phone/return"}) {
      var request = new MockHttpServletRequest("GET", route);
      request.setRemoteAddr("127.0.0.1"); request.addHeader("Host", "idp.example.test");
      var response = new MockHttpServletResponse();
      filter.doFilter(request, response, (req, res) -> {});
      String csp = response.getHeader("Content-Security-Policy");
      assertNotNull(csp);
      assertTrue(csp.contains("form-action 'self' https://sp.example.test/oidc/callback;"));
      assertTrue(csp.contains("connect-src 'self';"));
      assertTrue(csp.contains("frame-ancestors 'none';"));
      assertFalse(csp.contains("*")); assertFalse(csp.contains("unsafe-inline"));
    }
  }
  @Test void nonOidcPagesRemainSelfOnlyAndUntrustedOriginCannotEnterPolicy() {
    assertTrue(IdpApplication.phonePageCsp("https://sp.example.test", false).contains("form-action 'self';"));
    for (String origin : new String[]{"http://sp.example.test", "https://sp.example.test/path", "https://user@sp.example.test",
        "https://sp.example.test?redirect=evil", "https://sp.example.test#evil", "https://sp.example.test; form-action *"})
      assertThrows(IllegalArgumentException.class, () -> IdpApplication.phonePageCsp(origin, true));
  }
}

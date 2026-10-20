package lab.idp;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import lab.SyntheticRegistry;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurerAdapter;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

@SpringBootApplication
public class IdpApplication {
  private static final String PAGE_CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; manifest-src 'self'; worker-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
  @Bean WebAuthnService webAuthnService(SyntheticRegistry registry, @Value("${lab.idp-base}") String base,
      @Value("${lab.webauthn:false}") boolean enabled) {
    return new WebAuthnService(registry, base, java.time.Clock.systemUTC(), enabled);
  }
  @Bean
  AuthnServerConfigurerAdapter labProtocolSecurity(@Value("${lab.phone:false}") boolean phone) {
    return (http, configurer) -> {
      // Replace the upstream matcher that exempts ALL protocol/provider endpoints from CSRF.
      // Only the signed SAML HTTP-POST binding is exempt; approval routes remain protected.
      http.csrf(AbstractHttpConfigurer::disable);
      http.csrf(csrf -> csrf.ignoringRequestMatchers("/saml2/post/authn"));
      configurer.authnFlowMaxAge(java.time.Duration.ofSeconds(phone ? 120 : 60));
      if (phone) configurer.protocol(se.swedenconnect.spring.authnserver.saml.config.Saml2IdpConfigurer.class,
          saml -> saml.attributeMapping(lab.phone.PhoneAttributes.mapping()));
    };
  }
  @Bean @Order(2)
  SecurityFilterChain labPages(HttpSecurity http) throws Exception {
    // CSRF stays enabled for approval and revocation forms.
    return http.authorizeHttpRequests(a -> a.requestMatchers("/", "/phone/**", "/lab", "/lab/revoke", "/lab/webauthn/**", "/wallet/**", "/error").permitAll().anyRequest().denyAll())
        .headers(h -> h.contentSecurityPolicy(c -> c.policyDirectives(PAGE_CSP)))
        .build();
  }
  @Bean
  FilterRegistrationBean<OncePerRequestFilter> labBoundary(SyntheticRegistry registry, @Value("${lab.idp-base}") String base) {
    var filter = new OncePerRequestFilter() {
      @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        if (!request.getRemoteAddr().equals("127.0.0.1") || !java.net.URI.create(base).getAuthority().equals(request.getHeader("Host")) ||
            request.getHeader("Forwarded") != null || request.getHeader("X-Forwarded-Host") != null ||
            ((request.getRequestURI().startsWith("/lab") || request.getRequestURI().startsWith("/wallet") || request.getRequestURI().startsWith("/phone")) && request.getMethod().equals("POST") && !base.equals(request.getHeader("Origin")))) {
          response.sendError(403); return;
        }
        // no-referrer makes browser form POSTs send Origin:null, defeating the strict origin check.
        // strict-origin sends only the origin (never SAML query parameters) between the two HTTPS ports.
        response.setHeader("Cache-Control", "no-store"); response.setHeader("Referrer-Policy", "strict-origin");
        response.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), publickey-credentials-create=(self), publickey-credentials-get=(self)");
        // Provider endpoints use upstream's filter chain, not labPages.
        // Resume routes render upstream's separately protected SAML auto-POST page.
        if ((request.getRequestURI().startsWith("/lab") && !request.getRequestURI().equals("/lab/resume")) ||
            (request.getRequestURI().startsWith("/phone") && !request.getRequestURI().equals("/phone/resume")))
          response.setHeader("Content-Security-Policy", PAGE_CSP);
        // In lab mode, revocation cannot interleave status verification and SAML response signing.
        try {
          if (request.getRequestURI().equals("/lab/resume")) {
            synchronized (registry) { chain.doFilter(request, response); }
          } else chain.doFilter(request, response);
        } catch (UnrecoverableErrorException e) {
          // Expected protocol rejection: do not let Tomcat log attacker-controlled identifiers.
          response.sendError(400);
        }
      }
    };
    var bean = new FilterRegistrationBean<OncePerRequestFilter>(filter);
    bean.setOrder(Ordered.HIGHEST_PRECEDENCE); return bean;
  }
}

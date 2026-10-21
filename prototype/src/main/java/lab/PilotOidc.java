package lab;
import java.util.*;
import java.security.interfaces.RSAPublicKey;
import com.nimbusds.jose.jwk.*;
import com.fasterxml.jackson.databind.ObjectMapper;

/** Pinned private-beta client and keys. No dynamic clients or external metadata fetching. */
final class PilotOidc {
  static void configure(Map<String,Object> p, TestKeys keys, String issuer, String sp) throws Exception {
    var key = new RSAKey.Builder((RSAPublicKey)keys.certificate("sp").getPublicKey()).keyID("pilot-sp").keyUse(KeyUse.SIGNATURE).build();
    var metadata = new LinkedHashMap<String,Object>();
    metadata.put("client_name", "openID kontotjänst");
    metadata.put("redirect_uris", List.of(sp+"/oidc/callback"));
    metadata.put("response_types", List.of("code"));
    metadata.put("grant_types", List.of("authorization_code"));
    metadata.put("token_endpoint_auth_method", "private_key_jwt");
    metadata.put("token_endpoint_auth_signing_alg", "RS256");
    metadata.put("id_token_signed_response_alg", "RS256");
    metadata.put("jwks", new JWKSet(key).toJSONObject());
    p.put("authn-server.oidc.issuer", issuer);
    p.put("authn-server.oidc.keys.signing[0].credential.bundle", "lab-idp");
    p.put("authn-server.oidc.keys.signing[0].default-key", true);
    p.put("authn-server.oidc.clients[0].client-id", sp+"/sp");
    p.put("authn-server.oidc.clients[0].metadata", new ObjectMapper().writeValueAsString(metadata));
    p.put("authn-server.oidc.authorization-request.require-pkce", true);
    p.put("authn-server.oidc.client-authentication-methods", "private_key_jwt");
    p.put("authn-server.oidc.tokens.authorization-code-lifetime", "30s");
    p.put("authn-server.oidc.tokens.access-token-lifetime", "60s");
    p.put("authn-server.oidc.tokens.id-token-lifetime", "60s");
  }
}

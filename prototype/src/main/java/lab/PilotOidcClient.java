package lab;

import com.sun.net.httpserver.HttpExchange;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.*;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.id.*;
import com.nimbusds.oauth2.sdk.pkce.*;
import com.nimbusds.openid.connect.sdk.*;
import com.nimbusds.openid.connect.sdk.claims.*;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.*;
import lab.phone.*;
import org.springframework.web.util.HtmlUtils;

/** Authorization Code + S256 PKCE, nonce and pinned issuer/key; no persistent bearer token. */
final class PilotOidcClient {
  private static final String COOKIE="__Host-openid-oidc";
  private record Pending(State state, Nonce nonce, CodeVerifier verifier, Instant expires) {}
  private record Session(PhoneIdentity identity, Instant expires) {}
  private final Map<String,Pending> pending=new HashMap<>();
  private final Map<String,Session> sessions=new HashMap<>();
  private final String issuer, base, client;
  private final TestKeys keys;
  private final PhoneBridge bridge;
  private final IDTokenValidator validator;
  PilotOidcClient(TestKeys keys, String issuer, String base, PhoneBridge bridge) throws Exception {
    this.keys=keys;this.issuer=issuer;this.base=base;this.client=base+"/sp";this.bridge=bridge;
    validator=new IDTokenValidator(new Issuer(issuer),new ClientID(client),JWSAlgorithm.RS256,
        new com.nimbusds.jose.jwk.JWKSet(se.swedenconnect.spring.authnserver.oidc.keys.SigningKey.activeDefault(keys.credential("idp")).getPublicJwk()));
    validator.setMaxClockSkew(0);
  }
  boolean handle(HttpExchange x) throws Exception {
    String path=x.getRequestURI().getPath();
    if(!path.startsWith("/oidc/"))return false;
    if(!x.getRequestMethod().equals("GET")){send(x,405,"Metoden stöds inte.");return true;}
    try {
      if(path.equals("/oidc/login"))start(x);
      else if(path.equals("/oidc/callback"))complete(x);
      else if(path.equals("/oidc/me"))show(x);
      else send(x,404,"Sidan finns inte.");
    } catch(Exception e) {
      synchronized(this){pending.remove(cookie(x));sessions.remove(cookie(x));}
      send(x,400,"<h1>Inloggningen kunde inte slutföras</h1><p>Inget godkännande har bekräftats här. Begäran kan ha nekats, gått ut eller inte uppfyllt kontrollen.</p><p><a href='/oidc/login'>Starta en ny OIDC-inloggning</a></p>");
    }
    return true;
  }
  private void start(HttpExchange x)throws Exception {
    if(x.getRequestURI().getRawQuery()!=null){send(x,403,"<h1>Tillitsnivån stöds inte</h1><p>Betan intygar endast privat pilotstatus. LoA 1–4 kan inte utfärdas. Ingen inloggning startades.</p><a href='/'>Till testsidan</a>");return;}
    String sid=UUID.randomUUID().toString();
    var p=new Pending(new State(),new Nonce(),new CodeVerifier(),Instant.now().plusSeconds(120));
    synchronized(this){
      pending.values().removeIf(v->v.expires().isBefore(Instant.now()));
      sessions.values().removeIf(v->v.expires().isBefore(Instant.now()));
      if(pending.size()>=128 || sessions.size()>=128)throw new IllegalStateException();
      pending.remove(cookie(x));sessions.remove(cookie(x));pending.put(sid,p);
    }
    var claims=new LinkedHashMap<String,Object>();
    for(String name:PhoneIdentity.ATTRIBUTES)claims.put(Metadata.DISPLAY_NAME.equals(name)?"name":name,Map.of("essential",true));
    claims.put("acr",Map.of("essential",true,"value",PhoneIdentity.CONTEXT));
    var parameters=new LinkedHashMap<String,String>();
    parameters.put("response_type","code");parameters.put("scope","openid");parameters.put("client_id",client);
    parameters.put("redirect_uri",base+"/oidc/callback");parameters.put("state",p.state().getValue());parameters.put("nonce",p.nonce().getValue());
    parameters.put("code_challenge",CodeChallenge.compute(CodeChallengeMethod.S256,p.verifier()).getValue());parameters.put("code_challenge_method","S256");
    parameters.put("prompt","login");parameters.put("max_age","0");
    parameters.put("claims",new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(Map.of("id_token",claims)));
    var query=new StringJoiner("&");parameters.forEach((k,v)->query.add(URLEncoder.encode(k,StandardCharsets.UTF_8)+"="+URLEncoder.encode(v,StandardCharsets.UTF_8)));
    setCookie(x,sid);redirect(x,issuer+"/oidc/authorize?"+query);
  }
  private void complete(HttpExchange x)throws Exception {
    Pending p;
    synchronized(this){p=pending.remove(cookie(x));}
    if(p==null || !p.expires().isAfter(Instant.now()))throw new IllegalStateException();
    var response=AuthenticationResponseParser.parse(URI.create(base+x.getRequestURI()));
    if(!p.state().equals(response.getState()) || !response.indicatesSuccess())throw new IllegalStateException();
    var success=response.toSuccessResponse();
    if(success.getAuthorizationCode()==null || success.getIDToken()!=null || success.getAccessToken()!=null)throw new IllegalStateException();
    URI tokenEndpoint=URI.create(issuer+"/oidc/token");
    Date now=new Date();
    var assertion=new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("pilot-sp").build(),new JWTClaimsSet.Builder()
        .issuer(client).subject(client).audience(tokenEndpoint.toString()).issueTime(now)
        .expirationTime(new Date(now.getTime()+30000)).jwtID(UUID.randomUUID().toString()).build());
    assertion.sign(new RSASSASigner(keys.credential("sp").getPrivateKey()));
    var request=new TokenRequest(tokenEndpoint,new PrivateKeyJWT(assertion),new AuthorizationCodeGrant(success.getAuthorizationCode(),URI.create(base+"/oidc/callback"),p.verifier())).toHTTPRequest();
    request.setConnectTimeout(5000);request.setReadTimeout(10000);request.setFollowRedirects(false);
    var http=request.send();
    if(http.getStatusCode()!=200 || http.getBody()==null || http.getBody().length()>100000)throw new IllegalStateException();
    var tokens=OIDCTokenResponseParser.parse(http);
    if(!tokens.indicatesSuccess())throw new IllegalStateException();
    var jwt=((OIDCTokenResponse)tokens.toSuccessResponse()).getOIDCTokens().getIDToken();
    IDTokenClaimsSet c=validator.validate(jwt,p.nonce());
    if(!PhoneIdentity.CONTEXT.equals(c.getStringClaim("acr")))throw new IllegalStateException();
    // max_age=0 requires a fresh authentication and an auth_time claim (OIDC Core 3.1.2.1).
    Date authenticated=c.getAuthenticationTime();
    if(authenticated==null || authenticated.toInstant().isBefore(p.expires().minusSeconds(121))
        || authenticated.toInstant().isAfter(Instant.now()))throw new IllegalStateException();
    var identity=new PhoneIdentity(c.getStringClaim(PhoneIdentity.SUBJECT),c.getStringClaim(PhoneIdentity.CREDENTIAL),c.getStringClaim(PhoneIdentity.VERSION),
        c.getStringClaim("name"),c.getStringClaim(PhoneIdentity.BIRTH),c.getStringClaim(PhoneIdentity.PORTRAIT));
    if(!bridge.active(identity))throw new IllegalStateException();
    String sid=UUID.randomUUID().toString();
    synchronized(this){sessions.put(sid,new Session(identity,Instant.now().plusSeconds(300)));}
    setCookie(x,sid);redirect(x,"/oidc/me");
  }
  private void show(HttpExchange x)throws Exception {
    Session s;synchronized(this){s=sessions.get(cookie(x));}
    if(s==null || !s.expires().isAfter(Instant.now()) || !bridge.active(s.identity())){
      synchronized(this){sessions.remove(cookie(x));}
      send(x,401,"<h1>Du är inte inloggad</h1><p>Sessionen saknas, har gått ut eller ditt ID kan inte användas.</p><a href='/oidc/login'>Logga in igen</a>");return;
    }
    send(x,200,"<h1>Du är inloggad med OIDC</h1><p>"+HtmlUtils.htmlEscape(s.identity().displayName())+"</p><p>Tillitsstatus: privat pilot. Ingen Digg-godkänd tillitsnivå.</p><a href='/'>Till testsidan</a>");
  }
  private static String cookie(HttpExchange x){
    String value=x.getRequestHeaders().getFirst("Cookie");if(value==null)return "";
    String found="";for(String c:value.split(";")){String[] pair=c.trim().split("=",2);if(pair.length==2&&pair[0].equals(COOKIE)){if(!found.isEmpty())return "";found=pair[1];}}
    return found.matches("[a-f0-9-]{36}")?found:"";
  }
  private static void setCookie(HttpExchange x,String sid){x.getResponseHeaders().add("Set-Cookie",COOKIE+"="+sid+"; Path=/; Secure; HttpOnly; SameSite=Strict");}
  private static void headers(HttpExchange x){x.getResponseHeaders().set("Cache-Control","no-store");x.getResponseHeaders().set("Referrer-Policy","strict-origin");x.getResponseHeaders().set("Content-Security-Policy","default-src 'none'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'");x.getResponseHeaders().set("X-Content-Type-Options","nosniff");}
  private static void redirect(HttpExchange x,String location)throws Exception{headers(x);x.getResponseHeaders().set("Location",location);x.sendResponseHeaders(303,-1);}
  private static void send(HttpExchange x,int status,String html)throws Exception{headers(x);x.getResponseHeaders().set("Content-Type","text/html; charset=utf-8");byte[] data=("<!doctype html><html lang='sv'><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>openID · OIDC</title><link rel='stylesheet' href='/beta.css'><main>"+html+"</main></html>").getBytes(StandardCharsets.UTF_8);x.sendResponseHeaders(status,data.length);x.getResponseBody().write(data);}
}

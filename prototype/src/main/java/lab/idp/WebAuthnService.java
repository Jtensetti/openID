package lab.idp;

import com.yubico.webauthn.*;
import com.yubico.webauthn.data.*;
import jakarta.servlet.http.HttpSession;
import java.security.SecureRandom;
import java.time.*;
import java.util.*;
import java.util.stream.Collectors;
import lab.Passkey;
import lab.SyntheticRegistry;

/** WebAuthn registration and authentication ceremonies. */
public final class WebAuthnService {
  private static final String PENDING = WebAuthnService.class.getName() + ".pending";
  private static final Duration TTL = Duration.ofSeconds(60);
  private record Pending(String credential, String flow, Instant expires, Object request) {}
  public static final class Rejected extends RuntimeException {
    Rejected() { super("WebAuthn ceremony rejected"); }
  }
  private final SyntheticRegistry registry;
  private final Clock clock;
  private final boolean enabled;
  private final RelyingParty rp;
  private final SecureRandom random = new SecureRandom();
  private static final com.fasterxml.jackson.databind.ObjectMapper JSON =
      new com.fasterxml.jackson.databind.ObjectMapper().enable(com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION);

  public WebAuthnService(SyntheticRegistry registry, String origin, Clock clock, boolean enabled) {
    this.registry = registry; this.clock = clock; this.enabled = enabled;
    rp = enabled ? RelyingParty.builder()
        .identity(RelyingPartyIdentity.builder().id("localhost").name("openID — syntetisk labb").build())
        .credentialRepository(new Repository())
        .origins(Set.of(origin)).allowOriginPort(false).allowOriginSubdomain(false)
        .preferredPubkeyParams(List.of(PublicKeyCredentialParameters.ES256, PublicKeyCredentialParameters.RS256))
        .attestationConveyancePreference(AttestationConveyancePreference.NONE)
        .allowUntrustedAttestation(true).validateSignatureCounter(true).build() : null;
  }
  public boolean enabled() { return enabled; }
  private void requireEnabled() { if (!enabled) throw new Rejected(); }

  public String beginRegistration(HttpSession session, String credential, String acknowledgement) {
    requireEnabled();
    if (!"acknowledged".equals(acknowledgement)) throw new Rejected();
    synchronized (registry) {
      var entry = registry.authorize(credential);
      if (registry.passkeys().containsKey(credential)) throw new Rejected();
      byte[] handle = new byte[32]; random.nextBytes(handle);
      var request = rp.startRegistration(StartRegistrationOptions.builder()
          .user(UserIdentity.builder().name(credential).displayName(entry.identity()).id(new ByteArray(handle)).build())
          .authenticatorSelection(AuthenticatorSelectionCriteria.builder()
              .residentKey(ResidentKeyRequirement.PREFERRED).userVerification(UserVerificationRequirement.REQUIRED).build())
          .timeout(TTL.toMillis()).build());
      put(session, new Pending(credential, "registration", clock.instant().plus(TTL), request));
      try { return request.toCredentialsCreateJson(); } catch (Exception e) { clear(session); throw new Rejected(); }
    }
  }
  public void finishRegistration(HttpSession session, String response) {
    requireEnabled();
    Pending pending = consume(session, "registration");
    requireSize(response);
    synchronized (registry) {
      registry.authorize(pending.credential());
      try {
        var request = (PublicKeyCredentialCreationOptions) pending.request();
        var credential = PublicKeyCredential.parseRegistrationResponseJson(response);
        requireTopLevel(credential.getResponse().getClientDataJSON());
        var result = rp.finishRegistration(FinishRegistrationOptions.builder().request(request)
            .response(credential).build());
        if (!result.isUserVerified()) throw new Rejected();
        registry.registerPasskey(pending.credential(), new Passkey(result.getKeyId().getId().getBase64Url(),
            request.getUser().getId().getBase64Url(), result.getPublicKeyCose().getBase64Url(),
            result.getSignatureCount(), result.isBackupEligible(), result.isBackedUp()));
      } catch (Exception e) { throw new Rejected(); }
    }
  }
  public String beginAuthentication(HttpSession session, String credential, String flow) {
    requireEnabled();
    synchronized (registry) {
      registry.authorize(credential);
      if (!registry.passkeys().containsKey(credential)) throw new Rejected();
      var request = rp.startAssertion(StartAssertionOptions.builder().username(credential)
          .userVerification(UserVerificationRequirement.REQUIRED).timeout(TTL.toMillis()).build());
      put(session, new Pending(credential, flow, clock.instant().plus(TTL), request));
      try { return request.toCredentialsGetJson(); } catch (Exception e) { clear(session); throw new Rejected(); }
    }
  }
  public String finishAuthentication(HttpSession session, String flow, String response) {
    requireEnabled();
    Pending pending = consume(session, flow);
    requireSize(response);
    synchronized (registry) {
      registry.authorize(pending.credential());
      Passkey before = registry.passkeys().get(pending.credential());
      if (before == null) throw new Rejected();
      try {
        var credential = PublicKeyCredential.parseAssertionResponseJson(response);
        requireTopLevel(credential.getResponse().getClientDataJSON());
        var result = rp.finishAssertion(FinishAssertionOptions.builder().request((AssertionRequest) pending.request())
            .response(credential).build());
        if (!result.isSuccess() || !result.isUserVerified() || !pending.credential().equals(result.getUsername()) ||
            result.isBackupEligible() != before.backupEligible()) throw new Rejected();
        registry.usePasskey(pending.credential(), before, result.getSignatureCount(), result.isBackedUp());
        return pending.credential();
      } catch (Exception e) { throw new Rejected(); }
    }
  }
  public void clear(HttpSession session) { if (session != null) synchronized (session) { session.removeAttribute(PENDING); } }
  private void put(HttpSession session, Pending pending) {
    synchronized (session) { session.setAttribute(PENDING, pending); } // One outstanding ceremony per browser session.
  }
  private Pending consume(HttpSession session, String flow) {
    if (session == null) throw new Rejected();
    Pending pending;
    synchronized (session) {
      pending = (Pending) session.getAttribute(PENDING);
      session.removeAttribute(PENDING); // Consume on failure too, before parsing untrusted input.
    }
    if (pending == null || !pending.flow().equals(flow) || !pending.expires().isAfter(clock.instant())) throw new Rejected();
    return pending;
  }
  private static void requireSize(String response) {
    if (response == null || response.isEmpty() || response.length() > 65536) throw new Rejected();
  }
  private static void requireTopLevel(ByteArray clientData) throws java.io.IOException {
    // Deployment policy: embedded ceremonies are unsupported. Yubico 2.10.1 validates the
    // challenge, origin, type and signature but does not inspect these Level 3 fields.
    var data = JSON.readTree(clientData.getBytes());
    var crossOrigin = data.get("crossOrigin");
    if (data.has("topOrigin") || (crossOrigin != null && (!crossOrigin.isBoolean() || crossOrigin.booleanValue())))
      throw new Rejected();
  }
  private static ByteArray bytes(String value) {
    try { return ByteArray.fromBase64Url(value); } catch (Exception e) { throw new IllegalStateException("Invalid stored public key"); }
  }
  private static RegisteredCredential registered(Passkey key) {
    return RegisteredCredential.builder().credentialId(bytes(key.credentialId())).userHandle(bytes(key.userHandle()))
        .publicKeyCose(bytes(key.publicKeyCose())).signatureCount(key.signatureCount())
        .backupEligible(key.backupEligible()).backupState(key.backedUp()).build();
  }
  private final class Repository implements CredentialRepository {
    @Override public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String name) {
      Passkey key = registry.passkeys().get(name);
      return key == null ? Set.of() : Set.of(PublicKeyCredentialDescriptor.builder().id(bytes(key.credentialId())).build());
    }
    @Override public Optional<ByteArray> getUserHandleForUsername(String name) {
      return Optional.ofNullable(registry.passkeys().get(name)).map(k -> bytes(k.userHandle()));
    }
    @Override public Optional<String> getUsernameForUserHandle(ByteArray handle) {
      return registry.passkeys().entrySet().stream().filter(e -> e.getValue().userHandle().equals(handle.getBase64Url())).map(Map.Entry::getKey).findFirst();
    }
    @Override public Optional<RegisteredCredential> lookup(ByteArray id, ByteArray handle) {
      return lookupAll(id).stream().filter(k -> k.getUserHandle().equals(handle)).findFirst();
    }
    @Override public Set<RegisteredCredential> lookupAll(ByteArray id) {
      return registry.passkeys().values().stream().filter(k -> k.credentialId().equals(id.getBase64Url()))
          .map(WebAuthnService::registered).collect(Collectors.toUnmodifiableSet());
    }
  }
}

package lab.phone;

import java.util.*;
import lab.Metadata;
import se.swedenconnect.opensaml.saml2.attribute.AttributeTemplate;
import se.swedenconnect.spring.authnserver.attributes.*;
import se.swedenconnect.spring.authnserver.saml.attributes.SamlAttributeMapping;
import se.swedenconnect.spring.authnserver.saml.attributes.mapping.*;

/** Explicit mappings between the provider's attributes and the SAML profile. */
public final class PhoneAttributes {
  public static String genericName(String samlName) {
    return Metadata.DISPLAY_NAME.equals(samlName) ? AttributeIdentifiers.DISPLAY_NAME : samlName;
  }
  public static List<String> supported() {
    var supported = new ArrayList<>(PhoneIdentity.ATTRIBUTES.stream().map(PhoneAttributes::genericName).toList());
    supported.addAll(List.of(AttributeIdentifiers.GIVEN_NAME, AttributeIdentifiers.SURNAME, AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER));
    return List.copyOf(supported);
  }
  public static List<GenericAttribute<?>> values(PhoneIdentity identity) {
    var values = new ArrayList<GenericAttribute<?>>();
    identity.attributes().forEach((name, value) -> values.add(GenericAttribute.of(genericName(name), value)));
    return values;
  }
  public static List<GenericAttribute<?>> sandboxValues(PhoneIdentity identity, SandboxIdentity passport) {
    Objects.requireNonNull(passport, "Sandbox passport attributes required");
    var values = new ArrayList<GenericAttribute<?>>();
    values.add(GenericAttribute.of(AttributeIdentifiers.DISPLAY_NAME, identity.displayName()));
    values.add(GenericAttribute.of(PhoneIdentity.SUBJECT, identity.subject()));
    if (!passport.givenName().isBlank()) values.add(GenericAttribute.of(AttributeIdentifiers.GIVEN_NAME, passport.givenName()));
    if (!passport.surname().isBlank()) values.add(GenericAttribute.of(AttributeIdentifiers.SURNAME, passport.surname()));
    if (passport.personalNumber() != null) values.add(GenericAttribute.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, passport.personalNumber()));
    return values;
  }
  /** The app consent names the passport fields; SAD also needs the pairwise subject. */
  public static List<GenericAttribute<? extends java.io.Serializable>> sandboxRelease(
      se.swedenconnect.spring.authnserver.authentication.UserAuthentication authentication) {
    var use = authentication.getUsageTrack().getLatestUse();
    if (use == null || use.protocol() != se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol.SAML
        || !SandboxRelyingParties.NAMES.containsKey(use.requester())) return List.of();
    var released = new ArrayList<GenericAttribute<? extends java.io.Serializable>>();
    var permitted = new HashSet<>(Set.of(AttributeIdentifiers.DISPLAY_NAME, AttributeIdentifiers.GIVEN_NAME,
        AttributeIdentifiers.SURNAME, PhoneIdentity.SUBJECT));
    if (SandboxRelyingParties.requestsPersonalNumber(use.requester())) permitted.add(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER);
    for (var attribute : authentication.getAuthenticatedUser().getAttributes())
      if (permitted.contains(attribute.getIdentifier()))
        released.add(GenericAttribute.of(attribute.getIdentifier(), attribute.getStringValues()));
    return released;
  }
  public static SamlAttributeMapping mapping() {
    var definitions = new DefaultAttributeDefinitionRegistry();
    for (String name : PhoneIdentity.ATTRIBUTES) if (!Metadata.DISPLAY_NAME.equals(name)) definitions.register(AttributeDefinition.ofString(name, name));
    var mapping = new SamlAttributeMapping(definitions);
    for (String name : PhoneIdentity.ATTRIBUTES) {
      if (Metadata.DISPLAY_NAME.equals(name)) continue;
      mapping.getFromProtocolMapping().register(new SamlFromProtocolMapper(name, name));
      mapping.getToProtocolMapping().register(new SamlToProtocolMapper(name, new AttributeTemplate(name, null)));
    }
    return mapping;
  }
  public static se.swedenconnect.spring.authnserver.oidc.attributes.OidcAttributeMapping oidcMapping() {
    var definitions = new DefaultAttributeDefinitionRegistry();
    for (String name : PhoneIdentity.ATTRIBUTES) if (!Metadata.DISPLAY_NAME.equals(name)) definitions.register(AttributeDefinition.ofString(name, name));
    var mapping = new se.swedenconnect.spring.authnserver.oidc.attributes.OidcAttributeMapping(definitions);
    for (String name : PhoneIdentity.ATTRIBUTES) {
      if (Metadata.DISPLAY_NAME.equals(name)) continue;
      mapping.getFromProtocolMapping().register(new se.swedenconnect.spring.authnserver.oidc.attributes.mapping.ClaimFromProtocolMapper(name, name));
      mapping.getToProtocolMapping().register(new se.swedenconnect.spring.authnserver.oidc.attributes.mapping.ClaimToProtocolMapper(name, name));
    }
    return mapping;
  }

}

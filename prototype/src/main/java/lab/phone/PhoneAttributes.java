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
  public static List<String> supported() { return PhoneIdentity.ATTRIBUTES.stream().map(PhoneAttributes::genericName).toList(); }
  public static List<GenericAttribute<?>> values(PhoneIdentity identity) {
    var values = new ArrayList<GenericAttribute<?>>();
    identity.attributes().forEach((name, value) -> values.add(GenericAttribute.of(genericName(name), value)));
    return values;
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
}

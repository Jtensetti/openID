package lab.phone;

import java.util.*;
import lab.Metadata;
import org.opensaml.saml.saml2.core.Attribute;
import se.swedenconnect.opensaml.saml2.attribute.AttributeUtils;

public record PhoneIdentity(String subject, String credential, String version, String displayName, String birthDateMrz, String portrait) {
  public static final String CONTEXT = "urn:openid:authn:passport-native:v1";
  /** Same credential, plus the holder's 6-digit security code verified and counted by the registry. */
  public static final String PIN_CONTEXT = "urn:openid:authn:passport-native:pin:v1";
  public static final String SUBJECT = "urn:openid:attribute:subject";
  public static final String CREDENTIAL = "urn:openid:attribute:credential";
  public static final String VERSION = "urn:openid:attribute:profile-version";
  public static final String BIRTH = "urn:openid:attribute:birth-date-mrz";
  public static final String PORTRAIT = "urn:openid:attribute:passport-portrait-jpeg";
  public static final List<String> ATTRIBUTES = List.of(SUBJECT, CREDENTIAL, VERSION, Metadata.DISPLAY_NAME, BIRTH, PORTRAIT);
  public PhoneIdentity {
    for (String id : List.of(subject, credential, version)) if (!id.matches("[a-f0-9]{64}")) throw new IllegalArgumentException("Identity reference");
    if (!displayName.matches("[A-Z ]{1,89}") || !birthDateMrz.matches("[0-9]{6}")) throw new IllegalArgumentException("Identity fields");
    try { java.time.LocalDate.of(2000 + Integer.parseInt(birthDateMrz.substring(0, 2)), Integer.parseInt(birthDateMrz.substring(2, 4)), Integer.parseInt(birthDateMrz.substring(4, 6))); }
    catch (java.time.DateTimeException e) { throw new IllegalArgumentException("Birth date"); }
    if (portrait.length() > 32000) throw new IllegalArgumentException("Portrait size");
    byte[] bytes = Base64.getDecoder().decode(portrait);
    if (bytes.length < 4 || bytes[0] != (byte)0xff || bytes[1] != (byte)0xd8 || bytes[bytes.length-2] != (byte)0xff || bytes[bytes.length-1] != (byte)0xd9)
      throw new IllegalArgumentException("Portrait format");
  }
  public Map<String, String> attributes() {
    return Map.of(SUBJECT, subject, CREDENTIAL, credential, VERSION, version, Metadata.DISPLAY_NAME, displayName, BIRTH, birthDateMrz, PORTRAIT, portrait);
  }
  public static PhoneIdentity fromAttributes(List<Attribute> attributes) {
    var values = new HashMap<String, String>();
    for (var attribute : attributes) {
      if (!ATTRIBUTES.contains(attribute.getName()) || attribute.getAttributeValues().size() != 1 ||
          values.put(attribute.getName(), AttributeUtils.getAttributeStringValue(attribute)) != null) throw new IllegalArgumentException("Unexpected identity claims");
    }
    if (values.size() != ATTRIBUTES.size()) throw new IllegalArgumentException("Missing identity claims");
    return new PhoneIdentity(values.get(SUBJECT), values.get(CREDENTIAL), values.get(VERSION), values.get(Metadata.DISPLAY_NAME), values.get(BIRTH), values.get(PORTRAIT));
  }
  @Override public String toString() { return "Passport identity"; }
}

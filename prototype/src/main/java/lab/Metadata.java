package lab;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;

/** Local metadata is generated from pinned loopback endpoints and this run's test certificates. */
public final class Metadata {
  public static final String DISPLAY_NAME = "urn:oid:2.16.840.1.113730.3.1.241";
  public static final String LAB_CONTEXT = "urn:openid:lab:simulated";
  public static EntityDescriptor parse(String xml) throws Exception {
    return (EntityDescriptor) XMLObjectSupport.unmarshallFromInputStream(
        XMLObjectProviderRegistrySupport.getParserPool(), new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
  }
  private static String key(TestKeys keys, String alias) throws Exception {
    return "<md:KeyDescriptor><ds:KeyInfo><ds:X509Data><ds:X509Certificate>" +
        Base64.getEncoder().encodeToString(keys.certificate(alias).getEncoded()) +
        "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>";
  }
  private static String header(String entity) {
    return "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"" + entity + "\">";
  }
  public static String sp(TestKeys keys, String base) throws Exception {
    return sp(keys, base, false);
  }
  public static String sp(TestKeys keys, String base, boolean phone) throws Exception {
    String requested = (phone ? lab.phone.PhoneIdentity.ATTRIBUTES : java.util.List.of(DISPLAY_NAME)).stream()
        .map(name -> "<md:RequestedAttribute Name=\""+name+"\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\" isRequired=\"true\"/>")
        .collect(java.util.stream.Collectors.joining());
    return header(base + "/sp") + """
        <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:Extensions><mdui:UIInfo xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui"><mdui:DisplayName xml:lang="sv">%s</mdui:DisplayName></mdui:UIInfo></md:Extensions>
        """.formatted(phone ? lab.phone.PhoneBridge.SERVICE : "Lokal syntetisk testtjänst") + key(keys, "sp") + """
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s/acs" index="0" isDefault="true"/>
        <md:AttributeConsumingService index="0" isDefault="true"><md:ServiceName xml:lang="sv">openID</md:ServiceName>%s</md:AttributeConsumingService>
        </md:SPSSODescriptor></md:EntityDescriptor>
        """.formatted(base, requested);
  }
  public static String idp(TestKeys keys, String base) throws Exception {
    return header(base + "/idp") + """
        <md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        """ + key(keys, "idp") + """
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s/saml2/redirect/authn"/>
        </md:IDPSSODescriptor></md:EntityDescriptor>
        """.formatted(base);
  }
}

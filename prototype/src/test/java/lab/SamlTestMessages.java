package lab;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Consumer;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.security.credential.Credential;
import se.swedenconnect.opensaml.xmlsec.encryption.support.*;
import se.swedenconnect.opensaml.xmlsec.signature.support.SAMLObjectSigner;
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;
import net.shibboleth.shared.xml.SerializeSupport;

/** Malformed and incorrectly bound SAML messages for negative tests. */
final class SamlTestMessages {
  static Response decode(String encoded) throws Exception {
    return (Response) XMLObjectSupport.unmarshallFromInputStream(XMLObjectProviderRegistrySupport.getParserPool(),
        new ByteArrayInputStream(Base64.getDecoder().decode(encoded)));
  }
  static Assertion decrypt(Lab lab, Response response) throws Exception {
    return new SAMLObjectDecrypter(List.<Credential>of(new OpenSamlCredential(lab.keys.credential("sp"))))
        .decrypt(response.getEncryptedAssertions().getFirst().getEncryptedData(), Assertion.class);
  }
  static String encode(Response response) throws Exception {
    return Base64.getEncoder().encodeToString(SerializeSupport.nodeToString(XMLObjectSupport.marshall(response)).getBytes(StandardCharsets.UTF_8));
  }
  static String signedMutation(Lab lab, String encoded, Consumer<Response> changeResponse, Consumer<Assertion> changeAssertion, String signer) throws Exception {
    return signedMutation(lab, encoded, changeResponse, changeAssertion, signer, true, null);
  }
  static String signedMutation(Lab lab, String encoded, Consumer<Response> changeResponse, Consumer<Assertion> changeAssertion,
      String signer, boolean signAssertion, org.opensaml.xmlsec.SignatureSigningConfiguration config) throws Exception {
    Response response = decode(encoded); Assertion assertion = decrypt(lab, response);
    response.setSignature(null); assertion.setSignature(null);
    response.getEncryptedAssertions().clear(); response.releaseDOM(); assertion.releaseDOM();
    changeResponse.accept(response); changeAssertion.accept(assertion);
    var credential = new OpenSamlCredential(lab.keys.credential(signer));
    if (signAssertion) SAMLObjectSigner.sign(assertion, credential, config == null ? new org.opensaml.xmlsec.SignatureSigningConfiguration[0] : new org.opensaml.xmlsec.SignatureSigningConfiguration[]{config});
    EncryptedAssertion encrypted = (EncryptedAssertion) XMLObjectSupport.buildXMLObject(EncryptedAssertion.DEFAULT_ELEMENT_NAME);
    encrypted.setEncryptedData(new SAMLObjectEncrypter().encrypt(assertion,
        new SAMLObjectEncrypter.Peer(Metadata.parse(Metadata.sp(lab.keys, lab.spBase)))));
    response.getEncryptedAssertions().add(encrypted);
    SAMLObjectSigner.sign(response, credential, config == null ? new org.opensaml.xmlsec.SignatureSigningConfiguration[0] : new org.opensaml.xmlsec.SignatureSigningConfiguration[]{config});
    return encode(response);
  }
}

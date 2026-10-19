package lab;

import java.util.List;
import org.opensaml.xmlsec.SignatureValidationConfiguration;
import org.opensaml.xmlsec.impl.BasicSignatureValidationConfiguration;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import se.swedenconnect.opensaml.sweid.xmlsec.config.SwedishEidSecurityConfiguration;

/** Algorithm policy, enforced by OpenSAML's validators. No signature verification is implemented here. */
public final class LabSecurityConfiguration extends SwedishEidSecurityConfiguration {
  @Override protected SignatureValidationConfiguration createDefaultSignatureValidationConfiguration() {
    var policy = new BasicSignatureValidationConfiguration();
    policy.setIncludedAlgorithms(List.of(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256,
        SignatureConstants.ALGO_ID_DIGEST_SHA256));
    return policy;
  }
}

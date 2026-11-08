package lab;

import java.util.List;
import org.opensaml.xmlsec.SignatureValidationConfiguration;
import org.opensaml.xmlsec.impl.BasicSignatureValidationConfiguration;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import se.swedenconnect.opensaml.sweid.xmlsec.config.SwedishEidSecurityConfiguration;

public final class LabSecurityConfiguration extends SwedishEidSecurityConfiguration {
  private final boolean sandbox;
  public LabSecurityConfiguration() { this(false); }
  public LabSecurityConfiguration(boolean sandbox) { this.sandbox = sandbox; }

  @Override protected SignatureValidationConfiguration createDefaultSignatureValidationConfiguration() {
    var policy = new BasicSignatureValidationConfiguration();
    policy.setIncludedAlgorithms(sandbox
        ? List.of(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256,
            SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA256, SignatureConstants.ALGO_ID_DIGEST_SHA256)
        : List.of(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, SignatureConstants.ALGO_ID_DIGEST_SHA256));
    return policy;
  }
}

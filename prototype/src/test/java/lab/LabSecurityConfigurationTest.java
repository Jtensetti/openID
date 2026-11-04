package lab;

import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.List;
import net.shibboleth.shared.resolver.CriteriaSet;
import org.junit.jupiter.api.Test;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.impl.StaticCredentialResolver;
import org.opensaml.xmlsec.SignatureValidationParameters;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureValidationParametersCriterion;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import static org.junit.jupiter.api.Assertions.*;

class LabSecurityConfigurationTest {
  @Test void sandboxEcdsaStillRequiresTrustedKeyAndUnmodifiedContent() throws Exception {
    org.opensaml.core.config.InitializationService.initialize();
    var generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    var trusted = generator.generateKeyPair();
    var attacker = generator.generateKeyPair();
    var engine = new ExplicitKeySignatureTrustEngine(
        new StaticCredentialResolver(new BasicCredential(trusted.getPublic())),
        new StaticKeyInfoCredentialResolver(List.of()));
    byte[] content = "SAMLRequest=synthetic&RelayState=test".getBytes(StandardCharsets.UTF_8);
    var signer = Signature.getInstance("SHA256withECDSA");
    signer.initSign(trusted.getPrivate()); signer.update(content); byte[] signature = signer.sign();
    var parameters = new SignatureValidationParameters();
    parameters.setIncludedAlgorithms(new LabSecurityConfiguration(true)
        .createDefaultSignatureValidationConfiguration().getIncludedAlgorithms());
    var criteria = new CriteriaSet(new SignatureValidationParametersCriterion(parameters));
    String algorithm = SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA256;
    assertTrue(engine.validate(signature, content, algorithm, criteria, null));
    byte[] altered = content.clone(); altered[altered.length - 1] ^= 1;
    assertFalse(engine.validate(signature, altered, algorithm, criteria, null));
    signer.initSign(attacker.getPrivate()); signer.update(content);
    assertFalse(engine.validate(signer.sign(), content, algorithm, criteria, null));
    assertFalse(engine.validate(signature, content, SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA1, criteria, null));
    parameters.setIncludedAlgorithms(new LabSecurityConfiguration()
        .createDefaultSignatureValidationConfiguration().getIncludedAlgorithms());
    assertFalse(engine.validate(signature, content, algorithm, criteria, null));
  }
}

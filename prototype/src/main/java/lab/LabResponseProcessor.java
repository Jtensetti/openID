/*
 * Copyright 2025-2026 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package lab;

import jakarta.annotation.Nonnull;
import net.shibboleth.shared.component.ComponentInitializationException;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.security.credential.Credential;
import se.swedenconnect.opensaml.saml2.response.replay.InMemoryReplayChecker;
import se.swedenconnect.opensaml.saml2.response.validation.ResponseValidationSettings;
import se.swedenconnect.opensaml.sweid.saml2.validation.SwedishEidResponseProcessorImpl;
import se.swedenconnect.opensaml.xmlsec.encryption.support.SAMLObjectDecrypter;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;

import java.time.Duration;
import java.util.List;

/**
 * Adapted from Sweden Connect Test Client v1.0.19.
 * Local changes: package/class name, symmetric five-second freshness, required signed/encrypted assertions,
 * and an explicit RSA-SHA256/SHA256 validation policy.
 *
 * @author Martin Lindström
 */
public class LabResponseProcessor extends SwedishEidResponseProcessorImpl {

  public LabResponseProcessor(@Nonnull final MetadataResolver metadataResolver,
      @Nonnull final List<PkiCredential> decryptCredentials) {

    final List<Credential> credentials = decryptCredentials.stream()
        .map(OpenSamlCredential::new)
        .map(Credential.class::cast)
        .toList();

    this.setDecrypter(new SAMLObjectDecrypter(credentials));
    this.setMetadataResolver(metadataResolver);
    this.setSecurityConfiguration(new LabSecurityConfiguration());
    this.setRequireEncryptedAssertions(true);
    this.setMessageReplayChecker(new InMemoryReplayChecker());
    final ResponseValidationSettings validationSettings = new ResponseValidationSettings();
    // opensaml-addons 2.2.1 reverses both duration comparisons in ResponseValidator.
    // Zero extra age + five seconds skew bounds BOTH past and future to five seconds,
    // with or without that upstream defect. Regression-tested; no validator is bypassed.
    validationSettings.setMaxAgeResponse(Duration.ZERO);
    validationSettings.setStrictValidation(true);
    validationSettings.setAllowedClockSkew(Duration.ofSeconds(5));
    validationSettings.setRequireSignedAssertions(true);
    this.setResponseValidationSettings(validationSettings);

    try {
      this.initialize();
    }
    catch (final ComponentInitializationException e) {
      throw new RuntimeException(e);
    }
  }

}

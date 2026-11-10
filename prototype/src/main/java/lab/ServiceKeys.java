package lab;

import java.nio.file.Path;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import se.swedenconnect.security.credential.PkiCredential;

/** Private service credentials and explicitly pinned public peer certificates. */
public interface ServiceKeys {
  Path directory();
  Path storePath(String alias);
  String password(String alias);
  X509Certificate certificate(String alias) throws Exception;
  PkiCredential credential(String alias) throws Exception;
  default X509Certificate encryptionCertificate() throws Exception { return null; }
  SSLContext sslContext() throws Exception;
}

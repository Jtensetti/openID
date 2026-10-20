package lab;

/** Stored public WebAuthn credential. */
public record Passkey(String credentialId, String userHandle, String publicKeyCose,
    long signatureCount, boolean backupEligible, boolean backedUp) {
  public Passkey {
    for (String value : new String[]{credentialId, userHandle, publicKeyCose})
      if (value == null || !value.matches("[A-Za-z0-9_-]{1,8192}"))
        throw new IllegalArgumentException("Invalid public credential encoding");
    if (userHandle.length() > 86 || signatureCount < 0 || signatureCount > 0xffffffffL || (backedUp && !backupEligible))
      throw new IllegalArgumentException("Invalid authenticator state");
  }
  public Passkey used(long count, boolean backup) {
    return new Passkey(credentialId, userHandle, publicKeyCose, count, backupEligible, backup);
  }
}

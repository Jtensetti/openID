package lab.phone;

/** Authenticated passport attributes selected by the registry for this recipient. */
public record SandboxIdentity(String givenName, String surname, String personalNumber) {
  public SandboxIdentity {
    if (givenName == null || surname == null || !givenName.matches("[A-Z ]{0,44}")
        || !surname.matches("[A-Z ]{0,44}") || (givenName.isBlank() && surname.isBlank())
        || (personalNumber != null && !personalNumber.matches("[0-9]{12}")))
      throw new IllegalArgumentException("Invalid sandbox identity attributes");
  }
  @Override public String toString() { return "Sandbox passport identity"; }
}

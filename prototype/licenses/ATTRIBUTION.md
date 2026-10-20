# Attribution för införda källfiler och verktyg

`src/main/java/lab/LabResponseProcessor.java` är en ändrad version av Sweden Connects `CustomResponseProcessor.java`:

- Ursprung: <https://github.com/swedenconnect/sweden-connect-test-client/blob/87aac956a762928b11a640e30382f7e5ca5fef1b/src/main/java/se/swedenconnect/testclient/saml/CustomResponseProcessor.java>.
- Release 1.0.19, commit `87aac956a762928b11a640e30382f7e5ca5fef1b`.
- Originalfilens SHA-256: `71541cb2e09a0d46b1f821fd21d965238e7d13b10f517ff5c1ec3947e40f3f41`.
- Copyright 2025–2026 Sweden Connect; author Martin Lindström. Apache License 2.0, se [licenstext](Apache-2.0.txt). Originalhuvudet är bevarat.
- Ändringar: lokalt namn/paket, obligatoriskt signerade och krypterade assertioner, explicit algoritmpolicy samt ett symmetriskt femsekunders fönster för Response IssueInstant. Inga egna signatur-/krypteringsprimitiver eller kopierade protokollvalidatorer.
- Inga övriga G05-filer, referensidentiteter, privata nycklar, UI-bilder eller CI-workflows har kopierats.

`mvnw` och `mvnw.cmd` genererades från Apache Maven Wrapper 3.3.4, `only-script`. Ursprung: <https://github.com/apache/maven-wrapper/tree/524486aff97d0748926a977665d5befb3251ff17>. Apache License 2.0 och [upstream NOTICE](Maven-Wrapper-NOTICE.txt). Wrapperns konfiguration väljer Maven 3.9.11 med verifierad distributionschecksumma. Wrapper-filerna behåller sina licenshuvuden.

Playwright 1.62.1 används enbart som installerat utvecklingsverktyg, inte kopierad produktkod. Officiell tagg: <https://github.com/microsoft/playwright/tree/26a9e470a7b3c7822084b09fb7f13902c5f37b51>; Apache-2.0. Npm-låset innehåller paketens integritetshashar och licensdeklarationer. Chromium levereras separat av Playwright; dess tredjeparters licenser och systembibliotek ingår inte i Java-SBOM.

Övriga bibliotek hämtas som oförändrade Maven-artefakter. Se [THIRD_PARTY.md](../../THIRD_PARTY.md), beroendelåset och SBOM för omfattning, licensavvikelser och kvarstående distributionsbeslut. Denna attribution ger ingen ny licens till projektets egen kod och innebär inget stöd eller godkännande från Sweden Connect eller Apache.

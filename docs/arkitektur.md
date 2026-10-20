# Arkitektur

Appflödet består av en iPhone-klient, en verifieringsserver med SQLite-register
och två lokala Java-processer för SAML. Det finns också två äldre testlägen.

## Komponenter

| Del | Implementation | Uppgift |
|---|---|---|
| iPhone | `ios/PassportCapture/` | Läser passets chip, tar kamerabilder, skapar en enhetsnyckel och signerar användarens godkännande. |
| Verifierare | `verification/server.py`, `native.py`, `face.py`, `pad.py` | Kontrollerar App Attest, passunderlag och bilder. |
| Passkontroll | `prototype/src/main/java/lab/proofing/` | Bouncy Castle CMS, JCA PKIX och JMRTD för signaturkedja, datagruppshashar, MRZ och porträtt. Anropas via privat stdin/stdout. |
| Register | `verification/wallet.py`, `identity.py`, `profile-crypto.mjs` | Binder passprofil till publik nyckel, hanterar aktivering, godkännanden, utgång och spärr. |
| Lokal brygga | `verification/federation.py`, `lab/phone/PhoneBridge.java` | Avgränsat JSON-protokoll över Unix-socket mellan registret och SAML-processerna. |
| IdP | `lab/idp/PhoneProvider.java`, `PhoneController.java` | Sweden Connect-provider som inväntar appens godkännande och utfärdar SAML-svaret. |
| Kontotjänst/SP | `lab/RelyingParty.java`, `lab/phone/PhoneIdentity.java` | Validerar SAML-svar, skapar webbsession och kontrollerar aktuell spärr vid skyddad läsning. |

Java-sökvägarna är relativa till `prototype/src/main/java/`.
Versioner och licenser finns i [komponentregistret](../THIRD_PARTY.md).

## Registrering

1. Appen skapar en P-256-nyckel i Secure Enclave. Keychain lagrar den omslutna
   nyckelrepresentationen med `WhenPasscodeSetThisDeviceOnly`.
2. NFCPassportReader läser DG1, DG2, DG14 och SOD med PACE/BAC.
3. App Attest binder dokument och publik nyckel till en kortlivad serversession.
   Servern kontrollerar app-ID, certifikat, signatur, räknare och session.
4. Passverifieraren kontrollerar SOD-signaturen, kedjan till operatörens CSCA
   och DG1/DG2/DG14-hasharna. JMRTD utför PACE och CA på servern genom en
   andra CoreNFC-session i telefonen. Ny SELECT/READ av DG14 med verifierad
   MAC bekräftar chipnyckeln; sessionsnycklar lämnar inte serverprocessen.
5. Efter chipkontrollen får appen ett nytt engångsvärde och tar tre
   AVFoundation-bilder. En ny App Attest-assertion binder bilderna till
   sessionen. YuNet/SFace jämför dem med passfotot. MiniFASNet beräknar PAD-värden.
   Godkända kontroller skapar `PENDING_REVIEW`; operatören aktiverar separat.

Face ID/Touch ID bekräftar senare nyckelanvändning på telefonen. Jämförelsen
med passfotot sker på servern. App Attest styrker appinstans och signerade
data, men inte kamerans fysiska ursprung. Chipkontrollen bevisar nyckelinnehav,
inte närhet mellan pass och telefon; NFC-relä behöver prövas separat.

## Inloggning med SAML

1. Kontotjänsten skapar en signerad AuthnRequest till IdP:n. Metadata och
   mottagare är fasta: `https://localhost:8443` och `https://localhost:8444`.
2. IdP:n skapar en begäran i registret, bunden till SAML-flöde, SP och en
   hemlighet i IdP-sessionen. QR-koden innehåller endast begärans-ID.
3. Appen hämtar tjänst, syfte och kontrollkod genom en signerad `inspect`.
   Godkännande kräver ny lokal användarverifiering och signerar samma uppgifter.
4. Registret tillåter en nyckel och en konsumtion. Sweden Connect skapar
   signerat och krypterat SAML-svar med kontexten
   `urn:openid:authn:passport-native:v1`.
5. SP:n validerar signatur, issuer, audience, destination, InResponseTo,
   RelayState, tider och engångsanvändning. Sessionscookien byts vid inloggning.

Begäran gäller 120 sekunder, SP-sessionen högst fem minuter. Varje skyddad
läsning kontrollerar aktiv nyckel, subjekt och profilversion i registret.
Spärr, ersatt nyckel eller registeravbrott nekar fortsatt åtkomst.

Tjänsten får namn, MRZ-födelsedatum, förminskat passfoto, tjänstesubjekt,
credentialreferens och profilversion. MRZ:s tvåsiffriga årtal används utan
härledning av sekel, ålder eller svenskt personnummer.

## Livscykel och lagring

| Tillstånd | Tillåten förändring |
|---|---|
| `PENDING_REVIEW` | Operatörsaktivering inom 24 timmar eller permanent spärr. |
| `ACTIVE` | Utgång, spärr eller ersättning genom aktivering av ny nyckel för samma pass. |
| `EXPIRED`, `REVOKED` | Ny registrering med ny nyckel krävs. |

Standardgiltigheten är 24 timmar, högst 72 och aldrig längre än passets
giltighet. Ersättning för samma pass behåller det interna person-ID:t och
spärrar äldre nycklar atomiskt. Ett annat pass med samma namn och födelsedatum
slås inte ihop. Passförnyelse saknar ännu en färdig återställningsprocess.

Personprofil och förminskat foto krypteras med Node `crypto` AES-256-GCM.
Credential- och person-ID ingår i autentiserade kontextdata. En separat
HMAC-SHA-256-nyckel används för dokumentreferens och tjänstesubjekt.
Passnummer sparas inte i klartext; rå chipdata, kamerabilder och ansiktsmallar
sparas inte. Publika nycklar, status och händelser är okrypterade.

SQLite-databasen och `wallet.identity-key` ligger i en privat katalog.
Saknad eller fel nyckel stoppar profilåtkomst. Automatisk gallring och
nyckelrotation saknas. Återläsning av äldre register kan återuppliva spärrade
nycklar och stöds därför inte.

## Förtroendegränser

| Gräns | Kontroll och begränsning |
|---|---|
| Telefon → verifierare | HTTPS, exakt Host/Origin, kopplingskod och signerade anrop. Inga klientangivna identitetsfält accepteras som verifierade. |
| Verifierare → passprocess | Fast binär, JAR och CSCA väljs av operatören. Inga nätverkshämtade tillitsankare. |
| Register → SAML | Unix-socket 0600 i katalog 0700, avgränsade meddelanden och operationer. Ingen aktiveringsoperation. |
| Webbläsare → IdP/SP | TLS, CSP, CSRF, Origin och sessionsbindning. Endast signerad SAML POST har protokollundantag från CSRF. |
| Operatör → register | Lokal CLI. Samma OS-konto kan läsa nyckelfilen och aktivera credentials; administrativ rollseparation saknas. |

IdP, SP och verifierare är separata processer men delar operativsystemskonto.
De utgör därför inte separata administrativa säkerhetszoner.

## Övriga körlägen

- `start` och `start-web` i `prototype/` kör IdP och SP i samma JVM med ett
  separat testregister. Identitetskontrollen är simulerad; `start-web` använder
  riktiga WebAuthn-signaturer. Krasch och restore spärrar alla testnycklar.
- `verification/relying_party.py` är en enklare lokal HTTP-testtjänst utan
  SAML. Den använder samma appregister men separata webbsessioner.
- `ops/` bygger en fristående hälsokontrollcontainer. Den innehåller ingen
  verifierare, IdP, SP, identitetsdatabas eller testnyckel.

## Återstående kontroller

Fysisk iPhone-fångst, biometrisk/PAD-kalibrering, injektion och relä,
certifikatspärr, registerkontroll, HSM, rollseparation och återställning med
beständig spärrstatus återstår. Dokumentunderskrift är inte implementerad.
Se [krav](krav.md), [testning](testning.md) och [säkerhet](../SECURITY.md).

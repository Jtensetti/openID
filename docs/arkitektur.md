# Arkitektur

Appflödet består av en iPhone-klient, en verifieringsserver med SQLite-register
och separata Java-processer för SAML/OIDC. Den publika betan använder dessutom
en oberoende spärrtjänst och aviseringskö. Se [avisering och spärr](avisering-och-sparr.md). Det finns också två äldre testlägen.

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

## Körmiljö

`verification/serve.py` kör pilotens native-/wallet-API över TLS med Gunicorn.
En worker äger NFC-sessionerna. Kapacitetsgränser skiljer native-anrop från
inloggning och spärr; bildanalysen körs i en separat process med tidsgräns.
Databasens transaktioner avgör samtidiga godkännanden och spärrar. Ett fillås
hindrar flera runtime-processer på samma databas. Detta är en ensam nod,
inte en distribuerad tjänst. [Start och drift](../deployment/README.md).

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
   AVFoundation-bilder. Vision vägleder fotograferingen framifrån och från båda sidor
   utifrån huvudposition, bildkvalitet och hur länge användaren håller stilla. En ny App
   Attest-assertion binder bilderna till
   sessionen. YuNet/SFace jämför dem med passfotot. MiniFASNet beräknar PAD-värden.
   Godkända kontroller skapar `PENDING_REVIEW`; operatören aktiverar separat.

Ringen vägleder fotograferingen lokalt på telefonen. Ingen klientrapporterad färg, vinkel
eller liveness-flagga används i serverns beslut. Servern bestämmer ordningen för de
tre bilderna efter chipkontrollen och verifierar själv huvudvridningen i varje bild
med landmärkesparallax, men inte ett sammanhängande rörelseförlopp. Underkända
beslut räknas per pass; efter fem inom ett dygn görs ingen ny analys.

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
4. Varje begäran kan godkännas av en enda nyckel och användas en gång. Sweden Connect skapar
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

## Extern integrationsmäklare

GrandID/eID API är ett integrationsmål för OpenID som extern IdP via
SAML 2.0 eller OpenID Connect. En separat motpartsprofil ska binda metadata,
nycklar, identitetsattribut och appens visade mottagare till samma begäran.
Nuvarande pilot har fasta motparter; leverantörsanslutning är inte provad.
Se [GrandID-profilens omfattning och acceptans](grandid-integration.md).

## Livscykel och lagring

| Tillstånd | Tillåten förändring |
|---|---|
| `PENDING_REVIEW` | Operatörsaktivering inom 24 timmar eller permanent spärr. |
| `ACTIVE` | Utgång, spärr eller ersättning genom aktivering av ny nyckel för samma pass. |
| `EXPIRED`, `REVOKED` | Ny registrering med ny nyckel krävs. |

Standardgiltigheten är 24 timmar, högst 72 och aldrig längre än passets
giltighet. Ersättning för samma pass behåller det interna person-ID:t och
spärrar äldre nycklar atomiskt. Ett annat pass med samma namn och födelsedatum
slås inte ihop. Passförnyelse har ett separat, registerkontrollerat operatörsflöde i SQLite-koden.
Det saknar ännu verklig registeradapter och är inte aktiverat i betan.
Se [registerbindning och ersättning](registerbindning.md).

Personprofil och förminskat foto krypteras med Node `crypto` AES-256-GCM.
Credential- och person-ID ingår i autentiserade kontextdata. En separat
HMAC-SHA-256-nyckel används för dokumentreferens och tjänstesubjekt.
Passnummer sparas inte i klartext; rå chipdata, kamerabilder och ansiktsmallar
sparas inte. Publika nycklar, status och händelser är okrypterade.

SQLite-databasen och `wallet.identity-key` ligger i en privat katalog.
Saknad eller fel nyckel stoppar profilåtkomst. Automatisk gallring och
nyckelrotation saknas i SQLite-läget. `recovery.py restore` återläser till en ny katalog och
spärrar alla återställda nycklar. Manuell återläsning som bevarar aktiva nycklar
stöds inte, eftersom en äldre kopia kan sakna senare spärrar.

## PostgreSQL och OpenBao

Det separata körläget `cluster_serve.py` delar register, spärrstatus och
engångsutmaningar i PostgreSQL. Utmaningen konsumeras i en egen transaktion
före signaturkontroll. Villkorade uppdateringar hindrar dubbel konsumtion;
nyckelrader låses vid beslut. Giltighet använder databasens tid i transaktionen.

OpenBao Transit krypterar profiler med person- och enhetsbunden kontext.
Registreringskontot kan kryptera, autentiseringskontot dekryptera och
underhållskontot omkryptera. Två olika databaslogins krävs för aktivering.
Detta ändrar inte SQLite-lägets lokala administratörsrättigheter.

[Driftinstruktionen](../deployment/cluster/README.md) beskriver roller,
nyckelflöde, rotation, gallring och återställningsvillkor. Registreringens
NFC-session har fortsatt en enda process. Klusterläget har separat register;
SQLite-data flyttas inte automatiskt. `cluster_bridge.py` ansluter det
befintliga lokala SAML-socketprotokollet till PostgreSQL-registret.

`cluster_recovery.py` tar en konsekvent registerbackup via PostgreSQL COPY.
Återställning skapar en ny databas med betrodd schemakod, spärrar gamla
nycklar och kontrollerar profilernas dekryptering innan data får sparas.
Databasen lämnas stängd utan anslutningsrätt för applikationen. Backupen
omfattar inte OpenBao, databaslogins eller infrastrukturkonfiguration.

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
  riktiga WebAuthn-signaturer. Krasch och återläsning spärrar alla testnycklar.
- `verification/relying_party.py` är en enklare lokal HTTP-testtjänst utan
  SAML. Den använder samma appregister men separata webbsessioner.
- `ops/` bygger en fristående hälsokontrollcontainer. Den innehåller ingen
  verifierare, IdP, SP, identitetsdatabas eller testnyckel.

## Återstående kontroller

Bredare fysiska enhetsprov, biometrisk/PAD-kalibrering, injektion och relä,
certifikatspärr, registerkontroll, HSM, operativ befogenhetsseparation och återställning med
beständig spärrstatus behöver fortsatt operativ verifiering. Den separata
spärrtjänsten har provats med syntetiskt ID medan betans server var stoppad.
Federerad underskrift: `PhoneProvider` visar SignMessage i appen via registret,
som kräver en separat `sign`-åtgärd över exakt text. IdP:n intygar
`signMessageDigest` och utfärdar SAD (Sweden Connect DP 1.9 §7, SAP). Kontotjänstens
underskriftsentitet (`/sign`, kategori `sigservice`) kontrollerar digest och SAD och
skapar en PAdES-B-B-signatur med en ej betrodd test-CA (`TestConsole`, `PadesSigner`).
Klusterläget stöder ännu inte underskriftsbegäranden.
Dokumentunderskrift finns även i den separata syntetiska `start-web`-labben:
`SigningController` binder visad text och uttrycklig avsikt till en ny
WebAuthn-ceremoni; `SigningCeremony` kontrollerar spärr och engångsbruk;
`TestDocumentSigner` skapar CMS med en separat tillfällig testnyckel.
Detta flöde är inte aktiverat i telefonpiloten eller anslutet till SignService.
Se [prövningsunderlaget](provningsunderlag.md).
Se [krav](krav.md), [testning](testning.md) och [säkerhet](../SECURITY.md).

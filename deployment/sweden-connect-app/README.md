# Tjipp i Sweden Connects sandbox

`phone-sandbox-idp` använder appens passbundna nyckel och godkännande.
En vanlig inloggning och en underskrift är separata godkännanden i appen.

Anslutningen tillåter endast testklientens `testsp1`, `testsp2` och
`test-signservice1`. Deras nycklar hämtas ur signaturkontrollerad
sandboxmetadata med ett fast tillitsankare. Appen visar mottagaren och
syftet; godkännandet, tjänstesubjektet och SAML-svaret binds till mottagaren.
Förnamn, efternamn, visningsnamn och tjänstesubjekt lämnas till testklienten.
Test-SP 1 och underskriftstjänsten får också personnummer när det finns med
tolv siffror i den autentiserade svenska passprofilen. Test-SP 2 får inget
personnummer. Appens godkännandetext anger uppgifterna och mottagaren.
Passfoto, passnummer, födelsedatum och interna credentialreferenser lämnas inte ut.

## Aktivering

Behåll betans isolerade tjänster, UID/GID, privata IPC-kataloger,
nycklar och monteringar. Bygg från den revision som faktiskt körs där.
`Dockerfile.patch` lägger den verifierade JAR-filen och de ändrade
Pythonmodulerna ovanpå den verifierade befintliga image-ID:n. Den hämtar
inga nya beroenden. Ange `BASE_IMAGE` och `SOURCE_REVISION` vid bygget.

1. Kör Java- och registertesterna samt `saml-negative-test.py` i en isolerad
   container utan betans datamappar. Kör även `test_runtime_isolation`.
2. Kör `phone-sandbox-init <idp-nyckelkatalog>` en gång som IdP-tjänstens
   användare. Det lägger till en separat krypteringsnyckel och sandboxens
   offentliga tillitsankare. Befintliga TLS- och signeringsnycklar bevaras.
   Kopiera endast den offentliga `idp-encryption.crt` till kontotjänstens
   separata nyckelkatalog, så att dess krypterade SignMessage använder samma nyckel.
3. Ändra IdP-kommandot till
   `phone-sandbox-idp <nyckelkatalog> <bryggsocket> <origins.json>` och
   sätt `OPENID_SWEDEN_CONNECT_SANDBOX=true` för bryggan.
4. Starta de testade image-ID:erna med befintliga isoleringsregler.
   Kontrollera readiness, metadata, logotyper och appens vanliga flöde.
5. Registrera faktiskt genererad `/saml2/metadata` i sandboxregistret.
   Namnet är **Tjipp**. Metadata deklarerar appens egna autentiseringskontexter.

Återgång: återställ tidigare image-ID, IdP-kommandot `phone-idp` och bryggans
tidigare miljö. Ingen databasmigrering görs. Återställ aldrig identitetsregistret
från en säkerhetskopia för att backa denna kodändring.

## Funktionsprov

I Sweden Connect Test Client: välj Tjipp och Test-SP 1, signerad
HTTP-Redirect och exakt kontext `urn:openid:authn:passport-native:v1`.
Skanna QR-koden med appen och godkänn. Kontrollera signatur, kryptering,
InResponseTo, mottagare och returnerad kontext. Test-SP 2 kan kontrollera
att en annan mottagare ger ett annat tjänstesubjekt.

Vid timeout: starta om från testklienten i samma flik. Felsidan återgår till
sandboxen när den gamla begärans mottagare finns kvar i sessionen. Saknas
den kontexten visas ingen gissad länk till en annan tjänst.

Test-SP 1 och underskriftstjänsten begär personnummer i sin metadata;
Test-SP 2 begär eIDAS-identitet. Det senare är ingen profil som Tjipp utfärdar.
Personnummer vidarebefordras från passets autentiserade DG1-fält. Det är
inte ett SPAR-uppslag. Ett saknat eller tiosiffrigt nummer utelämnas;
inget sekel eller personnummer skapas ur födelsedatum. Redovisa då
personnummerprofilen som ofullständig även om protokollprovet fungerar.

För underskrift: välj `test-signservice1`, en kort ren text med
`MustShow=true` och samma autentiseringskontext. Läs texten
i appen och välj Skriv under. Prova också krypterat SignMessage.
Kontexten `urn:openid:authn:passport-native:pin:v1` kräver även säkerhetskod.
Kontrollera att `signMessageDigest` motsvarar SHA-256 över exakt visad UTF-8-text.
SAD kräver en separat SADRequest; ett test av enbart SignMessage verifierar
inte SAD eller en färdig PDF-underskrift. Kontotjänstens `/test` innehåller
separata SAD- och PDF-prov.

| Prov | Förväntat beteende |
|---|---|
| Inloggning med appgodkännande | Signerat, krypterat svar med rätt mottagare och egen autentiseringskontext |
| Underskrift | Separat godkännande av exakt text; korrekt signMessageDigest och SAD |
| Avbrott eller nekande | Inget lyckat identitetsintyg |
| Otillåten SignMessage, SAD utan text | Ingen underskrift |
| Osignerad begäran, okänd nyckel, fel ACS eller mottagare | Avvisas |
| Återspelning, utgång, spärrad legitimation | Avvisas |
| Begärd officiell nivå 1, 2 eller 3 | NoAuthnContext tills profilen stöds; ingen tyst sänkning |

Kontotjänstens `/test` har också inloggnings-, underskrifts- och nivåprov.
Ett godkänt negativt nivåprov visar korrekt felhantering, inte uppfyllelse
av tillitsnivån. Metadata-validatorns nivå- och kategorikontroller kan
därför fortfarande markeras. Formellt tillitsgodkännande ingår inte i proven.

Personliga prov görs av innehavaren på telefonen. Spara testresultaten privat;
lägg inte identitetsuppgifter, testintyg eller sessioner i publika PR:er.

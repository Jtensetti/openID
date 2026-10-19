# Isolerad e-id-prototyp – G1

En körbar lokal IdP och testtjänst med ett riktigt SAML-flöde. **Identitetskontroll och innehavarautentisering är uttryckligen simulerade. Ingen tillitsnivå, Digg-anslutning eller Digg-godkännande har uppnåtts.**

## Starta

Kräver JDK **21**, Python **3** för beroendekontroll och lediga portar **8443/8444**. Maven **3.9.11** hämtas av den medföljande wrappern och verifieras med SHA-256. Första bygget behöver internet för offentliga Maven-beroenden; den startade labben behöver ingen extern tjänst. Linux är verifierat. Windows-kommandon nedan finns, men Windows är inte provat.

Från repositoryroten:

```sh
cd prototype
./scripts/lab.sh build
./scripts/lab.sh init
./scripts/lab.sh start
```

`JAVA_HOME` ska peka på JDK 21 om den inte är standard. `init` skapar tre nya, separata RSA-testnycklar för TLS, IdP och SP i `.local/`, med 30 dagars certifikatgiltighet. Befintlig katalog skrivs aldrig över. Testlösenordet i koden är avsiktligt offentligt och skyddar inte mot användaren som kör labben. Inga privata nycklar följer med i Git.

1. Öppna först <https://127.0.0.1:8443/> och sedan <https://127.0.0.1:8444/> i en separat testprofil i webbläsaren. Båda använder det självsignerade certifikatet från just din `.local/tls.crt`. Kontrollera certifikatet och godta endast dessa lokala testadresser. Installera inte certifikatet som allmänt systemankare. Använd `127.0.0.1`, inte `localhost`.
2. Välj **Starta testinloggning**, behåll `SYNTHETIC-alice`, läs motparten, markera att kontrollen är simulerad och välj **Godkänn testinloggning**. Du ska komma tillbaka till testtjänstens `/me` med den syntetiska identiteten.
3. Prova `SYNTHETIC-revoked`, `SYNTHETIC-expired` eller **Avbryt**: ingen testsession ska skapas.
4. På IdP:ns startsida kan du spärra Alice. Det spärrar nya flöden och gör redan skapade SP-sessioner oanvändbara vid nästa kontroll. Öppna `/me` igen för att kontrollera detta.

Stoppa med **Ctrl+C**. Stoppa också labben innan du bygger om JAR-filen. En omstart återställer hela det syntetiska registret, inklusive spärrar, och alla sessioner. Alice gäller en timme från start. Vill du byta testnycklar: stoppa först, flytta `.local/` åt sidan och kör `init` igen. Denna återställning är avsiktlig labbsemantik och får inte användas för verkliga credentials.

PowerShell, motsvarande explicita kommandon:

```powershell
cd prototype
.\mvnw.cmd -B -ntp clean verify dependency:list -DoutputAbsoluteArtifactFilename=true -DoutputFile=target/dependencies.txt
python scripts/dependencies.py
java -jar target/isolated-eid-lab.jar init .local
java -jar target/isolated-eid-lab.jar start .local
```

Certifikatet kan inspekteras med `keytool -printcert -file .local/tls.crt`. Ett TLS-prov med explicit tillit till endast labbcertifikatet:

```sh
curl --cacert .local/tls.crt https://127.0.0.1:8444/
```

## Tester och beroenden

```sh
./mvnw -B -ntp clean verify dependency:list -DoutputAbsoluteArtifactFilename=true -DoutputFile=target/dependencies.txt
python3 scripts/dependencies.py
# Kör när den manuella labben är stoppad; startar och stoppar sin egen process.
python3 scripts/smoke.py
# Generera ny SBOM vid en granskad beroendeuppdatering.
./mvnw -B -ntp org.cyclonedx:cyclonedx-maven-plugin:2.9.1:makeBom
```

JUnit startar riktiga HTTPS-lyssnare på lediga loopbackportar och genererar tillfälliga nycklar. Klienterna verifierar certifikat och värdnamn mot exakt labbcertifikat. Negativa SAML-fall skapas med OpenSAML/Sweden Connect, inklusive **giltigt signerade men semantiskt felaktiga** meddelanden. Testerna ligger i `src/test/java/lab/`; detaljer och faktiskt resultat finns i [verifieringsrapporten](evidence/verification.md).

`dependencies.lock.json` låser den upplösta grafen inklusive testberoenden och SHA-256 för varje JAR. Kontrollskriptet nekar ändrad graf, checksumma, versionsintervall och snapshotberoenden. Ändring av låset är ett separat granskningsbart steg: `python3 scripts/dependencies.py --write`. Kör först ny `dependency:list`, granska ändringarna, licenser och säkerhetsmeddelanden samt kör testerna. Byggpluginer är versionslåsta via POM och dess låsta parent; deras hela transitiva graf omfattas **inte** av JAR-låset.

### Test i en riktig webbläsarmotor

Kräver Node.js 22–24 (CI: 24.19.0). Playwright 1.62.1 och dess graf är låsta i `package-lock.json`:

```sh
npm ci --ignore-scripts
npx --no-install playwright install chromium --only-shell
npm run test:browser
```

På Linux kan Playwright behöva systembibliotek: använd vid behov dess `install --with-deps chromium --only-shell` i din disponibla testmiljö. Testet genererar egna nycklar, startar JAR-filen och provar inloggning, verkliga Origin-headers, automatisk POST, utloggning och spärr. TLS-undantaget är bundet till just det tillfälliga certifikatets publika nyckel och all sidtrafik begränsas till de två loopbackadresserna. `CHROMIUM_EXECUTABLE` kan ange samma Chromium-version från en separat installation. Stoppa den manuella labben först.

## Vad som körs och vad som simuleras

| Del | Implementation och gräns |
|---|---|
| IdP | Sweden Connect Spring Authentication Server 1.0.3 med en egen, tydligt simulerad autentiseringsprovider. |
| Testtjänst/SP | Minimal lokal tjänst; Sweden Connect/OpenSAML genererar och validerar protokollet. En adapter från Test Client 1.0.19 återanvänds, inte hela dess konfigurerbara testapplikation. |
| Protokoll | Signerad AuthnRequest via HTTP-Redirect, signerad Response med krypterad och signerad Assertion via HTTP-POST. Endast RSA-SHA256 och SHA256 accepteras för signaturvalidering. |
| Profil | Privat labbkontext `urn:openid:lab:simulated`, inte verklig LoA. Enbart attributet `displayName=SYNTHETIC-…` efterfrågas och accepteras. Ingen komplett Sweden Connect-profilcertifiering. |
| Tillit | Lokalt genererade, fasta metadata för exakt en IdP och en SP; ingen metadatahämtning från internet. Separata lokala IdP-/SP-signaturnycklar. |
| Flödesbindning | Bibliotekets kontroll av issuer, audience, destination, recipient, InResponseTo, RelayState, signatur, tid och replay; därutöver engångskonsumtion av webbläsarsession och rotation av sessionscookie. |
| Identitet | Fördefinierade syntetiska poster. Val i en lista och uttryckligt labbgodkännande ersätter både identitetskontroll och innehavarautentisering. Det är inte MFA, BankID, passkey, ID-handlingskontroll eller enhetsbevis. |
| Livscykel | Minnesmodell för väntande, simulerat kontrollerad, aktiv, utgången och spärrad credential. Ersättning kräver ny simulerad kontroll av samma identitet och spärrar den gamla atomärt. Ersättning provas genom tester, inte via ett support-/återställningsgränssnitt. |
| Spärr | Status kontrolleras också vid återupptagning före signering. SP använder samma lokala register och en spärrversion per identitet; ny credential återupplivar inte gamla sessioner eller pågående svar. Detta är en labbkoppling, ingen lösning för distribuerad federationsspärr. |
| Tider | Begäran och godkännandeflöde: 60 s. Assertion: 30 s. Svar måste nå SP inom ±5 s från dess IssueInstant. SP-session: högst 5 min. SSO är avstängt. |

Tillståndsmodellen och negativa övergångar finns i `SyntheticRegistry.java` och `SyntheticRegistryTest.java`. Ersättning går från en **ny** `PENDING` post via `PROOFED` till `ACTIVE`; den gamla posten förblir `REVOKED`. En spärrad credential kan inte återaktiveras.

## Förtroendegränser och kvarstående hinder

Två HTTPS-adresser binds enbart till `127.0.0.1` i **en disponibel JVM**. De representerar separata protokollroller, men är inte säkerhetsisolerade processer. Datorn, operativsystemkontot och testprofilen måste vara betrodda. Vanliga Spring-miljövariabler/CLI kan inte byta till publik bindning, externa metadata eller produktionsnycklar. Det är inte en OS-sandbox eller ett skydd mot den som får ändra programmet/filerna. Kör helst i en disponibel utvecklingsmiljö, utan porttunnlar eller reverse proxy.

Labben har inga produktionsanslutningar, betalningar, rapporteringsanrop, dokumentunderskrifter eller AI-baserade identitetsbeslut. Den utfärdar ingen riktig e-legitimation. Den saknar beständig databas, robust missbruksbegränsning, full revisionslogg, HSM, verkliga faktorer, registerkontroller, återställningskanal, driftberedskap och oberoende granskning. Inga krav i huvudmatrisen har därför stängts.

OpenSAML-adapterns korta svarsfönster och ett upstream-varningsmeddelande om audit-autokonfiguration behandlas i [verifieringsrapporten](evidence/verification.md). Om ett flöde tar för lång tid: börja om; förläng inte säkerhetsfönstret för att få en demo att gå igenom.

Licenser, fullständiga upstream-revisioner, underhållsstatus och uppdateringsansvar finns i [THIRD_PARTY.md](../THIRD_PARTY.md). Projektets egen licens är fortfarande ett ägarbeslut. Ett passerat labbtest innebär varken oberoende säkerhetsacceptans eller Digg-godkännande.

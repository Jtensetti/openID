# Historisk verifiering: SAML

Rapport från [PR #1](https://github.com/Jtensetti/openID/pull/1), 2026-10-19.
Omfattning och antal nedan gäller den revisionen. Aktuella körningar finns i
[testöversikten](../../docs/testning.md). Maskinrapporter och låsfiler kan ha
uppdaterats efter denna körning; äldre versioner finns i Git-historiken.

## Faktiskt körd verifiering

Miljö: Linux, Temurin **21.0.12.1+1**, Maven **3.9.11**, Python **3.12**, Node **24.19.0**, Playwright **1.62.1**, Chromium **151.0.7922.34**. JDK hämtades från Adoptiums officiella release och kontrollerades mot dess checksumma. Initial beroendehämtning använde miljöns HTTP-proxy och betrodda CA; certifikatvalidering stängdes inte av. Wrapperns Maven-zip har fast SHA-256. Windows/macOS har inte körts.

| Körning | Resultat och faktiskt scope |
|---|---|
| `JAVA_HOME=<JDK21> ./scripts/lab.sh build` | Rent bygge, körbar JAR och **57 JUnit-testfall: 0 fel, 0 misslyckade, 0 överhoppade**. 44 protokoll-/HTTPS-fall och 13 livscykelfall. Upplöst graf: **170** JAR:er med godkända versions-/SHA-256-kontroller. |
| `JAVA_HOME=<JDK21> python3 scripts/smoke.py` | Nyckelgenerering och start via paketerad `java -jar`, båda HTTPS-adresserna, full syntetisk inloggning och stopp. Python-klienten kontrollerar certifikat och värdnamn mot enbart det nya labbcertifikatet. |
| `npm ci --ignore-scripts` och `npm run test:browser` | Chromium genomför inloggning, riktiga Origin-headers, automatisk SAML-POST, utloggning, nekad spärrad credential och spärr av aktiv session. Miljön blockerade Playwright-CDN; samma Chromium-version hämtades från Googles officiella Chrome for Testing-lagring och angavs med `CHROMIUM_EXECUTABLE`. |
| `./mvnw org.cyclonedx:cyclonedx-maven-plugin:2.9.1:makeBom` | SBOM genererad för samma Maven-graf, inklusive testberoenden. Artefakten finns i `bom.json`. |
| `npm audit --json` | 0 rapporterade sårbarheter i det låsta testverktygets npm-graf vid kontrolltillfället; `npm-audit.json`. Chromium/systembibliotek omfattas inte. |
| OSV `POST /v1/querybatch` | **170** slutliga Maven-koordinater kontrollerade, **0 träffar vid kontrolltillfället**. Resultat i `osv.json`; inget intyg om sårbarhetsfrihet. |

## Testkopplingar och negativa fall

| Krav / kontroll | Körda tester |
|---|---|
| FED-01, SEC-01, TEST-01 | `signedEncryptedLoginWorks`, giltigt omsignerad kontroll, fel tillitsankare, korrupt/utebliven signatur, SHA-1 med matematisk korrekt signatur, osignerad assertion inuti signerat svar. Verklig HTTPS; biblioteket sköter valideringen. |
| FED-02 | Giltigt signerad felaktig ACS/issuer/audience/recipient/destination/InResponseTo; fel RelayState; byte av browser-session; gamla/framtida requests och responses; utgången/framtida assertion. Inget test nöjer sig med att den ändrade signaturen råkar bli trasig. |
| FED-01/02, INT-02 | Begärd verklig LoA nekas, förhöjd tillitskontext och extra attribut i signerade svar nekas. Användaren ser motparten och måste uttryckligen bekräfta simuleringen; avbrott skapar ingen session. |
| FED-02, SEC-01 | Request-, godkännande- och response-replay; två parallella konsumenter av samma svar lyckas exakt en gång; CSRF och Origin på godkännande/utloggning/spärr; sessionen roteras vid lyckat svar. Chromium provar faktisk cookie- och navigeringssemantik. |
| ID-06/08/09 | Ogiltiga identifierare och dubbel credential; aktivering utan simulerad kontroll; fel person; återspelad kontroll; avbruten/utgången utgivning; irreversibel spärr; ersättning kräver ny kontroll och spärrar den gamla credentialen. |
| ID-10 | Spärr efter godkännande men före återupptagning/signering, efter svar men före konsumtion och efter inloggning; spärr skyddas mot samtidig signering. Ersättning får inte återuppliva gamla sessioner eller pågående svar. |
| SEC-01/03 | XXE/DOCTYPE nekas utan begäran till lokal nätverkskanariefågel; attackerarkontrollerad indata läcker inte in i loggar. Beroendelås och advisorykontroll kompletterar flödestesterna. |
| INT-01/03/04/05/06 | Kod-/konfigurationsgranskning: ingen AI-beslutsväg, rapporterings-/ersättningsväg eller produktion; licenser och lås redovisas. Oberoende granskning och behörig acceptans återstår. Ingen ekonomisk rapporteringsmodell har implementerats eller testats. |

Exakta testnamn finns i `src/test/java/lab/FlowTest.java` och `SyntheticRegistryTest.java`. SAML-negativfallen använder OpenSAML/Sweden Connect för dekryptering, ändring, omsignering och kryptering med disponibla testnycklar. Endast egna loopbacktjänster angrips.

## Upptäckta och rättade fel

- Upstreams standardundantag för CSRF omfattade även provider-endpoints. Adapterkonfigurationen ersätter det med undantag endast för signerat SAML HTTP-POST; simulerat godkännande och spärr kräver CSRF. Regressionen nekade tidigare inte saknad token och passerar nu.
- En explicit valideringspolicy saknades i den återanvända testklientadaptern. Matematiskt giltig SHA-1 nekas nu av OpenSAML:s algoritmpolicy; signatur och kryptering på assertion krävs.
- Statuskontroll bara på identitetsnamn kunde återuppliva en äldre SP-session vid credential-ersättning. Ett regressionstest reproducerade HTTP 200 där 401 krävdes. Identitetens spärrversion binds nu till både väntande flöde och session; regressionen passerar.
- `Referrer-Policy: no-referrer` gav `Origin: null` i Chromium och blockerade korrekt formulär-POST. `strict-origin` behåller kontrollbar Origin utan att dela SAML-queryparametrar som Referer. Ursprungs- och CSRF-kontrollerna är kvar. JUnit verifierar headern och Chromium hela flödet.
- JDK HTTPS-serverns trådar saknade Boot-JAR:ens klassladdare. OpenSAML kunde därför inte ladda sin signaturvalideringsprovider i paketerad drift trots gröna klasspath-tester. Trådarna får nu applikationens klassladdare. Både paketerat HTTP-test och Chromium passerar, utan att någon signaturkontroll kringgås. Byggskriptet gör ett rent bygge; bygg inte om en JAR medan labben kör den.
- OSV flaggade ursprungliga Tomcat 11.0.24, Jackson 2.21.5/3.1.5 och jsoup 1.21.2. De ersattes med 11.0.26, 2.21.7/3.1.7 och 1.23.2. Se primärkällor: [Tomcat](https://tomcat.apache.org/security-11.html), [Jackson advisory](https://github.com/FasterXML/jackson-databind/security/advisories/GHSA-cxp5-3px4-pw24), [jsoup 1.23.2](https://github.com/jhy/jsoup/releases/tag/jsoup-1.23.2). Hela sviten kördes på den upplösta, uppdaterade grafen.

## Kända avvikelser och ej körda prov

`opensaml-addons` **2.2.1**, `ResponseValidator.validateIssueInstant`, använder omvänd riktning i båda `Duration.between`-jämförelserna. Käll-JAR och senaste publicerade Maven-version kontrollerades. Labben ändrar ingen validator: `maxAgeResponse=0` och `allowedClockSkew=5s` ger ett symmetriskt ±5-sekundersfönster både med och utan den avvikelsen. Giltigt signerade svar tio sekunder bakåt/framåt nekas i regressionerna. Begränsningen måste omprövas med upstream och oberoende granskare innan annan användning eller tidskonfiguration.

G01:s audit-beroende ger ett startvarningsmeddelande om den saknade äldre klassen `org.springframework.boot.actuate.autoconfigure.audit.AuditAutoConfiguration`. Flödet fungerar, men en fullständig, beständig revisionslogg har inte implementerats eller verifierats. Varningen har inte dolts med generellt avstängd loggning.

Ej körda: hela Sweden Connects egen testsvit, extern federations-/profilcertifiering, Firefox/Safari, Windows/macOS, mobil/enhetsprov, HSM, verklig identitetskontroll, last/DoS-utvärdering, full fuzzning/XML Signature Wrapping-korpus, nyckelrotation under drift, beständig återläsning och oberoende penetrationstest. Dessa kräver annan scope/infrastruktur eller oberoende kompetens. De enskilda negativa fallen ovan är inte en fullständig SAML-säkerhetsrevision.

Fortsatt simulerat: person/identitetskontroll, credential och innehavarautentisering, utgivning/ersättning, spärrkanal och gemensamt lokalt register. Ingen egen enhetsnyckel, PIN, biometrik eller autentiseringsfaktor har verifierats. Alla register/sessioner försvinner vid omstart. Två lyssnare i samma JVM utgör inte processisolering; loopback är inte ett nätverkssandboxbevis.

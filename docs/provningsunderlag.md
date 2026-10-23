# Teknisk prövning av OIDC, SAML och dokumentunderskrift

Underlaget avser egen teknisk verifiering med syntetiska identiteter.
Det är inte ett godkännande från Digg, en OpenID-certifiering eller en
extern revisionsrapport. Ett godkänt bibliotek bevisar inte att den egna
konfigurationen och utgivningsprocessen uppfyller en federationsprofil.

## Profiler och källversioner

[protocol-sources.json](protocol-sources.json) anger dokumentens URL,
versionsrubrik, hämtningstidpunkt och SHA-256 för den lästa HTML-filen.
Avstämningen 2026-10-23 omfattar SAML Deployment Profile 1.9,
Sweden Connect OIDC Profile 1.1, Swedish OIDC Profile 1.0,
DSS Implementation Profile 1.7 och Certificate Profile 1.3.
Den följer också OIDC Signature Extension 1.2 samt Sweden Connects
säkerhets- och metadataunderlag. Käll-ID definieras i [SOURCES.md](SOURCES.md).

Indexet T01 länkar samtidigt till den samlade decemberutgåvan 2024.
`latest`-adresser och sökindex kan visa olika revisioner. Versionerna ovan
är därför granskningsbas, inte ett antagande om vilket avtal eller vilken
övergångsregel som gäller för OpenID. Tillämpad version måste framgå av
överenskommelsen med federationsoperatören inför extern prövning.

## Vad som går att visa

| Krav-ID | Källa / kontroll | Körbar evidens | Avgränsning |
|---|---|---|---|
| FED-01, SEC-01 | T02 §§5–6: signerad begäran, krypterat/signerat svar, mottagare och engångsbruk | `FlowTest`, `WebAuthnFlowTest`, `saml-negative-test.py` | Fasta lokala metadata och egna testmotparter. |
| FED-02, ID-10 | Avsikt, aktiv credential och spärr före/efter inloggning | `saml-negative-test.py`, `oidc-negative-test.py`, `test_identity` | Testnyckel ersätter fysisk telefon i automatiska prov. |
| FED-03 | T07 §§2–3: Code, S256, state, nonce och klientautentisering | OIDC-01–06 i `protocol-results.json` | Intern integration; inte OpenID Foundations svit. |
| FED-03 | T03 §2.3.1: private_key_jwt; felaktigt och återanvänt intyg avvisas | OIDC-03 | Även redan använd kod provas med ursprunglig verifierare och ny klientassertion. |
| FED-03/04 | T03 §3.1.1: begär och kontrollera essential acr | OIDC-02, OIDC-04, OIDC-09 | Endast egen pilotkontext; aldrig påhittad LoA. |
| FED-03 | T07 / OIDC Core: färsk autentisering | OIDC-02 med `max_age=0`; saknat/gammalt auth_time avvisas | Egen tidsgräns; ingen SSO i piloten. |
| SIG-01 | Exakt dokument och separat uttrycklig avsikt | `SigningFlowTest`, Chromium USB/plattform | Fast syntetiskt UTF-8-dokument, ingen uppladdning eller PDF-konvertering. |
| SIG-01, ID-10 | Fel signerare, byte av dokument, avbrott, spärr, utgång och samtidighet | `SigningCeremonyTest`, `SigningFlowTest` | Inloggningens WebAuthn-svar kan inte användas för underskrift. |
| SIG-02 | Dokumentets CMS-signatur och certifikatbindning | `DocumentSignatureTest`, SIG-OPENSSL-01–06 | Två kryptografiska implementationer; inte oberoende organisatorisk granskning. |
| SIG-01, FED-01/03 | T02 §7, T03 §2.4: underskrift får inte bli vanlig inloggning | `SignatureRequestPolicyTest` | Federerade SignMessage/SAD-begäranden avvisas tills en full integration finns. |

## Underskriftslabb

Starta `start-web` enligt [labbens instruktioner](../prototype/README.md).
Registrera en testnyckel och välj **Skriv under ett syntetiskt testdokument**.
Läs hela texten, markera underskriftsavsikten och bekräfta med WebAuthn.
Dokumentet innehåller version, transaktion och syntetisk undertecknare.
Samma UTF-8-byteföljd som visas skrivs under; ingen normalisering görs.

Servern kontrollerar credential och spärrversion på nytt och skapar en
engångsnyckel för dokumentunderskriften. Bouncy Castle 1.86 skapar en
fristående CMS-signatur med SHA-256/RSA-3072 och `signingCertificateV2`.
TLS-, SAML- och autentiseringsnycklar återanvänds inte för dokumentsignaturen.
Privata nycklar finns bara i processen; någon garanterad minnesradering
eller HSM-säkerhet påstås inte.

ZIP-filen innehåller `document.txt`, `document.p7s`, signerande certifikat,
test-CA och ett beskrivande `evidence.json`. Manifestet i ZIP-filen är
osignerat. Själva dokumentet och signerande certifikat binds kryptografiskt
i CMS-signaturen. Nedladdningen är sessionsbunden och gäller fem minuter.
Pågående flöden och nedladdningar försvinner vid omstart.

Detta är en testprofil, inte en implementerad Sweden Connect SignService,
inte verifierad CAdES/PAdES-baseline och inte en kvalificerad underskrift.
Identitetskontrollen är simulerad. Testcertifikatet gäller tio minuter;
test-CA:n saknar produktionsmässig tillit och spärrtjänst. Betrodd tidsstämpel,
långtidsvalidering, certifikatpolicy och arkivering återstår. Test-CA:n ska
aldrig installeras som ett generellt tillitsankare. `phone-idp` och
iPhone-piloten erbjuder inte dessa underskriftsrutter.

## Reproducerbar körning och bevispaket

Från `prototype/` med JDK 21:

```sh
./mvnw -B -ntp clean verify dependency:list -DoutputAbsoluteArtifactFilename=true -DoutputFile=target/dependencies.txt -Dsignature.fixtureDirectory=target/signature-fixtures
python3 scripts/dependencies.py
python3 scripts/verify-signature.py target/signature-fixtures/synthetic-signature.zip --report target/signature-fixtures/openssl-results.json
npm ci --ignore-scripts
npx --no-install playwright install chromium --only-shell
npm run test:browser
python3 scripts/collect-evidence.py --kind java --output target/assurance-evidence
```

OpenSSL-provet kontrollerar vid aktuell tid och måste därför köras innan
testcertifikatet går ut. En senare verifiering vid en angiven historisk tid
bevisar inte att den tiden är betrodd. Skapa ett nytt testresultat vid
omkörning; slå inte av certifikat- eller tidsvalidering.

CI-workflowen **Server and authentication tests** sparar
`saml-signature-evidence`: sanerade JUnit-resultat, dokumentunderskrift,
OpenSSL-resultat, låsfiler, källunderlag och kontrollsummor.
**Private pilot runtime** kör de två processproven i pilotimagen utan
externt nät och sparar `protocol-evidence`. Endast testhjälpare och den
normalt separat monterade federationsbryggan monteras in; plånbok och
kryptografikod hämtas ur imagen. Inga verkliga personakter används.

`manifest.json` skiljer PR:ns källrevision från den faktiskt testade
revisionen, som kan vara GitHubs tillfälliga merge-commit. Den anger
JAR-hash, workflowlänk och om arbetskopian var ren. Saknade, misslyckade
eller överhoppade obligatoriska Java-prov får inte ge ett komplett godkänt
paket. Även partiella resultat laddas upp när ett jobb misslyckas.
Artefakterna behålls i 90 dagar; de måste bevaras i ett beslutat bevisarkiv
innan retentionen löper ut om de ska användas i en senare granskning.

## Kvar inför extern prövning

| Arbete | Typ | Konkret slutbevis |
|---|---|---|
| Full OIDC-profil: metadata, språk, public/pairwise-subjekt över omstart/nyckelbyte, attributminimering, request objects och federativ tillit | Bygga eller verifiera per profilpunkt | Tester mot oberoende OP/RP och versionsbunden metadata; bibliotekets stöd räcker inte som bevis. |
| SAML: godkänd metadata, attributprofil, rollover, tillitsankare och samtliga tillämpliga bindningar | Bygga/verifiera + operatörsanslutning | Validerade metadata och extern interoperabilitetsrapport. |
| Authentication for Signature i SAML/OIDC och DSS SignService-integration | Bygga | SignMessage/signRequest, rätt signerare, dokumentbindning, separat avsikt och korrekt svar verifierade mellan olika implementationer. |
| Produktionsunderskrift: vald dokumentprofil, CA/HSM, certifikatpolicy, tid och långtidsbevis | Beslut + bygga/ansluta | Extern valideringsrapport för vald profil och fastställd bevarandepolicy. |
| OpenID Foundation OP- och RP-prövning | Extern svit, därefter separat certifieringsansökan | Testplan-ID, svitrevision, profil, konfiguration och exporterade resultat. Alla erforderliga tester avslutade. |
| Diggs tillitsprövning och Sweden Connect-anslutning | Formell granskning och avtal | Beslut från behörig part; teknikresultaten är bilagor. |
| Huvudman, kapital, registeråtkomst, fysisk kedja, driftansvar och biometri/dataskydd | Beslut, integration och extern/fysisk provning | Se [de sju utgivningsfrågorna](infor-utgivning.md) och [fysisk acceptans](fysisk-acceptans.md). |

För extern OIDC-prövning behöver en separat syntetisk testinstans registrera
svitens klient och dess verifierade nycklar/redirects. Dagens fasta
pilotmotpart och Basic-skyddade ingress är inte en färdig extern testinstans.
Svitkonto, verklig registrering och en vald testprofil saknas; inga
ansökningar eller intyg har skickats. [OpenID Foundations instruktioner](https://openid.net/certification/connect_op_testing/)
och [Sweden Connects testmiljöer](https://www.swedenconnect.se/teknisk-dokumentation/miljoer-for-produktion-och-test)
är utgångspunkter. Detta dokument får inte användas som ett utfärdat godkännande.

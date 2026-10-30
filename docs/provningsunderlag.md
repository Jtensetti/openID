# Teknisk prövning av OIDC, SAML och dokumentunderskrift

Test-PDF:ens [synliga underskriftskvitto](pdf-underskrift.md) ingår i dess
signaturfält och signerade bytes. Rendering av kvittot och kryptografisk
validering är skilda kontroller; test-CA:n blir inte allmänt betrodd av detta.

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

| Källa / kontroll | Körbar evidens | Avgränsning |
|---|---|---|
| T02 §§5–6: signerad begäran, krypterat/signerat svar, mottagare och engångsbruk | `FlowTest`, `WebAuthnFlowTest`, `saml-negative-test.py` | Fasta lokala metadata och egna testmotparter. |
| Avsikt, aktiv credential och spärr före/efter inloggning | `saml-negative-test.py`, `oidc-negative-test.py`, `test_identity` | Testnyckel ersätter fysisk telefon i automatiska prov. |
| T07 §§2–3: Code, S256, state, nonce och klientautentisering | OIDC-01–06 i `protocol-results.json` | Intern integration; inte OpenID Foundations svit. |
| T03 §2.3.1: private_key_jwt; felaktigt och återanvänt intyg avvisas | OIDC-03 | Även redan använd kod provas med ursprunglig verifierare och ny klientassertion. |
| T03 §3.1.1: begär och kontrollera essential acr | OIDC-02, OIDC-04, OIDC-09 | Endast egen pilotkontext; aldrig påhittad LoA. |
| T07 / OIDC Core: färsk autentisering | OIDC-02 med `max_age=0`; saknat/gammalt auth_time avvisas | Egen tidsgräns; ingen SSO i piloten. |
| Exakt dokument och separat uttrycklig avsikt | `SigningFlowTest`, Chromium USB/plattform | Fast syntetiskt UTF-8-dokument, ingen uppladdning eller PDF-konvertering. |
| Fel signerare, byte av dokument, avbrott, spärr, utgång och samtidighet | `SigningCeremonyTest`, `SigningFlowTest` | Inloggningens WebAuthn-svar kan inte användas för underskrift. |
| Dokumentets CMS-signatur och certifikatbindning | `DocumentSignatureTest`, SIG-OPENSSL-01–06 | Två kryptografiska implementationer; inte oberoende organisatorisk granskning. |
| T02 §7, T03 §2.4: underskrift får inte bli vanlig inloggning | `SignatureRequestPolicyTest`, `test_identity`, `WalletSecurityTests` | Underskrift kräver separat `sign`-åtgärd över exakt text; inloggningsgodkännande avvisas. |
| DP 1.9 §7.1: SignMessage visas (MustShow), signMessageDigest, text som inte kan visas ger fel | Testkonsolen: `sign`, `sign-encrypted`, `sign-html`, `sign-from-service` i `federation-browser-test.cjs` | Endast ren text, högst 400 tecken. Egen underskriftstjänst, inte Sweden Connects SignService. |
| SAP §3: SAD signerad av IdP, bunden till SADRequest, SignRequestID och dokumentantal | Testkonsolen `sign`, `sad-only`; validering med `SADParser.SADValidator` | IdP annonserar `scal2`. Ingen extern signeringstjänst har provat SAD:en. |
| PAdES-B-B: hela filen täcks, DER-kodad CMS, signingCertificateV2, ingen signing-time | `PadesSignerTest` inklusive OpenSSL `cms -verify` | Test-CA i processminnet; ingen betrodd tid, LTV eller extern valideringsrapport. |
| DP 1.9 §§5.3, 5.4.4–5.4.5, 6.4: IsPassive, ej stödd kontext, ny legitimering, cancel-status | Testkonsolen `passive`, `loa3`, `no-force`, `cancel` | IdP:n har ingen SSO; en ny legitimering krävs alltid. |

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

## Integrationens gränser

Testerna använder fasta egna motparter och syntetiska identiteter. De
prövar inte extern metadataförvaltning, federativ tillit eller en ansluten
DSS SignService. OIDC Signature Extension och PrincipalSelection ingår inte
i telefonflödets testade implementation. SAML SignMessage/SAD och PAdES med
test-CA finns; certifikattillit beskrivs i [PDF-instruktionen](pdf-underskrift.md).

[OpenID Foundations externa svit](https://openid.net/certification/connect_op_testing/)
är separat från dessa tester. En lyckad intern körning är ingen extern
certifiering. Se [säkerhetsinformationen](../SECURITY.md) och
[proven på fysisk telefon](fysisk-acceptans.md).

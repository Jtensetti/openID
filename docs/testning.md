# Testning

Betans klientadress provas i tre led: `test_ingress_client` nekar fel
proxykonfiguration och tvetydiga IP-värden; `RuntimeTests` kontrollerar
separata trafik- och registreringsgränser samt att förfalskningar inte når
tjänsterna; `deployment/test_beta_nginx.py` skickar förfalskade huvuden genom
riktig nginx/TLS och kräver exakt en adress från den faktiska anslutningen.
Det är syntetiska loopbackprov, inte bevis för installerad publik konfiguration.

Serverjobbet använder Ubuntus huvudarkiv via HTTPS för webbläsarens
systemberoenden. Bytet från testmaskinens Azure-spegel ändrar inte suites,
komponenter eller Ubuntus signeringsnyckel. Jobbet har 25 minuters total
tidsgräns för installation och hela provkedjan; inga prov får hoppas över.

Testkonsolens nginx-ingress har ett separat loopbackprov i
`deployment/test_beta_nginx.py`; direktprov mot Java-processen testar inte
nginx-adresser eller storleken på dess svarshuvuden. OIDC:s telefonsida tillåter
endast samma ursprung och den konfigurerade tjänstens `/oidc/callback` som
formulärmål. `PhonePagePolicyTest` provar det faktiska svarshuvudet och nekar
olämpliga ursprung. `test-phone-feedback.cjs` provar även blockerad, misslyckad
och utebliven återgång efter godkännande. Fysisk webbläsaråtergång efter
appgodkännande ska redovisas separat från protokollproven.
Loopbackprovet ingår i `Assurance checks` via infrastrukturjobbet.
Artefakten `nginx-ingress-evidence` innehåller resultat, faktisk nginx-version,
testad Git-revision och konfigurationens SHA-256. Den förinstallerade nginx
på Ubuntu 24.04 används utan att starta eller ändra värdens systemtjänst.

## Aktuell verifiering

`WalletHTTPTests` provar appens gemensamma nätverksgräns med syntetisk
URL-laddning: HTTPS-krav, JSON, exakt svarsadress, nekad omdirigering,
storleksgräns med/utan Content-Length, HTTP-fel och avbruten uppgift.
Samma transport används för den separata spärrtjänsten. Kodfelsrensning vid
låsning provas i modellen. XCUITest kontrollerar att version och byggnummer
går att läsa utan upplåsning. Dessa prov omfattar inte riktig TLS, NFC,
Apple-attestering eller fysisk identitetskontroll.

`test_audit_archive` provar faktisk SQLite-export, samtidig spärr mellan
tabelläsningar, offlineverifiering utan register/nyckel, fältminimering,
manipulerat manifest, trunkering, filinventering, symlänkar, privata
filrättigheter, resursgränser och städning efter fel. `test_cluster` provar
samma snapshotgräns i PostgreSQL med riktig läsroll, utgivningsbeslut och
operatörsjournal. Rollen nekas profilers chiffertext, subjects,
PIN-verifierare, sessionshemligheter och skrivning. Containerbygget provar
exportörens paketerade CLI. Detta är syntetiska utvecklingsprov; extern
arkivmottagning och fullständiga utgivningsbevis ingår inte.

`deployment/archive/test_store.py` provar leverans, separat mottagarroll och
senare återläsning med versionsbunden kvittens. Felaktig data, fel konto,
fel roll, ändrade versioner, bristande bevarande och kryptering nekar
bekräftelse. Stubber kontrollerar S3-API-kontrakt; CI kontrollerar även den
genererade CloudFormation-mallens säkerhetsregler. Ingen riktig AWS-stack
eller faktisk extern mottagning används i dessa prov.

`deployment/security/test_security_template.py` kör samma Guard-regler som
infrastrukturjobbet mot mallen och avsiktligt osäkra varianter. Proven nekar
offentlig eller okrypterad lagring, avstängd revisionslogg, för bred radering
av snapshots, utebliven backup utan larm samt extra beräkningsjobb och betald
skanning. Dessa lokala konfigurationsprov skapar inga AWS-resurser och provar
inte faktisk snapshot-, logg- eller larmleverans.

Aktuella körningar och deras exakta revisioner finns i
[GitHub Actions](https://github.com/Jtensetti/openID/actions).
[Prövningsunderlaget för OIDC, SAML och underskrift](provningsunderlag.md)
beskriver reproducerbara prov och CI-artefakter med källrevision,
testad revision, kontrollsummor och uttrycklig avgränsning mot formellt godkännande.
[PR #22](https://github.com/Jtensetti/openID/pull/22) redovisar den separata
spärrtjänstens syntetiska AWS-prov med betans verifierare stoppad, köexport
och SES-kvittens. Kvittensen bevisar inte leverans till inkorgen.
Fysisk iPhone-spärr och sammanhängande återstartsprov i avsedd driftmiljö återstår.

Privata telefonprov har bekräftat passläsning, personnummer och SAML-inloggning.
De är funktionella prov, inte oberoende säkerhets- eller tillgänglighetsgranskning.
För ett sammanhängande, revisionsbundet prov används
[protokollet för fysisk acceptans](fysisk-acceptans.md). En tom mall eller
en äldre lyckad delkontroll är inget nytt provresultat.

## Aktuella utgåvor och gränser

[PR #55](https://github.com/Jtensetti/openID/pull/55) redovisar införandet av
automatisk testaktivering och bygge 112. Hela Assurance checks
[#122](https://github.com/Jtensetti/openID/actions/runs/40947520993) passerade
på `c95cef7e78b0df3ea0b001fee5002e5f111398ba`. Innehavaren har bekräftat att
passformuläret åter öppnas efter statusfelet. Ett komplett nytt fysiskt
registreringsprov efter serveruppdateringen är inte redovisat.

Kameraguiden i utvecklingsbygge 113 har lokala enhets-/Vision-/UI-prov och
signerat installationsbevis, men fysisk fångsttid, kamera och registrering
återstår. Se [appens utgåvor](../ios/README.md#utgåvor). Resultat från olika
källträd får inte räknas som en gemensam releasekontroll.

De kvarvarande säkerhetsutkasten [#52](https://github.com/Jtensetti/openID/pull/52)
och [#53](https://github.com/Jtensetti/openID/pull/53) har underkända
OS-paketkontroller på sina senast redovisade revisioner. Deras nya kontroll
finns inte i denna kodbas och en grön ordinarie CI stänger inte de fynden.
Registreringskvitton, personutdrag och raderingsjournal i #53 är också separat
arbete; de får inte beskrivas som funktioner i den driftsatta betan.

## Daterat verifieringsresultat

Revision `246118bbd3dc754ad075852037248a011c4510ab`, 2026-10-20:

| Körning | Resultat |
|---|---|
| [Server-CI](https://github.com/Jtensetti/openID/actions/runs/39370813333) | 150 Java-tester, 77 Python-tester, 6 App Attest-signaturfall, 6 driftprov och Chromium-flöden passerade. 180 Maven-artefakters versioner och SHA-256 kontrollerades. |
| [iOS-CI](https://github.com/Jtensetti/openID/actions/runs/39370813340) | Xcode 16.4 Release-bygge, CryptoKit/server-interoperabilitet, 18 XCTest och 4 XCUITest passerade. |

Nya körningar finns i [GitHub Actions](https://github.com/Jtensetti/openID/actions).
Tabellen är ett daterat resultat för revisionen ovan.

## Omfattning

| Testlager | Vad som körs | Begränsning |
|---|---|---|
| Pass | Bouncy Castle/JMRTD/JCA mot genererad CSCA, DSC, SOD, MRZ och bild. Fel signatur, hash, ankare, datum och format nekas. Spärrad DSC, inaktuell spärrlista, främmande spärrlista och CSCA-nyckelbyte provas med genererade CRL:er. | Ingen myndighetsutfärdad testhandling. Polismyndighetens verkliga CSCA-nycklar och `SWE.crl` har lästs in manuellt, inte i CI. |
| Chip | Serverstyrd PACE, CA och färsk skyddad läsning mot ett mjukvaruchip. Kopierad data utan chipnyckel, återspelning, fel MAC och fel dokument nekas. Även CLI-transport och processgränser provas. | Testpeer använder JMRTD/JCA; det ersätter inte fysisk NFC eller oberoende protokollprovning. |
| Certifikatspärr vid registrering | `PassportVerifierTest` provar signerade CRL:er, spärrat ankare, `cRLSign`, partiella listor och giltighetsgränser. CLI-provet för över verkligt verifierad status. `test_passport_revocation` provar saknad/felaktig status, exakt utgång, avbrott före bildanalys och SQLite-rollback när listan går ut under lagring. PostgreSQL-provet avvisar okontrollerade och utgångna resultat före registrering/biometriförsök. | Apptransport och kameraflöde använder testdubblar. Ingen driftsatt hämtning, återgångskontroll eller myndighetskontroll av själva passets spärrstatus. |
| CRL-underhåll | `PassportVerifierTest` provar signerad versionsökning, återgång, återanvänt nummer, storleksgräns, förlorad utfärdare och dubbla versioner. `test_crl_maintenance` provar verkliga filbyten, lås, osäkra filtyper, skrivrättigheter, skrivfel och utgång. CLI-provet installerar signerade fixturer och nekar återgång till föregångaren. | Lokala filfelprov använder verifierardubbel; CI kör den riktiga Java-processen. Ingen automatisk hämtning, driftsatt larmleverans eller oberoende statuskälla efter helsystems-återställning. |
| Bildmodeller | Låsta OpenCV- och MiniFASNet-vikter, modellinferens och felhantering. `test_pose`: landmärkesparallax, vinklat foto utan parallax, serverstyrd ordning, försöksgräns per pass, modellfel, saknad nyckel och omstart. `test_biometric_budget` provar samtidiga SQLite-instanser; PostgreSQL-proven verifierar samma budget och beständig återläsning. En äldre backup, 24-timmarsgränsen, omstart och säker HTTP-felkod provas. | Ingen mätning av biometrisk träffsäkerhet eller attackmotstånd. Poskontrollen provas med syntetiska landmärken. |
| Kameraguide | XCTest för huvudpositioner, kvalitet, tidskontinuitet, stabilitet och negativa mätvärden. XCUITest för ringens status och instruktioner. | Testade observationer är fixturer. Vision-inferens, fysisk kamera och tillgänglighet behöver enhetsprov; detta är inget liveness-test. |
| App Attest | Verifiering av signatur, appbindning, räknare och ändrade bytes. | Ingen fysisk Apple-attestering i CI. |
| Register | Verklig SQLite, AES-GCM och ECDSA; samtidighet, spärr, ersättning och krypteringsfel. | Samma OS-konto; ingen HSM eller återställning i produktion. |
| SAML/webbläsare | Separata verifierar-, IdP- och SP-processer, signerade/krypterade meddelanden och Chromium. Samma flöde mot SQLite och mot PostgreSQL/OpenBao med verifierad TLS och separata konton. Testkonsolens inloggnings-, negativa profil-, avbrotts-, säkerhetskods- och SignMessage/SAD-fall samt den PAdES-signerade PDF:en körs i `federation-browser-test.cjs` mot båda registerlägena. Felaktiga koder, låsning, byte av nivå och text samt otillåten inloggningsåtgärd för en signering nekas. | Chiptransport, kamera, App Attest och biometriska poäng är testdubblar i helkedjefixturen. Ingen extern federation eller redundant IdP-/SP-sessionhantering. |
| WebAuthn | Webbläsarens WebAuthn-API och Yubico-validering med virtuella USB-/plattformsautentiserare. Fördröjt skript lämnar knappar låsta; HTTP 400 och nekad fortsatt inloggning efter spärr verifieras. | Inga fysiska nycklar eller OS-installationsprov. |
| iOS | Bygge, signerade bytes, tillstånd och SwiftUI i simulator. | NFC, Secure Enclave, Face ID och App Attest måste provas på telefon. |
| Pilotdrift | Riktig Gunicorn/TLS, signerade wallet-anrop, kapacitetsgräns, saknad databas, privat loggning och SIGTERM. SQLite-backup och återläsning spärrar alla nycklar och pausar ny registrering/analys i 24 timmar; fel nyckel och skadad backup avvisas. `test_recovery_operations` provar läsande CLI-backup med kontinuitetskrav, committad WAL, bevarat startskydd, äldre kopior samt felaktiga filer/markörer. | En nod. Ingen fysisk iPhone, publik ingress eller HA. Belastningsmått omfattar angivet delsystem. |
| Delat register | PostgreSQL 18.6, riktiga operatörsroller, OpenBao Transit, parallella TLS-workers, instansbortfall, rotation, bevarandegolv, migrering från schema 1, beständig försöksbudget, låsta PIN-funktioner och 120 sekunders begränsad last med resursmätning. Faktisk registeråterläsning spärrar gamla nycklar, pausar registrering/analys och provas med återställd nyckeltjänst. Direkta tjänsteanrop och temporär skuggtabell kan inte kringgå spärren. TLS/Raft-prov med tre noder, ledarbortfall och saknad nyckelversion. | Temporär CI-infrastruktur; inga fysiska enheter, ingen lastbalanserare, ingen PostgreSQL-failover eller återställning från extern lagring. |
| Drift | Hälsoroutes och stängda e-id-routes över HTTP samt containerisolering i CI. | Containern innehåller ingen e-id-tjänst. |

## Negativa säkerhetsfall

- Fel signatur, mottagare, ursprung, session eller signerad avsikt.
- Återspelning, dubbla godkännanden och samtidiga försök att använda samma begäran.
- Nekande, avbrott, utgång och spärr före och efter inloggning.
- Ersatt enhetsnyckel, registeravbrott och inaktuella sessionsvärden.
- Manipulerad profil, utbytta krypterade data och saknad/fel krypteringsnyckel.
- Klientangivna identitetsfält, NaN/oändliga modellvärden och felaktiga meddelanden.
- CSRF, annan webbläsare, externa callbacks, proxyhuvuden och överstora anrop.

## Kör lokalt

[Serverleveransen](../deployment/build/README.md) provar export och återinläsning
av den byggda imagen utan ombygge. Negativa paketprov avvisar skadade filer,
fel revision/plattform, saknat protokollbevis och otillräckligt utrymme.
Ingressprovet omfattar också stora SAML-POST utan temporärfillagring och
avvisar överstora anrop; det använder enbart egna temporära nginx-kataloger.

- [Pass, modeller, register och federation](../verification/README.md#tester).
- [SAML, WebAuthn, lagring och återläsning](../prototype/README.md#tester-och-beroenden).
- [iOS-bygge och simulator](../ios/README.md#bygg-och-testa).
- [Pilotens drift- och belastningsprov](../deployment/README.md#drift-och-kapacitet).
- [Delat register och nyckeltjänst](../deployment/cluster/README.md#tester).
- [Tidsbegränsat RDS-prov](../deployment/aws/README.md).
- [Driftcontainerns HTTP-prov](../ops/README.md#kör-lokalt).

Linux med Unix-sockets krävs för federationsproven. Xcode kräver macOS;
simulatorn ersätter inte fysisk iPhone-verifiering. Testloggar och artefakter
får inte innehålla verkliga handlingar, bilder, tokens eller privata nycklar.

## Tidigare verifieringsrapporter

[SAML](../prototype/evidence/verification.md),
[beständig lagring](../prototype/evidence/g2-verification.md) och
[WebAuthn](../prototype/evidence/web-verification.md) dokumenterar tidigare
revisioner. Deras testantal och omfattning gäller respektive daterade körning.
Maskinläsbara rapporter bevaras för spårbarhet.

## Återkoppling vid avbruten inloggning

`node verification/test-phone-feedback.cjs` provar webbklientens meddelanden,
begränsade återförsök för statushämtning och att ett avbrott inte utlöser
slutförande. Provet ingår i serverjobbet i `Assurance checks` och täcker även
blockerad, misslyckad och tidsutgången återgång. DOM och nätverk är
testdubblar i detta prov. Det separata
`federation-browser-test.cjs` provar samma slutlägen i Chromium.
`test_identity` verifierar att utgången status bara lämnas efter rätt
begäransbindning och aldrig tillåter konsumtion av ett godkännande.
`WalletSecurityTests` skiljer hämtfel från osäkra beslut och lokal avbruten
autentisering. En fysisk iPhone behövs för att bedöma timing och upplevelse
kring Face ID.

## Personas och tillgänglighetsprov

Fiktiva personas används för designhypoteser; de är inte deltagare i
användarprov. `WalletUITests` provar beständiga passfältnamn, ett saknat datum
utan startad kontroll, kontrollkod med inledande nolla vid största textstorlek
samt kamerainstruktion utanför förhandsvisningen vid stor text.
`PassportAccessKeyTests` jämför fälthjälpens formatbeslut med NFC-nyckelns
validering. Riktiga användarprov och hjälpmedelsprov behövs för att bedöma
självständighet, begriplighet och eventuell försämring för andra användare.

## Privat OIDC-pilot

`verification/oidc-negative-test.py` körs med kandidat-JAR i en engångscontainer
utan externt nät och utan pilotens data/nycklar. `idp.example.test` och
`sp.example.test` pekar endast på containerns loopback. Testet skapar egen
TLS-ingång, separata testnycklar, syntetisk identitet och signerat
enhetsgodkännande. TLS-validering är på både före och bakom ingången.

Verifierat 2026-10-21 med Spring Authentication Server 1.0.3:

- Positiv Authorization Code-inloggning med S256 PKCE och private_key_jwt.
- Korrekt signerade ID-token med fel nonce, issuer, audience, utgångstid
  eller autentiseringskontext avvisas. Fel algoritm/signatur avvisas.
- Fel code_verifier, token-redirect och saknad klientassertion avvisas.
- Saknad PKCE, plain-metod, okänd klient, fel redirect och krav på LoA3
  avvisas innan en godkännandebegäran skapas.
- Fel state, återanvänd callback och konsumerad pending-session avvisas.
- Nekande, utgången QR och spärr före/efter inloggning ger ingen åtkomst.
- Pilotens testval LoA1–4 avvisas; de nivåerna utfärdas inte.
- Syntetiska namn/födelseuppgifter finns inte i tjänsteloggarna.

Kör i pilotimagen med läsbar verifieringskatalog och kandidat-JAR,
`--network none --add-host idp.example.test:127.0.0.1
--add-host sp.example.test:127.0.0.1`, lässkyddad rot och skrivbar `/tmp`.
Testet behöver Python-standardbibliotek, OpenSSL, Java/keytool och samma
signeringshjälp som `test_wallet`. Skapa aldrig värdnamnspekningar eller
förtroendeundantag i den verkliga testmiljön för detta prov.

Live-provet verifierade publik TLS, betakontoskydd, SAML-/OIDC-QR,
avvisade nivåkrav, skyddade sessionssidor och nekad tokenväxling utan
klientautentisering. Det ersätter inte ett manuellt TestFlight-prov med
fysiskt pass och produktionsmiljön för App Attest. Extern
Sweden Connect-interoperabilitet och formell tillitsbedömning återstår.

CI kör nu `protocol_evidence.py`, som kräver lyckad avslutning av både
SAML- och OIDC-processprovet. OIDC-provet omfattar dessutom färsk `auth_time`,
felaktiga signerade klientintyg, återspelat klientintyg och återanvänd kod.
Resultatet innehåller 5 SAML- och 11 OIDC-kontrollgrupper; flera grupper
omfattar flera negativa varianter. Det är inte ett antal certifieringskrav.

Den syntetiska underskriftslabben provas med `DocumentSignatureTest`,
`SigningCeremonyTest`, `SigningFlowTest`, `SignatureRequestPolicyTest`
och Chromium för USB-/plattformsautentiserare. OpenSSL verifierar samma
exporterade CMS-dokument och avvisar förändring av innehåll/radslut,
fel CA, utgånget certifikat och manipulerad signatur. En skild
kryptografisk implementation är inte en oberoende organisatorisk revision.

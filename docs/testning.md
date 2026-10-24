# Testning

## Aktuell verifiering

`test_audit_archive` provar faktisk SQLite-export, samtidig spärr mellan
tabelläsningar, offlineverifiering utan register/nyckel, fältminimering,
manipulerat manifest, trunkering, filinventering, symlänkar, privata
filrättigheter, resursgränser och städning efter fel. `test_cluster` provar
samma snapshotgräns i PostgreSQL med riktig läsroll, utgivningsbeslut och
operatörsjournal. Rollen nekas profilers chiffertext, subjects,
PIN-verifierare, sessionshemligheter och skrivning. Containerbygget provar
exportörens paketerade CLI. Detta är syntetiska utvecklingsprov; extern
arkivmottagning och fullständiga utgivningsbevis ingår inte.

Aktuella körningar och deras exakta revisioner finns i
[GitHub Actions](https://github.com/Jtensetti/openID/actions).
[Prövningsunderlaget för OIDC, SAML och underskrift](provningsunderlag.md)
beskriver reproducerbara prov och CI-artefakter med källrevision,
testad revision, kontrollsummor och uttrycklig avgränsning mot formellt godkännande.
[PR #22](https://github.com/Jtensetti/openID/pull/22) redovisar den separata
spärrtjänstens syntetiska AWS-prov med betans verifierare stoppad, köexport
och SES-kvittens. Kvittensen bevisar inte leverans till inkorgen.
Fysisk iPhone-spärr och faktisk schemalagd nattstart återstår.

Privata telefonprov har bekräftat passläsning, personnummer och SAML-inloggning.
De är funktionella prov, inte oberoende säkerhets- eller tillgänglighetsgranskning.
För ett sammanhängande, revisionsbundet prov används
[protokollet för fysisk acceptans](fysisk-acceptans.md). En tom mall eller
en äldre lyckad delkontroll är inget nytt provresultat.

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
| Bildmodeller | Låsta OpenCV- och MiniFASNet-vikter, modellinferens och felhantering. `test_pose`: landmärkesparallax, vinklat foto utan parallax, serverstyrd ordning, försöksgräns per pass, modellfel, saknad nyckel och omstart. `test_biometric_budget` provar samtidiga SQLite-instanser; PostgreSQL-proven verifierar samma budget och beständig återläsning. En äldre backup, 24-timmarsgränsen, omstart och säker HTTP-felkod provas. | Ingen mätning av biometrisk träffsäkerhet eller attackmotstånd. Poskontrollen provas med syntetiska landmärken. |
| Kameraguide | XCTest för huvudpositioner, kvalitet, tidskontinuitet, stabilitet och negativa mätvärden. XCUITest för ringens status och instruktioner. | Testade observationer är fixturer. Vision-inferens, fysisk kamera och tillgänglighet behöver enhetsprov; detta är inget liveness-test. |
| App Attest | Verifiering av signatur, appbindning, räknare och ändrade bytes. | Ingen fysisk Apple-attestering i CI. |
| Register | Verklig SQLite, AES-GCM och ECDSA; samtidighet, spärr, ersättning och krypteringsfel. | Samma OS-konto; ingen HSM eller återställning i produktion. |
| SAML/webbläsare | Separata verifierar-, IdP- och SP-processer, signerade/krypterade meddelanden och Chromium. Samma flöde mot SQLite och mot PostgreSQL/OpenBao med verifierad TLS och separata konton. Testkonsolens inloggnings-, negativa profil-, avbrotts-, säkerhetskods- och SignMessage/SAD-fall samt den PAdES-signerade PDF:en körs i `federation-browser-test.cjs` mot båda registerlägena. Felaktiga koder, låsning, byte av nivå och text samt otillåten inloggningsåtgärd för en signering nekas. | Chiptransport, kamera, App Attest och biometriska poäng är testdubblar i helkedjefixturen. Ingen extern federation eller redundant IdP-/SP-sessionhantering. |
| WebAuthn | Webbläsarens WebAuthn-API och Yubico-validering med virtuella USB-/plattformsautentiserare. Fördröjt skript lämnar knappar låsta; HTTP 400 och nekad fortsatt inloggning efter spärr verifieras. | Inga fysiska nycklar eller OS-installationsprov. |
| iOS | Bygge, signerade bytes, tillstånd och SwiftUI i simulator. | NFC, Secure Enclave, Face ID och App Attest måste provas på telefon. |
| Pilotdrift | Riktig Gunicorn/TLS, signerade wallet-anrop, kapacitetsgräns, saknad databas, privat loggning och SIGTERM. SQLite-backup och återläsning spärrar alla nycklar och pausar ny registrering/analys i 24 timmar; fel nyckel och skadad backup avvisas. | En nod. Ingen fysisk iPhone, publik ingress eller HA. Belastningsmått omfattar angivet delsystem. |
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
slutförande. DOM och nätverk är testdubblar i detta prov. Det separata
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

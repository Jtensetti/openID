# openID för iPhone

SwiftUI-app med Mitt ID, Legitimera, Aktivitet och Inställningar.
Appen använder [verifieringsservern](../verification/README.md).

## Öppna i Xcode

Från repots rot:

```sh
open ios/PassportCapture.xcodeproj
```

1. Använd schemat **PassportCapture** och en ansluten
   iPhone med iOS 16 eller senare. Swift Package Manager hämtar de låsta
   beroendena. CI använder Xcode 16.4; TestFlight-bygge 106 byggdes med Xcode 27.1.
2. Välj Apple-utvecklingsteam och bundle-ID under **Signing & Capabilities**.
   Aktivera **NFC Tag Reading** och **App Attest** i App ID/provisioneringsprofilen.
   Standard-ID är `se.openid.PassportCapture`. Samma team och bundle-ID ska
   anges på servern.
3. För en egen privat server: starta [pilotmiljön](../deployment/README.md) på en Linux-dator.
   Telefonen måste nå HTTPS-adressen och lita på certifikatet. För en privat
   test-CA behöver dess rot installeras och betros på telefonen.
4. Kör appen och välj **Öppna openID**. Nya installationer ansluts automatiskt
   till `https://api.openid.tensetti.io`, utan VPN eller kopplingskod.
   Sparad serverkonfiguration behålls för befintliga privata test-ID:n.
5. Välj **Registrera med ditt pass**. Välj **Skanna passuppgifter** och rikta kameran mot kodraderna på fotosidan.
   Kontrollera de ifyllda uppgifterna. Manuell inmatning (datum ÅÅMMDD) finns kvar.
   Godkänn överföringen och läs chipet. Håll sedan
   telefonen mot passet igen när säkerhetskontrollen startar. Därefter tas
   tre kamerabilder: framåt och åt båda sidor. Följ ovalen och håll kvar tills
   respektive bild har tagits. NFC-kontrollen kräver kontakt med servern hela tiden.
6. Uppdatera **Mitt ID**. I det valda [TestFlight-testläget](../docs/testflight-beta.md)
   aktiveras test-ID:t automatiskt efter godkända kontroller, utan e-post.
   I standardläget väntar registreringen på ett separat
   [aktiveringsbeslut](../verification/README.md#aktivera-och-prova-inloggning).
   Prova sedan
   [QR-inloggningen](../verification/README.md#saml-inloggning-med-passets-identitet).

Debug använder App Attest `development` och en privat testserver med
`--development-attestation`. Release använder `production` så att ett
signerat bygge för registrerade telefoner kan använda den publika betan.
Miljön styrs av `APP_ATTEST_ENVIRONMENT` i projektgeneratorn. Installation
från Xcode kräver Apple-signering men ingen App Store-publicering.
TestFlight använder alltid produktionsmiljön. Betaservern tillåter automatisk
anslutning endast med produktionsattestering. Kontrollera den exporterade
appens entitlement och provisioneringsprofil före installation; byggläge
ensamt är inget attestbevis. Se [Apples miljöbeskrivning](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.devicecheck.appattest-environment).

## Funktioner

Appen följer iPhones inställning för ljust eller mörkt utseende, även när
systemet byter automatiskt. Bakgrunder, text, formulärpaneler, kontrollkod,
knappar och felmeddelanden har färger för båda lägena. ID-kortet och
kamerans överlägg behåller mörk bakgrund med ljus text. `PaletteTests`
kontrollerar färgbyte och minst 4,5:1 kontrast för de angivna textparen;
detta är inte en fullständig tillgänglighetsgranskning.

| Vy | Funktion |
|---|---|
| Mitt ID | Namn, passfoto, MRZ-födelsedatum och aktuell serverstatus. Status rensas vid låsning och nätverksfel. |
| Registrera | DG1/DG2/DG14/SOD, serverstyrd PACE och chipautentisering, tre AVFoundation-bilder och App Attest. Rådata sparas inte på telefonen; servern sparar en krypterad personprofil. |
| Legitimera | Tjänst, syfte, kontrollkod och giltighet visas före godkännande eller nekande. Ny lokal användarverifiering krävs. |
| QR och länkar | Endast `openid://request/<64 hextecken>`. Begäran hämtas från den konfigurerade servern. |
| Aktivitet | De 50 senaste serverhändelserna. |
| Inställningar | Anslutning, applås, permanent spärr och borttagning av en bekräftat spärrad nyckel. |

I den publika betan kan innehavaren spara en separat spärrkod under
Inställningar. Koden används av appen eller webbformuläret även när
verifieraren är stängd. Den måste ha hämtats före avbrottet och sparats utanför
telefonen för att fungera vid förlust. Privata ID:n migreras inte automatiskt.
Ny telefon kräver ny registrering och aktivering enligt det valda testläget.
Se [avisering och spärr](../docs/avisering-och-sparr.md).

### Avbruten registrering och ny nyckel

| Lokalt och verifierat tillstånd | Tillåten åtgärd |
|---|---|
| Ingen nyckel | Skapa en ny enhetsnyckel och starta passregistreringen. |
| Nyckel men ingen hämtad serverstatus, även efter nätverksfel | Fortsätt registreringen med samma nyckel. Ingen automatisk radering eller aktivering sker. Servern nekar återregistrering av en redan registrerad nyckel. |
| Väntande, aktivt eller utgånget ID | Behåll nyckeln och spärrkoden. Spärra först; utgång räcker inte för borttagning. |
| Spärrat ID, bekräftat för rätt nyckel av verifieraren eller den separata spärrtjänsten | Ta bort den lokala nyckeln och påbörja ny pass- och ansiktskontroll. |

Innehavaren initierar spärren efter lokal användarverifiering. Serverns
spärrbeslut kan inte skapas av borttagningsknappen. Den separata tjänstens
bekräftelse gäller under den aktuella upplåsningen även om verifieraren är
otillgänglig. Efter låsning hämtas status eller bekräftas spärren igen.
Om Keychain inte kan radera nyckeln behålls spärrkoden och appens tillstånd.
Ett misslyckat statusanrop får inte dölja fortsatt registrering.

`WalletRecoveryTests` provar återförsök med samma nyckel, förbud mot borttagning
före spärr, låsning, fel vid nyckelradering och ny nyckel efter bekräftad spärr.
XCUITest öppnar det riktiga passformuläret efter simulerat statusfel och provar
borttagningsflödet. Testerna använder syntetisk lagring och ersätter inte
fysiska prov av Secure Enclave, NFC, biometri och serverns aktivering.

## Fotografering

Vision vägleder placering, avstånd, huvudvinkel och bildkvalitet. Tre bilder
krävs: framåt, höger och vänster. Förhandsbilden är speglad; skickade bilder
är ospeglade. Ovalens båda halvor lyser lila för frontbilden, sedan respektive
sida. Grönt bekräftar fångsten i 0,65 sekunder. Bildnummer visas separat.

Varje position kräver 0,45 sekunders hålltid och minst fyra godtagbara
observationer. Kort korrigering får pausa hållningen högst 0,25 sekunder
sammanlagt; pausen ger ingen framdrift. Fel sida, flera eller försvunna
ansikten, stora rörelser och längre avbrott återställer hållningen.
Aktuella trösklar finns i `PassportCapture/CaptureGuide.swift` och provas i
`CaptureGuideTests`. Kameraguiden visar fångstvillkor, inte verifierad identitet.

Registreringen visar riktningsoval, bildnummer och en aktuell instruktion.
**Inställningar → Prova ansiktskameran** visar även diagnostikindikatorer och
kastar bilderna efter det lokala provet. Inget serveranrop eller registrering sker.
Ordningen för de tre bilderna kommer från servern efter chipkontrollen
(`poses` i svaret, `CapturePose.sequence(server:)`). Servern kontrollerar App
Attest, bildunikhet, ansiktsjämförelse, PAD och att huvudet är vridet enligt
begärd ordning (landmärkesparallax), men inte ett sammanhängande rörelseförlopp.
Oberoende prov av film och injektion återstår.

### Säkerhetskod

En begäran med `verification: "pin"` visar ett kodfält; **Godkänn/Skriv under**
skickar koden tillsammans med enhetssignaturen, som fortfarande kräver Face ID
eller enhetskod. Koden väljs eller byts under **Inställningar → Säkerhetskod**
(byte kräver nuvarande kod). Fel kod håller begäran öppen och visar antal försök
kvar; spärrad kod kräver ny registrering. Servern avgör, appen avvisar bara
uppenbart svaga koder i förväg.

### Underskrift

En begäran med `signMessage` visas som **Begäran om underskrift** med hela
texten som ren text (`Text(verbatim:)`). Knappen **Skriv under** skickar
åtgärden `sign`; den vanliga godkännandeåtgärden avvisas för underskrifter,
även av servern, så en äldre app kan inte skriva under utan att visa texten.

## Nycklar och avbrott

P-256-nyckeln skapas med `SecureEnclave.P256.Signing.PrivateKey`,
`privateKeyUsage` och `userPresence`. Enhetskod och Secure Enclave krävs.
Omsluten nyckelrepresentation, serveradress och kopplingskod lagras i
Keychain med `WhenPasscodeSetThisDeviceOnly`, utan synkronisering.

App Attest binder publik nyckel och registreringsunderlag till sessionen.
Servern får ingen separat hårdvaruattestering av Secure Enclave-nyckeln.
Face ID/Touch ID bekräftar nyckelanvändning; jämförelsen med passporträttet
sker på servern.

Första NFC-läsningen hämtar dokumentfiler med NFCPassportReader. Den andra
vidarebefordrar serverns APDU-kommandon med CoreNFC. Servern behåller PACE-/CA-
nycklarna och verifierar chipets svar. Klienten tillåter bara SELECT, READ
BINARY, MSE, GENERAL AUTHENTICATE och GET RESPONSE, högst 128 kommandon.
Stöd: PACE ECDH-GM/AES och CA version 1 ECDH/AES; andra profiler avvisas.

Appen döljs när scenen är inaktiv och låses i bakgrunden. Pågående uppgifter
och LAContext avbryts, och sena nätverkssvar ignoreras. En redan skickad
begäran kan ha nått servern; hämta status efter återkomst.

Låsning rensar även väntande länkar och kodfel. Inmatade säkerhetskoder rensas
när kodvyn lämnas eller appen låses. Ett fördröjt statusanrop efter kodspärr
får inte fortsätta in i en ny upplåsning. Registreringen kontrollerar avbrott
efter Apples nyckel-/attesteringsanrop innan nästa nätverks- eller NFC-steg.
En pågående NFC-läsning kan fortfarande behöva avslutas i systemrutan;
resultatet får inte skickas vidare efter avbrott.

`WalletHTTP` hanterar alla appens serveranrop, även separat spärr, med HTTPS,
exakt svarsadress, JSON och nekade omdirigeringar. Svar begränsas under
strömning till 256 KiB för verifieraren och 4 KiB för spärrtjänsten.
Överföringen avbryts även vid fel i svarshuvud eller storlek. Diskcache och
cookiehantering är avstängda. Negativa URL-laddningsprov använder testdubblar;
de ersätter inte TLS-prov mot vald miljö.

Inställningar visar den installerade appens version och byggnummer. Använd
detta tillsammans med källrevision, IPA-kontrollsumma och signerad profil vid
ett [fysiskt acceptansprov](../docs/fysisk-acceptans.md).

## Bygg och testa

```sh
python3 ios/scripts/project.py
xcodebuild -resolvePackageDependencies -project ios/PassportCapture.xcodeproj -scheme PassportCapture -onlyUsePackageVersionsFromResolvedFile
xcodebuild -project ios/PassportCapture.xcodeproj -scheme PassportCapture -configuration Release -destination 'generic/platform=iOS' -disableAutomaticPackageResolution CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO build
xcodebuild -project ios/PassportCapture.xcodeproj -scheme PassportCapture -destination 'platform=iOS Simulator,name=iPhone 16 Pro' CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO test
```

Projektfilen är incheckad. CI kontrollerar att generatorn `project.py` och
beroendeupplösningen lämnar projekt och låsfil oförändrade.

XCTest provar bindningen mellan visad begäran och signerade bytes, inklusive
byte av motpart, syfte, kod, nyckel, session och ursprung. XCUITest provar
SwiftUI-vyerna. Workflow `iPhone app` sparar testresultat och en
simulatorskärmbild i artefakten `iphone-app-evidence`.
`ChipRelayTests` provar kommandogränser, ordningsnummer och avvisade
skrivkommandon. NFC-sessionernas övergång och tidsgräns måste provas på telefon.
`CaptureGuideTests` provar positioner, stabilitet, tidsluckor, flera ansikten,
saknade mätvärden, låg kvalitet och upprepad sidovinkel. Kameravyn provas i
XCUITest med en separat simulatorfixtur, endast kompilerad i Debug/simulator.
CI sparar även `openID-capture-guide.png`. Fixturen öppnar ingen kamera och
kan inte registrera en identitet.

Simulatorn kan inte testa pass-NFC, Secure Enclave eller Apple App Attest.
Privat telefonprov har bekräftat passläsning, personnummer och SAML-inloggning.
Den nya separata spärrfunktionen behöver fortfarande ett sammanhängande telefonprov.

## Kvar att verifiera

Biometrisk/PAD-kalibrering, modellrättigheter, certifikatspärr, registerkontroll
och oberoende granskning återstår; se [verifierarens
begränsningar](../verification/README.md#begränsningar).
Appen utfärdar ingen godkänd e-legitimation. Myndighetsanslutning och pushnotiser
ingår inte. Underskriftsflödet ovan är en testfunktion utan kvalificerad
underskrift eller betrodda långtidsbevis. [Appens säkerhetsunderlag](../docs/iphone-sakerhet.md)
knyter kontroller till GAP-punkter och skiljer dem från kvarstående beslut.

## Kamerainläsning och fel i registreringen

VisionKit läser kodraderna lokalt med DataScannerViewController. Passnummer,
födelsedatum och utgångsdatum fylls i först när en entydig TD3-rad med
korrekta kontrollsiffror och kalenderdatum har hittats. Ingen OCR-bild sparas
eller skickas. Kontrollsiffrorna är formatkontroller; äktheten avgörs fortsatt
av serverns signatur-, hash- och chipkontroll. Utökade passnummer och andra
MRZ-format kräver separat stöd; manuell inmatning finns kvar.

NFC-rutan visar svenska instruktioner och procent för den aktuella datadelen,
inte för hela registreringen. Efter läsning visas ett kvitto på att uppgifterna
har lästs. Om kontrollen misslyckas visar vyn stoppsteget och **Börja om**;
formuläret öppnas inte automatiskt med en missvisande stegindikator.

`PassportMRZTests` använder endast genererade kodrader och provar giltig rad,
fel kontrollsiffra, ogiltigt datum, flera möjliga pass och ofullständig text.
Fysisk OCR, NFC och övergång till andra chipläsningen behöver provas på telefon.

API-underlag: [Apples DataScanner-delegate](https://developer.apple.com/documentation/visionkit/datascannerviewcontrollerdelegate)
(kontrollerat 2026-10-21).

Efter de två chipläsningarna väljer användaren **Starta ansiktskontrollen**.
Passet kan då läggas undan innan kameran startar. Serverns sessionsgränser gäller
även under väntan. Kameraavbrott och analysfel visas med avgränsade felkoder.

## Status och återkoppling

Efter upplåsning hämtas status automatiskt. Under hämtningen visas ett neutralt
vänteläge. En misslyckad statushämtning visas i vyn med anslutningsråd och
knappen **Hämta status**, utan en modal varning direkt efter Face ID.
Avbruten lokal autentisering ger ingen felruta. Efter godkännande eller nekande
visas en bekräftelse under Legitimera. Ett godkännande innebär inte att
webbtjänsten har slutfört inloggningen. Vid osäkert resultat av en skrivande
åtgärd uppmanas användaren att kontrollera status och Aktivitet innan nytt försök.
Utgångna begäranden går inte att godkänna eller neka från bekräftelsevyn.

**Neka begäran** respektive **Avböj underskrift** ligger fast längst ned i
bekräftelsevyn, även med lång text eller öppet kodtangentbord. Nekande kräver
ingen säkerhetskod. **Stäng** lämnar bara vyn; använd nekandevalet för att
avböja hos tjänsten. Under ett pågående beslut och efter utgång är båda
beslutsvalen inaktiva.

## Begriplighet och tillgänglighet

Ett aktivt ID visar **Legitimera mig** som huvudhandling. Under Legitimera
är QR-skanning huvudvalet; länkinmatning finns i **Öppna en länk i stället**.
Appen läser inte urklippet automatiskt. Samma-telefon-flödet förutsätter att
tjänsten går att nå på telefonen; den lokala labbsidan kräver dator och QR-kod, medan betans testsida
kan nås via publik HTTPS.

Passformuläret har beständiga fältnamn, datumexempel, valbara förberedelser
och ett lokalt kameraprov. Saknade eller felaktigt formaterade uppgifter
markeras först när användaren väljer Läs passet. Fokus flyttas till första
fältet som behöver ändras; inga nätverks-/NFC-anrop görs då. Samma
formatvalidering används för hjälpen och chipets åtkomstnyckel. Datumexempel
innebär inte att ett århundrade härleds från passets tvåsiffriga årtal.

Vid tillgänglighetsstorlek staplas identitetskortets innehåll. Kontrollkoden
visas på två rader och läses siffra för siffra, inklusive inledande nollor.
Kamerans instruktion flyttas under förhandsvisningen vid stor text utan att
ändra bildutsnitt, huvudvinklar eller säkerhetskrav. QR-vyn går att rulla.

Detta är förbättringar för provning, inte ett påstående om full tillgänglighet.
Fulla språkversioner, fysisk VoiceOver-provning, alternativ till huvudrörelser
och stödd fysisk minsta enhetsmodell återstår. Simulatorns testfixturer för
layout finns endast i Debug och kan inte aktiveras i Release.

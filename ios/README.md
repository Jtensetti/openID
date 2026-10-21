# openID för iPhone

SwiftUI-app med Mitt ID, Legitimera, Aktivitet och Inställningar.
Appen använder [verifieringsservern](../verification/README.md).

## Öppna i Xcode

Från repots rot:

```sh
open ios/PassportCapture.xcodeproj
```

1. Använd **Xcode 16.4**, schemat **PassportCapture** och en ansluten
   iPhone med iOS 16 eller senare. Swift Package Manager hämtar de låsta
   beroendena.
2. Välj Apple-utvecklingsteam och bundle-ID under **Signing & Capabilities**.
   Aktivera **NFC Tag Reading** och **App Attest** i App ID/provisioneringsprofilen.
   Standard-ID är `se.openid.PassportCapture`. Samma team och bundle-ID ska
   anges på servern.
3. Starta [pilotmiljön](../deployment/README.md) på en Linux-dator.
   Telefonen måste nå HTTPS-adressen och lita på certifikatet. För en privat
   test-CA behöver dess rot installeras och betros på telefonen.
4. Kör appen, välj **Öppna openID** och därefter **Anslut till servern**.
   Ange adress och kopplingskod från serverterminalen.
5. Välj **Registrera med ditt pass**. Välj **Skanna passuppgifter** och rikta kameran mot kodraderna på fotosidan.
   Kontrollera de ifyllda uppgifterna. Manuell inmatning (datum ÅÅMMDD) finns kvar.
   Godkänn överföringen och läs chipet. Håll sedan
   telefonen mot passet igen när säkerhetskontrollen startar. Därefter tas
   tre kamerabilder: framåt och åt båda sidor. Följ ovalen och håll kvar tills
   respektive bild har tagits. NFC-kontrollen kräver kontakt med servern hela tiden.
6. Uppdatera **Mitt ID**. Registreringen väntar på ett separat
   [aktiveringsbeslut](../verification/README.md#aktivera-och-prova-inloggning).
   Prova sedan
   [QR-inloggningen](../verification/README.md#saml-inloggning-med-passets-identitet).

App Attest-entitlement är `development`; använd serverflaggan
`--development-attestation` för detta bygge. Installation från Xcode kräver
Apple-signering men ingen App Store-publicering. TestFlight/distribution
ingår inte i byggkonfigurationen.

## Funktioner

| Vy | Funktion |
|---|---|
| Mitt ID | Namn, passfoto, MRZ-födelsedatum och aktuell serverstatus. Status rensas vid låsning och nätverksfel. |
| Registrera | DG1/DG2/DG14/SOD, serverstyrd PACE och chipautentisering, tre AVFoundation-bilder och App Attest. Rådata sparas inte på telefonen; servern sparar en krypterad personprofil. |
| Legitimera | Tjänst, syfte, kontrollkod och giltighet visas före godkännande eller nekande. Ny lokal användarverifiering krävs. |
| QR och länkar | Endast `openid://request/<64 hextecken>`. Begäran hämtas från den konfigurerade servern. |
| Aktivitet | De 50 senaste serverhändelserna. |
| Inställningar | Anslutning, applås, permanent spärr och borttagning av spärrad/utgången nyckel. |

Förlorad telefon spärras av operatören. Ny telefon kräver ny registrering
och aktivering. Aktivering för samma pass spärrar den äldre nyckeln.

## Fotografering

Vision kontrollerar att ett enda ansikte syns samt dess placering, storlek, huvudvinkel
och bildkvalitet
på telefonen. Första bilden tas framifrån. Användaren väljer sedan sida; sista
bilden kräver motsatt huvudvridning. Förhandsvisningen är speglad, skickade
bilder är ospeglade och stående. Ringen runt ovalen visar hur långt fotograferingen har kommit.

Varje position kräver minst 0,65 sekunders stabilitet och sex observationer.
Avbrott över 0,3 sekunder nollställer tiden för den aktuella positionen. Fotograferingen
avbryts efter
45 sekunder, vid avbrott eller kamerafel. Bilderna lämnar inte kameraflödet
förrän alla tre har tagits; ingen partiell serie skickas.

Bilden framifrån tillåter högst 8 graders vridning; sidobilder cirka 15–34 grader.
Pitch/roll begränsas till cirka 13 grader. Visions kvalitetsvärde ska vara
minst 0,25. Detta är startvärden för kameraguiden och behöver provas på
fysiska enheter, inklusive sidobilder, glasögon och olika ljusförhållanden.

Ringen visar fotograferingens förlopp, inte verifierad identitet eller liveness. Servern
kontrollerar fortfarande App Attest, bildunikhet, ansiktsjämförelse och PAD
för alla tre bilderna. Den verifierar inte huvudrörelsernas förlopp. Skydd mot
film, deepfake och kamerainjektion behöver separat utvärdering.

Vid överbelastning ber appen dig vänta och uppdatera status. Den skickar
inte automatiskt om godkännanden. Efter nätverksavbrott ska status hämtas
innan registrering eller annan åtgärd försöks igen.

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
Den fysiska integrationen återstår att prova på en signerad iPhone-installation.

## Kvar att verifiera

Biometrisk/PAD-kalibrering, modellrättigheter, certifikatspärr, registerkontroll
och oberoende granskning återstår; se [verifierarens
begränsningar](../verification/README.md#begränsningar).
Appen utfärdar ingen godkänd e-legitimation. Myndighetsanslutning,
dokumentunderskrift och pushnotiser ingår inte.

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

### Övergång till ansiktskameran och lokalt prov

Efter de två chipläsningarna väljer användaren **Starta ansiktskontrollen**.
Det ger utrymme att lägga undan passet och avsluta NFC-rutan innan kameran
startar. Serverns befintliga sessionsgränser gäller även under väntan.

Kamerakonfigurationen lägger till inmatningen före videoutmatningen och
slutför sessionens konfiguration innan videoanslutningens orientering ställs in.
Kameraavbrott, startfel och analysfel visas med en avgränsad steg-/sifferkod;
inga bilder eller passuppgifter ingår i feltexten.

**Inställningar → Prova ansiktskameran** kör samma fotograferingsguide lokalt,
utan pass, serveranrop eller registrering. Bildresultatet kastas efter provet.
Bakgrundsläge och navigering bort avbryter kameran. Ett lyckat kameraprov
är inte en identitetskontroll eller ett test av serverns bildanalys.

Kameraguiden visar korrigeringen direkt i bilden och en ram runt det upptäckta ansiktet. Indikatorerna Avstånd, Centrering, Vinkel och Bild visar vilka fångstvillkor som är uppfyllda. Sidovyer skiljer mellan för liten och för stor vridning. Dessa indikatorer är fångsthjälp, inte identitets- eller livenessgodkännande.

Kameraguiden tillåter små naturliga rörelser: 0,45 sekunders hålltid med minst fyra godtagbara observationer, centrumavvikelse högst 0,14 och lutning högst 0,30 radianer. Stora rörelser och avvisade observationer nollställer fortfarande aktuell hålltid. Gränserna för sidovridning, ansiktsstorlek och bildkvalitet är oförändrade. Fysisk användbarhetskalibrering återstår.

Riktningsguiden visar båda halvorna lila för frontbild, höger halva för högerbild och vänster för vänsterbild. Varje fångst bekräftas grönt i 0,65 sekunder innan nästa instruktion. Bildnummer visas separat. Kamerans obearbetade bild är ospeglad; förhandsbilden är speglad. Riktningarnas koppling till Vision-yaw måste även provas fysiskt.

En kort korrigering av bildkvalitet, centrering eller liten vinkelavvikelse kan pausa hållningen. Högst 0,25 sekunders sammanlagd paus tillåts per hållning; paustid ger ingen framdrift. Försvunnet/flera ansikten, ogiltiga mätvärden, fel sida, stora rörelser och längre avbrott återställer hållningen. Endast en aktuell godtagbar bild får tas.

Registreringens kameravy visar endast riktningsoval, pil/bekräftelse, bildnummer och en aktuell instruktion. Ansiktsram och upprepad stegrad är borttagna. De fyra diagnostikindikatorerna visas endast i Inställningar → Prova ansiktskameran. Fångstlogik och trösklar är oförändrade.

## Status och återkoppling

Efter upplåsning hämtas status automatiskt. Under hämtningen visas ett neutralt
vänteläge. En misslyckad statushämtning visas i vyn med anslutningsråd och
knappen **Hämta status**, utan en modal varning direkt efter Face ID.
Avbruten lokal autentisering ger ingen felruta. Efter godkännande eller nekande
visas en bekräftelse under Legitimera. Ett godkännande innebär inte att
webbtjänsten har slutfört inloggningen. Vid osäkert resultat av en skrivande
åtgärd uppmanas användaren att kontrollera status och Aktivitet innan nytt försök.
Utgångna begäranden går inte att godkänna eller neka från bekräftelsevyn.

## Begriplighet och tillgänglighet

Ett aktivt ID visar **Legitimera mig** som huvudhandling. Under Legitimera
är QR-skanning huvudvalet; länkinmatning finns i **Öppna en länk i stället**.
Appen läser inte urklippet automatiskt. Samma-telefon-flödet förutsätter att
tjänsten går att nå på telefonen; pilotens localhost-sida kräver fortfarande
Mac och QR-kod.

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

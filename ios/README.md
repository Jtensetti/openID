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
3. Starta servern enligt [instruktionerna](../verification/README.md#appens-privata-pilotregister).
   Telefonen måste nå HTTPS-adressen och lita på certifikatet. För en privat
   test-CA behöver dess rot installeras och betros på telefonen.
4. Kör appen, välj **Öppna openID** och därefter **Anslut till servern**.
   Ange adress och kopplingskod från serverterminalen.
5. Välj **Registrera med ditt pass**. Ange passnummer, födelsedatum och
   utgångsdatum (ÅÅMMDD), godkänn överföringen och läs chipet. Håll sedan
   telefonen mot passet igen när säkerhetskontrollen startar. Därefter tas
   tre kamerabilder: framåt och åt båda sidor. Följ ovalen och håll kvar tills
   respektive bild har tagits. NFC-kontrollen kräver kontakt med servern hela tiden.
6. Uppdatera **Mitt ID**. Registreringen väntar på ett separat
   [aktiveringsbeslut](../verification/README.md#aktivera-och-prova-inloggning).
   Prova sedan [QR-inloggningen](../verification/README.md#saml-inloggning-med-passets-identitet).

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

## Kamerafångst

Vision kontrollerar ett ansikte, placering, storlek, huvudvinkel och bildkvalitet
på telefonen. Första bilden tas framifrån. Användaren väljer sedan sida; sista
bilden kräver motsatt huvudvridning. Förhandsvisningen är speglad, skickade
bilder är ospeglade och stående. Ovalen visar fångstförloppet.

Varje position kräver minst 0,65 sekunders stabilitet och sex observationer.
Avbrott över 0,3 sekunder nollställer pågående hålltid. Fångsten avslutas efter
45 sekunder, vid avbrott eller kamerafel. Bilderna lämnar inte kameraflödet
förrän alla tre har tagits; ingen partiell serie skickas.

Rakt fram tillåter högst 8 graders vridning; sidobilder cirka 15–34 grader.
Pitch/roll begränsas till cirka 13 grader. Visions kvalitetsvärde ska vara
minst 0,25. Detta är startvärden för fångstguidning och behöver provas på
fysiska enheter, inklusive sidobilder, glasögon och olika ljusförhållanden.

Ringen visar bildfångst, inte verifierad identitet eller liveness. Servern
kontrollerar fortfarande App Attest, bildunikhet, ansiktsjämförelse och PAD
för alla tre bilderna. Den verifierar inte huvudrörelsernas förlopp. Skydd mot
film, deepfake och kamerainjektion behöver separat utvärdering.

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
och oberoende granskning återstår; se [verifierarens begränsningar](../verification/README.md#begränsningar).
Appen utfärdar ingen godkänd e-legitimation. Myndighetsanslutning,
dokumentunderskrift och pushnotiser ingår inte.

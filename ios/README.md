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
   utgångsdatum (ÅÅMMDD), godkänn överföringen och läs chipet. Därefter tas
   tre kamerabilder.
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
| Registrera | PACE/BAC, DG1/DG2/DG14/SOD, chipautentisering, tre AVFoundation-bilder och App Attest. Rådata sparas inte på telefonen; servern sparar en krypterad personprofil. |
| Legitimera | Tjänst, syfte, kontrollkod och giltighet visas före godkännande eller nekande. Ny lokal användarverifiering krävs. |
| QR och länkar | Endast `openid://request/<64 hextecken>`. Begäran hämtas från den konfigurerade servern. |
| Aktivitet | De 50 senaste serverhändelserna. |
| Inställningar | Anslutning, applås, permanent spärr och borttagning av spärrad/utgången nyckel. |

Förlorad telefon spärras av operatören. Ny telefon kräver ny registrering
och aktivering. Aktivering för samma pass spärrar den äldre nyckeln.

## Nycklar och avbrott

P-256-nyckeln skapas med `SecureEnclave.P256.Signing.PrivateKey`,
`privateKeyUsage` och `userPresence`. Enhetskod och Secure Enclave krävs.
Omsluten nyckelrepresentation, serveradress och kopplingskod lagras i
Keychain med `WhenPasscodeSetThisDeviceOnly`, utan synkronisering.

App Attest binder publik nyckel och registreringsunderlag till sessionen.
Servern får ingen separat hårdvaruattestering av Secure Enclave-nyckeln.
Face ID/Touch ID bekräftar nyckelanvändning; jämförelsen med passporträttet
sker på servern.

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
SwiftUI-vyerna. Workflow `iPhone capture build` sparar testresultat och en
simulatorskärmbild i artefakten `iphone-app-evidence`.

Simulatorn kan inte testa pass-NFC, Secure Enclave eller Apple App Attest.
Den fysiska integrationen återstår att prova på en signerad iPhone-installation.

## Kvar att verifiera

Biometrisk/PAD-kalibrering, modellrättigheter, certifikatspärr, registerkontroll
och oberoende granskning återstår; se [verifierarens begränsningar](../verification/README.md#begränsningar).
Appen utfärdar ingen godkänd e-legitimation. Myndighetsanslutning,
dokumentunderskrift och pushnotiser ingår inte.

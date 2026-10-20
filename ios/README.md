# iPhone-klient för pass och personkontroll

Öppna `PassportCapture.xcodeproj` i Xcode 16.4 eller kompatibel senare version.
Välj ditt Apple-utvecklingsteam och ett registrerat bundle-ID. Samma team-ID
och bundle-ID måste konfigureras på verifieringsservern. Aktivera NFC Tag
Reading och App Attest för App ID/provisioneringsprofilen.

Anslut din iPhone till Mac, välj telefonen som destination och kör appen.
Simulatorn kan bygga gränssnittet men kan inte utföra pass-NFC eller riktig
App Attest. App Store behövs inte för detta utvecklingstest. Signering och
provisionering kan inte ersättas med en osignerad IPA eller en PWA.

Appen använder iOS 16+, CoreNFC, AVFoundation, CryptoKit och DeviceCheck.
Det finns ingen egen kryptografisk primitiv. Den läser chipdata med den
revisionslåsta NFCPassportReader-komponenten och kräver chipautentisering.
Den skickar endast data till operatörens angivna HTTPS-server, med vanlig
systemvalidering av TLS och utan omdirigeringar. För en privat test-CA måste
dess betrodda rot installeras och uttryckligen betros på telefonen.

`PassportCapture.entitlements` använder App Attests **development**-miljö.
Servern behöver då `--development-attestation`. Produktionsattestering
kräver separat korrekt signerad konfiguration; det är inte ett godkännande
att utfärda e-legitimation.

Ange serveradress utan avslutande snedstreck, den tillfälliga kopplingskoden,
passnummer, födelsedatum och sista giltighetsdatum (ÅÅMMDD). Starta flödet,
håll telefonen mot passet och titta därefter mot kameran. Tre bilder tas med
minst 0,8 sekunders mellanrum. Hela paketet binds till serverns nonce och
signeras med App Attest. Appen har ingen bildimport, bildsparning eller
molnanalys. Uppgifter hålls i processminnet; egen loggning av pass/biometri
finns inte. Upstream använder OSLog, vars privata värden inte ska aktiveras
eller exporteras vid persondatatester.

Appen avbryter vid bakgrundsläge och skickar inte vidare ett senare NFC-svar
från en avbruten uppgift. Kameran stoppas vid avbrott, fel och slutförd fångst.
Ett nytt försök får en ny serverutmaning och ny App Attest-nyckel.

CI bygger iOS-målet utan signering:

```sh
xcodebuild -resolvePackageDependencies -project ios/PassportCapture.xcodeproj -scheme PassportCapture -onlyUsePackageVersionsFromResolvedFile
xcodebuild -project ios/PassportCapture.xcodeproj -scheme PassportCapture -configuration Release -destination 'generic/platform=iOS' -disableAutomaticPackageResolution CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO build
```

NFC/PACE/CA, Apple-attestering, kamera och ett verkligt pass måste därefter
testas tillsammans på fysisk telefon. Byggresultat ensamt bevisar inte detta.

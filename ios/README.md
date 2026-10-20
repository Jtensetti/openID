# openID för iPhone – öppna i Xcode

En sammanhållen SwiftUI-app med **Mitt ID, Legitimera, Aktivitet och Inställningar**.
Pass/NFC, kamerafångst, App Attest, Secure Enclave, Keychain, QR-läsning och
serveranrop är implementerade. Ingen skärmbild eller framgångssida ersätter
serverns svar. Appen används med den privata pilotservern i `verification/`.

## Imorgon: öppna och kör

1. Hämta branchen `feat/g4-complete-ios-app` från detta repo:

   ```sh
   git clone https://github.com/Jtensetti/openID.git
   cd openID
   git switch feat/g4-complete-ios-app
   open ios/PassportCapture.xcodeproj
   ```

2. Använd **Xcode 16.4**, välj schemat **PassportCapture** och din anslutna
   iPhone (iOS 16 eller senare). All källkod och projektfilen är redan klara
   att öppna; inget behöver klistras in i Xcode. Beroendena hämtas via Swift
   Package Manager enligt den incheckade låsfilen.
3. Under **Signing & Capabilities**, välj ditt Apple-utvecklingsteam och ett
   registrerat bundle-ID. Aktivera **NFC Tag Reading** och **App Attest** i
   App ID/provisioneringsprofilen. Samma team- och bundle-ID anges på servern.
   Standard-ID är `se.openid.PassportCapture`. App Store behövs inte för
   detta utvecklingstest, men Apple-signering/provisionering behövs.
4. Starta verifieringsservern enligt [serverinstruktionerna](../verification/README.md#appens-privata-pilotregister).
   För en privat test-CA: installera och betro dess rot på telefonen. Ingen
   TLS-kontroll kopplas bort i appen. Telefonen måste kunna nå HTTPS-adressen.
5. Kör appen, välj **Öppna openID**, bekräfta med Face ID/Touch ID/enhetskod
   och välj **Kom igång**. Ange serverns adress och den tillfälliga
   kopplingskod som skrivs i serverterminalen.
6. Välj **Registrera med ditt pass**. Ange passnummer, födelsedatum och
   utgångsdatum (ÅÅMMDD), godkänn överföringen och läs chipet. Tre nya
   kamerabilder tas efter NFC-läsningen. Passkontroll och jämförelse körs på
   din konfigurerade server.
7. Hämta aktuell status under **Mitt ID**. Efter lyckade tekniska kontroller
   väntar registreringen på ett separat operatörsbeslut. Pilotens
   [aktiverings- och inloggningskommandon](../verification/README.md#aktivera-och-prova-inloggning)
   driver det verkliga appflödet mot lokal testtjänst.

Appens App Attest-entitlement är **development**. Starta servern med
`--development-attestation` för denna signerade utvecklingsinstallation.
TestFlight/distribution använder en annan attesteringsmiljö och ingår inte
i detta utvecklingsbygge. Ingen app har laddats upp till App Store.

## Funktioner

- **Mitt ID:** aktuell serverstatus, registrering och uppdatering. Ingen
  sparad status används för att hävda att ett ID är aktivt efter omstart
  eller nätverksfel.
- **Registrera:** PACE/BAC, DG1/DG2/DG14/SOD, obligatorisk chipautentisering,
  tre AVFoundation-bilder och App Attest över hela underlaget inklusive
  telefonens publika nyckel. Avbrott eller bakgrundsläge stoppar fortsatta
  uppladdningar. Passuppgifter och bilder sparas inte av appen.
- **Legitimera:** hämtar väntande begäranden, visar tjänst, avsikt,
  kontrollkod och återstående tid. Godkänn/neka kräver ny lokal
  användarverifiering. Exakt dessa värden kontrolleras innan signering.
- **QR och länkar:** accepterar endast `openid://request/<64 hextecken>`.
  Appen hämtar begäran från den redan konfigurerade servern; QR-koden kan
  inte byta server, öppna en extern webbplats eller godkänna automatiskt.
- **Aktivitet:** visar upp till 50 faktiska serverhändelser.
- **Inställningar:** anslutning/kopplingskod, manuell applåsning, permanent
  spärr, borttagning av redan spärrad/utgången nyckel och väg för ny telefon.
  Förlorad telefon spärras av operatören, därefter krävs ny registrering.

## Nycklar och tillitsgränser

En P-256-nyckel skapas med Apples `SecureEnclave.P256.Signing.PrivateKey`,
`privateKeyUsage` och `userPresence`. Enhetskod krävs. Ingen mjukvarureserv
finns för enheter utan Secure Enclave. Den omslutna nyckelrepresentationen,
serveradressen och kopplingskoden lagras i Keychain med
`WhenPasscodeSetThisDeviceOnly` och utan synkronisering. Det är inte en
exporterbar privat nyckel eller en återställningsbackup.

App Attest binder publik nyckel och registreringsunderlag till appens
session. Servern får inte separat hårdvaruattestering av just denna
Secure Enclave-nyckel; den egenskapen måste bedömas tillsammans med
klientintegriteten. Face ID/Touch ID jämför inte mot passporträttet; de
bekräftar användarnärvaro för nyckelanvändning. Passjämförelsen sker separat.

Appen döljer innehåll när scenen är inaktiv, låser vid bakgrundsläge och
ogiltigförklarar pågående uppgifter/LAContext. Sena nätverkssvar kan inte
låsa upp appen, fylla tillbaka status eller starta en ny godkännandebegäran.
En redan skickad begäran kan ha nått servern innan ett avbrott; hämta
serverstatus efter återkomst. Ingen påhittad lokal framgång visas.

## Bygge, tester och skärmbild

```sh
python3 ios/scripts/project.py
xcodebuild -resolvePackageDependencies -project ios/PassportCapture.xcodeproj -scheme PassportCapture -onlyUsePackageVersionsFromResolvedFile
xcodebuild -project ios/PassportCapture.xcodeproj -scheme PassportCapture -configuration Release -destination 'generic/platform=iOS' -disableAutomaticPackageResolution CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO build
xcodebuild -project ios/PassportCapture.xcodeproj -scheme PassportCapture -destination 'platform=iOS Simulator,name=iPhone 16 Pro' CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO test
```

`project.py` är en liten incheckad generator utan egna paketberoenden.
Projektet är redan genererat. CI kontrollerar att regenerering inte ändrar
projektet och att Swift-låsfilen inte ändras vid upplösning.

XCTest kontrollerar bl.a. byte av motpart, avsikt, kod, nyckelreferens,
session och ursprung före signering. XCUITest kör verkliga SwiftUI-skärmar.
Workflow `iPhone capture build` sparar `iphone-app-evidence` med testresultat
och **en faktisk skärmbild från iPhone-simulatorn**, utan personuppgifter.

Simulatorn kan köra gränssnittet och programlogik men inte utföra riktig
pass-NFC, Secure Enclave-nyckelanvändning eller Apple App Attest. Fysisk
integration testas med din signerade app och telefon, inte genom att
ersätta dessa kontroller med framgångssvar.

## Omfattning

Detta är hela appklienten och en fungerande privat pilotkedja för enhets-
autentisering. Civil identitet, godkänd e-legitimation, anslutning till
myndigheter, dokumentunderskrift, pushnotiser och App Store-distribution
är inte levererade egenskaper. SAML/WebAuthn-spåret från Sweden Connect
finns kvar separat. Liveness-/ansiktsgränser, modelllicenser, certifikatspärr,
registerkontroll och oberoende granskning har kvar sina tidigare öppna frågor.

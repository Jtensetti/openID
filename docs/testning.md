# Testning

## Senast verifierad appintegration

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
| Pass | Bouncy Castle/JMRTD/JCA mot genererad CSCA, DSC, SOD, MRZ och bild. Fel signatur, hash, ankare, datum och format nekas. | Ingen myndighetsutfärdad testhandling eller certifikatspärrtjänst. |
| Bildmodeller | Låsta OpenCV- och MiniFASNet-vikter, modellinferens och felhantering. | Ingen mätning av biometrisk träffsäkerhet eller attackmotstånd. |
| App Attest | Verifiering av signatur, appbindning, räknare och ändrade bytes. | Ingen fysisk Apple-attestering i CI. |
| Register | Verklig SQLite, AES-GCM och ECDSA; samtidighet, spärr, ersättning och krypteringsfel. | Samma OS-konto; ingen HSM eller produktionsrestore. |
| SAML/webbläsare | Separata verifierar-, IdP- och SP-processer, signerade/krypterade meddelanden och Chromium. | NFC, kamera, App Attest och biometriska poäng är testdubblar i helkedjefixturen. |
| WebAuthn | Riktig browser-API och Yubico-validering med virtuella USB-/plattformsautentiserare. | Inga fysiska nycklar eller OS-installationsprov. |
| iOS | Bygge, signerade bytes, tillstånd och SwiftUI i simulator. | NFC, Secure Enclave, Face ID och App Attest måste provas på telefon. |
| Drift | Hälsoroutes och stängda e-id-routes över HTTP samt containerisolering i CI. | Containern innehåller ingen e-id-tjänst. |

## Negativa säkerhetsfall

- Fel signatur, mottagare, ursprung, session eller signerad avsikt.
- Återspelning, dubbla godkännanden och konkurrerande konsumtion.
- Nekande, avbrott, utgång och spärr före och efter inloggning.
- Ersatt enhetsnyckel, registeravbrott och stale sessionsvärden.
- Manipulerad profil, utbytt ciphertext och saknad/fel krypteringsnyckel.
- Klientangivna identitetsfält, NaN/oändliga modellvärden och felaktiga meddelanden.
- CSRF, annan webbläsare, externa callbacks, proxyhuvuden och överstora anrop.

## Kör lokalt

- [Pass, modeller, register och federation](../verification/README.md#tester).
- [SAML, WebAuthn, lagring och återläsning](../prototype/README.md#tester-och-beroenden).
- [iOS-bygge och simulator](../ios/README.md#bygg-och-testa).
- [Driftcontainerns HTTP-prov](../ops/README.md#kör-lokalt).

Linux med Unix-sockets krävs för federationsproven. Xcode kräver macOS;
simulatorn ersätter inte fysisk iPhone-verifiering. Testloggar och artefakter
får inte innehålla verkliga handlingar, bilder, tokens eller privata nycklar.

## Tidigare verifieringsrapporter

[SAML](../prototype/evidence/verification.md),
[beständig lagring](../prototype/evidence/g2-verification.md) och
[WebAuthn](../prototype/evidence/web-verification.md) dokumenterar tidigare
revisioner. Deras testantal och scope gäller respektive daterade körning.
Maskinläsbara rapporter bevaras för spårbarhet.

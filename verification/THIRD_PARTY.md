# Komponenter och verifieringsgränser

Kontrollerat 2026-10-19. Befintliga Sweden Connect-, Yubico- och BC-beroenden
redovisas i repots [THIRD_PARTY.md](../THIRD_PARTY.md). Inga egna
kryptografiska primitiver eller generativa identitetsmodeller införs.

| Komponent | Låsning och faktisk användning | Licens/underhåll |
|---|---|---|
| JMRTD | 0.8.9 från Maven Central; DG1/DG2/SOD-parsning. JAR SHA-256 `89959d0c8cb8cf7b93699b18d135675a7b8760489bddd924ee3174c447fa5409` | Källhuvud LGPL-2.1-or-later; release i Maven-metadata 2026-10-03. Fullständig passkontroll och trust management ingår inte i bibliotekets löfte. |
| Scuba Smartcards | 0.0.21, transitivt från JMRTD, hash i Maven-låset | LGPL enligt POM. Ingen NFC-serveranslutning; modeller/format används av JMRTD. Förvaltnings-/SLA-garanti saknas. |
| EJBCA cert-cvc | 1.4.13, transitivt från JMRTD, hash i Maven-låset | LGPL-2.1 enligt POM. Ingen modifiering. |
| Bouncy Castle | Befintlig 1.86 | Befintlig MIT-liknande BC-licens. CMS och X.509, ingen egen signaturmotor. |
| OpenCV Python | 4.13.0.92, exakt Linux-hjulhash i `requirements.lock` | Apache-2.0, med hjulens bevarade tredjepartslicenser. |
| YuNet / SFace | OpenCV Zoo commit `47534e27c9851bb1128ccc0102f1145e27f23f98`; modellhashar i `face.py` och `download_models.py` | YuNet MIT, SFace Apache-2.0 enligt respektive modellkatalog. Zoo ej arkiverat, senaste push 2026-05-28. |
| MiniFASNet V2 + V1SE | Upstream `b6d5f04ad78778917853b25c778acef6d5626d15`; båda viktfilerna SHA-256-kontrolleras före `torch.load(weights_only=True)` | Apache-2.0. Upstreams senaste commit 2020-08-05: tydlig underhållsrisk. Ingen påstådd ISO/PAD-certifiering. |
| PyTorch CPU / NumPy | Exakta versioner och hjulhashar i `requirements.lock` | BSD-3-Clause, plus inbäddade licenser i hjulen. Ingen CUDA eller modellnedladdning vid körning. |
| node-app-attest | 1.0.1, npm-integritet och transitiva versioner i `package-lock.json`; granskat upstream `f16c4bb71b737466872bc8b8a7dfd215364eaa83` | MIT. ASN1js, PKIjs, cbor och övriga transitiva licenser behålls i paketen. |
| NFCPassportReader | `6e37f1ab249fef82771da46d32707f2b94ed090f` (upstream 2026-07-28) | MIT, Andy Qua. NFC/PACE/CA, endast i iPhone-klienten. |
| OpenSSL-Package | 3.6.5000, commit `4ac3f9a68731cb3cf736a591814bad9a7a2008c8`; binär SHA-256 `f50188506490c643715489217d32e458d06cee5579399ff616f0ce2038169fea` | Apache-2.0; upstream Package.swift och LICENSE lästa. Swift-låset begränsar NFC-bibliotekets annars flytande versionsintervall. |

`vendor/minifas/MiniFASNet.py` och `generate_patches.py` är oförändrade
upstreamfiler vid ovanstående revision. Attribution till Minivision och
ursprungliga filhuvuden är bevarade; Apache-licensen finns i `licenses/`.
Vikter hämtas separat med låst revision och checksumma och checkas inte in.
MRZ-checksiffrehanteringen i iPhone-klienten är en anpassning av Andy Quas
MIT-licensierade `PassportUtils`; iPhone-katalogen innehåller licensen.

Modellkatalogens licensdeklaration är inte en fullständig rättighetsutredning
för träningsdata. OpenCV Zoo [issue #313](https://github.com/opencv/opencv_zoo/issues/313)
har fortfarande öppna frågor om SFace-vikternas träningsdata och kommersiella
användning. Ingen kommersiell rättighetsgaranti eller produktionsdistribution
görs i denna PR. Projektets egen licens är fortsatt ett separat ägarbeslut;
inga nya Apache-villkor läggs på projektets egen kod.

## Granskade integrationsdetaljer

- MiniFASNet-kommentaren beskriver 0–1 men den faktiska `to_tensor`-koden
  använder 0–255. Vår inferens följer koden, BGR och beskärningsskalorna 2,7/4,0.
- `node-app-attest` kontrollerar signaturkedja och protokollfält men inte
  certifikatdatum. Wrappern kräver aktuell giltighet, två certifikat med en
  CA samt exakt ett CBOR-objekt. Assertions kräver 37 bytes authData och
  strikt ökande räknare. Bibliotekets kryptografiska kontroll ersätts inte.
- Inga utvecklingsattesteringar accepteras utan explicit serverflagga.
- App Attest skapar ett Apple-beroende i just iPhone-fångsten. Befintlig
  WebAuthn-inloggning kräver fortfarande ingen obligatorisk appbutik eller
  Apple-identitet. Oberoende registreringsalternativ återstår.
- Python-låset avser Python 3.12 på Linux x86_64. Andra plattformar behöver
  separat låsning/verifiering, inte en tyst uppluckring av hashkravet.

## Källor

- [JMRTD:s avgränsning](https://jmrtd.org/), [0.8.9 källartefakt](https://repo.maven.apache.org/maven2/org/jmrtd/jmrtd/0.8.9/jmrtd-0.8.9-sources.jar).
- [OpenCV 4.13 ansikts-API](https://docs.opencv.org/4.13.0/d0/dd4/tutorial_dnn_face.html).
- [OpenCV Zoo](https://github.com/opencv/opencv_zoo/tree/47534e27c9851bb1128ccc0102f1145e27f23f98).
- [MiniFASNet](https://github.com/minivision-ai/Silent-Face-Anti-Spoofing/tree/b6d5f04ad78778917853b25c778acef6d5626d15).
- [NFCPassportReader](https://github.com/AndyQ/NFCPassportReader/tree/6e37f1ab249fef82771da46d32707f2b94ed090f).
- [Apple: validera anslutande appar](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server).
- [NIST SP800-63A-4: proofing](https://pages.nist.gov/800-63-4/sp800-63a/ial-general/), tekniskt underlag, inte Digg-godkännande.

Versions- och advisorykontroll finns i `dependency-audit.json` och
`npm-audit.json`. Uppdateringsägare föreslås vara repoägaren Jtensetti,
att bekräfta. Oberoende säkerhetsgranskning, biometrisk/PAD-kalibrering,
dataskyddsbedömning och beslut om verklig utgivning är inte utförda här.

## App-plånbok, 2026-10-19

Den sammanhållna SwiftUI-appen använder Apples systemramverk SwiftUI,
Foundation, CryptoKit/Secure Enclave, Security/Keychain, LocalAuthentication,
CoreNFC, DeviceCheck och AVFoundation via Xcode 16.4. Inga nya externa
runtimepaket eller modellvikter införs i denna etapp. NFC-/OpenSSL-versioner
är oförändrade och låsta i `ios/PassportCapture.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved`.

Serverns enhetssignaturer verifieras med Node 24.19.0 `node:crypto`
(createPublicKey/verify), SHA-256 och standard DER/SPKI för P-256.
Python 3.12:s sqlite3, hashlib och secrets används för beständighet,
standardhashar och slumputmaningar. Ingen egen kryptografisk primitiv.
DB och application-protokollets konkreta användning är egen kod som kräver
granskning; detta är inget nytt standardiserat SAML/OIDC-protokoll.

Primärkällor kontrollerade 2026-10-19:
- https://developer.apple.com/documentation/cryptokit/secureenclave/p256/signing/privatekey
- https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave
- https://developer.apple.com/documentation/security/secaccesscontrolcreateflags
- https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly
- https://developer.apple.com/documentation/localauthentication/lacontext/invalidate()
- https://nodejs.org/docs/latest-v24.x/api/crypto.html

CI använder GitHubs `actions/upload-artifact` **v4.6.2**, full commit
`ea165f8d65b6e75b540449e92b4886f43607fa02`, MIT. Taggreferens och LICENSE
kontrollerade i `actions/upload-artifact` samma datum. Den används endast
för simulatorbild och XCTest-resultat utan persondata, med 14 dagars
retention. Workflowbehörigheter är fortsatt `contents: read`; inga Apple-
eller produktionsnycklar läggs i CI. Projektgeneratorn är egen Pythonkod
utan externa beroenden. Projektlicensen är fortsatt obeslutad.

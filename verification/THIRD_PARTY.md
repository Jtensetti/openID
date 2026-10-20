# Komponenter och verifieringsgränser

Kontrollerat 2026-10-19. Befintliga Sweden Connect-, Yubico- och BC-beroenden
redovisas i repots [THIRD_PARTY.md](../THIRD_PARTY.md).

| Komponent | Låsning och faktisk användning | Licens/underhåll |
|---|---|---|
| JMRTD | 0.8.9 från Maven Central; LDS-parsning, serverstyrd PACE/CA och Secure Messaging. JAR SHA-256 `89959d0c8cb8cf7b93699b18d135675a7b8760489bddd924ee3174c447fa5409` | Källhuvud LGPL-2.1-or-later; release i Maven-metadata 2026-10-03. Fullständig passkontroll och trust management ingår inte i bibliotekets löfte. |
| Scuba Smartcards | 0.0.21, transitivt från JMRTD, hash i Maven-låset. APDU- och TLV-format samt `CardService` för serverns NFC-transport. | LGPL enligt POM. Förvaltnings-/SLA-garanti saknas. |
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
användning. Kommersiella modellrättigheter behöver därför utredas före distribution.
Projektets egen licens är inte beslutad.

## Granskade integrationsdetaljer

- MiniFASNet-kommentaren beskriver 0–1 men den faktiska `to_tensor`-koden
  använder 0–255. Inferensen följer koden, BGR och beskärningsskalorna 2,7/4,0.
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
`npm-audit.json`. Förvaltningsansvar och releasekrav finns i
[rotens komponentregister](../THIRD_PARTY.md#projektlicens-och-förvaltning)
och [SECURITY.md](../SECURITY.md).

## App och enhetssignaturer

Den sammanhållna SwiftUI-appen använder Apples systemramverk SwiftUI,
Foundation, CryptoKit/Secure Enclave, Security/Keychain, LocalAuthentication,
CoreNFC, DeviceCheck och AVFoundation via Xcode 16.4. NFC-/OpenSSL-versioner
är låsta i `ios/PassportCapture.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved`.

Serverns enhetssignaturer verifieras med Node 24.19.0 `node:crypto`
(createPublicKey/verify), SHA-256 och standard DER/SPKI för P-256.
Python 3.12:s sqlite3, hashlib och secrets används för beständighet,
standardhashar och slumputmaningar. Appens registrerings- och godkännande-API
är projektspecifikt och beskrivs i [arkitekturen](../docs/arkitektur.md).

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
för simulatorbild, XCTest-resultat, kapacitetsmätning och paketinventering
utan persondata, med 14 dagars
retention. Workflowbehörigheter är fortsatt `contents: read`; inga Apple-
eller produktionsnycklar läggs i CI. Projektgeneratorn är egen Pythonkod
utan externa beroenden.

## QR

`qrcode` **8.2** används endast för servergenererade SVG-koder. Officiellt
repository: [lincolnloop/python-qrcode](https://github.com/lincolnloop/python-qrcode/tree/3704f57a1107dbf553a50f5b531da3859abe19cf).
Tagg `v8.2` pekar via annoterad tagg på commit
`3704f57a1107dbf553a50f5b531da3859abe19cf`. Repositoryt var inte arkiverat,
senaste push 2026-03-25. [PyPI-versionen](https://pypi.org/project/qrcode/8.2/)
publicerades 2025-05-01 och var inte återkallad vid kontrollen.

Det installerade rena Python-hjulets SHA-256 är
`16e64e0716c14960108e85d853062c9e8bba5ca8252c0b4d0231b9df4060ff4f`,
låst i `rp-requirements.lock`. Inga extras väljs: SVG kräver varken Pillow
eller pypng. Inga transitiva runtimeberoenden installeras på målplattformen
Linux/Python 3.12. Windows-villkoret för colorama omfattas inte av vårt lås
eller plattformsstöd.

Upstreams [LICENSE](https://github.com/lincolnloop/python-qrcode/blob/3704f57a1107dbf553a50f5b531da3859abe19cf/LICENSE)
är BSD-3-Clause med ursprunglig MIT-attribution till Kazuhiko Arase.
Fullständig licenstext/attribution bevaras i `licenses/qrcode-LICENSE` och
i paketet. Ingen bibliotekskod modifieras. GitHubs automatiska
licensklassificering var NOASSERTION; bedömningen ovan utgår från filen.

OSV-frågan för exakt version gav inga publicerade fynd 2026-10-19, sparat i
`rp-dependency-audit.json`; PyPI rapporterade också en tom sårbarhetslista.
Det är ingen fullständig säkerhetsrevision. `rp-sbom.cdx.json` förtecknar
detta enda tillkommande paket, inte hela verifierarens befintliga graf.
QR-koden identifierar den begäran som appen hämtar och godkänner.

## Serverstyrd chipkontroll, 2026-10-20

JMRTD **0.8.9** återanvänds utan versionsbyte eller modifiering. Maven Centrals
metadata anger fortsatt 0.8.9 som release. Källartefaktens SHA-256 är
`a3065ec0891c3cd8e57b8c39f9073bb003bd8f417439803aff8f676169ede908`.
`PACEProtocol`, `EACCAProtocol`, `PassportService` och Secure Messaging lästes
i denna källartefakt; licenshuvudena anger LGPL-2.1-or-later. Biblioteket
sköter nyckelöverenskommelse, nyckelderivering, kryptering och MAC-kontroll.
Den egna transporten begränsar och vidarebefordrar APDU-meddelanden.

CoreNFC:s `NFCTagReaderSession` och `NFCISO7816Tag.sendCommand` används för
transporten i iPhone. NFCPassportReader behålls oförändrad för första
dokumentläsningen. Inga nya runtimeberoenden införs; Maven-/Swift-lås och
SBOM gäller samma artefakter. Mjukvaruchippet finns enbart i Java-testkoden.

## Personprofil och SAML, 2026-10-20

Sweden Connect `spring-authentication-server`
**1.0.3** återanvänds via `AbstractUserRedirectAuthenticationProvider`;
[senaste upstreamrelease](https://github.com/swedenconnect/spring-authentication-server/releases/tag/v1.0.3)
kontrollerades 2026-10-20 och var fortsatt 1.0.3 (publicerad 2026-10-13).
Apache-2.0, revision, transitiva licenser och JAR-hashar finns i rotens
komponentregister och befintliga Maven-lås.

Profilkryptering använder Node **24.19.0** `node:crypto` AES-256-GCM.
Dokumentreferenser och tjänstesubjekt använder Python 3.12 `hmac`/SHA-256
med separat nyckel. De befintliga OpenCV- och qrcode-versionerna används
för passfotots storlek respektive QR.


## Pilotens HTTP-server och container

Gunicorn **26.2.0** låses med hjulhash i `runtime-requirements.lock`.
Basinstallationen har inga transitiva paketberoenden. MIT-licens och NOTICE
finns i `licenses/gunicorn-*`; paket-SBOM i `runtime-sbom.cdx.json`.
[Upstream](https://github.com/benoitc/gunicorn) var inte arkiverat vid kontrollen
2026-10-20; senaste push 2026-09-06. Den daterade OSV-kontrollen i
`runtime-audit.json` gav inga fynd för den valda versionen. Det är ingen
säkerhetsbedömning av den egna integrationen.

[Gunicorns inställningar](https://gunicorn.org/reference/settings/) och
[ändringslogg](https://gunicorn.org/news/) ligger till grund för körmiljön.
HTTP/2, proxyprotokoll, kontrollsocket och automatiska omstarter efter ett
visst antal anrop används inte. NFC-sessionerna tillhör en enda worker.

`deployment/Dockerfile` låser officiella Python **3.12.15 slim-bookworm**,
Node **24.19.0 bookworm-slim** och befintliga Temurin **21.0.12.1+1** med
image-digests, avlästa från Docker Registry 2026-10-20. Python har PSF-licens,
Node MIT med tredjepartslicenser och Temurin GPL-2.0 med Classpath Exception.
Basimagens Debian-licenser, JRE:s `legal/` och Nodes LICENSE bevaras.
Maven 3.9.11 hämtas som samma SHA-256-låsta ZIP som wrappern; hela grafens
180 beroendehashar kontrolleras även i containerbygget. Bildvikter och
Python-/npm-paket hämtas enbart vid bygge med befintliga lås. CI inventerar
installerade Python-paket. OS-paket täcks av imagen, inte paket-SBOM:erna.

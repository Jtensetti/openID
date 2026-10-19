# Pass, ansiktsjämförelse, liveness och iPhone-fångst

Detta är verkliga verifieringskomponenter, inte ett simulerat godkännandeflöde.
Ingen e-legitimation utfärdas av arbetsytan. SAML/WebAuthn-labben är fortsatt
separat och dess identitetskontroll ändras inte.

## Körning på Linux x86_64

Kräver Java 21, Python 3.12, Node 24 och ett betrott CSCA-certifikatpaket
som operatören har hämtat och kontrollerat från en auktoritativ källa.
Certifikatet i en uppladdad SOD är **inte** ett tillitsankare. Skärmbilder från
ReadID räcker inte för kryptografisk verifiering.

Från repots rot:

```sh
cd prototype
./mvnw -B -ntp clean verify
cd ../verification
python3.12 -m venv .venv
.venv/bin/pip install --require-hashes --only-binary=:all: -r requirements.lock
npm ci --ignore-scripts
.venv/bin/python download_models.py
.venv/bin/python server.py --csca /privat/sokvag/trusted-csca.pem
```

Öppna `http://localhost:8765`. Ange ursprungliga EF.SOD, DG1 och DG2 från en
NFC-läsare och öppna kameran. Den signerade DG2-bilden extraheras på servern;
klienten kan inte välja ett separat referensporträtt. Filerna bearbetas i
minnet och skickas inte till externa verifieringstjänster. Kameran stoppas
efter fångst, när sidan döljs och när användaren stänger den. Servern lagrar
inga underlag eller begärandeloggar. Operativsystemets swap/kraschdumpar är
inte säkrade av applikationen; kör endast på en betrodd dator.

## iPhone: NFC → kamera → attesterat underlag

Se [iPhone-instruktionerna](../ios/README.md). Den native klienten använder
NFCPassportReader för PACE/BAC, DG1/DG2/SOD/DG14 och chipautentisering.
Klienten kräver lyckad chipautentisering, tar tre bilder direkt från
AVFoundation och signerar exakt payload med App Attest. Ingen bildimport
eller bildbiblioteksbehörighet finns.

För en privat nätverkstestserver krävs ett HTTPS-certifikat som iPhone
litar på. Ingen certifikatkontroll kopplas bort. Exempel med operatörens
egna värden (ingen publik produktionsdrift):

```sh
.venv/bin/python server.py \
  --native --team DITTTEAMID --bundle se.openid.PassportCapture \
  --development-attestation \
  --bind 192.168.1.20 --origin https://192.168.1.20:8765 \
  --tls-cert /privat/server.pem --tls-key /privat/server-key.pem \
  --csca /privat/trusted-csca.pem
```

Servern skriver en tillfällig kopplingskod till operatörens terminal.
Skriv in adress och kod i appen. I nätverksläget är webbsidan och endpointen
som lämnar ut kopplingskoden avstängda. HTTPS, rätt Host, Origin och koden
krävs för alla native-anrop. Koden gäller bara denna serverprocess.
Utvecklingsattestering måste tillåtas uttryckligen; utan flaggan krävs
Apples produktionsmiljö för App Attest. Detta är inte ett Digg-beslut.

Servern kontrollerar App Attest-certifikat, app-ID, signatur, räknare,
engångsutmaning, session och exakt payload före pass-/bildanalys. En session
kan slutföras en gång; fel och timeout förbrukar den. Max 16 väntande
sessioner, fem minuters giltighet, alla försvinner vid omstart. Attestering
sker per registreringsförsök i denna version; återanvändning av appnycklar
och Apples kvoter behöver hanteras inför bredare drift.

## Vad resultatet betyder

- **Pass:** Bouncy Castle CMS-signatur, JCA PKIX direkt DSC→konfigurerad CSCA,
  aktuella certifikatdatum, SHA-256/384/512 och exakta DG1/DG2-hashar.
  JMRTD tolkar MRZ/porträtt. TD3-pass, ett porträtt och giltighetsdatum
  inom dagens datum till 20 år framåt. Äldre algoritmer, länkcertifikat,
  historiskt giltiga men nu utgångna DSC och andra dokumentprofiler stöds
  inte. Certifikatspärr/CRL kontrolleras ännu inte.
- **Ansikte:** YuNet-detektion och SFace 1:1-inferens. Exakt ett tillräckligt
  stort ansikte krävs. Ingen LLM, identifiering i register eller egen tränad modell.
- **Liveness:** MiniFASNet V2 och V1SE med upstreams beskärningar och
  BGR-pixelvärden 0–255. Båda nätverken körs på CPU. Detta är faktisk RGB-PAD,
  men ingen certifierad detektionsnivå eller garanti mot alla angrepp.
- **Injektion/återspelning:** native-fångst utan import, App Attest och
  payload-/sessionsbindning. App Attest intygar appinstans och signerade data,
  inte kamerans fysiska verklighet. Komprometterad enhet, relä, avancerad
  bildinjektion, masker och modellomgångar behöver adversariell utvärdering.
- **Chipautentisering:** körs av NFC-biblioteket på iPhone. Servern tar emot
  ett App Attest-skyddat resultat, inte ett självständigt verifierbart
  CA-transkript. Passiv autentisering ensam bevisar inte ett levande chip.

Native-resultatets `checksPassed` använder experimentella gränser 0,5 för
ansiktslikhet och 0,8 för PAD på **alla tre** bilder. Dessa är inte kalibrerade
för svensk passutgivning. Resultatet hålls åtskilt från utgivning:
`issuanceEnabled` är alltid false. Ingen återställnings-/supportgenväg
eller bindning till en riktig WebAuthn-identitet införs här.

## Automatiserade tester

Alla pass-/nyckelfixturer genereras för tester; riktiga personuppgifter
läggs aldrig i repo eller CI. Testfixturer ersätter inte kodens verifierare.

```sh
cd prototype
./mvnw -B -ntp clean verify -Dproofing.fixtureDirectory=/tmp/openid-proofing-fixtures
cd ../verification
export PROOFING_FIXTURES=/tmp/openid-proofing-fixtures
export PROOFING_JAVA="$JAVA_HOME/bin/java"
export PROOFING_PYTHON="$PWD/.venv/bin/python"
.venv/bin/python -m unittest -v test_verification test_native
node --test test-attest.mjs
node browser-test.cjs
```

Webbläsartestet använder den tidigare låsta Playwright-installationen i
`prototype/` (`npm ci --ignore-scripts` och `npx --no-install playwright install chromium --only-shell`).
Det testar verklig kamera-API med Chromium-testkamera, kamerastopp, mobil
layout, ingen extern trafik, ingen webblagring och verklig verifieringskedja
som nekar ett ogiltigt porträtt. Modelltester visar att de faktiska graferna
körs, **inte** uppmätt biometrisk träffsäkerhet eller PAD-robusthet.

Berör ID-05/ID-06, tillitsgränser och supply chain. Kravstatus höjs inte till
accepterad. Läs även [komponentgranskningen](THIRD_PARTY.md).

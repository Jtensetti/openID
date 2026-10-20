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
.venv/bin/pip install --require-hashes --only-binary=:all: -r rp-requirements.lock
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
.venv/bin/python -m unittest -v test_verification test_native test_wallet test_relying_party
node --test test-attest.mjs
node browser-test.cjs
node rp-browser-test.cjs
```

Webbläsartestet använder den tidigare låsta Playwright-installationen i
`prototype/` (`npm ci --ignore-scripts` och `npx --no-install playwright install chromium --only-shell`).
Det testar verklig kamera-API med Chromium-testkamera, kamerastopp, mobil
layout, ingen extern trafik, ingen webblagring och verklig verifieringskedja
som nekar ett ogiltigt porträtt. Modelltester visar att de faktiska graferna
körs, **inte** uppmätt biometrisk träffsäkerhet eller PAD-robusthet.

Berör ID-05/ID-06, tillitsgränser och supply chain. Kravstatus höjs inte till
accepterad. Läs även [komponentgranskningen](THIRD_PARTY.md).

## Appens privata pilotregister

Den kompletta [Xcode-appen](../ios/README.md) använder även `wallet.py`.
Databasen innehåller publik enhetsnyckel, ett slumpmässigt pilotsubjekt,
registreringsstatus, kortlivade inloggningsbegäranden och säkerhetshändelser.
Den innehåller inga passnummer, bilder, namn eller ansiktsmallar.

Skapa en privat katalog utanför repot. Ange den när verifieraren startas:

```sh
mkdir -m 700 /privat/openid-pilot
.venv/bin/python server.py \
  --native --team DITTTEAMID --bundle se.openid.PassportCapture \
  --development-attestation \
  --bind 192.168.1.20 --origin https://192.168.1.20:8765 \
  --tls-cert /privat/server.pem --tls-key /privat/server-key.pem \
  --csca /privat/trusted-csca.pem \
  --wallet-db /privat/openid-pilot/wallet.sqlite
```

En ny serverprocess får en ny kopplingskod. Uppdatera koden i appens
Inställningar utan att byta server/nyckel. Både kopplingskoden och en giltig
enhetssignatur krävs för wallet-anrop; kopplingskoden ensam kan aldrig
aktivera, legitimera eller spärra ett ID. Ingen admin-endpoint exponeras.

### Aktivera och prova inloggning

Efter godkänd NFC-/kamera-/attesteringskedja visas `PENDING_REVIEW`.
Modellresultat aktiverar aldrig nyckeln. En operatör gör ett separat
beslut för **enbart denna privata tekniska pilot**. Det är ingen verifierad
civil identitet eller godkänd e-id-utgivning. Kommandot nedan ger giltighet
i 24 timmar (max 72) och kräver en icke personlig beslutsreferens.

```sh
.venv/bin/python wallet_cli.py --db /privat/openid-pilot/wallet.sqlite pending
.venv/bin/python wallet_cli.py --db /privat/openid-pilot/wallet.sqlite activate CREDENTIAL_ID --decision REVIEW-private-001 --private-pilot-only
.venv/bin/python wallet_cli.py --db /privat/openid-pilot/wallet.sqlite request CREDENTIAL_ID
```

`CREDENTIAL_ID` är registreringsreferensen i appens Inställningar eller
`pending`-utskriften. Testtjänstens `request`-kommando ger begärans-ID,
kontrollkod och en hemlighet för att hämta resultatet. Behåll hemligheten i
den lokala operatörsterminalen. Den skickas aldrig till iPhone-appen.

I appen: uppdatera Mitt ID, gå till **Legitimera**, hämta begäran, kontrollera
samma kod och godkänn. Hämta resultatet i testtjänsten med:

```sh
.venv/bin/python wallet_cli.py --db /privat/openid-pilot/wallet.sqlite consume REQUEST_ID
```

Klistra därefter in `secret` via standard input (inte som kommandoargument).
Resultatet är `PENDING` eller ett engångsresultat `AUTHENTICATED`, med
`audience=openid-local-demo` och `assurance=PRIVATE_PILOT`. Fel, nekat val,
utgång, spärr eller upprepad konsumtion ger inget inloggningsresultat.
Det är en lokal testmotpart, inte en anslutning till Sweden Connect.

En QR-kod kan innehålla `openid://request/REQUEST_ID`. Koden är bara ett
sätt att välja en redan existerande begäran; appen kontrollerar dess ägare
och detaljer via sin fasta server innan användaren får godkänna.

För förlorad telefon, spärra via den lokala operatörskanalen:

```sh
.venv/bin/python wallet_cli.py --db /privat/openid-pilot/wallet.sqlite revoke CREDENTIAL_ID
```

Spärr är permanent och stoppar även godkända men ännu inte konsumerade
inloggningar. Ny telefon kräver ny nyckel, ny pass-/personkontroll och nytt
beslut. Det finns ingen återaktivering eller e-poståterställning.

### Tillstånd och säkerhetsmodell

| Från | Händelse och behörighet | Till |
|---|---|---|
| Ingen nyckel | Attesterat underlag med publik nyckel och passerade tekniska kontroller | PENDING_REVIEW |
| PENDING_REVIEW | Lokal operatörsaktivering inom 24 timmar efter kontrollen | ACTIVE |
| ACTIVE | Giltighetstiden passerar | EXPIRED |
| Valfritt befintligt tillstånd | Signerad spärr eller lokal operatörsspärr | REVOKED |
| REVOKED / EXPIRED | Nytt försök att aktivera samma nyckel | Nekas |

Varje wallet-operation binder protokollversion, HTTPS-ursprung,
nyckelreferens, handling, begärans-ID, motpart, syfte, kontrollkod och
utgångstid. Servern lagrar exakt bytes som ska signeras. Klienten validerar
värdena mot det visade valet innan CryptoKit signerar; Node/OpenSSL gör
ECDSA-validering. En felaktig signatur förbrukar utmaningen. Utmaningar
försvinner vid omstart. Databastransaktioner serialiserar spärr, godkännande
och resultatkonsumtion, och status kontrolleras på nytt i varje led.

SQLite körs med full synkronisering och privat katalog/fil (0700/0600).
Databasen är inte krypterad av appen. Skydda disk, operatörskonto och
säkerhetskopior separat. **Återläsning av gamla databasfiler stöds inte:** en
rollback kan återställa gammal status; ett externt oföränderligt spärrankare
behövs innan sådan återställning får införas. Systemet är inte en
produktionslösning för rollseparation eller drift. Den lokala operatören
har faktisk kontroll över databasen. Ingen sådan egenskap döljs som två
knappar eller automatiskt godkännande.

Nya tester körs med `.venv/bin/python -m unittest -v test_wallet` och ingår
i CI. Nycklar för dessa tester genereras vid körning; inga verkliga pass
eller privata enhetsnycklar används. Testerna inkluderar verkliga signaturer,
HTTP-gränser, motparts-/handlingsbyte, replay, samtidighet och spärr.

## Logga in i testtjänsten via webbläsaren

Starta verifieraren med `--wallet-db` enligt ovan och aktivera pilotnyckeln
efter separat operatörsbeslut. Öppna en andra terminal på **samma dator**,
med samma operativsystemskonto och samma databasfil:

```sh
cd verification
.venv/bin/pip install --require-hashes --only-binary=:all: -r rp-requirements.lock
.venv/bin/python relying_party.py --db /privat/openid-pilot/wallet.sqlite
```

Öppna **http://localhost:8766** i datorns webbläsare. Kopiera appens
registreringsreferens från Inställningar, klistra in den och välj **Logga in
med openID**. I telefonen: **Legitimera → Skanna en QR-kod**, kontrollera tjänst
och kontrollkod, godkänn med enhetsnyckeln. Webbsidan visar därefter det lokala
pilotsubjektet. **Logga ut** avslutar webbsessionen. **Avbryt inloggningen**
stoppar även ett godkännande som ännu inte hämtats av testtjänsten.

Webbläsaren körs på datorn som har databasen; telefonen använder fortfarande
verifierarens privata HTTPS-adress på port 8765. Testtjänsten binder enbart
`127.0.0.1` och accepterar exakt `Host: localhost:8766` (eller vald `--port`).
Använd alltså `localhost`, inte IP-adressen i webbläsaren. Den här processen
är en lokal testmotpart med Python HTTPServer, **inte** en publik server eller
en Render-installation. Ingen nätverksproxy eller tunnel konfigureras.

### Sessions- och förtroendegränser

QR-koden innehåller endast `openid://request/REQUEST_ID`. RP-hemligheten
som kan konsumera resultatet stannar i serverprocessens minne. Webbsessionen
och CSRF-token byts vid lyckad inloggning; det gamla paret kan inte användas
igen. Inga namn, passnummer eller bilder lämnas till testtjänsten. Den
får samma slumpmässiga lokala pilotsubjekt för denna nyckel, inte en civil
identitet eller ett federerat SAML/OIDC-intyg.

| Tillstånd | Tillåten övergång och kontroll |
|---|---|
| READY | Rätt webbsession, CSRF och aktiv pilotnyckel får starta PENDING. |
| PENDING | Signerat appgodkännande + serverns RP-hemlighet konsumerar begäran en gång och byter session till AUTHENTICATED. |
| PENDING | Avbrott, nekat val, spärr eller 120 sekunders utgång stoppar konsumtion. |
| AUTHENTICATED | Varje `/poll` läser aktuell credential och subjektbindning i SQLite. Spärr/utgång/databasfel ger inget autentiserat svar. |
| Alla | Utloggning och högst 10 minuters absolut sessionslivstid tar bort sessionen. Omstart tappar alla webbsessioner. |

Webbsidan hämtar väntande begäran varje sekund och aktiv sessionsstatus
varannan sekund. Visningen kan därför ligga efter en spärr med pollintervallet
och nätverksfördröjningen; nästa serverkontroll nekar direkt. Nätverksfel,
dold flik och sidbyte tar bort framgångsvyn. Återkomst hämtar status på nytt.
Giltighetstiden begränsas även av nyckelns utgångstid. Vid timeout tas vyn
bort lokalt. Inga andra skyddade verksamhetsoperationer finns i testtjänsten.

Cookies är HttpOnly/SameSite=Strict. `Secure` används inte på denna avgränsade
loopback-HTTP-tjänst. Exakt Origin, Host och CSRF krävs för POST; korsande
Fetch Metadata, proxyhuvuden, dubbla JSON-fält, dubbla säkerhetshuvuden,
godtycklig callback och administrativa routes nekas. Svar är `no-store`,
CSP begränsar innehåll till den egna tjänsten, inga CDN:er används. Högst
64 sessioner hålls i minnet; begäranden och kroppsstorlekar begränsas.
Operativsystemets betrodda lokala konto förblir en förtroendegräns.

### Verifierat i denna etapp

`test_relying_party` innehåller 20 tester av riktiga SQLite-transaktioner,
Node/OpenSSL-signaturer och HTTP. De omfattar fel session/CSRF, annan
webbläsare, fel RP-hemlighet, återspelning, samtidig konsumtion, nekande,
utloggning före/efter godkännande, spärr efter inloggning, utgång, omstart,
databasfel och HTTP-gränser. Hela verifierarsviten har 61 Python-tester.

`rp-browser-test.cjs` kör Chromium mot den riktiga lokala HTTP-tjänsten.
Det avkodar den renderade QR-bilden med OpenCV, jämför appens kontrollkod,
signerar godkännanden med en tillfällig Node/OpenSSL-nyckel och provar
cookiesbyte, annan webbläsare, utloggning, nekande, avbrott, spärr,
nätverksavbrott/återanslutning, utgång, mobil layout och frånvaro av extern
trafik/webblagring. `RP_SCREENSHOT=/absolut/sokvag/bild.png` sparar en riktig
skärmbild. Fixturens kontrollkanal är enbart subprocessens stdin och den
skapar alltid en ny temporär DB; inga testgodkännanderoutes finns i tjänsten.

Testnyckeln ersätter telefonen i dessa automatiserade tester. De bevisar
inte fysisk NFC, Secure Enclave, Face ID eller Apple App Attest på användarens
iPhone. Berörda krav är ID-09/10, SEC-01/03, FED-02 och TEST-01; deras formella
status ändras inte. Oberoende granskning och fysisk iPhone-verifiering återstår.

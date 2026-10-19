# Passverifierare och testtjänst

Server för passkontroll, ansiktsjämförelse, liveness och iPhone-appens
pilotregister. Testtjänsten erbjuder QR-inloggning med appens enhetsnyckel.
SAML/WebAuthn-labben i `prototype/` körs separat.

## Körning på Linux x86_64

Kräver Java 21, Python 3.12, Node 24 och ett CSCA-certifikatpaket som
operatören har hämtat och kontrollerat från en auktoritativ källa.
Certifikat i en uppladdad SOD används inte som tillitsankare.

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

Öppna `http://localhost:8765`. Välj ursprungliga EF.SOD, DG1 och DG2 från en
NFC-läsare och öppna kameran. Servern extraherar referensporträttet ur
signerad DG2. Filer och kamerabild behandlas i minnet utan externa anrop.
Kameran stängs efter fångst, när sidan döljs eller när den stängs manuellt.
Detta analysgränssnitt registrerar ingen nyckel.

## Appens privata pilotregister

[iPhone-appen](../ios/README.md) läser passet, tar tre kamerabilder och binder
underlaget till telefonens publika nyckel med App Attest. Starta servern med
HTTPS och en privat databas utanför repot:

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

Byt adresser och sökvägar till din miljö. Telefonen måste lita på
HTTPS-certifikatet. Ange adressen och terminalens kopplingskod i appen.
Koden byts vid serveromstart. Uppdatera den under Inställningar utan att
byta server eller nyckel.

Nätverksläget stänger webbsidan och endpointen som lämnar kopplingskoden.
Native-anrop kräver rätt HTTPS/Host/Origin och kopplingskod.
`--development-attestation` tillåter utvecklingssignerade appar; annars krävs
Apples produktionsmiljö för App Attest.

Servern kontrollerar certifikatkedja, app-ID, signatur, räknare, session
och signerade bytes före pass- och bildanalys. Fångstsessioner gäller i fem
minuter, förbrukas även vid fel och försvinner vid omstart. Högst 16 får
vänta samtidigt. App Attest registreras på nytt för varje försök.

Registret sparar publik enhetsnyckel, slumpmässigt pilotsubjekt, status,
inloggningsbegäranden och säkerhetshändelser. Passnummer, bilder, namn och
ansiktsmallar sparas inte.

## Aktivera och prova inloggning

Godkända tekniska kontroller ger `PENDING_REVIEW`. En lokal operatör aktiverar
nyckeln separat för piloten. Standardgiltigheten är 24 timmar, högst 72.

```sh
.venv/bin/python wallet_cli.py --db /privat/openid-pilot/wallet.sqlite pending
.venv/bin/python wallet_cli.py --db /privat/openid-pilot/wallet.sqlite activate CREDENTIAL_ID --decision REVIEW-private-001 --private-pilot-only
```

`CREDENTIAL_ID` är registreringsreferensen i appens Inställningar eller
`pending`-utskriften. Använd en beslutsreferens utan personuppgifter.

Prova inloggningen i [webbgränssnittet](#logga-in-i-testtjänsten-via-webbläsaren)
eller via terminalen:

```sh
.venv/bin/python wallet_cli.py --db /privat/openid-pilot/wallet.sqlite request CREDENTIAL_ID
.venv/bin/python wallet_cli.py --db /privat/openid-pilot/wallet.sqlite consume REQUEST_ID
```

`request` ger begärans-ID, kontrollkod och en RP-hemlighet. Kontrollera och
godkänn begäran i appen. Klistra därefter in hemligheten på standard input
till `consume`; lägg den inte i kommandoargument. Resultatet är `PENDING`
eller ett engångsresultat `AUTHENTICATED` med
`audience=openid-local-demo` och `assurance=PRIVATE_PILOT`.
Avbrott, nekande, utgång, spärr och upprepad konsumtion nekas.

## Logga in i testtjänsten via webbläsaren

Kör i en andra terminal på samma dator och operativsystemskonto som
verifieraren, med samma databas:

```sh
cd verification
.venv/bin/python relying_party.py --db /privat/openid-pilot/wallet.sqlite
```

Öppna **http://localhost:8766** i datorns webbläsare. Klistra in appens
registreringsreferens och välj **Logga in med openID**. I appen: välj
**Legitimera → Skanna en QR-kod**, kontrollera tjänst och kod och godkänn.
Webbsidan visar pilotsubjektet. Avbryt stoppar även godkännanden som ännu
inte konsumerats; Logga ut avslutar sessionen.

Telefonen använder verifierarens HTTPS-adress på port 8765. Webbtjänsten
binder enbart `127.0.0.1` och accepterar `Host: localhost:8766` (eller vald
`--port`). Använd `localhost` i datorns webbläsare. Python HTTPServer och
HTTP-cookien utan Secure-flagga är avsedda för denna lokala testmiljö.

QR innehåller bara `openid://request/REQUEST_ID`; RP-hemligheten stannar i
serverminnet. Sessionscookie och CSRF-token byts vid inloggning.
Varje `/poll` läser aktuell spärr, giltighet och subjektbindning i SQLite.
Begäranden gäller i 120 sekunder, webbsessioner i högst tio minuter eller
till nyckelns utgång. Omstart tappar alla webbsessioner.

Sidan pollar väntande begäran varje sekund och aktiv session varannan sekund.
Spärr syns efter pollintervallet och nätverksfördröjningen; nästa
serverkontroll nekar direkt. Nätverksfel, dold flik och utgång rensar
framgångsvyn. Cookies är HttpOnly/SameSite=Strict och svar är `no-store`.
POST kräver exakt Origin, Host och CSRF. Proxyhuvuden, dubbla säkerhetshuvuden,
dubbla JSON-fält, externa callbacks och adminroutes nekas. Högst 64 sessioner
lagras i minnet. Sidan använder inga externa resurser eller webblagring.

## Spärr och lagring

Spärra från appen eller via operatörskanalen om telefonen är förlorad:

```sh
.venv/bin/python wallet_cli.py --db /privat/openid-pilot/wallet.sqlite revoke CREDENTIAL_ID
```

| Tillstånd | Övergång |
|---|---|
| PENDING_REVIEW | Operatörsbeslut inom 24 timmar efter kontrollen → ACTIVE. |
| ACTIVE | Giltighetstiden passerar → EXPIRED. |
| Alla befintliga tillstånd | Signerad spärr eller operatörsspärr → REVOKED. |
| REVOKED / EXPIRED | Samma nyckel kan inte aktiveras igen. Ny registrering krävs. |

Spärr stoppar även godkända men ännu inte konsumerade inloggningar.
Wallet-anrop kräver både kopplingskod och enhetssignatur. Signaturen binder
version, ursprung, nyckel, handling, begäran, motpart, syfte, kod och utgångstid.
Felaktig signatur förbrukar utmaningen. Utmaningar försvinner vid omstart.

SQLite serialiserar spärr, godkännande och konsumtion med full synkronisering.
Katalog och fil kräver 0700/0600. Databasen är inte krypterad av applikationen;
operatör, disk och säkerhetskopior måste skyddas separat.
**Återläsning av gamla databasfiler stöds inte**: den kan återställa en spärrad
nyckel. Ett externt spärrankare saknas. Inga adminfunktioner exponeras via HTTP.

## Kontroller

| Del | Kontroll |
|---|---|
| Pass | Bouncy Castle CMS, JCA PKIX direkt DSC→CSCA, aktuella certifikatdatum, SHA-256/384/512 och DG1/DG2-hashar. JMRTD läser MRZ och porträtt. |
| Dokumentprofil | TD3, ett porträtt, giltighetsdatum från idag till högst 20 år framåt. |
| Ansikte | YuNet-detektion och SFace 1:1-jämförelse. Exakt ett tillräckligt stort ansikte krävs. |
| Liveness | MiniFASNet V2 och V1SE på CPU, BGR och upstreams beskärningsskalor 2,7/4,0. |
| Fångst | App Attest binder session, bytes och publik nyckel. Appen har ingen bildimport. |
| Chip | iPhone kör PACE/BAC och chipautentisering via NFCPassportReader. |

Native-flödet kräver ansiktslikhet ≥0,5 och PAD ≥0,8 för alla tre bilder.
Passiva passkontroller, ansiktsjämförelse och liveness avgör inte utgivning;
`issuanceEnabled` är alltid false.

## Begränsningar

- Gränsvärden för ansiktslikhet och PAD är inte kalibrerade för e-id-utgivning.
  Motståndskraft mot masker, injektion och relä behöver utvärderas.
- App Attest styrker appinstans och signerade data, inte kamerans fysiska
  ursprung. Servern tar emot chipautentiseringens resultat, inte ett
  självständigt verifierbart CA-transkript.
- Certifikatspärr/CRL, länkcertifikat, äldre algoritmer och historiskt giltiga
  men nu utgångna DSC stöds inte.
- Statisk QR ger inget närhetsbevis. Apple-kvoter och återanvändning av
  App Attest-nycklar behöver hanteras inför bredare drift.
- Operatören kontrollerar databasen. Rollseparation, swap/kraschdumpar,
  dataskydd, modellrättigheter och oberoende granskning återstår.

Detta är en privat pilot utan godkänd e-id-utgivning eller federation.
Se [komponentregistret](THIRD_PARTY.md) för versioner och licenser.

## Tester

Fixturer och nycklar genereras vid körning. Inga verkliga pass används i CI.

```sh
cd prototype
./mvnw -B -ntp clean verify -Dproofing.fixtureDirectory=/tmp/openid-proofing-fixtures
npm ci --ignore-scripts
npx --no-install playwright install chromium --only-shell
cd ../verification
export PROOFING_FIXTURES=/tmp/openid-proofing-fixtures
export PROOFING_JAVA="$JAVA_HOME/bin/java"
export PROOFING_PYTHON="$PWD/.venv/bin/python"
.venv/bin/python -m unittest -v test_verification test_native test_wallet test_relying_party
node --test test-attest.mjs
node browser-test.cjs
node rp-browser-test.cjs
```

Python-testerna omfattar passkedja, modellinferens, sessionsbindning,
signaturer, återspelning, samtidighet, spärr, utgång, omstart, databasfel
och HTTP-gränser. Modellinferens mäter inte biometrisk träffsäkerhet.

Chromium-testerna provar kamerastopp, verifieringsfel, avkodning av
renderad QR, kontrollkod, signerat godkännande, sessionsbyte, annan webbläsare,
utloggning, nekande, avbrott, spärr, offline/återanslutning och mobil layout.
`RP_SCREENSHOT=/absolut/sokvag/bild.png` sparar QR-vyn.
RP-fixturen använder en temporär databas och testnyckel; styrningen går via
stdin och inga HTTP-testvägar läggs till.

Fysisk NFC, Secure Enclave, Face ID och Apple App Attest på iPhone återstår
att prova. Testerna berör ID-05/06/09/10, SEC-01/03, FED-02 och TEST-01;
formell kravstatus ändras inte.

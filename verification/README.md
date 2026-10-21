# Passverifierare och testtjänst

Server för passkontroll, ansiktsjämförelse, liveness och iPhone-appens
pilotregister. [SAML-inloggningen](#saml-inloggning-med-passets-identitet) binder
appens nyckel till passets personuppgifter och använder Sweden Connect.

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
.venv/bin/pip install --require-hashes --only-binary=:all: -r runtime-requirements.lock
npm ci --ignore-scripts
.venv/bin/python download_models.py
.venv/bin/python server.py --csca /privat/sokvag/trusted-csca.pem
```

Öppna `http://localhost:8765`. Välj ursprungliga EF.SOD, DG1 och DG2 från en
NFC-läsare och öppna kameran. Servern extraherar referensporträttet ur
signerad DG2. Filer och kamerabild behandlas i minnet utan externa anrop.
Kameran stängs när bilden har tagits, när sidan döljs eller när den stängs manuellt.
Detta analysgränssnitt registrerar ingen nyckel.

## Appens privata pilotregister

För telefonprov med paketerad server används [pilotmiljön](../deployment/README.md).
Den kör Gunicorn med separata kapacitetsgränser och processisolering för
bildanalys. Kommandot nedan startar den äldre seriella testservern.

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
  --wallet-db /privat/openid-pilot/wallet.sqlite \
  --federation-socket /privat/openid-pilot/federation.sock
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

### Serverstyrd chipkontroll

Appen skickar signerad SOD, DG1, DG2 och DG14 till `/native/chip/start`.
Servern verifierar dokumentkedjan och datagruppshasharna innan DG14:s
publika chipnyckel används. En separat JMRTD-process genomför PACE och CA;
iPhone vidarebefordrar kommandon och svar via `/native/chip/step`.
Sessionsnycklarna stannar i serverprocessen.

CA version 1 bekräftas genom en ny SELECT/READ BINARY av DG14 med MAC-kontroll
under de nya sessionsnycklarna. Ingen cachad fil eller klientrapporterad
status godtas som chipbevis. Först därefter skapas kamerastegets engångsvärde.
App Attest binder dokument, enhetsnyckel och kamerabilder till samma session,
med strikt ökande räknare mellan de signerade anropen.

Stödda profiler är PACE version 2 ECDH-GM/AES med standardkurvor 12–18 och
CA version 1 ECDH/AES med minst 256-bitars kurva. BAC, CA version 2, DH,
3DES och okända profiler avvisas i serverkontrollen. Fel i PACE orsakar
ingen nedgradering. SOD måste innehålla DG14:s hash.

Högst fyra chipprocesser kan vara aktiva. Varje process har 75 sekunders
livslängd, högst 128 kommandon och begränsade meddelanden. Fel ordningsnummer,
token, MAC, avbrott eller timeout avslutar försöket. `/native/cancel` stänger
en pågående session. Äldre klienter som skickar `chipAuthentication: true`
till `/native/finish` måste uppdateras.

Detta bevisar kontroll över chipets privata nyckel i sessionen. Det bevisar
inte geografisk närhet till telefonen, passets spärrstatus eller kamerans
ursprung. Fysisk iPhone/NFC och nätverkets tidsmarginal återstår att verifiera.

Registret sparar publik nyckel, status och händelser. Namn, födelsedatum i
MRZ-format, nationalitet, utfärdarland, passets giltighet och en förminskad
version av det signerade passfotot sparas krypterat. Rå chipdata,
kamerabilder och ansiktsmallar sparas inte. Passnumret ingår endast i en
HMAC-referens för att känna igen samma pass vid nyregistrering.

Personen får ett internt slump-ID. Tjänsten får ett separat pseudonymt
subjekt. Aktivering av en ny nyckel för samma pass spärrar äldre nycklar
atomiskt. Ett annat pass med samma namn och födelsedatum slås inte ihop.
Passförnyelse och registerkontroll kräver en framtida återställningsprocess.

## Aktivera och prova inloggning

Godkända tekniska kontroller ger `PENDING_REVIEW`. En lokal operatör aktiverar
nyckeln separat för piloten. Standardgiltigheten är 24 timmar, högst 72.

```sh
.venv/bin/python wallet_cli.py --db /privat/openid-pilot/wallet.sqlite pending
.venv/bin/python wallet_cli.py --db /privat/openid-pilot/wallet.sqlite activate CREDENTIAL_ID --decision REVIEW-private-001 --private-pilot-only
```

`CREDENTIAL_ID` är registrerings-ID:t i appens Inställningar eller
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

## SAML-inloggning med passets identitet

Starta verifieraren ovan med `--federation-socket`. SAML-inloggningen
kräver en registrering som innehåller verifierade passuppgifter. Äldre
registreringar utan personprofil kan inte användas.

Kör följande från repots rot. Skapa tillfälliga TLS-/SAML-nycklar en gång:

```sh
java -jar prototype/target/isolated-eid-lab.jar phone-init /privat/openid-federation
```

Starta IdP och kontotjänst i varsin terminal på samma Linux-dator och
operativsystemskonto som verifieraren:

```sh
java -jar prototype/target/isolated-eid-lab.jar phone-idp /privat/openid-federation /privat/openid-pilot/federation.sock
```

```sh
java -jar prototype/target/isolated-eid-lab.jar phone-sp /privat/openid-federation /privat/openid-pilot/federation.sock
```

Betro det genererade `tls.crt` i datorns testwebbläsare. Öppna
**https://localhost:8444**, välj **Logga in med openID**, skanna QR-koden i
appen och kontrollera tjänst, uppgifter och kod. Efter godkännandet visar
kontotjänsten ditt namn, passfoto och födelsedatum från MRZ. Du behöver inte
klistra in något registrerings-ID.

MRZ använder tvåsiffrigt årtal. Sekel, ålder och svenskt personnummer
härleds inte. Namnet följer passets MRZ-translitterering.

IdP och SP körs i separata processer på loopback-HTTPS. Sweden Connect
1.0.3 verifierar den signerade begäran och skapar ett signerat, krypterat
SAML-svar. SP använder bibliotekets validering för signatur, mottagare,
InResponseTo, RelayState och giltighet. Profilen är projektets
`urn:openid:authn:passport-native:v1`, utan LoA3-anspråk. Attributen är
namn, MRZ-födelsedatum, passfoto, tjänstesubjekt, credentialreferens och
profilversion. Passnummer och nationalitet lämnas inte till tjänsten.

Bryggan är en Unix-socket med 0600 i en katalog med 0700. Den kan skapa,
läsa, avbryta och konsumera inloggningar samt kontrollera spärr; den har
ingen utgivnings- eller aktiveringsoperation. Samma OS-konto är fortfarande
en gemensam administrativ tillitsgräns. Flytta den inte till en publik TCP-port.

QR-koden innehåller enbart begärans-ID. Hemligheten stannar hos IdP och
begäran binds till autentiseringsflöde och tillåten SP. Appens `inspect`
hämtar uppgifter utan att godkänna. `approve` signerar exakt visad tjänst,
syfte och kod. Bara en nyckel och en konsumtion kan vinna. Begäran gäller
120 sekunder; SP-sessionen högst fem minuter. Varje skyddad SP-förfrågan
kontrollerar aktuell nyckel, personbindning och profilversion. Spärr,
nyckelbyte eller otillgängligt register stoppar fortsatt åtkomst.

De genererade servernycklarna är testnycklar med 30 dagars giltighet.
Ingen extern tjänst eller federation ansluts av dessa kommandon. Den
simulerade `/lab`-providern är avstängd i `phone-idp`.

## Logga in i testtjänsten via webbläsaren

Kör i en andra terminal på samma dator och operativsystemskonto som
verifieraren, med samma databas:

```sh
cd verification
.venv/bin/python relying_party.py --db /privat/openid-pilot/wallet.sqlite
```

Öppna **http://localhost:8766** i datorns webbläsare. Klistra in appens
registrerings-ID och välj **Logga in med openID**. I appen: välj
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
Katalog och fil kräver 0700/0600. Personprofiler krypteras med Node 24.19.0 AES-256-GCM, slumpmässig 96-bitars
nonce och credential/person-ID som autentiserade kontextdata. Separata
256-bitars nycklar används för kryptering och HMAC-SHA-256. Nyckelfilen
`wallet.identity-key` skapas med 0600. Saknad eller fel nyckel stoppar
profilåtkomst; den ersätts inte automatiskt när profiler finns.

Nyckeln ligger i samma privata katalog som databasen, utan HSM. Detta
skyddar en separat databasfil men inte ett övertaget serverkonto eller en
kopia av hela katalogen. Metadata och händelser är okrypterade. Profiler
behålls efter spärr men lämnas inte ut till appen eller tjänsten. Automatisk
gallring och nyckelrotation saknas; operatören måste fastställa lagringstid
och radera pilotens data och nyckel efter provet.
**Återläsning av gamla databasfiler stöds inte**: den kan återställa en spärrad
nyckel. Ett externt spärrankare saknas. Inga adminfunktioner exponeras via HTTP.

## Kontroller

| Del | Kontroll |
|---|---|
| Pass | Bouncy Castle CMS, JCA PKIX direkt DSC→CSCA, aktuella certifikatdatum, SHA-256/384/512 och DG1/DG2-hashar. Appflödet kräver även signerad DG14. |
| Dokumentprofil | TD3, ett porträtt, giltighetsdatum från idag till högst 20 år framåt. |
| Ansikte | YuNet-detektion och SFace 1:1-jämförelse. Exakt ett tillräckligt stort ansikte krävs. |
| Liveness | MiniFASNet V2 och V1SE på CPU, BGR och upstreams beskärningsskalor 2,7/4,0. |
| Fångst | App Attest binder session, bytes och publik nyckel. Appen har ingen bildimport. |
| Chip | Servern kör JMRTD PACE/CA och kontrollerar en färsk MAC-skyddad DG14-läsning genom CoreNFC. |

Native-flödet kräver ansiktslikhet ≥0,5 och PAD ≥0,8 för alla tre bilder.
Passiva passkontroller, ansiktsjämförelse och liveness avgör inte utgivning;
`issuanceEnabled` är alltid false.

## Begränsningar

- Gränsvärden för ansiktslikhet och PAD är inte kalibrerade för e-id-utgivning.
  Motståndskraft mot masker, injektion och relä behöver utvärderas.
- App Attest styrker appinstans och signerade data, inte kamerans fysiska
  ursprung. NFC-transporten förhindrar inte relä till ett annat fysiskt chip.
- Certifikatspärr/CRL, länkcertifikat, äldre algoritmer och historiskt giltiga
  men nu utgångna DSC stöds inte.
- Statisk QR ger inget närhetsbevis. Apple-kvoter och återanvändning av
  App Attest-nycklar behöver hanteras inför bredare drift.
- Operatören kontrollerar databasen. Rollseparation, swap/kraschdumpar,
  dataskydd, modellrättigheter och oberoende granskning återstår.

Detta är en privat pilot med lokal SAML-federation, utan godkänd e-id-utgivning.
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
.venv/bin/python -m unittest -v test_verification test_native test_chip test_wallet test_relying_party test_identity test_runtime test_crypto_runtime
node --test test-attest.mjs
node browser-test.cjs
node rp-browser-test.cjs
node federation-browser-test.cjs
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

SAML-webbtestet kör verifierare, IdP och SP i separata processer. Passets
CMS/PKIX/hashar, profilkryptering, ECDSA-godkännande och SAML-validering körs
på riktigt. NFC, kamera, App Attest och biometriska poäng ersätts med
explicita testdubblar i just denna fixtur. Testet bevisar integrationen,
inte fysisk personkontroll. Linux med Unix-sockets krävs.

CI kör samma SAML-webbtest även mot PostgreSQL och OpenBao över verifierad
TLS. `OPENID_TEST_POSTGRES` väljer denna variant och måste peka på en tom,
temporär testdatabas med administratörsbehörighet. `OPENID_TEST_BAO` anger
den låsta OpenBao-binären. Fixturen skapar schema, tjänstekonton, två separata
operatörskonton och en tillfällig nyckeltjänst. Använd aldrig en befintlig
driftdatabas. Körningen finns i `.github/workflows/prototype.yml`.

## Flera autentiseringsinstanser

[Driftinstruktionen](../deployment/cluster/README.md) beskriver PostgreSQL,
OpenBao, separata operatörsroller, TLS-workers, rotation, gallring och larm.
`cluster_serve.py` är ett separat körläge; SQLite-piloten ändrar inte lagringsformat.

## Utvärdera biometriska trösklar

`evaluate_biometrics.py` läser en privat CSV med kolumnerna
`sample,subject,partition,kind,score`. Använd studiekoder, inte namn.
`partition` är `calibration` eller `evaluation`; samma person får inte förekomma
i båda. `kind` är `genuine`, `impostor`, `bona_fide` eller `attack`. En
`impostor`-jämförelse anger båda personkoderna i `subject`, separerade med
semikolon. Övriga typer anger en personkod.
Filen ska ha läge 0600. Välj trösklar från kalibreringsmaterialet och lås dem
innan utvärderingsmaterialet används:

```sh
python evaluate_biometrics.py --scores /private/holdout.csv --face-threshold 0.5 --pad-threshold 0.9
```

Värdena ovan är kommandosexempel, inte kalibrerade produktionsgränser.
Resultatet innehåller FMR, FNMR, APCER, BPCER, antal och Wilson-intervall på
95 procent. Inga individuella koder eller poäng skrivs ut. Noll observerade
fel innebär inte noll risk. Utvärdera varje relevant angreppstyp, enhetsgrupp
och användargrupp separat med tillräckligt och lagligt insamlat material.
Beroende observationer kan kräva en annan statistisk analys. Verktyget
provar poängberäkningen; representativa data och oberoende prov återstår.

### Privat bilddiagnostik
Biometriarbetaren lämnar vid fel en fast stegkod (modellstart, passporträtt, kamerans ansikte, matchning eller PAD) och en tillåten orsakskod. Huvudprocessen validerar båda igen innan loggning. Bilder, råpoäng, identifierare och godtycklig undantagstext ingår inte. Modell-/arbetarfel ger otillgänglig tjänst, medan avvisad bildanalys inte ger godkänd kontroll. Detta ändrar inte experimentella trösklar eller den kvarstående kalibreringen.

Ansiktsdetektionen görs i originalskala och, för bilder större än 480 pixlar, även med hela bilden proportionellt förminskad till högst 480 pixlar. [YuNet beskriver ett träningsområde på ungefär 10–300 pixlar per ansikte](https://github.com/opencv/opencv_zoo/blob/main/models/face_detection_yunet/README.md). Box och landmärken mappas tillbaka till originalpixlar; jämförelse och PAD använder originalbilden. Flera ansikten i endera skalan eller detektioner som inte överlappar tillräckligt avvisas. Modellversioner och trösklar är oförändrade. Förbättringen kräver fortsatt fysisk verifiering och biometrisk utvärdering.

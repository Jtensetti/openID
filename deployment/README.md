# Privat pilotmiljö

Verifieraren, bildmodellerna och den lokala inloggningstjänsten paketeras i
Docker. Kör på en **Linux x86_64-dator i ett privat nätverk**. Telefonen behöver
nå datorns HTTPS-adress. Appen installeras separat från Xcode.

Detta är en miljö för telefonprov. Den är inte öppnad för publik e-id-utgivning.
Modellkalibrering, fysisk NFC/App Attest och oberoende granskning återstår.

## Publik TestFlight-beta

Serverpaket byggs och provas i den
[separata byggmiljön](build/README.md), exporteras med proveniens och importeras
utan ombygge på betavärden. Lokala labbinstruktioner nedan är för separata
utvecklingsdatorer; använd dem inte som byggprocedur på en körande betaserver.
Betans programkod, inklusive SAML-brygga och hälsoprob, ingår i samma image.
Endast data och driftkonfiguration monteras utifrån. Leveranskontrollen
nekar äldre kodmonteringar även om de är skrivskyddade.

Instruktionerna nedan gäller den egna privata miljön. Betan använder i stället
`beta-compose.yaml` tillsammans med `continuity-compose.yaml`, produktions-App
Attest och den fasta publika HTTPS-adressen. Följ
[instruktionen för automatisk testaktivering](../docs/testflight-beta.md).
[Spärrtjänstens driftinstruktion](continuity/README.md) beskriver behörigheter,
återställningsgränser och standardlägets kontaktbindning/manuella aktivering.
Privata ID:n migreras inte genom att byta serveradress i appen.

Testkonsolens ingress provas med `python3 deployment/test_beta_nginx.py`
på Linux med nginx och OpenSSL installerade. Provet startar en separat nginx
på loopback med genererade certifikat och en syntetisk bakomliggande tjänst.
Det kontrollerar samtliga testadresser, inklusive `loa3`, långa signerade
omdirigeringar för krypterat SignMessage, betakontoskydd och nekade adresser.
Det provar även SAML-POST på 64/128 KiB utan användbar temporärfilskatalog,
bevarat innehåll, betakontoskydd och avvisning över 128 KiB. Nginx-provets
samtliga temporära kataloger ligger i dess egen engångskatalog.
Inga pilotnycklar eller riktiga konton används. Resultatet anger nginx-versionen.

## Betans öppettider

Från 29 oktober 2026 kör den befintliga testservern **dygnet runt till och med
30 november 2026**. Den stängs av **1 december 2026 kl. 00.00 svensk tid**
(`Europe/Stockholm`), motsvarande 30 november kl. 23.00 UTC.

Den dagliga autostarten är avstängd. AWS-stoppschemat och serverns befintliga
lokala avstängningstimer är båda satta till slutdatumet. Vid återskapande av
servern måste även bootstrap-konfigurationens lokala timer följa denna plan.
Driftplanen ger ingen garanterad tillgänglighet eller bemannad support dygnet runt.
Stoppet raderar inte data; lagring och reserverad IP-adress fortsätter debiteras.
Den separata spärrtjänsten omfattas inte av testserverns stopp.

Den publika projektsidans statiska filer finns i `project-site/`; se
[publicering och routning](project-site/HOSTING.md). `beta-site/`
innehåller betavärdens egen hjälpsida. Håll deras öppettider och slutdatum
samstämmiga med README och appens informationstext när driftplanen ändras.

## Klientadresser bakom ingressen

API-ingressen skriver `X-OpenID-Client-IP` från sin egen anslutningsadress
och ersätter klientens eventuella värde. Betans `runtime.json` måste därför
innehålla `"trustedProxy": "127.0.0.1"` tillsammans med
`"bind": "127.0.0.1"`. Driftsätt runtime, konfiguration och nginx tillsammans
under ett registreringsstopp, och prova nyregistrering och inloggning efter
omstart. Uppdatera inte bara nginx framför en äldre runtime.

Proxyförtroendet gäller en enda uttryckligt vald loopbackadress. En annan
anslutande adress, saknad/felaktig klientadress, dubbletter eller alternativa
headernamn med understreck nekas av runtime. Vanliga `Forwarded`-huvuden
förblir otillåtna. Direktläget saknar `trustedProxy` och nekar det särskilda
adresshuvudet. Hälsokontroller behöver inte detta huvud. Ingen klientadress
används som identitetsbevis eller sparas i HTTP-loggarna.

Värddatorns lokala processer hör till förtroendegränsen. Lägg inte till en
yttre proxy eller nginx `real_ip`-omskrivning utan en separat prövad
konfiguration. Flera telefoner bakom samma NAT delar fortfarande gräns;
detta är trafikskydd, inte en beständig försöksbudget per innehavare.

## Förbered och starta

Kräver Docker med Compose, Python 3 och OpenSSL på värddatorn. Använd ett
vanligt användarkonto. Kontrollera att minst 4 GB RAM och utrymme för flera GB
byggartefakter finns. Containern får använda högst 2 GB RAM och två CPU-kärnor.

Du behöver Apple-team-ID:t från Xcode och ett CSCA-paket från en kontrollerad
källa. Passets egna certifikat ersätter inte det paketet.

Från repots rot, byt IP-adress, team-ID och CSCA-sökväg:

```sh
python3 deployment/setup.py \
  --directory "$HOME/openid-pilot" \
  --address 192.168.1.20 \
  --team DITTTEAMID \
  --csca /privat/trusted-csca.pem \
  --csca-crl /privat/csca.crl

export OPENID_DIRECTORY="$HOME/openid-pilot"
export OPENID_UID="$(id -u)" OPENID_GID="$(id -g)"
docker compose -f deployment/compose.yaml up --build -d
```

Konfigurationen, datan och hemligheterna hamnar utanför repot. Installera
`secrets/server.pem` som betrott testcertifikat på telefonen. Det genererade
certifikatet gäller i 30 dagar och bara för den valda IP-adressen. Begränsa
värddatorns brandvägg till testtelefonens nät. Öppna ingen routerport eller tunnel.

I appen: ange `https://192.168.1.20:8765` och koden från filen
`$OPENID_DIRECTORY/secrets/pairing`. Koden skrivs inte till containerloggarna.
Efter registreringen aktiverar du nyckeln med ett separat lokalt kommando:

```sh
docker compose -f deployment/compose.yaml exec verifier \
  python wallet_cli.py --db /srv/openid/data/wallet.sqlite pending

docker compose -f deployment/compose.yaml exec verifier \
  python wallet_cli.py --db /srv/openid/data/wallet.sqlite \
  activate CREDENTIAL_ID --decision REVIEW-private-001 --private-pilot-only
```

Öppna `http://localhost:8766` på Linux-datorn och prova QR-inloggningen med
appen. Testtjänsten lyssnar bara på loopback. Ingen SAML-federation startas av
Compose; den separata [SAML-miljön](../verification/README.md#saml-inloggning-med-passets-identitet)
har egna startkommandon.

Compose använder värddatorns nätverk för att verifieraren ska kunna bindas
till exakt den angivna privata adressen. Filsystemet är skrivskyddat utom
privat datavolym och tidsbegränsade temporärfiler. Inga Linux capabilities
eller privilegiehöjningar tillåts. Verifierare och testtjänst delar databas
för detta prov; de är inte skilda administrativa säkerhetszoner.

## Drift och kapacitet

`serve.py` kör Gunicorn 26.2.0 med en worker, 16 trådar, högst 32 anslutningar
och en anslutningskö på 32. En fillåsning hindrar två runtime-processer från
att använda samma databas. Flera repliker stöds inte: NFC-sessioner och
signeringsutmaningar finns i processminnet.

Linux x86-64-värden måste stödja Landlock ABI minst 3 och seccomp-filter.
Bildarbetarna aktiverar [fil-/systemanropspolicyn](../docs/bildarbetare.md)
före bildinläsning. Saknat skydd stoppar även modellkontrollen vid start.
Kod, modeller och runtime ska vara skrivskyddade och hållas åtskilda från
personakter, säkerhetskopior och nycklar. Värdens stöd behöver verifieras
innan denna kandidat driftsätts.

- Högst ett native-anrop och åtta wallet-anrop behandlas samtidigt. Extra
  anrop får 503 och `Retry-After: 2`, utan att läsas in eller köas för analys.
- TLS/HTTP-huvuden har en tidsgräns på 10 sekunder, request-body 15 sekunder.
  Headerantal, headerstorlek, JSON-storlek och tillåtna routes begränsas.
- Per klient-IP tillåts 10 API-anrop/sekund med en buffert på 160 anrop.
  Nyregistrering begränsas separat till 10/minut med en buffert på fem.
  Den publika betan använder den validerade nginx-adressen enligt ovan;
  motsvarande IPv4-/IPv6-skrivsätt ger samma räknare. Minnesgränsen på
  1 024 klienter och separata kapacitetsgränser består. Räknarna är lokala
  till processen och nollställs vid omstart; klusterläget aktiverar inte
  proxyförtroende genom denna ändring.
- Bildanalys körs i en separat process med 45 sekunders tidsgräns. Alla
  modellhashar kontrolleras före laddning. Misslyckad analys återanvänder
  inte registreringssessionen.
- Signaturer och profilkryptering använder två återanvända Node-processer med
  tio sekunders tidsgräns och omstart efter 1 000 anrop. Ett processfel avvisar
  anropet; nästa anrop får en ny process.
- SIGTERM stoppar nya arbetsanrop och låter pågående anrop avslutas inom
  60 sekunder. Compose väntar 70 sekunder. Nycklar och spärrar ligger kvar;
  pågående NFC-flöden och signeringsutmaningar måste startas om efter omstart.
- Loggar innehåller route, HTTP-status och varaktighet. Avvisad passkontroll
  kan dessutom ange en fast stegkod (exempelvis TRUST_CHAIN eller DATA_HASHES),
  aldrig undantagstext, anropsdata,
  nycklar eller personreferenser. Docker roterar loggarna vid 3 × 10 MB.

`GET /health/live` visar att processen svarar. `GET /health/ready` kontrollerar
att databasen och eventuell profilnyckel är åtkomliga och att avstängning inte
pågår. Readiness är ingen end-to-end-verifiering av identitetskontrollen.
`GET /metrics` kräver kopplingskoden i `X-CSRF-Token` och ger räknare per
känd route/status. Hälsokontroller kräver korrekt HTTPS och Host. Om databasen
försvinner avvisas anrop och omstart; markören `wallet.initialized` förhindrar
att tjänsten då skapar ett tomt register. Behåll markören i datavolymen.

```sh
docker compose -f deployment/compose.yaml ps
docker compose -f deployment/compose.yaml logs --tail 50 verifier
docker compose -f deployment/compose.yaml stop
```

Mät på den avsedda maskinen före kapacitetsbeslut. Verktygen testar egna,
genererade underlag och skriver inga riktiga personuppgifter:

```sh
cd verification
.venv/bin/python runtime_smoke.py
.venv/bin/python load_runtime.py --requests 400 --concurrency 32 --output /tmp/openid-load.json
```

`runtime_smoke.py` provar riktig TLS/Gunicorn, signerad status, godkännande,
spärr, återspelning, överbelastning, databasbortfall och avstängning.
`load_runtime.py` mäter signaturer, krypterade profilläsningar och SQLite.
Dess kapacitetstal omfattar inte HTTP, NFC, Apple-attestering eller bildanalys.
Mätresultat hör till respektive maskin och revision och redovisas i PR:n.

## Säkerhetskopiering och återställning

Kör som registerkatalogens ägare och använd en separat privat lagringsplats.
Backupens och återställningens målkatalog ska ligga direkt under en befintlig
katalog som ägs av användaren, har läge 0700 och inte är en symbolisk länk.
Verktyget avvisar delade målföräldrar innan en kopia skapas. Överordnade
kataloger och filsystemets åtkomstregler behöver också skyddas av operatören.

```sh
cd verification
.venv/bin/python recovery.py backup --db /privat/data/wallet.sqlite \
  --destination /privat/backups/kopia-001
.venv/bin/python recovery.py restore --backup /privat/backups/kopia-001/wallet.sqlite \
  --destination /privat/aterstalld \
  --identity-key /separat/nyckelforvaring/wallet.identity-key \
  --binding /privat/aterstallningsunderlag/kopia-001.json \
  --binding-sha256 "$RECOVERY_BINDING_SHA256" --require-continuity \
  --erasure-ledger /separat/forvarare/raderingsbeslut.json \
  --erasure-ledger-sha256 "$CURRENT_ERASURE_LEDGER_SHA256"
```

Före återläsning måste förvararen skapa och oberoende förankra
[återställningsbindningen](../docs/aterstallningsbindning.md) med `recovery.py bind`.
Den binder exakta backupbyte till originalnyckelns båda halvor; den krävs
även när inga profiler finns kvar. Variabeln ovan hämtas från det externa ankaret.

Säkerhetskopian använder SQLite backup-API i läsläge, utan Wallet-start,
schemaändring eller nätverksanrop, och innehåller ingen profilnyckel. En befintlig
`wallet.continuity-required` följer med kopian och återställningen. Felaktiga
markörer avvisas. Behåll hela backupkatalogen. `--require-continuity` kräver
oberoende spärr och avisering även när en äldre kopia saknar markören;
använd flaggan för driftsatta tjänster. Driftkonfigurationen och IAM-åtkomsten
till den **aktuella** oberoende spärrtjänsten måste ordnas separat före start.
Flaggan återskapar inte den tjänsten eller dess aktuella spärrhistorik.
Förvara nyckeln separat och skydda även backupmediet. Återställning kräver en
ny katalog, kontrollerar databasen och dekrypteringen och **spärrar samtliga
återställda nycklar**. Alla användare måste registrera sig på nytt. Byt aldrig
ut en databas under en körande tjänst. Att manuellt kopiera in en gammal
databas kringgår denna procedur och stöds inte.

Prova återläsning i en isolerad miljö innan en kopia används: kontrollera att
samtliga gamla ID:n är spärrade, att gamla förfrågningar inte kan slutföras,
att registreringskarantänen består efter omstart och att saknad oberoende
spärrkonfiguration stoppar start. Registrera revision, kopians kontrollsumma,
ålder, återställningstid och resultat utan personuppgifter. Denna procedur
ersätter inte extern backupförvaring eller en genomförd driftövning.

## Gräns mot publik drift

Paketet saknar flerinstansdrift, HSM/KMS, administrativ rollseparation,
automatisk nyckelrotation och gallring samt ansluten larmmottagare. En förvaltare
behöver fastställa tillgänglighetsmål, dimensionera och bevaka miljön, ordna
certifikatförnyelse och öva återställning. Publik ingress kräver separat
nätverksdesign och granskning; denna konfiguration nekar proxyhuvuden.

iPhone-signering, betrodda passankare, modellrättigheter och kalibrering,
extern säkerhetsgranskning och utgivningsbeslut måste också vara ordnade.
Teknisk driftberedskap innebär inget Digg-godkännande. Se [SECURITY.md](../SECURITY.md).

### Svenska CSCA-certifikat och EC-parametrar

Både passkontrollen och den andra chipkontrollen läser operatörens CSCA-paket
med den redan versionslåsta Bouncy Castle-providern. Detsamma gäller
PKIX-valideringen. Detta stöder certifikat med explicita EC-parametrar,
som Javas standardparser kan avvisa redan när paketet laddas. Tillitsankare,
signerad data, giltighetstider och direkt DSC–CSCA-kedja kontrolleras fortsatt.
Ingen nätverkshämtad eller passlevererad rot läggs till som betrodd.

Regressionsprovet genererar en Brainpool-rot med explicita parametrar,
kontrollerar en giltig kedja och avvisar obetrodd kedja och ändrad datagrupp.

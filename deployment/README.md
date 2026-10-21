# Privat pilotmiljö

Verifieraren, bildmodellerna och den lokala inloggningstjänsten paketeras i
Docker. Kör på en **Linux x86_64-dator i ett privat nätverk**. Telefonen behöver
nå datorns HTTPS-adress. Appen installeras separat från Xcode.

Detta är en miljö för telefonprov. Den är inte öppnad för publik e-id-utgivning.
Modellkalibrering, fysisk NFC/App Attest och oberoende granskning återstår.

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
  --csca /privat/trusted-csca.pem

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

- Högst ett native-anrop och åtta wallet-anrop behandlas samtidigt. Extra
  anrop får 503 och `Retry-After: 2`, utan att läsas in eller köas för analys.
- TLS/HTTP-huvuden har en tidsgräns på 10 sekunder, request-body 15 sekunder.
  Headerantal, headerstorlek, JSON-storlek och tillåtna routes begränsas.
- Per klient-IP tillåts 10 API-anrop/sekund med en buffert på 160 anrop.
  Nyregistrering begränsas separat till 10/minut med en buffert på fem.
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

```sh
cd verification
.venv/bin/python recovery.py backup --db /privat/data/wallet.sqlite \
  --destination /privat/backups/kopia-001
.venv/bin/python recovery.py restore --backup /privat/backups/kopia-001/wallet.sqlite \
  --destination /privat/aterstalld \
  --identity-key /separat/nyckelforvaring/wallet.identity-key
```

Säkerhetskopian använder SQLite backup-API och innehåller ingen profilnyckel.
Förvara nyckeln separat och skydda även backupmediet. Återställning kräver en
ny katalog, kontrollerar databasen och dekrypteringen och **spärrar samtliga
återställda nycklar**. Alla användare måste registrera sig på nytt. Byt aldrig
ut en databas under en körande tjänst. Att manuellt kopiera in en gammal
databas kringgår denna procedur och stöds inte.

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

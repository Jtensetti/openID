# Delat register och centrala profilnycklar

`cluster_serve.py` kör autentisering i flera processer eller instanser mot
PostgreSQL och OpenBao Transit. Registrering körs separat med en process;
ett avbrott i en pågående NFC-session kräver att registreringen startas om.
Det befintliga SQLite-läget finns kvar för en lokal pilot.

## Förutsättningar

- PostgreSQL 18.6, en ny dedikerad databas och administratör för schema/roller.
- OpenBao 2.7.1 med TLS, separat lagring och åtkomsthantering. `bao.hcl`
  är en nodkonfiguration; redundant drift kräver ett riktigt Raft-kluster,
  separata felzoner och provad återställning. Stäng av swap på värdarna.
- Python 3.12 och Node 24.22.1, eller den låsta autentiseringscontainern.
- Certifikat för API, PostgreSQL och OpenBao. Hemliga filer ska ha läge 0600
  i en katalog med läge 0700, utanför repot.

Databasen och nyckeltjänsten ska vara privata. Servern kräver verifierad
TLS till båda. CI:s uttryckliga loopbackundantag exponeras inte i start-CLI:n.
Databasanslutningen måste gå till en skrivbar primär; läsrepliker används inte
för autentiseringsbeslut. Synkron replikering och failover måste konfigureras
så att bekräftade spärrar inte går förlorade.

## Databas och befogenheter

Kör `schema.sql` en gång som databasägare med `CREATEROLE`; återställning
kräver även `CREATEDB`. PostgreSQL-superuser behövs inte. Schemat ägs av
`openid_owner`, som saknar inloggning. Installationen ger administratören
medlemskap med `SET` och `INHERIT` i ägarrollen, vilket även behövs för
återställning på RDS. Ge aldrig applikations- eller operatörskonton medlemskap
i ägarrollen. Skapa separata LOGIN-konton och tilldela dessa grupproller:

| Roll | Tillåtet |
|---|---|
| `openid_enroller` | Registrera nyckel och krypterad profil i väntan på granskning |
| `openid_wallet` | Signerade operationer, förfrågningar och spärr |
| `openid_requester` | Föreslå aktivering med beslutsreferens |
| `openid_approver` | Godkänna en annan inloggnings aktiveringsförslag |
| `openid_revoker` | Spärra en nyckel eller hela registret efter återläsning |
| `openid_maintenance` | Omkryptera profiler och köra begränsad gallring |
| `openid_auditor` | Läsa operatörshändelser och aktiveringsförslag |
| `openid_backup` | Läsa registrets tabeller för backup; ingen skriv- eller dekrypteringsrätt |

Ett förslag gäller en timme och binds till nyckeln och profilversionen.
Aktivering kräver en registrering som är högst ett dygn gammal och en ännu
giltig handling. Giltigheten är fortsatt begränsad till högst 72 timmar.
Samma databaslogin kan aldrig attestera sitt eget förslag, även om kontot
har båda rollerna. Ägare och databasadministratörer har högre privilegier;
deras åtkomst måste hanteras separat från den ordinarie operatörsprocessen.

| Övergång | Villkor och effekt |
|---|---|
| Ny → PENDING_REVIEW | Registreringsrollen skriver verifierad profil och ny enhetsnyckel |
| PENDING_REVIEW → ACTIVE | Två olika operatörsinloggningar, färskt förslag och giltigt pass |
| ACTIVE/PENDING_REVIEW → REVOKED | Spärr; väntande godkännanden annulleras |
| ACTIVE → EXPIRED | Giltighet kontrolleras vid varje användning |
| Nyckelbyte | Samma person låses; gamla nycklar spärras i samma transaktion |
| REVOKED → ACTIVE | Förbjuden; ny registrering och ny nyckel krävs |

Aktivering kräver fortfarande en faktisk granskningsprocess och tillgång
till beslutsunderlaget. Två databaskonton är en teknisk befogenhetskontroll,
inte ett bevis på att två personer har gjort en oberoende identitetskontroll.

## OpenBao

Initiera och lås upp OpenBao enligt organisationens nyckelceremoni. Behåll
unseal-delar och administratörsåtkomst hos andra personer än applikationsdriften.
Aktivera en skyddad audit destination med standardmaskering; använd aldrig
`log_raw`. Efter initiering används avgränsade serviceidentiteter, inte root-token.

Med en separat administrativ CLI-session:

```sh
bao secrets enable transit
bao write transit/keys/openid-profile type=aes256-gcm96 derived=true exportable=false
bao write transit/keys/openid-profile/config auto_rotate_period=720h
bao write transit/keys/openid-index type=hmac key_size=32 exportable=false
bao policy write openid-enroller deployment/cluster/enroller.hcl
bao policy write openid-wallet deployment/cluster/wallet.hcl
bao policy write openid-maintenance deployment/cluster/maintenance.hcl
bao policy write openid-backup deployment/cluster/backup.hcl
bao policy write openid-recovery deployment/cluster/recovery.hcl
```

Utfärda en separat kortlivad token för varje tjänst med dess policy och utan
`default`-policy. Tokenfiler läses på nytt vid varje anrop och kan ersättas
atomiskt av en behörig agent. Förnyelse och leverans av dessa autentiserings-
uppgifter måste konfigureras i den valda driftsmiljön.

Profilnyckeln roteras var 30:e dag. Omkrypteringen använder Transit `rewrap`;
underhållskontot saknar dekrypteringsrätt. Nyckelmaterial lämnar inte OpenBao.
Kontexten binds till både personen och enhetsnyckeln. OpenBao i denna
konfiguration är programvarubaserat nyckelskydd, inte ett verifierat HSM.

Dokumentets blinda index använder separat HMAC-nyckelversion 1. Den roteras
inte automatiskt: utan passnumret går det inte att återskapa indexet från
lagrade profiler. Byte av denna nyckel kräver en planerad omregistrering.
Tjänstespecifika personreferenser lagras slumpmässigt och påverkas inte av
profilnyckelrotation. Radera inte gamla profilnyckelversioner innan även
säkerhetskopiornas bevarandetid har löpt ut.

## Start

Installera `verification/cluster-requirements.lock` och
`verification/runtime-requirements.lock` med `--require-hashes --only-binary=:all:`.
Kopiera `wallet.example.json` till en privat konfigurationskatalog. Databasfilen
innehåller en libpq-anslutningssträng med `host`, `dbname`, separat `user`,
autentiseringsuppgifter, `sslmode=verify-full` och `sslrootcert`.

```sh
cd verification
.venv/bin/python cluster_serve.py --config /srv/openid/runtime.json
```

Alternativt, från reporoten:

```sh
docker build -f deployment/cluster/Dockerfile -t openid-wallet .
docker run --read-only --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 128 --memory 512m --cpus 2 --network host \
  --tmpfs /tmp:size=32m,mode=1777 \
  -v /srv/openid:/srv/openid:ro openid-wallet
```

Anpassa filägaren till containeranvändaren 10001. Två workers ger högst 16
poolanslutningar per instans. Båda instanserna använder samma `origin` och
databas men kan lyssna på olika interna portar. Balansera `/wallet/*` mellan
dem; skicka `/native/*` till en separat registreringsinstans. Behåll Host och
Origin, verifiera TLS även till backend och skicka inga Forwarded-headers.
Proxykonfigurationen måste provas i den valda driftplattformen; den ingår
inte i flerprocessprovet, som ansluter direkt till respektive TLS-instans.

Registreringsinstansen använder `role: proofing`, `workers: 1`, enroller-
konton samt fälten `team`, `bundle`, `developmentAttestation`, `csca` och `jar`.
Den behöver verifierarens fulla modell-/Java-installation. Den mindre
containern ovan innehåller endast autentisering och driftverktyg.

SQLite-registret migreras inte automatiskt. Börja med ett separat register
och nyregistrering; kopiera inte SQLite-rader med lokala profilnycklar in i
PostgreSQL. Den enklare HTTP-testtjänsten använder fortfarande SQLite.
SAML-bryggan kan däremot anslutas till det delade registret enligt nedan.

## SAML-brygga

Kör `cluster_bridge.py --config /srv/openid/federation.json` bredvid den
befintliga Java-IdP:n/SP:n. Konfigurationen innehåller samma fyra anslutningsfält
som `maintenance.example.json`, men med ett separat wallet-konto och dess
Transit-policy, samt `origin`, `socket` och exakt `audience`. Socketen ska
ligga i en privat katalog med läge 0700. Ange dess absoluta sökväg i den
befintliga SAML-startkonfigurationen enligt verifierarens README.

Bryggan återanvänder `FederationServer` och Sweden Connect-flödet. Flera
IdP-instanser kan ha var sin lokal brygga mot samma register. CI provar
socketprotokollet med PostgreSQL, QR, godkännande i en annan instans,
mottagar-/sessionsbindning, engångskonsumtion och spärr. Samma helkedjeprov
med Java-IdP, Java-SP och Chromium körs mot både SQLite och PostgreSQL.
PostgreSQL-varianten använder verifierad TLS till databasen och OpenBao,
separata tjänstekonton samt aktivering av två operatörskonton. Extern federation
och redundant IdP-/SP-sessionhantering är inte verifierade.

## Operatörer

Kör respektive kommando med den berörda personens egen anslutningsfil:

```sh
python cluster_operator.py --database-file /private/requester-db request CREDENTIAL_ID REVIEW_REFERENCE
python cluster_operator.py --database-file /private/approver-db approve PROPOSAL_ID
python cluster_operator.py --database-file /private/revoker-db revoke CREDENTIAL_ID
```

Spara beslutsreferenser utan namn eller personnummer. Det finns inget
HTTP-API för aktivering eller administrativ rolltilldelning.

## Underhåll och övervakning

Kör `maintenance.py` schemalagt med ett separat underhållskonto. Välj
lagringstider efter fastställd policy; följande värden är endast ett körningsexempel:

```sh
python maintenance.py --config /srv/openid/maintenance.json --profile-days 7 --event-days 1827
```

Händelser och aktiveringsbeslut får inte gallras tidigare än 1827 dagar
efter det senaste av händelsen/beslutet och credentialens sista giltighet.
Kontrollen finns även i databasfunktionen. Råa biometriska underlag ingår
inte i detta bevarande; profilernas gallring styrs separat. Administrativa
loggar har ingen automatisk gallring. Oberoende arkiv, läsbarhetsprov,
fastställd lagringspolicy och rättslig grund behöver etableras i driften.

### Uppgradering till schema 2

För ett läsbart journaluttag med separat kontrollsumma, använd
[privat arkivexport](../../docs/arkivexport.md). `archive-access.sql` ger
befintliga `openid_auditor` kolumnbegränsad läsrätt utan profilchiffertext,
PIN-verifierare, sessionshemligheter eller ändringsrätt. Det är ett separat,
valfritt behörighetssteg, även efter återställning; schema och backupformat
ändras inte. Exportören behöver ingen OpenBao-token.

Schema 2 innehåller även SignMessage, verifieringsnivå, säkerhetskod och
en beständig registreringsspärr efter återläsning.
Signering kräver den separata `sign`-åtgärden med exakt textbindning. PIN-
verifierare lagras som credentialbundna Transit-HMAC, aldrig som sex siffror.
Tjänstekontot kan bara läsa kodstatus och anropa begränsade kontroll- och
bytesfunktioner; det kan inte läsa verifierarna, återställa en låst kod
eller ändra begärans text, nivå, motpart eller sessionsbindning.

Nya installationer använder `schema.sql`, version 2. Version 1 nekas av den
nya applikationen. Stoppa applikationer och underhåll, ta och verifiera en
backup med den tidigare, låsta kodrevisionen och kör `migrate-1-to-2.sql`
med databasens kontrollerade ägarkonto. Migreringen är transaktionell och
nekar annan startversion. Starta därefter den nya revisionen och verifiera
readiness, rollgränser och försöksspärren innan trafik öppnas.

Den nya backupen omfattar även biometribudgeten och registreringsspärren.
Äldre backuper återläses med sin tidigare kodrevision i en stängd miljö,
spärras och migreras innan ny kod får ansluta. Kör därefter
`revoke_all_after_restore()` innan applikationskonton får tillgång.

Återställning kan förlora försök som gjorts efter backupen. Det stödda
återställningsflödet blockerar därför automatiskt all ny registrering och
biometrisk analys i minst 24 timmar, även efter omstart och återöppnad
databas. Tjänster och operatörer kan inte förkorta spärren, inte heller
genom egen sökväg eller temporär skuggtabell. Ny återläsning förlänger den.
HTTP svarar `503 REGISTRATION_PAUSED` redan före fångsten. Tiden måste
ingå i registreringens återställningsmål; det finns ingen API-/CLI-genväg.

Varje körning omkrypterar högst 100 profiler och gallrar högst 100 rader per
tabell. Ett avbrott rullar tillbaka den pågående transaktionen. Profiler kan
gallras först efter giltighetens slut plus vald tid. Personlänkar, nyckel-
tombstones och operatörsloggen bevaras; deras slutliga bevarandepolicy återstår.
Övervaka `maintenance_runs.completed_at` och dimensionera intervallet efter
mängden data. Nyckelrotation får inte springa ifrån omkrypteringsjobbet.

`/health/live` visar processen; `/health/ready` kontrollerar databasschema och
nyckeltjänst. `/metrics` kräver separat bearer-token och innehåller enbart
fasta routenamn, statuskoder och latensintervall, per worker. Mätvärdena är
inte en färdig central SLO-beräkning för hela klustret.

Kör `monitor.py --config /srv/openid/monitor.json` varje minut från en separat
värd. Tre på varandra följande fel ger ett `UNAVAILABLE`-meddelande; återhämtning
ger `RECOVERED`. Endast tjänsteetikett och status skickas till den valda
HTTPS-webhooken. Leveransen måste kvitteras innan tillståndet sparas. Schemaläggarens
missade körningar och leveransfel måste också larma. Ingen mottagare konfigureras
automatiskt.

## Återställning

`cluster_recovery.py` exporterar registret genom PostgreSQL:s binära `COPY`
i en gemensam skrivskyddad snapshot. Använd ett separat login med
`openid_backup`. Föräldrakatalogen ska ägas av användaren och ha läge 0700:

```sh
python cluster_recovery.py backup --database-file /private/backup-db \
  --destination /private/backups/register-20261020
```

Backupen innehåller krypterade profiler, publika nycklar och registerhändelser.
Den innehåller inga OpenBao-nycklar, databaslösenord eller körbara SQL-skript.
Filerna får läge 0600; storleken begränsas till 10 GiB och körningen till 30
minuter. SHA-256 och radantal upptäcker skadade eller ofullständiga filer.
Kontrollsummorna autentiserar inte avsändaren: backupkatalogen måste skyddas
mot ändring och kopieras till separat krypterad lagring med fastställd retention.
Detta är en logisk backup av registret, inte PostgreSQL-klustrets roller,
konfiguration, repliker eller WAL. Spara den matchande kodrevisionen;
återställning kräver PostgreSQL 18 och exakt samma `schema.sql`.

Ta därefter en separat OpenBao-snapshot, så att den omfattar alla
profilnyckelversioner som registerbackupen behöver:

```sh
bao operator raft snapshot save /private/key-backups/bao-20261020.snap
```

Kör med verifierad TLS och `openid-backup`, som bara får läsa snapshots.
Skydda katalogen och
behåll unseal-materialet separat. En snapshot är krypterad men innehåller
även policyer och tokens; återkalla och ersätt återställda serviceuppgifter
innan extern trafik tillåts. Radera inte äldre nyckelversioner under
backupens livstid. Följ OpenBaos instruktioner för ett separat, isolerat
återställningskluster. En nyinitierad tjänst har annan seal och kräver
uttrycklig `snapshot restore -force` följt av ursprungligt unseal-material.
Kör aldrig force restore mot en aktiv tjänst.

Med tillgång till de återställda profilnycklarna:

```sh
python cluster_recovery.py restore --admin-file /private/restore-admin-db \
  --backup /private/backups/register-20261020 \
  --target openid_restore_20261020 --key-config /private/recovery-key.json
```

Nyckelkonfigurationen har fälten `baoAddress`, `baoTokenFile` och `baoCA`,
med en tillfällig `openid-recovery`-token för dekryptering. Filen ska ha läge 0600. Administratörens
anslutning ska gå till en kontrolldatabas på återställningsservern.
Verktyget skapar en ny databas; befintliga databaser får aldrig skrivas över.
Tabeller och privilegier skapas från repots schema, enbart data läses från
backupen. Alla nycklar spärras och väntande beslut annulleras i samma
transaktion. Varje profil måste kunna dekrypteras innan transaktionen får
slutföras. En felaktig eller saknad nyckel avbryter återställningen.

Resultatet `QUARANTINED` betyder att databasen fortfarande är stängd:
`ALLOW_CONNECTIONS false` och ingen publik CONNECT-behörighet. Även ett
avbrott lämnar applikationskontona utan anslutningsrätt. Administratören
behöver därefter kontrollera spärrstatus, återställa separata operatörskonton,
rotera serviceuppgifter och uttryckligen öppna anslutning samt ge CONNECT till
avsedda logins. Den separata 24-timmarsspärren för ny registrering kvarstår
även när databasanslutning öppnas. Därefter krävs ny registrering och
tvåpersonersaktivering för användarna.
Administratörer kan kringgå dessa rutiner; deras åtkomst måste skyddas separat.

CI återläser ett faktiskt register och OpenBao-snapshots samt stoppar ledaren
i ett lokalt trenodskluster. Samma förlopp behöver övas på vald driftplattform,
inklusive extern lagring, förlorad värd, återställningstid och larmmottagning.

Format och kommandon följer [PostgreSQL COPY](https://www.postgresql.org/docs/18/sql-copy.html)
och [OpenBao Raft](https://openbao.org/docs/commands/operator/raft/).

## Tester

Workflow `cluster.yml` startar låsta PostgreSQL 18.6 och OpenBao 2.7.1,
använder riktiga separata databas-/Transit-konton och kör `test_cluster.py`.
Databasanslutningarna använder verifierad TLS; fel CA och fel värdnamn nekas.
Proven omfattar rollrättigheter, engångskonsumtion, parallella beslut,
nyckelbyte, instansbortfall, databas-/nyckeltjänstfel, rotation, gallring och
återläsning. `test_key_recovery.py` använder verklig TLS och Raft med separat
initiering, unseal och ledarbyte. En del av CI använder en enda unseal-del;
detta är en testfixtur, inte en operativ nyckelceremoni.
Kapacitetsrapporten gäller signerad autentisering och profilhämtning över TLS,
inte NFC eller biometrisk registrering. Efter instansbortfall körs även 120
sekunder med åtta samtidiga klienter, avsiktligt begränsat till fyra operationer/s.
Det motsvarar åtta HTTP-anrop/s och ryms under hastighetsgränsen även om
alla anslutningar hamnar i samma worker. Svartider, worker-minne och öppna
filbeskrivare mäts; omstart, kvarlämnade challenges och växande resursåtgång
kan få provet att misslyckas. Detta är inte ett mått på maximal kapacitet.
CI:s OpenBao dev-läge används endast i övriga tillfälliga integrationstester.

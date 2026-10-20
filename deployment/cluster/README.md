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
- Python 3.12 och Node 24.19.0, eller den låsta autentiseringscontainern.
- Certifikat för API, PostgreSQL och OpenBao. Hemliga filer ska ha läge 0600
  i en katalog med läge 0700, utanför repot.

Databasen och nyckeltjänsten ska vara privata. Servern kräver verifierad
TLS till båda. CI:s uttryckliga loopbackundantag exponeras inte i start-CLI:n.
Databasanslutningen måste gå till en skrivbar primär; läsrepliker används inte
för autentiseringsbeslut. Synkron replikering och failover måste konfigureras
så att bekräftade spärrar inte går förlorade.

## Databas och befogenheter

Kör `schema.sql` en gång i den nya databasen. Schemat ägs av `openid_owner`,
som saknar inloggning. Ge aldrig applikations- eller operatörskonton medlemskap
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
mottagar-/sessionsbindning, engångskonsumtion och spärr. Hela Java-/browserkedjan
körs fortsatt mot SQLite i den separata federationssviten; extern federation
eller redundant IdP-/SP-sessionhantering är inte verifierad.

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
python maintenance.py --config /srv/openid/maintenance.json --profile-days 7 --event-days 30
```

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

Återläs PostgreSQL i ett avskilt nät med applikationernas inloggningar avstängda.
Återställ också tillgången till rätt OpenBao-nyckelversioner från separat,
skyddad backup. Kör sedan `cluster_operator.py ... revoke-after-restore` och
verifiera att samtliga nycklar är spärrade innan trafik släpps på. Kommandot
annullerar väntande förfrågningar, utmaningar och aktiveringsförslag atomiskt.
Det skyddar inte mot att en administratör kopplar in en obehandlad gammal backup.
Återläsning av PostgreSQL/Raft och automatisk failover behöver övas på den
valda infrastrukturen; CI provar återställningens spärrfunktion.

## Tester

Workflow `cluster.yml` startar låsta PostgreSQL 18.6 och OpenBao 2.7.1,
använder riktiga separata databas-/Transit-konton och kör `test_cluster.py`.
Proven omfattar rollrättigheter, engångskonsumtion, parallella beslut,
nyckelbyte, instansbortfall, databas-/nyckeltjänstfel, rotation och gallring.
Kapacitetsrapporten gäller signerad autentisering och profilhämtning över TLS,
inte NFC eller biometrisk registrering. CI:s OpenBao dev-läge används endast
i den tillfälliga testmiljön.

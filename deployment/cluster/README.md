# Delat register och centrala profilnycklar

`cluster_serve.py` kör autentisering i flera processer eller instanser mot
PostgreSQL och OpenBao Transit. Registrering körs separat med en process;
ett avbrott i en pågående NFC-session kräver att registreringen startas om.
Den [gemensamma Compose-kandidaten](../production/README.md) kopplar detta
register till federation, nyckeltjänst, separat spärrkontroll och avisering.
Den är under verifiering och inte driftsatt. Källkoden ensam gör inte bytet;
äldre kommandons standardläge för SQLite finns kvar.

Det befintliga CI-jobbet bygger autentiseringsimagen, provar dess integration
och skannar därefter samtliga Debianpaket med Trivy och kontrollerar aktuell tillämplighet.
Bas, lås och stoppvillkor beskrivs i [bygginstruktionen](../build/README.md).
Kontrollen binds till den byggda imagens exakta ID och nekar tillämpliga/obehandlade fynd eller
ofullständig täckning. OS-resultat bevaras i `cluster-os-inventory` även när
grinden underkänns. Detta omfattar inte PostgreSQL-/OpenBao-tjänsternas
egna paket eller driftsatta värdar. Se [byggkontrollerna](../build/README.md).

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
| `openid_registry` | Läsa verifierad profil och lagra versionsbundet registerbevis genom en begränsad funktion |
| `openid_requester` | Föreslå aktivering med beslutsreferens |
| `openid_approver` | Skapa ett fem minuter giltigt intent för en annan inloggnings aktiveringsförslag |
| `openid_contact` | Förbereda krypterad spärrkod och binda oföränderlig, separat kontrollerad kontakt |
| `openid_continuity` | Kvittera extern spärr och slutföra ett giltigt operatörsintent |
| `openid_revoker` | Spärra en nyckel lokalt efter bekräftad extern spärr |
| `openid_maintenance` | Omkryptera profiler och köra begränsad gallring |
| `openid_auditor` | Läsa operatörshändelser och aktiveringsförslag |
| `openid_backup` | Läsa registrets tabeller för backup; ingen skriv- eller dekrypteringsrätt |

Ett förslag gäller en timme och binds till nyckeln, profilversionen och det
aktuella registerbevisets referens och en separat kontrollerad kontaktversion. Både förslag och attest kräver samma
oförändrade, ännu giltiga registerbevis för handlingen. Syntetiska identiteter
kan inte användas för aktivering. En ny registerkontroll efter förslaget kräver
ett nytt förslag när det gamla löpt ut. Registerbevis gäller högst ett dygn.
Aktivering kräver en registrering som är högst ett dygn gammal och en ännu
giltig handling. Giltigheten är fortsatt begränsad till högst 72 timmar.
Samma databaslogin kan aldrig attestera sitt eget förslag, även om kontot
har båda rollerna. Ägare och databasadministratörer har högre privilegier;
deras åtkomst måste hanteras separat från den ordinarie operatörsprocessen.

| Övergång | Villkor och effekt |
|---|---|
| Ny → PENDING_REVIEW | Registreringsrollen skriver verifierad profil och ny enhetsnyckel |
| PENDING_REVIEW → ACTIVE | Två olika operatörsinloggningar, färskt intent, giltigt pass/register/kontakt, extern spärrkontroll och atomisk aviseringspost |
| ACTIVE/PENDING_REVIEW → REVOKED | Spärr; väntande godkännanden annulleras |
| ACTIVE → EXPIRED | Giltighet kontrolleras vid varje användning |
| Nyckelbyte | Samma dokumentgrupp låses; gamla nycklar spärras först externt och därefter lokalt i aktiveringstransaktionen |
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
bao policy write enroller deployment/cluster/enroller.hcl
bao policy write wallet deployment/cluster/wallet.hcl
bao policy write openid-registry deployment/cluster/registry.hcl
bao policy write openid-contact deployment/cluster/contact.hcl
bao policy write openid-maintenance deployment/cluster/maintenance.hcl
bao policy write openid-backup deployment/cluster/backup.hcl
bao policy write openid-recovery deployment/cluster/recovery.hcl
```

För de långlivade API-/bryggprocesserna utfärdas en separat periodisk orphan-
token per tjänst, utan `default`-policy, med exakt `enroller` eller `wallet`
och högst en timmes period. Bryggan får en egen token med `wallet`-policy;
den delar inte plånbokens tokenfil. Klienterna förnyar endast den egna
token och nekar nyckeloperationer vid misslyckad förnyelse. Efter utgång eller
återkallelse behövs en ny behörigt utfärdad token som levereras med atomiskt
0600-filbyte och rätt tjänsteägare. Se [den samlade driftinstruktionen](../production/README.md#privat-konfiguration-och-nycklar)
för livscykel, begränsningar och faktisk testomfattning. Övriga kortlivade
operatörskommandon använder sin särskilt avgränsade policy; de startar ingen
bakgrundsförnyelse och får inte lämnas som obevakad drift.

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
Databasen ska använda SCRAM-SHA-256. Alla anslutningar via den gemensamma
klientgränsen tvingar `require_auth=scram-sha-256` och `gssencmode=disable`;
GSS/Kerberos, MD5 och anslutning utan autentisering stöds inte. Det hindrar
GSS från att ersätta den verifierade TLS-anslutningen.

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
Bakom den lokala nginx-ingressen väljs `trustedProxy: "127.0.0.1"` tillsammans
med samma uttryckliga `bind`. Då kräver API:t att nginx ersätter
`X-OpenID-Client-IP` med anslutningens adress. Direktläget nekar det huvudet.
Flerprocessprovet omfattar båda lägena, inklusive saknat eller otillåtet huvud.
Den samlade profilens separata CI-prov kör nginx-routning och komposition ihop;
ett godkänt faktiskt utfall måste knytas till samma revision före release.
Readiness-proben ansluter till den privata lyssnaren; bakom lokal ingress
kontrollerar den TLS-namnet `localhost` och behåller API:ts publika Host.

Registreringsinstansen använder `role: proofing`, `workers: 1`, enroller-
konton samt fälten `team`, `bundle`, `developmentAttestation`, `csca` och `jar`.
Ange även `cscaCrl` med absolut sökväg till en aktuell, betrodd CSCA-spärrlista
för att kunna registrera identiteter. Utan den startar tjänsten men avvisar
registrering. Fältet tillåts bara för `proofing`; autentiseringsinstanserna
behöver ingen passverifiering. Se [spärrkontrollen](../../verification/README.md#spärrade-dokumentsignerare).
Den behöver verifierarens fulla modell-/Java-installation. Den mindre
containern ovan innehåller endast autentisering och driftverktyg.
Den gemensamma [appimagen](../Dockerfile) innehåller också de oförändrade,
hashlåsta PostgreSQL-hjulen och registermodulerna. Den kan därför köra
`cluster_serve.py` för proofing eller wallet samt `cluster_bridge.py` med
explicit konfiguration. Dess befintliga standardkommando för SQLite behålls;
en installation byter inte register genom att bara importera imagen.
CI kör bryggans tre kommandoprov och flerprocessprovet även med denna
appimage. De fyra proven verifierar paketeringen och API-gränserna.
Den samlade driftprofilens egna körprov använder även separata faktiska
tjänste-UID:n, PostgreSQL-/OpenBao-images och kortlivade AWS-sessioner mot en
lokal syntetisk ersättning. Det ersätter inte prov på verklig värd eller
verifiering av AWS-IAM och varaktig nyckeltjänståtkomst.

Prova den versionsbundna TLS-proben lokalt med:

```sh
python3 -m unittest discover -s deployment/cluster -p test_probe.py -v
```

SQLite-registret migreras inte automatiskt. Börja med ett separat register
och nyregistrering; kopiera inte SQLite-rader med lokala profilnycklar in i
PostgreSQL. Den enklare HTTP-testtjänsten använder fortfarande SQLite.
SAML-bryggan kan däremot anslutas till det delade registret enligt nedan.

## SAML-brygga

Kör `cluster_bridge.py --config /srv/openid/bridge.json` med
[bridge.example.json](bridge.example.json) som mall. Använd en separat
wallet-login och Transit-token, samma PostgreSQL-register som API:t och
samma skyddade `origins.json` och `federation.json` som Java-processerna.
Bryggan härleder lokal audience som `sp + "/sp"`; ingen separat audience
eller gammal miljövariabel får styra mottagaren. Profilen läses med den
gemensamma läsaren och lägger endast till den befintliga fasta Sandbox-listan.
Profilvalet ger ingen godkänd tillitsnivå.

Konfigurationen kräver `databaseFile`, `baoAddress`, `baoTokenFile`,
`baoCA`, `origin`, `continuityFile`, `originsFile`, `federationFile`,
`socket`, `federationGroup`, `noticeSocket` och `noticeGroup`.
Den privata konfigurationsfilen har läge 0600. Anslutningen och dess
authority-referens är samma bindning som i
[kontinuitetskedjan](#fristående-spärr-och-atomisk-avisering-schema-9).

Federations- och aviseringssocket har separata ägarkontrollerade kataloger
med läge 2710, angiven grupp och sockets med läge 0660. Kontrollera båda
katalogerna före rensning. Bara en övergiven socket som ägs av processen får
tas bort; aktiv tjänst, annan ägare, vanlig fil och symlänk nekas. Om
aviseringens start misslyckas stängs den nyss startade federationsbryggan.
De slutliga serviceidentiteterna/grupperna fastställs och provas i
driftkompositionen.

Samma wallet betjänar login, underskriftsgodkännande och den begränsade
aviseringsytan `next/ack/fail`. Köexportören får ingen profil, aktivering,
spärrfunktion eller databasanslutning. Ett fel efter kömottagning kan ge samma
event igen; den oberoende leveransen måste deduplicera event-ID.
Operatörsbeslut, spärr och kontaktförberedelse behåller sina separata roller.

CI startar det faktiska bryggkommandot med PostgreSQL/SCRAM/TLS, verklig
Transit-kryptografi och syntetisk fristående authority. Proven omfattar
båda profilerna, fasta mottagare, login och underskrift, aviseringsfel och
kvittens, återstart, fel vid delvis start samt extern spärr/avbrott efter
godkännande men före konsumtion. Den byggda registerimagen används också.
Java-/Chromium-provet verifierar samma PG-kärna över TLS genom sin
separata fixturbrygga. Hela den slutliga Java/API/PG-kompositionen,
externa federationsklienter och faktisk kö-/inkorgsleverans behöver
fortfarande provas tillsammans före driftbytet.

## Operatörer

Kör respektive kommando med den berörda personens egen anslutningsfil:

```sh
python cluster_operator.py --database-file /private/requester-db request CREDENTIAL_ID REVIEW_REFERENCE
python cluster_operator.py --database-file /private/approver-db approve PROPOSAL_ID
python cluster_operator.py --continuity-file /private/controller-client.json complete INTENT_ID
python cluster_operator.py --database-file /private/revoker-db --continuity-file /private/controller-client.json revoke CREDENTIAL_ID
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

### Uppgradering av databasschema

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

Nya installationer använder `schema.sql`, version 10. Version 1–9 nekas av den
nya applikationen. Stoppa applikationer och underhåll, ta och verifiera en
backup med den tidigare, låsta kodrevisionen och kör `migrate-1-to-2.sql`
med databasens kontrollerade ägarkonto och fortsätt med `migrate-2-to-3.sql`, `migrate-3-to-4.sql`, `migrate-4-to-5.sql`, `migrate-5-to-6.sql`, `migrate-6-to-7.sql` `migrate-7-to-8.sql`, `migrate-8-to-9.sql` och `migrate-9-to-10.sql`. Börja vid
databasens befintliga version; hoppa inte över steg. Migreringarna är transaktionella och
nekar annan startversion. Starta därefter den nya revisionen och verifiera
readiness, rollgränser och försöksspärren innan trafik öppnas.

Schema-10-backupen omfattar även kontrollgenerationer och registerbindningar, operatörsintent, kontakt-
och aviseringsposter samt externa spärrreferenser. Exakt låsta schema-7-, schema-8- och
schema-9-backuper kan återläsas direkt med det nya verktyget;
den får inga fabricerade registerbevis. Äldre backuper återläses med sin tidigare kodrevision i en stängd miljö,
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
återställning kräver PostgreSQL 18 och den granskade schemakoden. Äldre
schema-7/8-arkiv accepteras endast med sina uttryckligen låsta schemadigester.

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
  --target openid_restore_20261020 --key-config /private/recovery-key.json \
  --erasure-ledger /separate/custodian/erasure-ledger.json \
  --erasure-ledger-sha256 "$CURRENT_ERASURE_LEDGER_SHA256"
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

### Schema 3: registreringsinformation

Schema 3 tillför versionsbundna användarval och återkallelse enligt [registreringsprotokollet](../../docs/registreringsinformation.md). För befintligt schema 2: stoppa skrivare, verifiera backup med tidigare låsta verktyg, kör `migrate-2-to-3.sql` som kontrollerad ägare och verifiera den nya revisionens roller och readiness innan trafik återöppnas. Migreringen skapar inga historiska samtycken. Uppdatera den valfria arkivläsarens `archive-access.sql` separat. Backup omfattar nu också de tre samtyckestabellerna; äldre backuper återläses med tidigare verktyg i stängd miljö innan migrering och återställningsspärr. Ingen produktionstext levereras i repot.

### Schema 4: gallringsjournal för registreringskvitton

Schema 4 tillför den separata journalen och den begränsade funktionen
`retain_consent_evidence`. `openid_maintenance` får anropa funktionen och
läsa journalen, men får ingen läsrätt till samtyckesbevis eller direkt
raderingsrätt. `migrate-3-to-4.sql` körs med stoppade skrivare och verifierad
schema-3-backup från dess låsta verktyg. Uppdatera `archive-access.sql`
separat för arkivläsaren. Den nya journalen ingår i backup och arkivformat 4.
[Förhandsvisning och gallring](../../docs/gallring-samtycken.md) kräver en
explicit policyfil; inget nytt schemalagt jobb aktiveras.


### Schema 5: skydd för underskriftstext vid generell gallring

`purge_expired` väljer endast `federation_requests` där `sign_message IS NULL`.
Utgångna inloggningsbegäranden kan fortfarande gallras i begränsade batcher.
Begäranden med underskriftstext bevaras oavsett utfall; det är samma avgränsning
som i SQLite-verktyget. Bevarandetid, riktad radering, ärendeundantag och
hantering hos motpart/kopior behöver beslutas och genomföras separat.
Skyddet är inte ett beslut om obegränsad lagring eller ett fullständigt
underskriftsarkiv.

Schema 4 och tidigare saknar detta undantag i den generella PostgreSQL-gallringen.
Stoppa applikationer och underhåll, verifiera en backup med den tidigare låsta
revisionen och kör `migrate-4-to-5.sql` som kontrollerad ägare. Migreringen
ersätter funktionen och höjer versionskravet i samma transaktion, utan att
radera några rader eller ge tjänstekonton nya rättigheter. Fel startversion,
upprepad körning eller uteblivet lås stoppar den. Gör efterprov innan underhåll
eller trafik återöppnas. Ny applikation, backupverktyg och individuellt
ärendeuttag kräver numera schema 10; personlänksmigreringen nedan ska också köras. Äldre backuper återläses med sina ursprungliga
verktyg i stängd miljö och migreras innan aktuell revision används.
Migreringen återskapar inte tidigare raderad text. Arkivlayouten är fortsatt
format 4, med faktisk databasversion i manifestet.

## Personlänkar efter profilgallring (schema 6)

`credential_persons` behåller endast registreringens och personens interna
referenser när profilinnehållet tas bort. En trigger registrerar länken i samma
transaktion som profilen; en felande profilinsättning rullar tillbaka även länken.
En främmande nyckel och triggerkontroll nekar en profil som byter känd personkoppling.
Tjänsterna får inte skriva länktabellen direkt. Det befintliga backupkontot får
läsa den; inga nya konton eller externt anropbara mutationsfunktioner införs.

`migrate-5-to-6.sql` låser registret och fyller länkar från befintliga profiler.
Den gissar inte vilka personer tidigare gallrade eller oavslutade registreringar
tillhör. Fel startversion, omkörning eller uteblivet lås nekar migreringen.
Aktuell app, full backup och rättighetsuttag kräver schema 10. Ta/verifiera först
backup med tidigare låst verktyg, stoppa skrivare och kör migreringen som
kontrollerad ägare; gör efterprov före öppning.

Full backup läser länkar före profiler och återställer dem i samma ordning.
`COPY FROM` aktiverar triggers: ett felaktigt arkiv som utelämnar en befintlig
profils länk får därför inte tyst kompletteras. Återställningen kontrollerar
slutantalet länkar, rullar tillbaka data vid fel och lämnar måldatabasen stängd.
En korrekt kopia bevarar länkar även utan profil och spärrar alla äldre nycklar
enligt ordinarie återställningsmodell.

Länkar ingår i individuella rättighetsuttag och full backup, men inte i det
avgränsade journalarkivet. Arkivformatet förblir 4 med faktisk schema-version 6.
Länken är fortsatt personuppgift, inte anonymisering eller ett beslut om
obegränsat bevarande. Riktad radering, motiverad bevarandetid och kopiehantering
behöver genomföras separat; detta inför inte PostgreSQL-stöd för
SQLite-adapterns byte av personkoppling vid registerkontrollerat passbyte.

## Beslutad radering och återställning (schema 7)

Se [radering i rättighetsärende](../../docs/radering-rattighetsarende.md) för planering med läskonto, verkställighet med registerägaren och obligatorisk extern beslutsförteckning vid återställning. `migrate-6-to-7.sql` lägger till atomisk raderingsjournal och spärrar som också gäller nycklar utan kvarvarande registrering. App, full backup och ärendeverktyg kräver nu schema 10. Arkivformatet är 5; äldre journalarkiv förblir läsbara.


## Registerbevis före tvåpersonersbeslut (schema 8)

`migrate-7-to-8.sql` körs med stoppade skrivare efter verifierad backup med
schema-7-kodens låsta revision. Den nya backup-CLI:n säkerhetskopierar schema 8;
den ska inte användas mot databasen före uppgraderingen. Migreringen bevarar
profiler och historik, skapar tomma registertabeller och låter gamla väntande
aktiveringsförslag löpa ut. Den gör ingen registerkontroll i efterhand.

`RegistryBindings` använder samma frågor, svar, kryptering och identitetskontroller
som tidigare. PostgreSQL skriver beviset genom `record_registry_binding` med en
separat databaslogin i `openid_registry` och en egen Transit-token enligt
`registry.hcl`. Rollen kan inte aktivera, föreslå, attestera eller skriva direkt
i registertabellerna. Förbrukade källreferenser är unika i registret. Kontrollens
referens, källkod, typ, profilversion, handling och tid binds till förslaget och
kontrolleras igen vid attest, även efter väntan på databaslås. Själva identiteten
lagras krypterad. En ändrad person/källa/typ nekas; nationella attribut är fortfarande
frikopplade från SAML/OIDC-utlämning.

Full backup tar med registerbindningar och bevisreferenser. Återläsning spärrar
alla gamla nycklar, annullerar väntande beslut och tar bort aktiveringsdugliga
registerbindningar. Förbrukade referenser behålls tills en separat behörig
raderingsåtgärd beslutas. En exakt låst schema-7-backup kan återläsas till schema 8
utan fabricerad registerhistorik. Personuppgiftsutdrag och beslutade raderingar
omfattar de nya tabellerna. Bindningar följer profilens gallring; bevisjournalens
gallring kan beslutas separat, för redan spärrade nycklar. Journalarkivet i format 5
behåller sitt begränsade innehåll och innehåller inte det fulla registerbeviset
eller den nya förslagsreferensen; använd full backup/rättighetsuttag för dessa.

Detta är en kodmässig förutsättning för sammanhållen drift. En autentiserad verklig
registeradapter, dess åtkomstavtal och återkommande uppdateringar återstår. Testerna
använder en uttrycklig testadapter med reserverade SPAR-exempel och bevisar inte
pass/registermatchning i verklig drift. Kopplingen till fristående spärr och atomisk avisering beskrivs nedan.
Den gemensamma federationsprofilen, tillåtna motparter och det slutliga driftpaketet
måste fortfarande kopplas till samma PostgreSQL-väg innan driftpaketet byts. Byte av pass/personlänk och nationellt attribututlämnande
är separata kontroller. Drifts-, databas- och nyckeladministrationens mandat samt
faktiska oberoende personer ingår i den organisatoriska bedömningen; två olika
login är inte ett färdigt bevis för Diggs K3.4.


## Fristående spärr och atomisk avisering (schema 9)

`migrate-8-to-9.sql` körs med stoppade skrivare efter verifierad schema-8-backup.
Gamla väntande förslag upphör; tidigare genomförda beslut behålls. En behörig
administratör binder `continuity_config` till den nya utfärdarens faktiska
Lambda-ARN. Ingen standard-ARN eller gammal pilotförteckning används.
Kontrollen startar inte om klientens/kontrollerns ARN avviker från databasens.

`postgres_continuity.py` körs som egen process med egen databaslogin i
`openid_continuity` och AWS-identitet som bara får anropa den bundna
spärrfunktionen. Den får inte skriva ENABLED-poster, skapa operatörsbeslut,
läsa profiler eller ändra kontakter. Använd befintlig
[fristående authority och leveranskedja](../continuity/README.md) med ett nytt
namnrum och `TestBeta=false`. En färsk förteckning har ingen pilotfrist;
en gammal kampanjmarkör får aldrig återanvändas eller tas bort för att
förlänga en tidigare pilot.

Den privata kontrollkonfigurationen innehåller exakt `databaseFile`,
`continuityConfig`, `socket` och numerisk `socketGroup`.
`continuityConfig` använder det befintliga privata AWS-formatet med version 1,
region eu-north-1 och fullständig backendFunction-ARN. Socketens katalog ska
ägas av processen, ha rätt grupp och läge 2710; socketen får läge 0660.
Endast behöriga klienter får tillträde. Klienternas privata `continuityFile`
innehåller version 1, absolut `socket` och samma `authority`-ARN.
API och federation har varken AWS-anropsrätt eller kontrollerns databaslogin.

Kontaktoperatören använder en egen login i `openid_contact`, en separat
Transit-token enligt `contact.hcl` och separat IAM-rätt för villkorad,
atomisk initialisering av kontakt och spärrpost. Kommandot
`continuity_operator.py --postgres-config /private/contact.json` använder
fält för databaseFile, origin, baoAddress, baoTokenFile, baoCA och continuityFile.
Övriga argument är samma som i kontinuitetsinstruktionen; mottagaren läses
från standard input. En förlorad kvittens får inte skriva över en spärr eller
byta mottagare. Den separata kontaktpolicyn har i nuläget kryptografisk tillgång
till profilnyckeln och kräver samma skydd som övriga granskningskonton.

Ordinarie beslut följer denna ordning:

1. Kontakt och extern ENABLED-post förbereds efter separat kontaktkontroll.
2. Första operatören kör `cluster_operator.py --database-file /private/requester request CREDENTIAL REFERENCE`.
3. En annan operatör kör `cluster_operator.py --database-file /private/approver approve PROPOSAL`
   och får ett fem minuter giltigt intent. Registreringen är fortfarande väntande.
4. Behörig klient kör `cluster_operator.py --continuity-file /private/controller-client.json complete INTENT`.
   Varje steg spärrar högst en gammal nyckel externt utan databaslås och
   sparar kvittens för samma intent. Om svaret tappas återupptas samma intent.
5. En kort sluttransaktion låser dokumentgruppen och dess nycklar, kräver
   exakt samma nyckelmängd samt färska, oförändrade pass-/register-/kontaktbevis.
   Aktivering, faktiskt operatörsbeslut och aviseringspost skrivs atomiskt.

Aviserings-ID är SHA-256 av `activation:v1:` följt av registreringens ID.
`notice_ipc` kan lämna den opersonliga transportposten till befintlig köexport.
En transportkvittens bevisar kömottagning; den bevisar inte inkorgsleverans.
Gamla referenser blir inte nya aktiveringar vid ett omförsök.

Operatörsspärr kräver både `--continuity-file` och spärrkontots
`--database-file`. Innehavarens spärr går genom samma controller.
Extern spärr består även om det efterföljande databassteget misslyckas.
Avsaknad av aktuell status, okänd nyckel och nätfel får aldrig ge lokalt
ACTIVE som autentiseringsbeslut. Databaskvittenser är kontrollerns intyg om
det utförda steget; den är en betrodd komponent, inte ett oberoende
kryptografiskt bevis på AWS-tjänstens riktighet.

Återläsning är en separat, helt lokal karantänfas. Den gör inga externa
masspärrar, annullerar väntande intent och oskickade aviseringsposter och
lämnar databasen stängd. Kvittenser i en backup är historik. Ett faktiskt
återgångsbeslut kräver separat kontroll mot aktuell authority, operativ spärr
av berörda nycklar och verifierat driftpaket före återöppning.
Ett vanligt återläsningsprov får aldrig utföra den globala åtgärden.
Endast kontrollerad ägare får köra `revoke_all_after_restore()`.

Personkopplingen är ännu baserad på samma verifierade dokumentbindning.
Ett nytt pass är inte automatiskt samma persongrupp i PostgreSQL; granskad
koppling och spärr över passbyte återstår. Detta, verklig registeråtkomst,
aviseringsleverans, HSM, faktisk tvåpersonersorganisation och
produktionsrelease är separata beroenden. Samma container innehåller den
redan låsta AWS SDK-grafen från `deployment/aws/requirements.lock`, dess
licenser och SBOM; inga paketversioner ändras. Tillämplighetsbedömningen
måste förnyas för den nya källrevisionen.


Generell journalgallring hoppar över förslag med kopplat intent. Deras
sammanhängande historik, intentkvittenser och aviseringsposter hanteras genom
ett uttryckligt livscykel-/kontaktbeslut i rättighetsverktyget. Externa
permanenta spärrreferenser bevaras som skyddade säkerhetsreferenser;
motivering och slutlig bevarandetid kräver separat verksamhetsbeslut.


## Registeromkontroll före nytt beslut (schema 10)

Kör `migrate-9-to-10.sql` med stoppade tjänster efter verifierad full backup
från den låsta schema-9-revisionen. Migreringen har begränsad lås- och körtid.
Gamla bevis för väntande utgivning samt ofullbordade förslag och intent löper
ut. Aktiva nycklar behålls. Den gamla tioparameterfunktionen för registerbevis
tas bort; använd aktuell app och aktuella operatörsverktyg tillsammans.

Registerprocessen sparar beständig invalidation och en ny engångsgeneration
före varje anrop. Endast senaste generation får skriva nytt bevis inom
300 sekunder. Förslag, attest och slutförande prövar bevisreferens och
giltighet igen. Ett avbrutet eller misslyckat anrop lämnar det äldre
utgivningsbeviset obrukbart; ett nytt positivt svar kräver nya beslut.
Ingen automatisk spärr av redan aktiva ID:n införs av detta flöde.
Se [registerbindningen](../../docs/registerbindning.md).

Full backup innehåller `registry_checks`. Återställning tar bort både dessa
generationer och registerbindningar innan tjänster får åtkomst. Förbrukade
bevisreferenser bevaras. Produktionsåtkomst och nationell attribututlämning
tillkommer inte genom korrigeringen.

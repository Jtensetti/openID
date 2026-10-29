# Radering i ett verifierat rättighetsärende

`subject_erasure.py` verkställer ett uttryckligt beslut för valda registreringsnycklar.
Förhandsvisning, radering, journal och spärr av samma nycklar stöds för SQLite och
PostgreSQL schema 7. Verktyget avgör varken identitet, rättslig grund eller undantag.
Det har ingen webbendpoint och kontaktar inga deltagare, motparter eller molntjänster.

Handläggaren måste pröva begäran, söka relaterade registreringar och bedöma
bevarande, kopior och mottagare. Rätten till radering har villkor och undantag;
en lyckad databaskörning avgör inte om hela begäran har hanterats.
Se [IMY om radering](https://www.imy.se/privatperson/dataskydd/dina-rattigheter/radering/)
och [verktyget för personuppgiftsutdrag](personuppgiftsutdrag.md).

## Beslut och omfattning

Beslutsfilen är privat JSON med exakt följande fält:

| Fält | Innehåll |
|---|---|
| `format` | `openid-erasure-decision-v1` |
| `case` | Samma `version: 1`, `reference`, `identityCheck` och lista `credentials` som ärendeuttaget. Högst 64 SHA-256-ID:n. |
| `decisionReference` | Referens till det behöriga raderingsbeslutet. |
| `holdReviewReference` | Referens till prövningen av bevarandekrav och undantag. |
| `decidedAt` | Beslutstid som heltal i Unixsekunder. |
| `categories` | Ett uttryckligt beslut för varje kategori i tabellen nedan. |
| `copies` | Referenserna `inventoryReference`, `restoreReference` och `recipientReference` för separat hantering. |

Referenser ska vara 8–96 tecken från `A-Z a-z 0-9 _ -`, utan namn eller personnummer.
Varje kategori har `action: "erase"` eller `"retain"` samt `reasonReference`.
Bevarande kräver också `reviewBy` i Unixsekunder, efter beslutstid och aktuell tid.
En saknad kategori, framtida beslutstid eller förfallen bevarandeprövning stoppar
en ny verkställighet. Referensformatet bevisar inte att ett giltigt beslut finns.

| Kategori | Raderbara uppgifter |
|---|---|
| `profiles` | Krypterat profilinnehåll och SQLite-registrets krypterade registerbindning. |
| `securityCodes` | Säkerhetskodens verifierare och försökstillstånd. |
| `authentication` | Autentiseringsbegäranden och challenge-data; federationsbegäranden utan underskriftstext. |
| `signatures` | Federationsbegäranden med underskriftstext. |
| `consents` | Kvitton och deras registreringsbindningar; policyarkiv bara när inga andra kvitton använder policyn. |
| `contacts` | Lokala kontaktreferenser, aviseringsköposter och spärrkoder där dessa tabeller finns. |
| `lifecycle` | Valda registreringars händelser, aktiveringsförslag, operatörshändelser, profilgallringsbevis och SQLite-registerbevis. |
| `securityReferences` | Måste bevaras av detta verktyg: spärrade nycklar, person-/dokumentlänkar, ersättningskedjor, försökshistorik och parvisa motpartsidentiteter. |
| `sharedJournals` | Måste bevaras av detta verktyg: gemensamma kontroll-, gallrings- och raderingsjournaler. |

De två sista kategorierna är en teknisk avgränsning, inte ett generellt rättsligt
undantag eller en beslutad evig lagring. Om bevarande inte kan motiveras krävs
separat åtgärd och säkerhetsbedömning. En ny raderingsjournal och minimal
`erasure_subjects`-spärr skapas; dessa referenser är också personuppgifter.
Globala poster utan säker koppling och nycklar vars kopplingar förlorats kräver
separat utredning.

Alla befintliga valda registreringar ska redan vara `REVOKED`. Verktyget spärrar
inte ett aktivt ID åt handläggaren. Kända relaterade nycklar måste ingå, blandning
av kända personer nekas, och flera okopplade nycklar kräver separata verifierade
ärenden. Detta bevisar inte att alla system eller alla historiska nycklar hittats.

## Separat beslutsförteckning

Före verkställighet ska förvararen föra in beslutet i en aktuell, kumulativ fil:

- `format: "openid-erasure-ledger-v1"`
- `authorityReference`: referens till ansvarig förvarare
- `reviewedAt`: senaste kontrolltid i Unixsekunder
- `decisions`: de fullständiga beslutsobjekten, även äldre redan verkställda beslut

`erasure_policy.write_ledger(path, value)` kan serialisera en uttryckligt tillförd
förteckning till en ny privat fil och returnerar dess SHA-256. Funktionen fattar
inga beslut. Det finns inget produktionsläge som gissar en tom förteckning från
en gammal backup. En verkligt tom förteckning behöver också verifieras av förvararen.

Förvara filen och dess aktuella hash utanför registerbackupen enligt beslutad
åtkomst- och återställningsrutin. SHA-256 kontrollerar byteinnehåll, inte behörighet
eller aktualitet. En gammal backup kan inte avslöja ett senare beslut som också
saknas i en föråldrad förteckning. Förvararens aktuella förteckning är därför ett
nödvändigt externt underlag. Högst 128 beslut och 4 MiB stöds; gränsen ska hanteras
kontrollerat, aldrig genom att tappa bort historiska beslut.

Förteckningen är instruktioner, inte kvitton på lyckade raderingar. En misslyckad
körning kan ha ett registrerat beslut men ingen verkställighet. Databasjournalen
är det atomiska kvittot; befintliga journalbeslut får inte saknas i förteckningen.

## Körning

Stoppa berörda skrivande tjänster och aviseringsarbetare, slutför spärrkontrollen
och hantera redan köade externa operationer. Förvara källdata, ärende och resultat
i privata kataloger. Filer ska ha läge 0600 och kataloger 0700. CLI skriver inga
profilvärden, koder eller anslutningssträngar till terminalen.

```sh
cd verification
python subject_erasure.py plan --sqlite /private/data/wallet.sqlite \
  --decision /private/rights/decision.json --output /private/rights/plan.json
python subject_erasure.py apply --sqlite /private/data/wallet.sqlite \
  --decision /private/rights/decision.json --output /private/rights/result.json \
  --expected-plan-sha256 "$REVIEWED_PLAN_SHA256" \
  --ledger /separate/custodian/erasure-ledger.json \
  --ledger-sha256 "$CURRENT_ERASURE_LEDGER_SHA256"
```

För PostgreSQL ersätt `--sqlite` med `--database-file`. Planering använder ett
befintligt läskonto utan skriv- eller administratörsrättigheter. Verkställighet
kräver det kontrollerade registerägarkontot. DSN läses ur en privat fil och
kräver `sslmode=verify-full`; CLI erbjuder inget oskyddat testläge.

Granska planens antal och avgränsningar innan dess `planSHA256` används.
Även ändrat innehåll med oförändrat radantal gör planen ogiltig. SQLite använder
`BEGIN IMMEDIATE`, PostgreSQL låser de kända tabellerna innan data läses i en
skrivtransaktion. Tjänstekonton får inte skriva raderingsjournal eller nyckelspärrar.
Okänt schema, sidotrigger i SQLite, ofullständigt urval eller fel journal stoppar
operationen. Högst 10 000 lästa rader och 8 MiB per urval stöds, med tidsgräns.

Radering och journal/spärrar committas tillsammans. Återupprepat beslut skapar
ingen extra journal; återkommet raderbart innehåll efter ett registrerat beslut
stoppar körningen. Resultatfilen skrivs efter databascommit och får inte skrivas
över. Ett fil- eller anslutningsfel kan lämna ett osäkert svar trots commit:
kontrollera den privata journalen före ett nytt försök.

Detta är logisk databasradering. `secure_delete` i SQLite är inte ett intyg om
WAL, lagringsmedia eller andra kopior. Verktyget raderar inte DynamoDB, SES,
externa köer, mottagarnas data, telefoner, processminne, tidigare exporter,
säkerhetskopior eller filsystemets ögonblicksbilder.

## Återställning utan att återinföra raderade uppgifter

Både `recovery.py restore` och `cluster_recovery.py restore` kräver:

```sh
--erasure-ledger /separate/custodian/erasure-ledger.json \
--erasure-ledger-sha256 "$CURRENT_ERASURE_LEDGER_SHA256"
```

Verktygen verifierar förteckningen, återläser i isolering, spärrar återställda ID:n
och verkställer samtliga beslut innan resultatet lämnas för driftgranskning.
Även en nyckel som ännu inte fanns i backupen får en beständig registreringsspärr.
Saknade registrerade beslut, bruten journalbindning eller fel vid radering
underkänner återställningen. PostgreSQL lämnas stängd för anslutningar; SQLite
lämnas med återställningskarantän och privat `erasure-replay.json`.

Gamla raderingsbeslut upphör inte när en bevarandekategori behöver omprövas.
Återspelningen raderar fortfarande beslutad data och rapporterar förfallna
bevarandeprövningar, även när samma beslut redan finns i kopian.
Mänsklig kontroll, aktuell oberoende spärrtjänst och hantering av externa kopior
krävs före driftstart. Besluten raderar inte själva originalbackupen.

## Schema och verifiering

PostgreSQL uppgraderas från schema 6 med `migrate-6-to-7.sql` efter stoppade
skrivare och en verifierad backup med den tidigare låsta revisionen. Migreringen
uppfinner inga äldre beslut. Nyckelspärrar kontrolleras både vid registrering
och vid införande av nya kvitton. SQLite får tabellerna vid normal schemaöppning;
radering kräver ett känt komplett schema. Äldre ofullständiga SQLite-scheman
behöver separat verifierad migrering i isolering före återställningsförsöket.

Full backup omfattar journal och nyckelspärrar. Begränsad arkivexport använder
format 5. Applicera även aktuell `archive-access.sql` separat som kontrollerad
ägare om arkivläsaren används; schema 7 ger inte automatiskt denna roll läsrätt
till de nya journalfälten. Äldre arkivformat 1–4 är fortsatt läsbara. Arkivets hashkontroll
ersätter inte den separata aktuella beslutsförteckningen.

`test_subject_erasure` provar SQLite-urval, andra personers data, bevarandeval,
stale plan, rollback, journalbindning, privat CLI, verklig backup och spärr av
kvittobaserade nycklar. `test_cluster` provar PostgreSQL-roller, migrering,
databastransaktioner och full COPY-återställning med Transit.
Proven använder syntetiska beslut; de utgör varken faktisk ärendehantering
eller ett rättsligt godkännande.


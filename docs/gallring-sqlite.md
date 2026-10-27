# Gallring i SQLite-betan

`verification/sqlite_retention.py` förhandsvisar eller genomför en begränsad
gallring i ett befintligt pilotregister. Den behöver en uttrycklig policyfil
och körs av kontot som äger den privata databasen. Ingen schemaläggning
eller standardpolicy aktiveras av kodändringen.

Före införande behöver ansvarig besluta ändamål, tider, undantag, backuphantering
och vad som måste bevaras som utgivnings-/underskriftsbevis. Policyreferensen
är operatörens uppgift; verktyget verifierar format och tillämpning, inte
beslutsfattarens mandat. Detta är en teknisk del av ID-11 och F14, inte ett
beslut om tillåten behandling eller uppnådd ISO-/Digg-nivå.

## Policy och förhandsvisning

Följande är ett syntetiskt format- och körningsexempel. Värdena är inte
antagna lagringstider. Filen ska vara vanlig, utan länkar eller skrivbehörighet
för andra, och ägas av körkontot eller root.

```json
{
  "version": 1,
  "reference": "EXAMPLE_POLICY_001",
  "profileDays": 30,
  "authenticationRequestDays": 1
}
```

Tiderna måste vara heltal mellan 1 och 3650 dagar, utan implicita standardvärden.
Referensen är 8–96 ASCII-bokstäver, siffror, understreck eller bindestreck;
använd en dokumentreferens utan personuppgifter. Dubbla JSON-fält avvisas.

Kör samma kodrevision som registret. Wallet lägger till tabellerna för
gallringsjournal och bevarad profilmetadata vid sin vanliga schemauppdatering.
Gallringsverktyget skapar varken databas, schema eller identitetsnyckel och
nekar ett äldre schema. Bevara en verifierad backup inför införandet.

```sh
python verification/sqlite_retention.py plan \
  --db /private/wallet.sqlite --policy /private/retention-policy.json --batch 100
```

`plan` öppnar databasen läsande och visar antal per tabell samt om fler rader
är berättigade till gallring. Inga identifierare, profilinnehåll eller PIN-
verifierare skrivs ut. En ändrad databas kan ge annat urval vid genomförandet;
villkoren prövas på nytt under skrivlås.

## Genomförande och journal

Efter granskad ändring och fastställd policy:

```sh
umask 077
python verification/sqlite_retention.py apply \
  --db /private/wallet.sqlite --policy /private/retention-policy.json --batch 100
```

Varje körning tar högst angivet antal rader per tabell, högst 1000.
Profiler och PIN-verifierare kvalificerar efter credentialens sista giltighet
plus `profileDays`. En aldrig aktiverad credential räknas från slutet av dess
24-timmars granskningsfönster. Exakt gränstid, okända tillstånd och felaktiga
tidsfält kvalificerar inte. En spärr förkortar inte automatiskt giltighetstiden
som används för gallringen.

Utgångna autentiseringsbegäranden kvalificerar efter `authenticationRequestDays`.
Federationsbegäranden med `sign_message` bevaras som signeringsunderlag.
Credentials, spärrar, person-/dokumentkopplingar, händelser, försöksbudgetar,
aviseringar, återställningsspärr och identitetsnyckel bevaras.

Före radering av profilinnehåll bevaras credential, profilversion,
verifieringstid och dokumentets sista giltighet i `profile_evidence`.
[Arkivexporten](arkivexport.md) inkluderar dessa metadata i samma fasta
profilkolumner som tidigare. Motstridiga levande/bevarade profilrader nekar
exporten; befintlig metadata skrivs inte över av gallringen.

Urval, metadata, radering och journal skrivs i en enda transaktion med
`BEGIN IMMEDIATE`. Fel rullar tillbaka hela körningen. Databasskyddet nekar
triggerstyrda sidoreffekter och skrivningar utanför gallringstabellerna.
Låsväntan är högst tre sekunder; SQL-arbetet har tio sekunders tidsbudget.
Blockerande kernel-I/O är ingen hård realtidsgaranti.

`retention_runs` innehåller tid, deklarerad policyreferens, hash av den
kanoniska policyn, tider och antal per tabell. Kvittensen på stdout innehåller
journal-ID. Bevara den i den beslutade driftjournalen. Databasjournalen följer
backupen men ingår ännu inte i det separata arkivuttaget; oberoende mottagning
och skyddad förvaring behöver genomföras operativt.

## Kvarstående datalivscykel

`secure_delete=ON` används och återläses. Logisk SQLite-gallring intygar inte
utplåning ur WAL, tidigare kopior, snapshots, backupmedier eller fysisk lagring.
Policy för dessa kopior, spärrad återställning och återtillämpad gallring krävs.
Efter gallring behövs originalnyckeln fortfarande för kvarvarande skyddade
person-/dokumentkopplingar. Saknad nyckel stoppar readiness och nyregistrering;
en ny nyckel skapas inte för att ersätta den gamla historiken.

Fullständig gallring av personkopplingar, journaler, signeringsunderlag,
aviseringar och nycklar kräver egna bevarande-/avvecklingsbeslut. F14 förblir
öppen tills funktionerna införts och faktisk effekt, rotation och oberoende
bevarande är verifierade.

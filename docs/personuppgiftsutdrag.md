# Privat underlag för ett rättighetsärende

`verification/subject_access.py` läser SQLite-betan och `verification/postgres_subject_access.py` läser PostgreSQL-registret för en behörig handläggare. Uttagen ersätter inte identifiering, juridiskt beslut eller ett fullständigt svar till personen. De ändrar inga registeruppgifter, spärrar, nycklar eller scheman och skickar ingenting. Externa tjänster omfattas inte av verktygen.

## Urval och innehåll

En privat ärendefil anger kontrollerade enhetsnyckeldigestar, en icke personlig ärendereferens och referens till den faktiska identitetskontrollen. Referenserna är handläggarens uppgifter; programmet intygar inte att kontrollen har gjorts. En digest för ett oavslutat registreringsförsök kan användas om dess samtyckeskvitto finns kvar. En nyckeldigest är inte i sig en verifierad person.

Uttaget omfattar urvalets registreringar, dekrypterade profiler och lagrat foto, profilgallringsbevis, passreferenser, försöksräknare, förfrågningar, underskriftstext, händelser, informationsversioner, kvitton och lokal aviseringsstatus. Det inkluderar egna undantagna kvitto-ID:n i gallringsjournalen; andra personers undantag följer inte med.

SQLite använder kvarvarande person-/dokumentlänkar även efter profilgallring. PostgreSQL schema 6 använder kvarvarande `credential_persons` även när profilen har gallrats. Ett känt relaterat ID som saknas i ärendet stoppar uttaget; programmen lägger inte automatiskt till det. Urval som korsar kända registrerade personer stoppas. Andra nycklar utan kvarvarande länk måste utredas av handläggaren. Avsaknad av länk bevisar inte att personen saknar fler uppgifter.

Uttaget stöder även TestFlight-registrets kampanjregler och spärrkodsreferenser.
PIN-verifierare, spärrkodens krypterade innehåll (inklusive betakoden), förfrågningshemligheter, kontrollkoder och råa attestbevis lämnas inte i standarduttaget. De lagrade ja-valen och deras textdigest följer med efter kontroll mot kvitto/textversion, men Apple-attestsignaturen omprövas inte här. Fälten anges i `securityFieldsForSeparateReview`. Detta är en teknisk avgränsning, inte ett automatiskt rättsligt avslagsbeslut. Handläggaren ska separat pröva ytterligare information och säker leverans. Underskriftstext kan innehålla andra personers uppgifter och måste granskas före utlämnande.

## Körning i tillåten privat miljö

Verifiera begäran och mottagaren proportionerligt. Dokumentera urvalet i det verkliga ärendet. Skapa en ärendefil med mode `0600`, ägd av körande konto: `version: 1`, `reference`, `identityCheck`, `credentials` (1–64 unika 64-teckens hexvärden). Referenser är 8–96 tecken: bokstäver, siffror, bindestreck eller understreck. Skriv inga personnummer i referenserna.

Använd befintlig privat databas och originalnyckeln i dess vanliga `.identity-key`-fil. Verktyget skapar ingen ersättningsnyckel och använder befintlig Node-baserad profilkryptografi. Enbart kvitton utan profil kräver ingen profilnyckel. Ange en **ny** målkatalog under en befintlig privat katalog. Ersätt exempelvärden med egna sökvägar och aktuell full kodrevision:

```sh
python verification/subject_access.py \
  --db /private/wallet.sqlite \
  --case /private/case-selection.json \
  --destination /private/cases/new-case \
  --revision FULL_40_CHARACTER_COMMIT_SHA
```

Databasen öppnas `mode=ro` i en sammanhängande lästransaktion som tar med committade WAL-data. Ingen `Wallet`-instans eller migrering körs. Kända äldre schemagrupper från huvudgrenen stöds; frånvarande tabeller redovisas. Okända tabeller/kolumner, vyer eller ofullständiga migreringsgrupper stoppar uttaget i stället för att tyst utelämna uppgifter.

Resultatet `case.json` har mode `0600` i en katalog med mode `0700`. Det innehåller känsliga uppgifter i klartext och kräver skyddad förvaring. Terminalen visar enbart kontrollsumma, storlek och krav på granskning. Befintliga mål skrivs aldrig över. Fel lämnar ingen partiell uttagskatalog. En överskriden gräns ger ett misslyckat uttag, inte ett avkortat svar. Normalgränser: 4 MiB, 10 000 lästa rader och 30 sekunders datainsamling; lokala I/O-stopp eller pågående kryptografiprocess har egna begränsningar.

## PostgreSQL

Använd samma privata ärendefil och ett befintligt läskonto, exempelvis en inloggning med rollen `openid_backup`. Administratörsattribut, effektiva skrivrättigheter på registertabeller/kolumner och rätt att köra registrets privilegierade ändringsfunktioner avvisas. `openid_auditor` räcker inte för profiler. Separat behörighet till befintlig Transit-dekryptering krävs för profiler; verktyget ger inga nya behörigheter eller nycklar. Använd inte tjänstens driftkonto som databasläsare.

En privat konfigurationsfil, ägd av körande konto med mode `0600`, innehåller exakt följande fält. Sökvägar är absoluta; `baoCA` får vara `null` om den vanliga betrodda CA-lagringen ska användas. Databas- och tokenfiler måste också vara privata, ägda vanliga filer utan extra hårdlänkar. Lägg aldrig DSN eller token direkt på kommandoraden:

```json
{
  "databaseFile": "/private/reader-dsn",
  "baoAddress": "https://keys.example.invalid",
  "baoTokenFile": "/private/reader-transit-token",
  "baoCA": "/private/keys-ca.pem"
}
```

```sh
python verification/postgres_subject_access.py \
  --config /private/rights-reader.json \
  --case /private/case-selection.json \
  --destination /private/cases/new-case \
  --revision FULL_40_CHARACTER_COMMIT_SHA
```

DSN ska använda `sslmode=verify-full` och uttrycklig värd, användare och databas. CLI har inget läge som stänger av TLS. Uttaget kräver registerschema 7, tar en `REPEATABLE READ READ ONLY`-ögonblicksbild och använder UTC. Kända tabeller låses med `ACCESS SHARE` under läsningen för att hindra samtidig strukturändring; vanliga registerskrivningar kan fortsätta. Okända tabeller/kolumner, vyer, genererade kolumner och radfiltrering (RLS) stoppar uttaget. Rader hämtas med servercursor och storlekskontroll; gränsöverskridande ger inget partiellt svar. Se [PostgreSQLs behörighetskontroller](https://www.postgresql.org/docs/18/functions-info.html#FUNCTIONS-INFO-ACCESS-TABLE) och [Psycopgs servercursor](https://www.psycopg.org/psycopg3/docs/advanced/cursors.html#server-side-cursors).

PostgreSQL-uttaget inkluderar även parvisa motpartsidentiteter, aktiveringsförslag och operatörshändelser. Råa challenge-payloads undantas för separat prövning. Operatörsnamn och fritext kan behöva begränsas vid utlämnandet. SQLite-specifika dokumentlänkar, profilgallringsbevis och aviseringstabeller finns inte i PostgreSQL-schemat. Schema 6 bevarar en intern registrering/person-länk utan foto eller profilinnehåll. Den ingår i uttaget och används även för att hitta relaterade registreringar efter profilgallring. Migreringen fyller länkar från kvarvarande profiler; en länk som förlorats före migreringen eller aldrig skapats vid ett oavslutat försök kan inte återskapas. Sådana valda nycklar redovisas i `credentialsWithoutRetainedPersonLink`. Detta är en konkret sökbegränsning som handläggaren måste utreda, inte ett fullständighetsintyg.

## Komplettering och avslut

Stäm av DynamoDB/SES/köer, kontaktinkorgar, motpartssystem, telefonen, processminne, backuper, snapshots, arkiv och tidigare exporter. Områdena listas i `notCovered`. Delade globala journaler kräver egen prövning. Uttaget garanterar inte fullständighet för alla uppgifter om en person.

Lägg till ändamål, källor, mottagare, bevarandetider/kriterier och övrig information som ska följa svaret. Pröva tredje mans uppgifter och varje begränsning individuellt; dokumentera motiveringen. Använd en verifierad säker leveransväg och dokumentera faktisk leverans och arbetskopians borttagning. En maskinläsbar fil är inte ensam ett begripligt eller fullständigt rättighetssvar. [IMY om rätten till tillgång](https://www.imy.se/verksamhet/dataskydd/det-har-galler-enligt-gdpr/de-registrerades-rattigheter/) och [proportionerlig identifiering](https://www.imy.se/verksamhet/dataskydd/det-har-galler-enligt-gdpr/de-registrerades-rattigheter/identifiering/), kontrollerade 2026-10-28.

`test_subject_access` använder syntetiska personer med riktig SQLite och profilkryptering. Proven kontrollerar urval, äldre profilbevis, hemligheter, journalundantag, fel nyckel, historiskt schema, WAL, gränser, privata filer och oförändrade källdata. Ingen verklig deltagares ärende har hanterats.

`test_cluster` provar PostgreSQL-uttaget mot den tillfälliga databasen och verklig OpenBao Transit: olika personer, flera egna registreringar, saknad personlänk, enbart kvitto, samtidiga spärrar, kontobehörigheter, okända scheman, RLS, gränser och nekad dekryptering. Testerna kräver den separata registertestmiljön; en lokal SQLite-körning verifierar inte PostgreSQL-beteendet.

Beslutad radering och aktuell beslutsförteckning vid återställning beskrivs i [radering i rättighetsärende](radering-rattighetsarende.md). Skyddsreferenser och externa kopior kräver separat prövning.

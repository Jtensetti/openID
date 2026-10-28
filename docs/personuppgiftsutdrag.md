# Privat underlag för ett rättighetsärende

`verification/subject_access.py` gör ett läsande uttag från SQLite-betan för en behörig handläggare. Det ersätter inte identifiering, juridiskt beslut eller ett fullständigt svar till personen. Det ändrar inga registeruppgifter, spärrar, nycklar eller scheman och skickar ingenting. PostgreSQL och externa tjänster omfattas ännu inte av verktyget.

## Urval och innehåll

En privat ärendefil anger kontrollerade enhetsnyckeldigestar, en icke personlig ärendereferens och referens till den faktiska identitetskontrollen. Referenserna är handläggarens uppgifter; programmet intygar inte att kontrollen har gjorts. En digest för ett oavslutat registreringsförsök kan användas om dess samtyckeskvitto finns kvar. En nyckeldigest är inte i sig en verifierad person.

Uttaget omfattar urvalets registreringar, dekrypterade profiler och lagrat foto, profilgallringsbevis, passreferenser, försöksräknare, förfrågningar, underskriftstext, händelser, informationsversioner, kvitton och lokal aviseringsstatus. Det inkluderar egna undantagna kvitto-ID:n i gallringsjournalen; andra personers undantag följer inte med.

Kända person-/dokumentlänkar upptäcker ofullständiga urval även efter profilgallring. Ett känt äldre ID som saknas i ärendet stoppar uttaget; programmet lägger inte automatiskt till det. Urval som korsar registrerade personer stoppas. Andra nycklar utan kvarvarande länk måste utredas av handläggaren. Avsaknad av länk bevisar inte att personen saknar fler uppgifter.

PIN-verifierare, spärrkodens krypterade innehåll, förfrågningshemligheter, kontrollkoder och råa attestbevis lämnas inte i standarduttaget. De lagrade ja-valen och deras textdigest följer med efter kontroll mot kvitto/textversion, men Apple-attestsignaturen omprövas inte här. Fälten anges i `securityFieldsForSeparateReview`. Detta är en teknisk avgränsning, inte ett automatiskt rättsligt avslagsbeslut. Handläggaren ska separat pröva ytterligare information och säker leverans. Underskriftstext kan innehålla andra personers uppgifter och måste granskas före utlämnande.

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

## Komplettering och avslut

Stäm av DynamoDB/SES/köer, kontaktinkorgar, motpartssystem, telefonen, processminne, backuper, snapshots, arkiv och tidigare exporter. Områdena listas i `notCovered`. Delade globala journaler kräver egen prövning. Uttaget garanterar inte fullständighet för alla uppgifter om en person.

Lägg till ändamål, källor, mottagare, bevarandetider/kriterier och övrig information som ska följa svaret. Pröva tredje mans uppgifter och varje begränsning individuellt; dokumentera motiveringen. Använd en verifierad säker leveransväg och dokumentera faktisk leverans och arbetskopians borttagning. En maskinläsbar fil är inte ensam ett begripligt eller fullständigt rättighetssvar. [IMY om rätten till tillgång](https://www.imy.se/verksamhet/dataskydd/det-har-galler-enligt-gdpr/de-registrerades-rattigheter/) och [proportionerlig identifiering](https://www.imy.se/verksamhet/dataskydd/det-har-galler-enligt-gdpr/de-registrerades-rattigheter/identifiering/), kontrollerade 2026-10-28.

`test_subject_access` använder syntetiska personer med riktig SQLite och profilkryptering. Proven kontrollerar urval, äldre profilbevis, hemligheter, journalundantag, fel nyckel, historiskt schema, WAL, gränser, privata filer och oförändrade källdata. Ingen verklig deltagares ärende har hanterats.

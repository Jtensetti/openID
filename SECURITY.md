# Säkerhet

## Nuvarande status

Detta repository innehåller förstudie, arkitekturförslag och arbetsinstruktioner. Det är inte en godkänd e-legitimation och har ingen deklarerad produktionsrelease eller garanterad drifts-/supportnivå.

Det finns ännu ingen genomförd oberoende säkerhetsrevision, konfigurerad produktionsmiljö eller verifierad komplett testsvit för en produkt. Frånvaro av rapporterade sårbarheter ska inte tolkas som att en säkerhetsgranskning har utförts.

## Data och hemligheter

Lägg inte följande i detta publika repository, inklusive issues, pull requests, Actions-loggar och bilagor:

- Verkliga ID-handlingar, biometriska underlag, personakter eller autentiseringshistorik.
- Produktionsnycklar, lösenord, API-nycklar, sessionsvärden eller åtkomstuppgifter.
- Känsliga revisionsbilagor eller detaljerade exploateringsunderlag för andra aktörers system.

Prototypdata ska vara tydligt syntetiska. Använd interna test-ID:n, inte slumpade personnummer eller organisationsnummer som kan förväxlas med verkliga uppgifter. Kontrollerade testidentiteter från en uttryckligen godkänd testmiljö hanteras enligt dess villkor och ska inte antas fria att publicera.

Om en hemlighet råkar publiceras: behandla den som röjd, stoppa fortsatt exponering, återkalla/rotera genom behörig funktion och utred användningen. Att bara ta bort en rad ur senaste commit löser inte exponeringen. Historikändring kräver separat kontrollerat beslut.

## Rapportering av säkerhetsproblem

En särskild privat rapporteringskanal är **ännu inte konfigurerad och verifierad**. Ingen övervakad säkerhetsadress, svarstid eller bug bounty utlovas.

Publicera inte känsliga sårbarhetsdetaljer i en öppen issue. Vid behov kan en allmänt formulerad fråga till projektägaren be om en privat kontaktväg utan att avslöja detaljerna. Före en pilot eller produktionsrelease ska projektet etablera en fungerande privat kanal, namngivna ansvariga och en dokumenterad triage-/kommunikationsprocess.

## Tillåten testyta

Säkerhetstester ska riktas mot egna isolerade miljöer eller motparter som uttryckligen godkänt testet. Att ett testverktyg är öppet eller kan skapa felaktiga protokollmeddelanden ger inte tillstånd att använda det mot myndigheters eller andra leverantörers produktion.

Skilj utveckling, extern testanslutning och produktion åt med separata nycklar, ankare, behörigheter och data. Test- och demonstrationsnycklar får aldrig registreras som produktionsankare.

## Före produktionsdiskussion

Följ grindarna i `docs/05-genomforande.md`. Minst följande ska ha verkliga bevis och ansvariga: utgivningskontroll, befogenhetsseparation, säker nyckelhantering, spärr och återställning, protokollvalidering, dataskydd, incidenthantering, kontinuitet, oberoende tester samt nödvändiga formella beslut och avtal.

Skydd av grenar (branch protection), CODEOWNERS, CI-kontroller och privat rapportering ska kontrolleras i GitHubs faktiska inställningar. Förekomsten av den här filen betyder inte att sådana skydd är aktiverade. En kodagent får inte godkänna sin egen produktionsrelease.

## Arkitektur och beroenden

Se `AGENTS.md`, `docs/04-arkitektur.md` och `THIRD_PARTY.md`. Ingen egen kryptografisk primitiv och ingen generativ AI som identitets- eller underskriftsdomare. Ett bibliotek kan vara en bra byggsten men ersätter inte granskning av den konkreta tjänsten.

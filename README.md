# openID – förstudie för en öppen svensk e-legitimation

**Status: förstudie och agentarbetsyta, inte en utfärdad eller godkänd e-legitimation.**

Målet är att undersöka en självständig svensk e-legitimation med öppen källkod, med tillitsnivå 3 som föreslaget första produktionsmål och möjlighet till anslutning till Diggs auktorisationssystem. Namnet är ett arbetsnamn, inte ett påstående om koppling till OpenID Foundation, Digg eller någon offentlig arbetsgivare.

Underlaget kontrollerades **2026-10-19**. Det skiljer på publicerade krav, vår tolkning, föreslagna teknikval och frågor som behöver skriftliga svar. Det är ett beslutsunderlag, inte ett juridiskt utlåtande eller ett intyg om efterlevnad.

## Läsordning

1. [Avtal, ersättning och affärshypotes](docs/01-avtal-och-affarsmodell.md).
2. [Krav- och evidensmatris](docs/02-kravmatris.md).
3. [Återanvändning från Sweden Connect, Digg och Ena](docs/03-ateranvandning.md).
4. [Föreslagen arkitektur och hotmodell](docs/04-arkitektur.md).
5. [Genomförande, tester och beslutspunkter](docs/05-genomforande.md).
6. [Frågor till Digg – utkast, inte skickat](docs/06-fragor-till-digg.md).
7. [Källregister](docs/SOURCES.md).

## För den som bygger med en kodagent

Läs [AGENTS.md](AGENTS.md). Projektets egna arbetsinstruktioner finns som `SKILL.md` i `.agents/skills/`:

- `digg-compliance`: källkontroll och kravspårbarhet.
- `sweden-connect-integration`: federationsprotokoll och återanvändning.
- `eid-lifecycle-security`: utfärdning, nycklar, spärr och återställning.
- `electronic-signatures`: skillnaden mellan identifiering och underskrift.
- `supply-chain-and-release`: beroenden, licenser, tester och releasebevis.
- `eid-economics-and-reporting`: ersättningsvillkor och rapporteringskontroller.

Instruktionerna är projektspecifika originaltexter. De är inte officiella Digg-skills och ersätter inte sakkunnig granskning. Agentverktyg som inte automatiskt upptäcker denna katalog ska läsa filerna uttryckligen via AGENTS.md.

## Nuvarande avgränsning

Det här steget innehåller dokumentation och arbetsmetodik, inte en mobilapp, produktionsinfrastruktur eller kopierad tredjepartskod. Återanvändbara komponenter är kandidater tills version, licens, beroenden, byggbarhet och säkerhet har granskats.

All prototyputveckling ska använda syntetiska identiteter och isolerade testnycklar. Inga verkliga personuppgifter, ID-handlingar, produktionsnycklar eller ersättningsanspråk hör hemma här. Ingen AI-komponent ska besluta vem en person är eller om en inloggning/underskrift ska godkännas.

Se [SECURITY.md](SECURITY.md) och [THIRD_PARTY.md](THIRD_PARTY.md). Finansiering, organisation, driftansvar och projektlicens behöver beslutas innan ett produktionsspår öppnas.

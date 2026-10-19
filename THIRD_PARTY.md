# Tredjepartsmaterial och licensbeslut

Kontrolldatum: 2026-10-19.

## Vad som faktiskt finns här

Förstudien, arkitekturförslaget, kravmatrisen, agentinstruktionerna och projektets övriga nytillkomna Markdown-filer är projektspecifika originaltexter. De hänvisar till primärkällor och återger korta faktasammanfattningar. De utgör inte officiella Digg-dokument.

Ingen källkod, binär, myndighetslogotyp, font, certifikatuppsättning eller fullständig avtalskopia från de inventerade projekten har importerats i detta steg. Den här filen är därför ett register över **kandidater**, inte en deklaration att deras licenser redan är färdighanterade i en distribuerad produkt.

## Kandidater och kontrollstatus

| Kandidat | Nu känd licensuppgift | Kvar före eventuell införsel |
|---|---|---|
| Sweden Connect Spring Authentication Server, G01 | Apache-2.0 enligt README. | Läs LICENSE/NOTICE, lås release, granska beroenden och distribution. |
| Äldre SAML Identity Provider, G02 | Apache-2.0 enligt README; ersatt projekt. | Ingen nyutveckling planerad här. Vid eventuell referenskopiering krävs separat filgranskning. |
| Credentials Support, G03 | Apache-2.0 enligt README. | Fullständig fil-/beroendegranskning och ansvar för uppdateringar. |
| SignService, G04 | Apache-2.0 enligt README. | Fullständig licens- och beroendegranskning samt avgränsad produktanvändning. |
| Sweden Connect Test Client, G05 | Apache-2.0 enligt README; uttalat testverktyg. | Verifiera licens och begränsa till egen/godkänd testmiljö. |
| Diggs Open Source Project Template, G06 | Lästa README-filen är CC0-1.0. | Kontrollera varje mallfil, SPDX/REUSE och eventuella separata villkor. |
| REST API-profil Lint Processor, G07 | README CC0-1.0; kod EUPL-1.2 enligt projektuppgifter. | Separera text, verktyg och produktkod; pröva licenskonsekvenser för faktisk användning. |
| Wallet Account, G08 | EUPL-1.2 enligt repositorysidan. | Läs licensfil och aktuell revision; ingen implementation vald. |
| Ena-samverkansplattform, G09 | Inte verifierad för kopiering. | Länka som referens; kopiera inte förrän villkor är klarlagda. |

Exakta repositorylänkar och lästa dokumentversioner finns i `docs/SOURCES.md`. En README-etikett är en första uppgift, inte en fullständig licensrevision.

## Införselkontroll

Före kopiering, paketering, inlänkning eller distribution ska ändringen innehålla:

```text
Ursprunglig URL och fullständig revision:
Filer/paket som faktiskt används:
Kod, dokumentation, bild eller verktyg:
Licens och filnivåundantag:
Nödvändig attribution/NOTICE:
Lokala ändringar:
Transitiva komponenter:
Distribution/drift och licensbedömning:
Granskare och uppdateringsägare:
```

Behåll ursprunglig attribution där licensen kräver det. Skriv inte om copyright-rader så att projektet ser ut att ha skapat någon annans kod. Använd inte myndighetsnamn, kvalitetsmärken eller logotyper som ett påstående om rekommendation eller godkännande.

## Projektets egen licens

**Projektlicensen är ännu inte beslutad eller tillagd.** Ambitionen är öppen källkod, men denna dokumentationsleverans har inte fattat ett fullständigt licensbeslut för framtida kod och bidrag.

Apache-2.0 kan utredas för egen kod med hänsyn till de primära kandidaterna; dokumentationens licens och hantering av eventuella EUPL-komponenter behöver bedömas separat. Detta är ett förslag, inte en juridisk kompatibilitetsgaranti eller en redan utfärdad licens.

Före externa kodbidrag eller första distribution ska ägaren besluta licens, lägga till rätt LICENSE-/NOTICE-filer och dokumentera bidragsvillkor. Skapa inga licens-/REUSE-badges som antyder att detta redan är klart.

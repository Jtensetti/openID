---
name: digg-compliance
description: >-
  Använd när en uppgift rör Diggs tillitsramverk, auktorisationsavtal,
  ansökningskrav, offentlig acceptans eller påståenden om godkännande.
  Spårar krav till aktuella primärkällor och håller isär design, test och beslut.
---

# Digg: kravspårning och evidens

Projektspecifik originalinstruktion. Inte officiell vägledning eller en ersättning för juridisk och oberoende säkerhetsgranskning.

## Börja här

Läs `AGENTS.md`, `docs/SOURCES.md`, `docs/01-avtal-och-affarsmodell.md` och berörda rader i `docs/02-kravmatris.md`. Fastställ vilken utfärdare, produkt, tillitsnivå, utgivningsmetod och tidpunkt uppgiften gäller. Saknas dessa uppgifter, markera antaganden och avgränsa arbetet utan att konstruera ett godkännande.

## Arbetsgång

1. Hitta originalhandlingen: författning, tillitsramverk, avtalsavsnitt, bilaga eller teknisk specifikation. En nyhet eller en README får inte ersätta den bindande källa som frågan kräver.
2. Kontrollera publicerings-/ändringsdatum, ikraftträdande och aktuell lydelse. Skilj framtida regler från regler som redan gäller. Spara källa, version och åtkomstdatum.
3. Extrahera det minsta relevanta kravet med exakt avsnitt. Skilj på kravtext, vår tolkning och ett eget designförslag. Återge inte hela externa dokument när en hänvisning och kort sammanfattning räcker.
4. Knyt påståendet till stabilt krav-ID. Lägg till bevis som behövs, ansvarig funktion, kontrollmetod och kvarvarande osäkerhet.
5. Kontrollera beroenden: andra tillitsnivåer, alternativa utgivningsmetoder, avtalsbilagor, underleverantörer och undantag. Ett villkor som gäller statlig utgivning får inte automatiskt användas som stöd för privat utgivning.
6. Vid motstridiga eller oklara källor: dokumentera konflikten och formulera en konkret fråga i `docs/06-fragor-till-digg.md`. Skriv inte en bekväm tolkning som ett fastställt faktum.
7. Uppdatera analysen och kravmatrisen. Status får bara höjas när motsvarande bevis faktiskt finns.

## Granskningsfrågor

- Har godkänd e-legitimation förväxlats med anslutning till auktorisationssystemet?
- Har rätt till offentlig identifiering förväxlats med behörighet till myndighetens uppgifter?
- Har ersättningsvillkor behandlats som en ovillkorlig finansieringsgaranti?
- Har ett biblioteks säkerhetsfunktion förväxlats med verifierad efterlevnad i vår drift?
- Har en viss certifiering, användarvolym eller driftsmodell påståtts obligatorisk utan stöd?
- Framgår det vem som faktiskt godkänt vad och på vilket underlag?

## Leveransformat

```text
Fråga och avgränsning:
Krav-ID:
Primärkälla, avsnitt, version och kontrolltidpunkt:
Kort kravsammanfattning:
Vår tolkning:
Föreslagen kontroll och evidens:
Kvarvarande osäkerhet:
Behövt besked eller granskare:
Status före/efter och skäl:
```

## Stoppsignal

Om ett produktionsbeslut hänger på ett obekräftat villkor ska det blockeras och eskaleras till behörig människa. Fortsätt gärna med avgränsad analys eller syntetiska tester; ersätt inte det saknade beskedet med modellens självförtroende.

## Exempel på uppdrag

”Kontrollera om vår föreslagna utgivning med befintlig e-id täcks av den aktuella metoden, identifiera avtalsberoenden och uppdatera ID-04 utan att anta att vi är godkända.”

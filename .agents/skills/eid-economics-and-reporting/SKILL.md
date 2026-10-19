---
name: eid-economics-and-reporting
description: >-
  Använd vid Digg-ersättning, transaktionsvolymer, kostnadskalkyl,
  månadsrapportering, fakturering eller rättelser. Skiljer intjänad
  ersättning från antaganden och blockerar testtrafik och dubbelräkning.
---

# Ekonomi och korrekt beräkningsdata

Projektspecifik originalinstruktion. Läs `AGENTS.md`, `docs/01-avtal-och-affarsmodell.md` och D02–D05/D12 i källregistret. Läs originalbilagorna på nytt när villkor eller format ska implementeras.

## Två olika uppgifter

**Affärskalkyl:** bedöm om en verklig, avtalsenlig tjänst kan bära sina kostnader och finansieras före intjäning.

**Rapporteringssystem:** redovisa bara faktiska, kvalificerande händelser med spårbar härledning. En attraktiv kalkyl ger inte rätt att klassificera fler händelser som ersättningsgrundande.

## Arbetsgång för kalkyl

1. Dokumentera ersättningsvillkorens version, aktuell period och vilka leveransvillkor som antas uppfyllda. Skilj grundersättning, Sweden Connect-tillägg och rörlig ersättning.
2. Använd inte både full grundersättning och rörlig ersättning på samma volym på ett sätt som originalbilagan inte medger. Årsillustrationen i förstudien är inte en månadsalgoritm.
3. Pröva delår, fördröjd anslutning, uteblivet tillägg, ändrad tariff och kostnadsökning. Nollvolym och första ersättningsmånad ska behandlas enligt faktiskt besked, inte modellens önskade tolkning.
4. Märk varje kostnad som offert, faktisk kostnad eller antagande. Räkna personal, säker drift, identitetskontroll, support, granskning, försäkring och avvecklingsberedskap.
5. Redovisa omsättning, resultat och likviditet separat. Moms och faktureringstid får inte döljas i ett enda belopp.

## Arbetsgång för rapportering

1. Definiera en terminal händelsemodell för identifiering respektive underskrift. Skilj begäran, försök, avbrott och faktisk framgång.
2. Kontrollera miljö, offentlig motpart, avtalsomfattning och transaktionstyp före aggregation. Testtrafik får aldrig övergå till verkligt ersättningsunderlag.
3. Härled aggregerade antal med stabila händelsereferenser och dubblettkontroll. Rapporten ska inte innehålla medborgarnas personuppgifter.
4. Validera fält, datum, typer och antal mot D05 och kompletterande anslutningspaket. Gissa inte bas-URL, autentiseringsheader eller kvittensformat.
5. Avstäm originalhändelser mot rapport och låt en oberoende behörig funktion godkänna underlaget. Bevara versionsspår och rättelseorsak.
6. Testa återförsök, timeout, fel period, dubblett, avbruten underskrift, rättelse och årsskifte mot lokal stub. Följ bekräftade regler för korrigering och idempotens.
7. Prototypen får bara skapa offlineunderlag. Verklig insändning eller fakturering är ett separat behörigt uppdrag med kvalificerande leverans och produktionsgrind.

## Kontrollfrågor

- Har digital posts volymgräns av misstag använts för e-id?
- Har `swedenConnect` behandlats som ett val som automatiskt ger pengar?
- Har en UI-klickning eller skapad begäran räknats som framgång?
- Kan ett återförsök eller en korrigering dubblera antal?
- Har ett obekräftat nollvolymsantagande presenterats som intäkt?
- Går varje rapporterat antal att återskapa och granska utan att sprida personakter?

## Leverans

```text
Period, avtalsversion och källor:
Leveransförutsättningar och obekräftade antaganden:
Formel/klassificeringsregel:
Kostnadsunderlag eller händelsekälla:
Avstämning och testresultat:
Rättelser och revisionsspår:
Likviditet/utfall och känslighetsanalys:
Behörigt godkännande som återstår:
Insändningsstatus: INTE SKICKAT om inget verifierat anrop skett:
```

## Stoppsignal

Kalkylen kräver fabricerade användare, konstgjord trafik, dold felklassificering eller ett okänt avtalsvillkor. Blockera ersättningsanspråket, rätta modellen och dokumentera osäkerheten. Optimering av en legitim verksamhet får inte bli manipulering av underlaget.

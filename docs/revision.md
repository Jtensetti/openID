# Revision av hela tjänsten

Detta dokument beskriver hur kod, drift och verksamhetskontroller kan följas
upp tillsammans. Det är ett förslag till arbetssätt. En behörig ledning behöver
besluta om omfattning, resurser och ansvar. En oberoende internrevisor ska
självständigt fastställa revisionsplanen och genomföra granskningen.

Utvecklingens egna tester och AI-baserade granskningar är underlag för revision.
De utgör inte oberoende internrevision, ISO-certifiering eller Digg-godkännande.
Formell kravstatus framgår av [kravmatrisen](digg-kravmatris.md).

## Omfattning

Målet är ett ledningssystem för informationssäkerhet som omfattar hela
verksamheten bakom tjänsten: utveckling, grundidentifiering, utgivning,
autentisering, intyg, eventuell dokumentunderskrift, spärr, återställning,
support, bevarande och avveckling. Personal, arbetsstationer, CI, privilegier,
nyckelförvaltning och säkerhetskritiska underleverantörer behöver ingå.

Den juridiska utfärdaren, ansvariga funktioner, informationstillgångar och
externa gränssnitt behöver framgå av omfattningsbeslutet. Molnutförande
flyttar inte bort utfärdarens ansvar för kontrollerna.

Varje revisionsbevis ska ange körläge och miljö. SQLite-betan,
PostgreSQL/OpenBao, WebAuthn-labben och den stängda driftcontainern är olika
implementationer. En kontroll i ett körläge får inte räknas som införd i ett
annat. Ej mergade ändringar redovisas separat från den fasta baslinjen.

## Kriterier

- [Diggs tillitsramverk](https://www.digg.se/digitala-tjanster/e-legitimering/om-e-legitimering/tillitsnivaer-for-e-legitimering/tillitsramverk-for-svensk-e-legitimation)
  och aktuell vägledning, med vald tillitsnivå och utgivningsmetod.
- [ISO/IEC 27001:2022](https://www.iso.org/standard/27001) med
  [Amd 1:2024](https://www.iso.org/standard/88435.html), enligt projektets mål
  om ett ledningssystem som kan certifieras. Klimatrelevans ska beaktas i
  kontext och intressentkrav.
- Beslutad riskbehandlingsplan och Statement of Applicability, SoA. Samtliga
  93 referenser i Annex A behöver övervägas. Val och uteslutningar motiveras
  utifrån risker och andra tillämpliga krav.
- Beslutade interna krav, avtal och de protokollprofiler som faktiskt gäller
  för tjänsten och motparterna.

Utgåvor kontrollerade 2026-10-24. Exakta revisionskriterier ska fastställas
mot tillgänglig licensierad standardtext. Digg kräver på nivå 3 ett LIS
baserat på ISO 27001 eller likvärdiga principer. Projektets mål om full
ISO-överensstämmelse är ett separat, mer omfattande åtagande.

[ISO 19011:2026](https://www.iso.org/standard/19011) är aktuell vägledning för
revisionsarbetet. Revisionsfunktionens kompetens, opartiskhet och rapportering
till ledningen behöver dokumenteras. Digg K2.9 kräver självständig planering
över tre år. Certifiering och Diggs prövning är separata bedömningar.

## Bevisregister

Ett bevisregister bör innehålla följande fält:

| Fält | Innehåll |
|---|---|
| Referens | Stabilt bevis-ID och berörda krav |
| Baslinje | Full källrevision och vid behov artefaktens kontrollsumma |
| Miljö | Körläge, konfiguration, datum och dataklass |
| Kontroll | Förväntat beteende, metod och faktiska resultat |
| Begränsning | Testdubblar, ej provade delar och kvarstående osäkerhet |
| Ansvar | Utförare, granskare och eventuell beslutsfattare |
| Förvaring | Skyddad referens, åtkomst, bevarandetid och läsbarhet |

En testspecifikation visar vad som ska provas. Kod visar en avsedd kontroll.
En testkörning visar resultatet i angiven miljö. Verksamhetsjournaler och
oberoende kontroll behövs för att styrka faktisk tillämpning över tid.
Uteblivet privat underlag markeras som ej styrkt, inte som bevisat obefintligt.

Personakter, avtal, nyckelceremonier, riskacceptanser och känsliga
revisionsbilagor ska hanteras utanför det publika repot. Se
[SECURITY.md](../SECURITY.md). Daterade granskningsresultat hör till PR:n och
den skyddade rapporten; denna sida beskriver det återanvändbara arbetssättet.

## Förslag till första revision

1. Bekräfta omfattning, juridisk huvudman, kriterier och revisorns oberoende.
2. Granska ledningskraven i avsnitt 4–10 samt beslutad riskmetod och SoA.
3. Följ utgivningsfall genom ansökan, identitetskontroll, oberoende beslut,
   nyckelbindning, avisering, användning, spärr och bevarande.
4. Prova befogenhetsseparation genom kodrelease, databasadministration,
   nycklar, återställning och säkerhetslogg. Två konton är inte bevis för
   två oberoende personer.
5. Bevittna nyckelceremoni och en sammanhängande återställningsövning.
   Kontrollera separat spärr, larm, leveransfel och förlorad telefon.
6. Bedöm leverantörer, personal, dataskydd, incidenthantering, support,
   kontinuitet och avveckling med intervjuer och skyddade stickprov.
7. Rapportera kriterium, bevis, slutsats och kvarstående avvikelse till ledningen.
8. Följ upp rotorsak, korrigerande åtgärd och verifierad effekt. Ledningen
   genomför sin dokumenterade genomgång av LIS.

Urvalet bestäms av revisorn utifrån risk och väsentlighet. Få pilotärenden kan
behöva granskas i sin helhet. Syntetiska övningar ska skiljas från inträffade
ärenden. En leverantörs certifikat och ett positivt komponenttest ersätter
inte granskning av OpenID:s egen integration och ansvar.

## Förslag till treårigt program

Programmet räknas från beslutad start. Kvartalsindelningen är ett förslag,
inte en föreskriven ISO-frekvens. Revisorn kan ändra moment och intervall
utifrån risk, tidigare avvikelser och väsentliga ändringar.

| Period | Moment |
|---|---|
| Före extern revision | Samlad förstagångsrevision av hela omfattningen |
| År 1 kvartal 1 | Utgivning, personbindning och administrativa befogenheter |
| År 1 kvartal 2 | Nycklar, ankare och leverantörer |
| År 1 kvartal 3 | Incident, spärr, larm och kontinuitetsövning |
| År 1 kvartal 4 | Samtliga ledningskrav, SoA och årsrapport till ledningen |
| År 2 kvartal 1 | App, stödmatris, biometri och identifieringsmetod |
| År 2 kvartal 2 | Federation, metadata, attribut och eventuell underskrift |
| År 2 kvartal 3 | Dataskydd, logg, bevarande och gallring |
| År 2 kvartal 4 | Samlad LIS-uppföljning och tidigare avvikelser |
| År 3 kvartal 1 | Nyckelceremonier, privilegier, CI och release |
| År 3 kvartal 2 | Leverantörsbyte och avvecklingsövning |
| År 3 kvartal 3 | Helkedjekapacitet, återställning och incidentlärande |
| År 3 kvartal 4 | Samlad återrevision och nästa treårsplan |
| Vid större ändring | Extra granskning av berörda risker och kontroller |

## När en punkt får stängas

Ett stängningsförslag ska ange berört krav, rotorsak, genomförd åtgärd,
revision, miljö, test eller verksamhetsbevis och ansvarig verifierare.
Verifieraren bedömer även att samma brist inte kvarstår i en annan del av
omfattningen. Riskacceptans får inte ersätta ett bindande krav.

Ett nytt dokument, ett grönt test eller en ifylld statusruta kan inte ensamt
höja formell kravstatus. Oberoende granskning och behörigt beslut ska anges
när kontrollen eller projektets releasekrav kräver det.

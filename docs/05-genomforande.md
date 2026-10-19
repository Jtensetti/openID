# Genomförandeplan och teststrategi

Datum: 2026-10-19. Planen nedan behåller sina beslutspunkter. **G1 har nu en körbar lokal implementation** för P0-02–P0-05 i [prototype/](../prototype/README.md), med exakt scope, tester och avvikelser i [verifieringsrapporten](../prototype/evidence/verification.md). Övriga aktiviteter är planerade om inget separat resultat anges. En komplett e-id-produkt eller oberoende accepterad grind finns inte.

## 1. Två parallella spår

Ett teknikspår kan skapa lärande utan att vi först köper en full produktionsorganisation. Ett verksamhetsspår måste samtidigt avgöra om ett verkligt utfärdaransvar går att finansiera och bemanna. Ingen av dem ersätter den andra.

Prototypen får aldrig användas som bevis på att verksamhetsspåret är klart. En ekonomisk prognos får heller inte användas för att hoppa över ett negativt säkerhetstest.

## 2. Beslutspunkter

| Grind | Arbete | Bevis för att gå vidare | Det som fortfarande inte är tillåtet |
|---|---|---|---|
| G0: avgränsad förstudie | Besvara blockerande avtalsfrågor, välja målgrupp och tillitsmål, ta fram kostnadsunderlag. | Skriftliga besked där tolkningen är osäker, budget med stressfall och ansvarig beställare. | Löften om intäkt, tillitsgodkännande eller produktionsstart. |
| G1: isolerad protokollprototyp | Utvärdera G01/G05, låsa versioner och köra syntetisk autentisering. | Reproducerbart bygge, licensunderlag och protokolltestresultat med exakt scope. | Verklig utgivning, riktiga personuppgifter eller produktionsfederation. |
| G2: utgivnings- och säkerhetsdesign | Välja utgivningsmetod och autentiseringsmedel; specificera spärr, återställning, HSM och underskrift. | Granskade designbeslut, hotmodell, dataflöden och stängda kritiska designluckor. | Att marknadsföra en granskningsplan som godkänd säkerhet. |
| G3: verksamhet och oberoende verifiering | Etablera finansiering, roller, avtal, drift, revision och specialisttester. | Fungerande kontroller och spårbar oberoende granskning; komplett ansökningsunderlag. | Att anta att ansökan redan innebär beslut. |
| G4: formella beslut och kontrollerad introduktion | Inhämta erforderliga godkännanden, teckna relevanta avtal och genomföra accepterad teknisk anslutning. | Faktiska beslut/avtal med scope; godkänd drifts- och incidentberedskap; dokumenterat startbeslut. | Att använda tidigare labbresultat som generellt produktionsgodkännande. |
| G5: löpande förvaltning | Drift, support, kontroll, revision, rapportering och förändringshantering. | Regelbundna kontrollresultat och hanterade avvikelser. | Ersättningsanspråk för testtrafik eller icke kvalificerande leverans. |

G0 och G1 kan pågå parallellt inom en beslutad begränsad budget. Grinden är ett beslut, inte en kalenderdeadline. Projektet har ingen verifierad total kostnad eller garanterad ansökningstid.

## 3. Prioriterad arbetskö

### P0 – kan påbörjas utan verkliga identiteter

| Uppgift | Leverans | Beroende/acceptans |
|---|---|---|
| P0-01: svar från Digg | Daterad fråge-/svarsmatris mot `docs/06-fragor-till-digg.md`. | Utkastet ska först få riktiga bolags-/kontaktuppgifter. Inget är skickat. |
| P0-02: upstream-granskning | Beslutsunderlag för G01/G03/G04/G05 med release, commit, licens och kompatibilitet. | Följ `supply-chain-and-release`; använd inte obestämda `latest`-versioner. |
| P0-03: lokal labbstruktur | Föreslagen `prototype/` med självbeskrivande start-/stopp-/testinstruktioner. | Exponera inte mot internet; inga riktiga personnummer, hemligheter eller produktionsankare. |
| P0-04: protokollminimum | Ett syntetiskt lyckat flöde plus negativa motpartstester. | Loggar visar test-ID och resultat, inte en påhittad tillitscertifiering. |
| P0-05: livscykelmodell | Tillståndsdiagram och tester för spärr, utgång och ersättning. | Negativa tillståndsövergångar nekas även vid parallella anrop. |
| P0-06: rapporteringsmodell | Offlineklassificering och aggregation med syntetiska händelser. | Ingen nätverksinsändning, inga riktiga organisationsidentiteter i exempel. |
| P0-07: kostnad och organisation | Offerter eller öppet markerade antaganden; roll-/ansvarskarta. | Intäktsosäkerhet och separation av befogenheter måste synas. |

### P1 – kräver specialistval och prövade avtal

| Uppgift | Leverans | Beroende/acceptans |
|---|---|---|
| P1-01: utgivningskanal | Granskad metod med rättsligt och avtalsmässigt stöd. | D08/D09, målgrupp och vald tillitsnivå. |
| P1-02: autentiseringsbärare | Dokumenterade säkerhetsegenskaper och återställningsstrategi. | Inga antaganden om att alla telefoner eller passkeys är likvärdiga. |
| P1-03: nyckelförvaltning | Ceremonier, HSM-design, backup, rotation och incidentövning. | Oberoende granskning av både teknik och roller. |
| P1-04: avancerad underskrift | Avgränsad profil, prototyp och fullständig valideringskedja. | Separat ansvarig specialist och syntetiska dokument först. |
| P1-05: dataskydd | Datakarta, rättsliga bedömningar, åtkomst- och lagringsregler. | Kontrollerad hantering av utgivningsunderlag; inget känsligt i publika repot. |
| P1-06: förvaltningsberedskap | Incident-, support-, kontinuitets- och revisionsprocesser. | Övning och mätresultat, inte enbart policydokument. |

### P2 – först efter föregående grindar

Formella ansökningar, avtalstecknande, godkänd anslutning, kontrollerad användarintroduktion och eventuell produktionsrapportering. Dessa är separata uppdrag som kräver behörig människa, verklig verksamhet och verifierade förutsättningar.

## 4. Testlager

**Enhetstester:** tillståndsövergångar, datum-/periodgränser, klassificering, attributminimering och behörighetsregler.

**Egenskaps- och samtidighetstester:** återspelning, dubbel konsumtion av samma transaktion, parallell spärr, återutgivning och dubbla rapporteringshändelser.

**Protokollintegration:** versionerade profiler och motparter; positiva och negativa SAML-/OIDC-fall för de flöden vi faktiskt implementerar.

**Säkerhetsgranskning:** specialistbedömning av identitetskontroll, kryptografisk användning, federation, administration, återställning och leveranskedja. Vanlig kodtäckning räcker inte.

**Driftprov:** last, kapacitet, tjänstebortfall, nyckel-/certifikatbyte, återläsning och operativ incidenthantering. Avtalsmätning ska ha tydlig avgränsning.

**Användbarhet och tillgänglighet:** begriplig motpart och avsikt, användning med hjälpmedel, felmeddelanden, förlorad enhet och alternativ vid särskilda behov.

## 5. Obligatoriska negativa testfall för första säkerhetsgranskningen

| Test-ID | Scenario | Förväntat systembeteende |
|---|---|---|
| NEG-01 | Fel mottagare eller oregistrerad returadress. | Inget användbart identitetsintyg till den otillåtna mottagaren. |
| NEG-02 | Felaktig signatur, fel ankare eller otillåten algoritm. | Begäran/svaret nekas enligt vald profil, utan osäker fallback. |
| NEG-03 | Samma begäran eller godkännande används igen. | Ingen andra framgång som kringgår profilens replay-skydd. |
| NEG-04 | Utgången eller spärrad credential. | Nekad autentisering/underskrift; ingen ersättningsgrundande framgång. |
| NEG-05 | Spärr konkurrerar med pågående autentisering. | Utfallet följer dokumenterad konsistensregel och kan granskas. |
| NEG-06 | Administratör försöker ensam utfärda åt annan person. | Separationen stoppar även alternativa databas-/driftsvägar. |
| NEG-07 | Support manipuleras till ny enhet eller PIN-reset. | Återställningskraven består; avvikelsen är spårbar. |
| NEG-08 | Signerat dokument skiljer sig från godkänt dokument. | Underskrift nekas eller valideringen avslöjar felet; ingen dold substitution. |
| NEG-09 | Test, avbrott eller dubblett når rapporteringslagret. | Händelsen utesluts med dokumenterad orsak. |
| NEG-10 | Rapporteringsanrop time-outar efter möjlig mottagning. | Ingen blind dubblering; kvittens-/rättelseregler måste kunna tillämpas. |
| NEG-11 | Metadata pekar på otillåtna interna nätverksmål. | Ingen godtycklig serverförfrågan till interna resurser. |
| NEG-12 | Loggning råkar få hemlighet eller känsligt underlag. | Testet upptäcker läckan; artefakten får inte publiceras eller releasas. |

NEG-10 körs mot lokal stub i prototypen tills Diggs verkliga protokollregler är bekräftade. Körda G1- och G2-fall samt kvarstående luckor redovisas i [aktuell verifieringsrapport](../prototype/evidence/g2-verification.md); NEG-10 är ännu inte kört.

## 6. Definition av klart för en utvecklingsuppgift

En uppgift är klar först när den avgränsade förändringen är granskad, relevanta testfall faktiskt körts, beroenden och källor är dokumenterade och kvarvarande risker redovisats. Rapportera exakta kommandon, miljö, revision och resultat. Skriv uttryckligen om ett test inte gick att köra.

Minimirapport:

```text
Uppgift / krav-ID:
Ändrade filer:
Källor och profilversioner:
Vad som implementerades:
Vad som fortfarande är simulerat:
Körda kommandon och resultat:
Negativa testfall:
Licens-/beroendeförändring:
Kvarvarande risk:
Granskare och beslut:
```

Agenten får inte byta `OPEN` till `ACCEPTED` för att den själv tycker att lösningen är rimlig.

## 7. Avbryt eller ompröva när

Ekonomin förutsätter en obekräftad ersättningsrätt; ensam kontroll över utgivning inte går att undanröja; nödvändig register-/identitetskontroll saknar stöd; en kritisk komponent saknar hållbart underhåll; återställning blir en svag genväg; eller oberoende verifiering inte kan finansieras.

Att avbryta det egna utfärdarspåret behöver inte göra teknikspåret värdelöst. En separat, ärligt avgränsad produkt som testverktyg, integrationsstöd eller förvaltningskomponent kan vara ett annat affärsbeslut. Den får inte marknadsföras som samma sak som en godkänd e-legitimation.

G2-fortsättningen inför beständig syntetisk livscykel, atomisk revisionslogg, backup/återläsning och offline-avstämning samt ett separat stängt driftpaket. Se [körinstruktioner](../prototype/README.md) och [driftpaketets status](../ops/README.md). P0-06 är delvis implementerat: inga verkliga underlag skickas och transport/kvittens/korrigering återstår. Ingen G2–G4-grind har accepterats.

Nästa tekniska del är nu implementerad i labben: WebAuthn-registrering och
inloggning med testnyckel samt webbklient/PWA utan obligatorisk appbutik.
[Verifieringen](../prototype/evidence/web-verification.md) beskriver positiva
och negativa prov, beständig nyckel/spärr och återstående enhets-/utgivningstest.
Detta är teknisk evidens för ett alternativ, inte slutligt val av godkänd
autentiseringsbärare eller accepterad G2-grind.

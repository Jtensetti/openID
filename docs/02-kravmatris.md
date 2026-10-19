# Preliminär krav- och evidensmatris

Kontrollerat 2026-10-19. Källor: [SOURCES.md](SOURCES.md). **Samtliga rader är ÖPPNA. Ingen efterlevnad är verifierad.** En dokumenterad plan är inte bevis på en fungerande kontroll.

Matrisen prioriterar etableringskritiska delar. Den är inte en fullständig genomgång av varje tillitskrav, ansökningsblankett, teknisk profil eller tillämplig lag. Formuleringarna under Kontrollområde är indexetiketter; läs originalets fullständiga villkor, avgränsningar och tillitsnivå. Bevisförslagen är projektets egna arbetsuppgifter, inte dokumentmallar som Digg har godkänt.

## Status och ansvar

Tillåtna statusvärden: `OPEN`, `DESIGNED`, `IMPLEMENTED`, `INDEPENDENTLY_TESTED`, `ACCEPTED`, `NOT_APPLICABLE_WITH_REASON`.

`ACCEPTED` ska alltid ange vem som accepterat vad och med vilket mandat. Intern acceptans, ett passerat test och Diggs formella beslut är olika saker. Rollnamnen nedan är föreslagna funktioner; ingen person är ännu utsedd. Externa specialister kan bidra men får inte vara en osynlig ansvarslucka.

## A. Företag, ledning och oberoende

| ID | Kontrollområde | Primärkälla | Föreslaget bevis/arbete | Ansvarsfunktion |
|---|---|---|---|---|
| GOV-01 | Företagsbehörighet | D02 §§5.2–5.3 | Samla registrerings-, representations- och skatteunderlag; kontrollera ägar- och avtalskedjan. | Bolagsledning |
| GOV-02 | Ekonomisk bärkraft | D02 §5.4; D08 K2.3 | Finansieringsbeslut och likviditetsstress för minst ett års åtaganden; granska beroendet av ännu inte intjänad ersättning. | Ekonomi |
| GOV-03 | Försäkring/garanti | D02 §5.5; D08 K2.1 | Jurist och försäkringsgivare jämför faktisk tjänst, undantag och avtalsansvar. | Ledning/juridik |
| GOV-04 | Tillitsgodkännande | D02 §5.6; D07 | Beslut med exakt utfärdare, tjänst, nivå och godkänd utgivningsmetod. Håll isär kvalitetsmärke och auktorisationsavtal. | Regelefterlevnad |
| GOV-05 | Säkerhetsledning | D08 K2.4–K2.5 | Riskregister, policyägare, kontrollkalender och dokumenterade ledningsbeslut. Utred nivåkraven utan att anta att en viss certifiering alltid krävs. | Säkerhetsledning |
| GOV-06 | Intern granskning | D08 K2.9; D03 §8.16 | Oberoende granskningsplan, rapport, åtgärdsägare och spårbar insändning när avtalet kräver den. | Internrevision |
| GOV-07 | Separation av befogenheter | D08 K3.4 | Behörighetsmatris och test där en ensam administratör försöker skapa en annan persons identitet. Granska även indirekta CI-/databasvägar. | Säkerhetsarkitekt |
| GOV-08 | Underleverantörskedja | D02 §5.10; D03 §8.10 | Register över underbiträden/underleverantörer, avtalskrav, granskningsåtkomst, reservlösningar och uppsägning. | Leverantörsansvarig |
| GOV-09 | Arbetsvillkor och etik | D03 §§8.17–8.19 | Dokumentera arbetsvillkor, diskrimineringsförebyggande arbete och korruptionsrisker; verifiera även relevanta leverantörsled. | Ledning/HR |

## B. Identitetens livscykel

| ID | Kontrollområde | Primärkälla | Föreslaget bevis/arbete | Ansvarsfunktion |
|---|---|---|---|---|
| ID-01 | Utgivningspolicy | D08 K5.1–K5.3 | Versionerad utfärdardeklaration, målgrupp, kanaler, användarvillkor och ansvar. | Utfärdaransvarig |
| ID-02 | Identitets- och registerkontroll | D08 K5.7–K5.9 | Dokumentera laglig registeråtkomst, avvikelsehantering och särskilt flöde för skyddade identiteter; använd syntetiska fall i repot. | Registreringsfunktion |
| ID-03 | Val av utgivningsmetod | D08 K5.10–K5.13; D09 | Välj en huvudmetod. Gör separat gap-analys för fysisk kontroll, befintlig godkänd e-id respektive fjärrkontroll; slå inte ihop deras villkor. | Utfärdaransvarig |
| ID-04 | Återanvändning av befintlig e-id | D08 K5.12; D09 | Dokumentera tillitsnivå, avtalsrätt och säker bindning från verifierad person till ny nyckel. En brokerinloggning räcker inte som bevis på egen utgivning. | Juridik/arkitekt |
| ID-05 | Fjärrkontroll med identitetshandling | D08 K5.13; D09 | Beställ bedömning av dokumentäkthet, chipkedja, aktuell giltighet, personbindning och skydd mot injicerad inspelning. En selfie-demo ska inte accepteras. | Identitetsspecialist |
| ID-06 | Innehavarregister | D08 K5.14 | Modellera spårbar koppling mellan verifierad identitet, utgivningsbeslut, autentiseringsmedel och status. Testa felaktiga och konkurrerande uppdateringar. | Livscykelansvarig |
| ID-07 | Faktorer och kopieringsskydd | D08 K6.1–K6.2 | Granska valda enheter, faktorer, export-/synkroniseringsbeteende och attackmotstånd. Ingen automatisk likställning mellan passkey och godkänd nivå. | Säkerhetsarkitekt |
| ID-08 | Återställning | D08 K6.3 | Separat missbruksgranskning av borttappad telefon, PIN-reset, support och ny enhet. Återställningen får inte bli en enklare alternativ utgivning. | Livscykelansvarig |
| ID-09 | Bindning, giltighet och avisering | D08 K6.4–K6.7 | Testa fel person, gammal utgivning, utgången giltighet och oberoende avisering; specificera exakta nivåvillkor före kod. | Livscykelansvarig |
| ID-10 | Spärr dygnet runt | D03 §8.6 | Öva spärr utan åtkomst till den förlorade enheten. Visa att spärr påverkar nästa beslut och alla relevanta aktiva flöden. | Drift/livscykel |
| ID-11 | Avveckling och bevis | D08 K2.7–K2.8, K5.5 | Upprätta lagrings- och avvecklingsplan med rättslig prövning. Varken obegränsad insamling eller löfte om noll historik är förhandsbeslutade. | Dataskydd/ledning |

## C. Kryptografi, protokoll och underskrift

| ID | Kontrollområde | Primärkälla | Föreslaget bevis/arbete | Ansvarsfunktion |
|---|---|---|---|---|
| SEC-01 | Skyddade kanaler | D08 K4.2; T01–T03 | Inventera samtliga förtroendegränser; testa manipulation, återspelning och fel motpart i egen labbmiljö. | Säkerhetsarkitekt |
| SEC-02 | HSM och aktivering | D08 K4.3 | Granska HSM-egenskaper, roller, flerpersonskontroll, backup och återställning. Biblioteksstöd eller SoftHSM är inte produktionsbevis. | Nyckelförvaltning |
| SEC-03 | Sårbarhetsarbete | D08 K4.4 | Tillgångs-/beroenderegister, bevakning, prioritering, patchtest och dokumenterade undantag. | Säker utveckling |
| FED-01 | Federationsprofil | D03 §8.4; T01–T03 | Lås accepterad specifikationsversion, metadata, attribut och tillitsankare; dokumentera vilka profiler som faktiskt testats. | Protokollansvarig |
| FED-02 | Mottagare och användaravsikt | D03 §§8.2–8.3; T01–T03 | Visa verifierad tjänst och login/underskrift tydligt; testa fel audience, ACS/redirect, session, nonce och gammal begäran. | Protokoll/UX |
| SIG-01 | Avancerad underskrift | D03 §8.3; D04 §2; T01 | Kartlägg hela dokument-, nyckel-, samtyckes- och valideringskedjan. Ett autentiseringsintyg eller en signerad JWT är inte ensamt slutbevis. | Signaturspecialist |
| SIG-02 | Underskriftens beviskedja | T01 och dess underskriftsspecifikationer | Spara verifierbar bindning till exakt godkänt innehåll och valideringsunderlag enligt vald profil; juridik granskar långtidsbehov. | Signatur/juridik |
| TEST-01 | Motpartstestmiljö | D03 §8.9 | Separata nycklar och testidentiteter, reproducerbara testfall, integrationsguide och stöd för offentlig aktörs acceptanstest. | Testansvarig |

## D. Drift och ekonomisk rapportering

| ID | Kontrollområde | Primärkälla | Föreslaget bevis/arbete | Ansvarsfunktion |
|---|---|---|---|---|
| OPS-01 | Månadsvis tillgänglighet: 99,9 % | D03 §8.5.1 | Mät enligt avtalets omfattning; definiera mätpunkter, avbrottsberäkning och revisionsspår. En grön startsida är inte ett fullständigt tjänstetest. | Drift |
| OPS-02 | Svarstid: under 1 s för 99,9 % | D03 §8.5.1 | Skilj serverbehandling från användar- och nätverkstid; belastningstesta kompletta kritiska flöden med realistisk HSM-latens. | Prestanda/drift |
| OPS-03 | Support | D03 §8.7 | Språk, åtkomliga kontaktvägar, ärendespårning och bemanning. Skilj supportens öppettider från spärrfunktionens krav. | Support |
| OPS-04 | Incidenter och avbrott | D03 §§8.13–8.14; D06 | Kontaktmatris och övningar; för planerat avbrott följ 48-timmarsregeln, för oplanerat/säkerhet omedelbar rapportering enligt rutin. | Incidentledning |
| OPS-05 | Integrationspåverkande ändring | D03 §8.12 | Förhandsavisering enligt sexmånaderskravet, kompatibilitetstest, migration och rollback. | Förvaltning |
| OPS-06 | Missbruk | D03 §8.11 | Säker utredningsprocess, proportionerliga skydd, behörighetsstyrd bevisåtkomst och tester av falsklarm. | Bedrägeri/säkerhet |
| OPS-07 | Kontinuitet | D08 K2.4 | Återläsningsövning, beroendebortfall, nyckelförlust och frånvaro av nyckelpersoner. Fastställ egna återställningsmål utifrån risk, inte gissad lagtext. | Kontinuitetsansvarig |
| FIN-01 | Transaktionsklassificering | D04 §§2–4; D05 | Händelsemodell som skiljer slutförd identifiering, slutförd underskrift, avbrott, försök, test och dubblett. | Ekonomi/utveckling |
| FIN-02 | Beräkningsdata | D05 | Validera schema, period, motpartsorganisation, typ och antal. Inga personnummer eller dokument i aggregerad rapport. | Rapportansvarig |
| FIN-03 | Korrigering och avstämning | D03 §8.15; D05 | Signerad intern avstämning, versionshistorik och fyrögonskontroll; reda ut återförsök och årsskiften med Digg före implementation. | Ekonomi |
| FIN-04 | Ändrings- och ansvarsberedskap | D03 §§13, 15, 18, 20 | Bevaka tariff-/formatändringar, revision, återkrav och avtalets upphörande; uppdatera ekonomisk stresstest. | Ledning/juridik |

## E. Projektets egna säkerhetsbeslut – inte påstådda Digg-krav

| ID | Föreslagen intern regel | Bevis före acceptans |
|---|---|---|
| INT-01 | Ingen AI beslutar identitet, tillitsnivå eller underskriftsgodkännande. | Arkitektur- och beroendegranskning av beslutsvägar. |
| INT-02 | Prototypen får inte utfärda verkliga identiteter. | Separata miljöer, tydlig testmärkning, stängda produktionsvägar. |
| INT-03 | Testtrafik får aldrig ge ersättningsanspråk. | Negativt rapporteringstest och separation av rapporteringsbehörigheter. |
| INT-04 | Ingen agent godkänner sin egen produktionsrelease. | Mänsklig beslutspunkt och oberoende granskningsunderlag. |
| INT-05 | Säkerhetskritiska ändringar ska ha oberoende granskare. | Namngiven granskning av kod, konfiguration och hotmodell; inte bara en lyckad CI-körning. |
| INT-06 | Tredjepartskod införs med spårbar licens och version. | Versionslåst beroendelista, licensgranskning, SBOM och uppdateringsägare. |

## Evidenspost att skapa per rad

```text
Krav-ID:
Status:
Källa, version och kontrolltidpunkt:
Tolkning och tillitsnivå:
Ansvarig funktion/person:
Designbeslut:
Implementation och konfiguration:
Test-ID och faktiskt resultat:
Oberoende granskare och datum:
Kvarvarande avvikelse/risk:
Beslutsfattare och acceptansomfattning:
Nästa omprövning:
```

Känsliga evidensbilagor ska lagras i en separat kontrollerad yta. Här kan deras referens och granskningsstatus finnas, inte personakter, produktionsnycklar eller detaljer som underlättar angrepp.

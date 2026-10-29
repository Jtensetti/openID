# Kravmatris: mål tillitsnivå 3

Teknisk bas efter PR #41: `3a064b5`, omkontrollerad 2026-10-26. Appens senare
kontroller beskrivs separat i [iPhone-underlaget](iphone-sakerhet.md); deras
bygg-/testrevision ska anges i leveransbeviset. 40 relevanta numrerade punkter för
passbaserad distansutgivning. Varje rad är en samlad punkt, inte varje underkrav.
Status: **T** stark teknisk täckning (6), **D** delvis (23), **S** saknas/ej styrkt (11).
Samtliga har formell status **OPEN**. T betyder inte uppfyllt eller godkänt.
Utkast och nya skydd ändrar inte status utan verifierad tillämpning och evidens.
Detta är en preliminär egenbedömning, inte en revision eller ett procentmått.

Källor: [Diggs ramverk](https://www.digg.se/digitala-tjanster/e-legitimering/om-e-legitimering/tillitsnivaer-for-e-legitimering/tillitsramverk-for-svensk-e-legitimation)
och [vägledning](https://www.digg.se/digitala-tjanster/e-legitimering/om-e-legitimering/tillitsnivaer-for-e-legitimering/tillitsramverk-for-svensk-e-legitimation/vagledning-for-utfardare).
Ramverket omkontrollerat 2026-10-26; vägledning enligt källregistrets senaste
omkontroll. Ramverkstexten anger 2022-10-04; sidfoten 2024-12-20.
Kravnamnen nedan är våra arbetsrubriker. Originaltexten styr.

K2.5 (nivå 4), K5.10–K5.12 (alternativa identifieringsmetoder) och K6.7
(personligt utlämnande) är utanför vald metod, inte uppfyllda. Om metoden ändras
ska tillämpligheten omprövas. Auktorisationsavtal, eIDAS och full Sweden
Connect-profil kräver separata bedömningar.

Rollkolumnen anger behövd funktion, inte tillsatta personer. Evidens finns i
[tekniska krav](krav.md), [arkitektur](arkitektur.md), [testöversikt](testning.md)
och respektive komponent. Klusterfunktioner i CI räknas inte som driftsatta i SQLite-betan.

| Krav | Status | Ansvarig funktion | Område | Kvar för att stänga punkten |
|---|---|---|---|---|
| K2.1 | S | Organisation | Juridisk person, försäkring | Beslut om utfärdarorganisation och försäkringsbevis; enskild firma uppfyller inte juridisk-personkravet. |
| K2.2 | S | Organisation | Operationell verksamhet | Visa bemanning, ansvar och fungerande processer i hela verksamheten. |
| K2.3 | S | Organisation | Ekonomisk uthållighet | Dokumentera finansiering och riskbärande för minst ett år. |
| K2.4 | D | Säkerhetsansvarig | Ledningssystem | Fastställ rutiner, roller och riskregister; genomför och dokumentera risk- och incidentövningar. |
| K2.6 | S | Avtalsansvarig | Underleverantörer | Kartlägg säkerhetskritiska leverantörer och kontrollera avtal, ansvar och underlag. |
| K2.7 | D | Dataskydd/drift | Spårbarhet | PR #41 exporterar minimerade registerjournaler med konsekvent snapshot och separat manifestkontroll. Fullständiga utgivningshandlingar, faktisk arkivmottagning och åtkomstskyddad historik behöver styrkas. |
| K2.8 | D | Dataskydd | Bevarande | PR #41 innehåller COMPLIANCE-lås, separat kvittens och återläsningskontroll; kod-/kontraktsprov ger delvis teknisk täckning. Beslutad bevarande-/gallringsplan, separat förvaltare, driftsättning och operativa läsbarhetsprov återstår. |
| K2.9 | S | Oberoende revisor | Internrevision | Utse oberoende kompetent funktion och upprätta treårig revisionsplan. |
| K3.1 | D | Drift | Fysiskt skydd | Kontrollera molnleverantörens underlag och egna datorer, medier och åtkomst. |
| K3.2 | S | Organisation | Personal | Dokumentera rollanpassad bakgrundskontroll och utbildning före tillträde. |
| K3.3 | D | Drift | Behörigheter | Inventera verkliga konton och inför återkommande åtkomstgranskning och avslutsrutin. |
| K3.4 | D | Organisation/drift | Arbetsfördelning | Klusterkod kräver skilda operatörslogins; verkliga personer, administratörer och drift behöver separeras. |
| K4.1 | D | Säkerhetsansvarig | Kontrollernas effektivitet | Samla hotmodell, riskbeslut och oberoende prov av tillämpliga kontroller. |
| K4.2 | T | Utveckling | Skyddad kommunikation | Negativa kanal-/replaytester finns; granska samtliga driftvägar och extern interoperabilitet. |
| K4.3 | D | Nyckelförvaltare | Servernycklar | Lokala filer/OpenBao är inte bevisad HSM; verifiera hårdvaruskydd, flerpersonskontroll, rotation och återställning. |
| K4.4 | D | Drift | Säker förändring | Lås, samlad CI-grind och daglig advisory-workflow finns. Verifiera faktisk bevakning/larmmottagning, branchskydd, sårbarhetsundersökning, patchansvar och incidentberedskap. |
| K5.1 | D | Utfärdare | Villkor | Publicera fastställda villkor och begränsningar för innehavare och förlitande parter. |
| K5.2 | D | Utveckling/utfärdare | Villkor i ansökan | Visa rätt versions villkor före ansökan och bevara acceptansbevis. |
| K5.3 | S | Utfärdare | Utfärdardeklaration | Färdigställ och fastställ utfärdardeklarationen i organisationens styrande dokument. |
| K5.4 | S | Organisation | Ägande och styrning | Förbered verifierbar redovisning för behörig mottagare. |
| K5.5 | S | Utfärdare | Avveckling | Fastställ ansvar, information, spärr, arkiv och kontrollerad avvecklingsplan. |
| K5.6 | D | Utveckling/utfärdare | Ansökan | Användarinitierad registrering finns; knyt acceptans och villkorsversion till ansökan. |
| K5.7 | D | Utveckling | Nationell identitetsbeteckning | Signerat passfält implementerat och privat prov bekräftat; besluta hantering av saknat nummer utan automatisk aktivering. |
| K5.8 | S | Registeransvarig | Registerjämförelse | SPAR är kandidat; verklig åtkomst, adapter och avvikelseprov saknas. Ingen beställning gjord. |
| K5.9 | S | Registeransvarig | Skyddade uppgifter | Fastställ likvärdig kontroll och begränsad manuell handläggning; syntetiska avvisningsprov räcker inte. |
| K5.13 | D | Utveckling/granskare | Passbaserad distanskontroll | Chip, spärrlista för dokumentsignerare, serverstyrd vridning och försöksgräns finns; kalibrera PAD/biometri och pröva injektion och relä oberoende. |
| K5.14 | D | Registeransvarig | Innehavarregister | Krypterat register finns; inför aktualisering, registeravstämning och dokumenterad avvikelsehantering. |
| K6.1 | T | Utveckling | Två faktorer | Enhetsnyckel och lokal användarverifiering finns; styrk bindning och beteende på stödda fysiska enheter. |
| K6.2 | D | Utveckling | Aktiveringsskydd | Verifiera hårdvarubindning, kloningsmotstånd och spärr vid förändrade lokala skydd. |
| K6.3 | D | Utveckling/support | Byte av aktiveringsmedel | Komplettera säker ersättning vid förlorad telefon och nytt pass utan supportgenväg. |
| K6.4 | D | Utveckling | Unik personbindning | Nyckel/passbindning finns; verifiera registeranknytning, dubbletter och dokumentbyte. |
| K6.5 | T | Utveckling | Giltighetstid | Betan begränsar giltighet till 24–72 timmar och passets datum; fastställ produktionspolicy och riskunderlag. |
| K6.6 | D | Utveckling/utfärdare | Oberoende avisering | Transaktionell utkorg och separat SQS/SES-konsument är inkopplade i den publika betan; syntetisk aktivering och transportkvittens provade. Verklig separat person–kontaktkontroll, leveransbevis och operativ felhantering kvarstår. |
| K6.8 | D | Drift/support | Tillgänglig spärr | Publik beta och appkod är kopplade till separat spärrtjänst. Syntetiskt prov med stoppade betatjänster och återstartad wallet nekar gammal ACTIVE-status och session. Fysisk app, sammanhängande återstartsprov i avsedd driftmiljö, operativ beredskap och oberoende prov återstår; formell status OPEN. |
| K6.9 | D | Utveckling/drift | Säker verkställighet | Signerad spärr, sessionsavslag och negativa tester finns; verifiera drift, missbruksskydd och återstart. |
| K7.1 | T | Utveckling | Giltighetskontroll | Signatur och aktuell spärr/utgång kontrolleras; oberoende kontroll av alla produktionsvägar återstår. |
| K7.2 | T | Utveckling | Angreppsskydd | Engångsutmaningar och bindningar testas; oberoende test av relä, missbruk och full drift återstår. |
| K8.1 | D | Drift | Intygstjänstens tillgänglighet | Testservern kör dygnet runt till och med 30 november 2026, med stopp 1 december 2026 kl. 00.00 svensk tid. Se [driftplan](../deployment/README.md#betans-öppettider). Tidsbegränsad ensam betanod; produktionsnivå och SLA är inte verifierade. |
| K8.2 | D | Utveckling | Intygsskydd | SAML signeras/krypteras och OIDC har bunden kodväxling; full profilmappning och extern validering återstår. |
| K8.3 | T | Utveckling | Förnyad identifiering | Kortlivade begäranden/sessioner finns; verifiera sammanhängande policy för SAML och OIDC i avsedd drift. |

## Uppdateringsregel

Varje stängningsförslag ska ange revision, miljö, provresultat, bevisreferens,
ansvarig och oberoende kontroll där sådan krävs. Verkliga personakter,
konton, nycklar och känsliga revisionsunderlag lagras separat; publikt anges
endast en referens. Varken manuell aktivering eller godkänd CI ersätter granskning.

## Första arbetsordning

1. Fastställ organisationens styrningsrutiner och utse ansvariga utanför kodrepot.
2. Verifiera infört lokalt nyckelskydd och appens [åtta kontrollområden](iphone-sakerhet.md) på avsedd enhet och miljö.
3. Slutför användarprov och driftberedskap för [avisering och spärr](avisering-och-sparr.md),
   inklusive verklig separat kontaktkontroll och leveransfel.
4. Utvärdera SPAR-åtkomst; beställ ingen anslutning utan kostnadsbeslut.
5. Förbered oberoende provning och beslut om utfärdarorganisation.

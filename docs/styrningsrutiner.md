# Drift- och säkerhetsrutiner – förslag att fastställa

Version 0.1, 2026-10-22. Gäller förberedelse för passbaserad distansutgivning.
Dokumentet är ett arbetsförslag. Det är inte en utfärdardeklaration som redan
har trätt i kraft eller ett bevis för att processerna används.

## Fastställande och ansvar

Utfärdaren dokumenterar beslutsdatum, omfattning, dokumentägare, nästa
översyn och utsedda personer i ett privat beslutsregister. Funktioner som
behövs: verksamhetsansvarig, säkerhetsansvarig, nyckelförvaltare,
registreringshandläggare, aktiveringshandläggare, drift, dataskydd och
oberoende revisor. Samma persons två konton är inte personseparation.
Ingen utvecklare eller agent attesterar sin egen säkerhetskritiska release.

## Riskhantering och ändringar (K2.4, K4.1, K4.4)

Inför varje ändring av identitetskontroll, nycklar, kontaktväg, spärr eller
leverantör: registrera tillgång, hot, konsekvens, sannolikhet, befintlig
kontroll, kvarstående risk, ägare och nästa kontroll. Ompröva minst årligen
samt efter allvarlig incident. Kvarstående risk accepteras av behörig person.

För varje release dokumenteras revision och artefakt, ändrade krav,
negativa tester, behörighetsändringar, beroenden, granskningsunderlag,
återställningsväg och beslut. Testdata ska vara syntetiska. Stoppa release
vid oklar nyckelbindning, återupplivad spärr eller saknat säkerhetsbevis.
Återställ aldrig en äldre databas som kan återaktivera spärrade nycklar.

## Behörighet och nycklar (K3.3–K3.4, K4.3)

För privat inventarium över system, roller, rättigheter, ägare, motivering,
senast granskad tid och slutdatum. Granska vid rollbyte, avslut och föreslaget
kvartalsvis intervall. Ta bort överflödig behörighet och dokumentera provet.

Inventera varje nyckels ändamål, algoritm, version, skapande, lagringsskydd,
användande tjänst, backup, rotation och förstöring. Dokumentera inga nyckelvärden.
Pilotens lokala profilnyckel och klustrets OpenBao är inte en verifierad HSM.
Lokalt filskydd minskar felkonfiguration men skyddar inte mot root eller
komprometterat tjänstekonto. Före driftändring: prova saknad, fel, otillgänglig
nyckel och återställning. En saknad nyckel får inte ersättas så att gamla
personprofiler eller identiteter blir felaktigt tillgängliga.

## Incident (K2.4, K4.4)

1. Mottagare registrerar privat ärende-ID, upptäcktstid, berörda system och
   begränsad teknisk evidens. Begär inte passbilder eller lösenord via e-post.
2. Klassificera misstänkt nyckelröjning, felaktig utgivning och förlorad
   spärrstatus som allvarliga. Stoppa berörd utgivning/autentisering vid osäkerhet.
3. Drift isolerar berörd komponent. Behörig operatör spärrar berörda nycklar
   med befintligt granskat förfarande. Bevara relevanta loggar under åtkomstkontroll.
4. Säkerhets- och dataskyddsansvarig bedömer underrättelser och tillämpliga
   tidsfrister mot lag och avtal. Dokumentera beslut, mottagare och tid.
5. Återstart kräver åtgärdad orsak, provade spärrar, aktuella nycklar och
   behörigt beslut. Dokumentera efteranalys och följ upp åtgärder.

## Spärr och återställning (K6.3, K6.8–K6.9)

En mottagen begäran är inte en verkställd spärr. Bekräfta verkställighet först
efter beständig statusändring och kontroll att tidigare sessioner nekas.
Använd befintlig signerad appspärr under pilotens öppettid. Vid förlorad
telefon krävs beslutad alternativ autentisering; namn, personnummer eller
avsändaradress räcker inte. Support får inte aktivera ersättningsnyckel som
bieffekt av spärr. Ingen automatisk återaktivering är tillåten.

Återställ pilot med `verification/recovery.py` enligt deployment-dokumentationen,
vilket spärrar återställda nycklar. Öva i isolerad miljö med syntetiska data:
backup före spärr, spärr efter backup, återställning, avvisning av tidigare
nyckel och session, därefter nyregistrering. Dokumentera tid till återställning,
förlorad information och ansvarigt beslut. Kopiera inte skarpa akter till CI.

## Bevarande och gallring (K2.7–K2.8)

Dataskyddsansvarig fastställer en tabell per datakategori: ändamål, rättslig
grund, åtkomst, bevarandetid, startpunkt, gallringsmetod, backuphantering och
lagstöd för undantag. Ansökan, acceptans, utfärdande, spärr, policyversioner
och revisionsbevis behöver bedömas separat. Ramverkets bevarandekrav får inte
förväxlas med att råa passbilder ska lagras. Inför inte femårig råbildslagring.
Verifiera att nödvändiga bevis faktiskt finns; dagens minimala lagring är inte
bevis för fullständigt arkiv. Inga nya lagringstider införs av detta utkast.

## Underlag till utfärdardeklaration (K5.1–K5.6)

Deklarationen ska färdigställas med faktisk utfärdare och kontakt, tjänstens
omfattning, utgivningsmetod, aktivering, spärr, återställning, giltighet,
parternas skyldigheter och ansvar, personuppgiftsbehandling, leverantörer,
tillgänglighet, ändringsförfarande och avveckling. Publicera en versionsmärkt
fastställd handling och visa den före ansökan. Bevara vilken version användaren
accepterade och när. Utfäst inte godkänd tillitsnivå eller dygnet-runt-stöd
innan underlaget finns. Pilotens server är öppen varje dag 09–17 svensk tid.

## Avveckling (K5.5)

Beslut utser ansvarig och datum för stopp av nyutgivning. Informera innehavare,
förlitande parter och Digg där tillämpligt. Spärra kvarvarande legitimationer,
avveckla federation kontrollerat och håll nödvändig spärrkontroll tillgänglig
under övergången. Utse arkivansvarig, säkra läsbarhet och åtkomst samt gallra
övriga data enligt fastställd plan. Nycklar förstörs först när skyldigheter
för dekryptering och bevarande är omhändertagna. Prova planen före skarp avveckling.

## Övningsprotokoll

Registrera: scenario, datum, deltagare och roller, miljö/revision, förväntat
utfall, observerat utfall, tidsmått, avvikelse, åtgärdsägare och omprov.
Genomför minst nyckelincident, databasåterställning och spärr med förlorad
telefon före påstående om fungerande produktionsrutiner.

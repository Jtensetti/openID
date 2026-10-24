# Registerbindning och ersättning i SQLite-piloten

Implementationen i `verification/registry_binding.py` förbereder ID-02 och
ID-08–10. Den är inte ansluten till ett personregister och ändrar inte
pilotens tillitsnivå. Ingen registeradapter, ny HTTP-route eller automatisk
aktivering ingår. PostgreSQL-lägets befintliga flerpersonsprocess ändras inte;
den nya tjänsten avvisar det backendvalet tills motsvarande implementation finns.

## Förutsättningar för en registeradapter

`RegistryBindings(wallet, source=..., lookup=...)` konfigureras i en separat,
betrodd operatörsprocess. `lookup` får en engångsfråga som binder credential,
profilversion och intern dokumentreferens till passets autentiserade namn,
MRZ-födelsedatum, utfärdarland, nationalitet och giltighet. Foto skickas inte.
Om den krypterade passprofilen innehåller `passportPersonalNumber` skickas även
det autentiserade DG1-fältet med exakt de 10 eller 12 siffror som passet gav.
En saknad uppgift utelämnas; inget nummer eller sekel beräknas från namn eller
födelsedatum. Frågeobjektets representation döljer fälten; adaptern får inte
logga innehållet.

En verklig adapter måste autentisera registerkällan, ha rätt till åtkomst,
entydigt verifiera personens koppling till dokumentet och validera källans
svar. Frågans interna dokumentreferens är en HMAC, inte ett passnummer som
myndigheten kan slå upp. Namn och MRZ-födelsedatum räcker inte för entydig
identifiering. Vilka ytterligare auktoritativa underlag som behövs ska avgöras
med registerleverantören; implementationen gissar varken personnummer eller sekel.
Ett svar måste också överensstämma med passets nummer när det finns. Tolv
siffror jämförs exakt; tio siffror jämförs med registersvarets sista tio,
medan registerkällan måste fastställa seklet. Avvikelse eller syntetisk
ersättning för ett sådant nummer nekas före lagring. Kontrollen upprepas
vid användning av lagrade bevis, även för äldre bindningar. Ett korrekt
återgivet nummer är fortfarande inte bevis på att en registerfråga utförts.

Resultatet måste vara `RegistryResult`, återge frågans fyra bindningar och
innehålla en unik bevisreferens, kontrolltid och sluttid. Endast `MATCH` med
`protected=False` accepteras. Tvetydighet, avvikande namn/datum, skyddade
uppgifter, okänd status eller registerfel ska ge stopp för separat utredning.
Adaptern ansvarar också för att person-/samordningsnumret faktiskt är utfärdat
och användbart, inklusive relevanta statusuppgifter. Syntaxkontrollen av datum
och kontrollsiffra ersätter inte detta.

Beviset gäller högst ett dygn och får vara giltigt kortare. Detta är en lokal,
konservativ pilotgräns, inte ett påstående om en av Digg beslutad tidsgräns.
Bevisreferenser förbrukas och indexeras med HMAC. Identitetsvärde, källa,
kontrolltider, profilversion och dokumentreferens lagras krypterat med separat
autentiserad kontext från passprofilen. Händelseloggen innehåller endast fasta
händelsetyper och interna nyckelreferenser.

## Tillstånd och behörigheter

| Övergång | Förvillkor | Vem / resultat |
| --- | --- | --- |
| Passkontroll → `PENDING_REVIEW` | Befintliga chip-/bildkontroller och ny enhetsnyckel | Registreringstjänsten; ingen aktivering |
| Profil → registerbunden profil | Betrodd adapter, entydigt och färskt svar för exakt profil/nyckel/dokument | Operatörsprocess; nyckelstatus ändras inte |
| Aktiv nyckel → `REVOKED` | Signerad innehavaråtgärd eller behörig operatör | Befintlig spärrfunktion; gamla godkännanden/sessioner nekas |
| Nytt pass → ersatt identitet | Tidigare utgiven identitet, samma verifierade registeridentitet och källa för båda profilerna, nytt underlag inom 24 timmar, manuell beslutspunkt | Operatörsprocess; atomisk aktivering av ny nyckel och spärr av tidigare nycklar |
| Förlorad telefon → ny nyckel | Ny registrering och manuell aktivering; vid nytt pass även registervillkoren ovan | Den gamla nyckeln kan redan vara spärrad, men återaktiveras aldrig |
| Backup → återställd miljö | Befintlig kontrollerad återläsning | Alla återlästa nycklar spärras, godkännanden avbryts, registerbindningar tas bort |

En ersättning bevarar det interna person-ID:t och därmed tjänstens befintliga
subjekt, men skapar en ny profilversion. En dokumentreferens kopplas till den
gemensamma personen först i samma transaktion som aktiveringen. Ett ersatt
pass spärras för fortsatt registrering/aktivering i piloten. Senare telefonbyte
med det nya passet behåller kopplingen. Ett annat pass med samma namn och
födelsedatum kopplas aldrig ihop automatiskt.

En tidigare nyckel kan bara användas som utgångspunkt för en lyckad
registerkontrollerad ersättning en gång. En redan använd separat persongrupp
slås inte ihop automatiskt. Om aktiveringen misslyckas återställs också
personkoppling, profilkryptering, dokumentspärr och ersättningsmarkering.

SQLite-operatören har fortfarande tillgång till både databas och nyckelfil.
Detta ger inte verklig personseparation eller skydd mot en illvillig
systemadministratör. Stulna och borttappade telefoner kräver en dokumenterad
operatörskontroll innan administrativ spärr/ersättning; ingen e-postbaserad
återställning införs. Den publika betan har nu en [separat spärrkanal](avisering-och-sparr.md);
privata ID:n är inte automatiskt migrerade och sammanhängande fysiska prov återstår.

## Operatörsflöde

1. Spärra den förlorade telefonens credential genom befintlig `revoke`.
2. Låt innehavaren genomföra ny pass-/kameraregistrering med en ny nyckel.
3. För nytt pass: inhämta nya registerbevis genom den granskade adaptern.
   Om tidigare bevis har gått ut behövs även en ny kontroll för den äldre
   bindningen. Saknad registerkälla eller otillräckligt underlag innebär stopp.
4. Efter separat granskning, använd `wallet_cli.py --db ... replace-passport
   PREVIOUS NEW --registry-source SOURCE --decision REVIEW_REFERENCE
   --private-pilot-only`. Beslutsreferensen ska inte vara en personuppgift.
5. Kontrollera status på den nya telefonen. Den gamla nyckeln får aldrig
   återaktiveras. Fel under ersättningen får inte lösas genom att ändra SQL manuellt.

CLI:t tar inte emot personnummer eller ett manuellt ”verifierad”-påstående.
Det finns ännu ingen installerad adapter som kan skapa skarpa bindningar.
`identity_attributes` är inte kopplad till SAML/OIDC; attribututlämning kräver
en separat policy för motpart, ändamål och användarens information/godkännande.

## Prov och kvarstående begränsningar

`test_registry_binding` använder interna `TEST-...`-identiteter och en uttrycklig
testadapter. Syntetiska bindningar måste aktiveras separat i testkoden och kan
aldrig lämna ut nationella identitetsattribut eller godkännas genom operatörens
CLI. För gränssnittets nummerjämförelse används även publicerade SPAR-testnummer
med en lokal testadapter. Inga SPAR-anrop görs och inget sådant resultat
påstås vara registerverifierat. Bilder och registerkontroll är testdubblar; SQLite, AES-GCM, ECDSA,
transaktioner, sessionskontroller och backup/återläsning är verkliga i proven.

Testerna täcker fel person, fel nyckel/dokument/profil, återspelning, skyddade
uppgifter, utgång, rollback, samtidiga ersättningar, spärr som konkurrerar med
aktivering, uppgradering av befintlig pilotdatabas och återställning av äldre
backup. Återlästa registerbevis kasseras. Historik efter backupens tidpunkt kan
inte återskapas ur backupen; nya registerkontroller och operativ avstämning
krävs före ny utgivning.

Verklig registeranslutning, rättslig grund, skyddade uppgifter, oberoende
säkerhetsprov, fysisk telefonprovning och motsvarande PostgreSQL-stöd återstår.
Varken tillitsnivå eller formell kravstatus höjs av denna implementation.

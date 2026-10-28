# Information och val före registrering

WSGI-flödet kräver en uttryckligen vald informationsfil för att öppna nya
registreringar. `newRegistrationsEnabled` är fortfarande `false` som standard.
Detta är tekniska kontroller för ID-01/ID-11/GOV-08. De avgör inte rättslig
grund, giltigt samtycke eller om texterna är beslutade.

## Informationsfil

Ange `enrollmentPolicyFile` som absolut sökväg i pilotens eller PostgreSQL-
proofing-tjänstens privata konfiguration. Filen ska ägas av processens
användare eller root, vara högst 64 KiB, sakna grupp-/övrig åtkomst och ha en
hårdlänk. Symboliska länkar, dubbla JSON-fält och extra fält nekas. Start
med öppnad registrering utan giltig fil nekas. Efter policybyte krävs
kontrollerad omstart; pågående sessioner får börja om med den nya texten.

Filens exakta struktur:

| Fält | Innehåll |
|---|---|
| `schema` | Heltalet `1`. |
| `decisionReference` | Referens till ansvarigs faktiska beslut; 8–96 ASCII-tecken, bokstäver/siffror, punkt, bindestreck eller understreck. Referensen är inte en attest. |
| `notice.version` | Versionsbeteckning med samma teckengräns. |
| `notice.controller`, `notice.contact` | Faktisk ansvarig och kontaktväg, högst 1 024 UTF-8-byte vardera. |
| `notice.locale` | `sv-SE`. |
| `notice.notBefore`, `notice.notAfter` | Heltal i Unix-sekunder, början inkluderad och slutet exkluderat. |
| `notice.terms` | Fullständig, beslutad villkorstext. |
| `notice.privacy` | Fullständig information om den faktiska behandlingen, mottagare, lagring, rättigheter och kontakt. |
| `notice.biometrics` | Det separata biometriska ändamålet och vad det uttryckliga valet omfattar. |
| `notice.withdrawal` | Hur återkallelse görs, följderna, kontakt vid förlorad enhet och gränsen mot spärr/radering. |

De fyra sista texterna har vardera gränsen 16 384 UTF-8-byte. Gränsen för
hela filen gäller också. Text renderas utan markup; osynliga riktningsbyten
nekas. Syntetiska provtexter finns bara i testerna. De får inte användas som
verkliga användarvillkor eller som ersättning för en saknad ansvarig.

## Tillstånd och bevis

| Övergång | Villkor och skrivning |
|---|---|
| Information → användarval | `/native/notice` returnerar exakta base64-kodade JSON-byte och SHA-256. Appen verifierar hashen och visar dessa texter. Passformuläret öppnas först efter två separata, initialt avmarkerade val. Integritetsinformationen är information, inte ett tredje samtycke. |
| Start → attestering | En tidsbegränsad registreringssession skapas. App Attest prövas som tidigare. |
| Attestering → accepterad information | `/native/consent` verifierar en App Attest-assertion med session, nonce, aktuell textdigest, två uttryckliga booleska val, enhetsnyckel och kvitto-ID. Kvittot och exakt policy skrivs före passkontroll. Ny nonce utfärdas först efter commit. |
| Accept → chip → bilder | Samma enhetsnyckel krävs. Utgång, återkallelse och återställningsspärr kontrolleras innan dokumentkontroll, chipsteg och biometrisk analys. |
| Godkända kontroller → väntande credential | Credential, profil och kvittobindning skrivs i samma transaktion. Kvittot får bindas en gång och högst 300 sekunder efter registrerat val. Återkallelse eller utgång före commit nekar utgivningen. Aktivering är fortfarande separat. |
| Återkallelse | `/native/withdraw` kräver en signatur från kvittots enhetsnyckel över åtgärd, exakt origin och kvitto. Upprepning är idempotent. Databasens ursprungliga val ändras inte; återkallelsetid tillkommer permanent. |

En kvittorad före identitetskontrollen avser en enhetsnyckel, inte en
verifierad person. App Attest-signaturen, dess verifierade publika appnyckel
och valets payload sparas; passuppgifter, råbilder, IP-adress och poäng läggs
inte i kvittot. Underlaget är systemets registrering av ett verifierat
anrop, inte en oberoende Apple-/identitets-/juridisk attest eller ett bevis
på att människan förstått texten.

## Återkallelse och fel

Appen sparar kvittoreferensen i enhetens nyckelring **före** insändning.
Den markerar mottagande eller återkallelse som bekräftad först efter ett
matchande serversvar. Inställningar → Dina samtycken visar texten, erbjuder
export och separat återkallelse med Face ID, Touch ID eller enhetskod.
Mottagande med osäkert utfall visas som obekräftat; okänt kvitto eller
nätverksfel får inte visas som bekräftad återkallelse. Försök igen eller
använd ansvarigs kontaktväg. Appen behåller högst 32 kvitton per enhetsnyckel;
full kvittolagring stoppar insändning, utan att gamla kvitton skrivs över.

Återkallelsevägen är tillgänglig även med registreringspausen aktiverad och
efter serveromstart. Den kräver fortfarande fungerande server, databas,
ordinarie behörighetskontroller och ledig kapacitet. En redan pågående
analys kan hinna avslutas innan återkallelsen behandlas, men ett återkallat
kvitto får inte därefter skapa en credential. Denna väg spärrar inte ett
redan utfärdat ID och utger sig inte för att radera tidigare behandling.
Spärr, radering och rättighetsbegäran har separata flöden och bevarandegrunder.

Avbryt stänger lokal fångst och pågående chiputbyte. Det är inte samma sak
som en bekräftad, beständig återkallelse. Sessioner och oanvända acceptbevis
upphör att auktorisera registrering efter högst fem minuter. Ingressen kan
ta emot en anropskropp innan applikationen nekar den; kontrollerna innebär
inte att felaktiga klienter omöjligen kan sända byte till servern.

## Databas och återställning

SQLite lägger till tre tabeller utan att fabricera kvitton för äldre ID:n.
PostgreSQL använder schema 3 och `migrate-2-to-3.sql`; ägarkontrollerad
migrering krävs innan den nya applikationen startas. Enroller får infoga
kvittot men inte skriva om dess text eller bevis. PostgreSQL låser samma
kvittorad vid bindning och återkallelse; SQLite använder `BEGIN IMMEDIATE`.

Samtliga tre tabeller ingår i backup och [arkivformat 3](arkivexport.md).
Återläsningens befintliga spärr av alla credentials och 24 timmars
registreringskarantän gäller även här. Gamla kvitton återöppnar därför inte
registrering från en gammal backup. En återställning kan dock förlora en
senare återkallelse i själva journalhistoriken; oberoende arkiv/replikering
och avstämning krävs för att återställa historiken korrekt.

Ingen automatisk gallring av kvittobevis införs här. Ansvarig måste besluta
bevarandetid och rättslig grund för genomförda respektive avbrutna försök
och införa provad gallring även för arkiv och backup. Detta är ett öppet
produktionskrav. Befintliga testpersoners tidigare information och val måste
utredas separat; nya kvitton får inte bakdateras.

## Verifiering

`test_enrollment_policy`, `test_acceptance_journal` och
`test_enrollment_consent` provar textbindning, separata val, fel nyckel,
assertion, nonce, återspelning, utgång, omstart, återkallelse under analys,
atomisk bindning, samtidighet och SQLite-backup/arkiv. Apple-, pass- och
biometrikontroller är uttryckliga testdubblar där; kryptografiska gränser
har separata verifierartester. `test_cluster` provar riktiga PostgreSQL-
roller, migrering, samtidighet, backup och återställning i CI.
Appens tester provar manipulerade texter, val, utgång och formulärets spärr.
Fysisk iPhone, faktisk serverkonfiguration, information till deltagare och
ansvarigs beslut återstår före användning med verkliga uppgifter.

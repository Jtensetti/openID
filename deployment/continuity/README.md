# Separat spärrtjänst för pilot

Utvecklingskandidat. Den här komponenten kopplas inte automatiskt till en
befintlig pilot. Ingen existerande credential migreras av mallen.

`template.py` genererar CloudFormation för två Lambda-funktioner, en DynamoDB-
tabell och ett HTTP-API i en region. Den publika funktionen får endast uppdatera
spärrtabellen. Den privata funktionen får läsa status och spärra. Ingen funktion
har rätt att lägga in en aktiveringspost, ta bort poster eller ändra IAM.
Operatören registrerar en credential genom villkorad `PutItem` med
`attribute_not_exists(credential)`. Ett befintligt spärrbeslut får aldrig skrivas
över. Registrering i spärrtjänsten ersätter inte manuell ID-aktivering.

Tabellen använder kryptering i vila, raderingsskydd och punktåterställning.
Spärrposter har ingen TTL. Återställning av **denna** tabell kräver separat
avstämning av senare spärrar; återställ inte en äldre tabell direkt som auktoritet.
En gammal lokal wallet-backup måste alltid kontrolleras mot den aktuella tabellen.

## Gränssnitt

Privat Lambda-anrop, autentiserat med IAM:

```json
{"operation":"status","credential":"64 lowercase hex characters"}
```

Operationen `revoke` spärrar permanent och kan skapa en spärrpost även om en
credential ännu inte är registrerad. Svaret innehåller samma credential och
`ENABLED`, `REVOKED` eller `UNKNOWN`. `UNKNOWN` ger aldrig åtkomst.
Läsningar är starkt konsistenta och klienten cachar inte positiva besked.
En legitimering som redan pågår när spärren skrivs kan ha läst föregående status;
slutlig konsumtion och sessionsanvändning måste därför kontrollera status igen.

Publik `POST /revoke` kräver JSON med `credential`, `token` och `confirm: true`.
Token skapas med `secrets.token_urlsafe(32)` vid separat registrering. Endast dess
SHA-256-hash lagras som `token_hash`. Den är endast ett spärrbevis, aldrig ett
återställnings- eller aktiveringsbevis. Spärrkod får inte ligga i URL eller logg.
Fel kod och okänd credential ger samma svar. GET ändrar ingenting. Upprepad
korrekt spärr är tillåten och ändrar inte den ursprungliga spärrtidpunkten.

## Aviseringskö

`verification/notices.py` lägger aviseringspost och ID-aktivering i samma
SQLite-transaktion. Kontaktversion och granskningsreferens ska först bindas
separat av operatören. Kontaktversionen är oföränderlig. Kön innehåller inga
adresser, passuppgifter eller spärrkoder. Exportens stabila händelse-ID följer
med vid omförsök. Transportkvittens betecknas `QUEUED`, inte levererat.
Efter fem misslyckade exportförsök behövs operativ åtgärd.

## Tester och kvarvarande integration

```sh
python3 -m unittest discover -s deployment/continuity -p 'test_*.py' -v
python3 -m unittest discover -s verification -p test_revocation.py -v
python3 -m unittest discover -s verification -p test_notices.py -v
python3 deployment/continuity/template.py > /tmp/openid-continuity.json
```

Lokala tester använder syntetiska identiteter, injicerad kryptostubb och en
atomisk tabellmodell. De är inte prov av NFC, signaturer eller AWS-behörigheter.
Mallen använder AWS Python 3.12-runtime med dess medföljande SDK. Före pilotens
skyddade ID-trafik ska SDK paketeras med projektets låsta beroenden och SBOM;
den inline-paketerade mallen är en isolerad integrationsmiljö.

Kvar innan användare kan förlita sig på tjänsten:

- Obligatorisk konfiguration och IAM-klient i både verifierare, operatörsverktyg
  och federationsbrygga. De injicerade testgränssnitten aktiverar inte detta.
- Migration av alla befintliga ID:n utan möjlighet att tyst stänga av kontrollen.
- Säker utlämning av spärrkod och tillgängligt webbformulär för förlorad telefon.
- Beständig leveranskö, oföränderliga kontaktversioner, SES-arbetare samt hantering
  av leverans, studs och klagomål. Utkorgsexporten är ännu ett injicerat gränssnitt.
- Ändamålsenlig separat kontaktkontroll; verifierad e-postadress bevisar inte ensam
  att adressen tillhör den passkontrollerade personen.
- Sammanhängande tester av SAML/OIDC, befintliga sessioner, nattstopp och återstart
  mot den driftsatta auktoriteten. Övervakning och operativ felhantering.

API:t begränsas till 0,1 anrop/sekund med burst 5. Lambda har två samtidiga
körningar per funktion och tabellen max fem läs-/skrivenheter per sekund.
Det begränsar resursanvändning men är ingen garanterad fakturagräns och kan
begränsa tillgänglighet vid missbruk. Inga request-body-loggar skapas. CloudWatch
standardmätvärden finns; egna diagnostikloggar och larm återstår.

Källor: [DynamoDB konsistens](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.ReadConsistency.html),
[villkorade uppdateringar](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateItem.html),
[SES testläge](https://docs.aws.amazon.com/ses/latest/dg/request-production-access.html).

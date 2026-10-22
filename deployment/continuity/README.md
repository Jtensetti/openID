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
Mallen använder AWS Python 3.12-runtime. Före pilotens skyddade ID-trafik ska
`SdkLayerArn` peka på en versionslåst Lambda-layer byggd från
`deployment/aws/requirements.lock`, inklusive dess licenser och SBOM. Utan detta
är mallen en isolerad integrationsmiljö med AWS medföljande SDK.

Kvar innan användare kan förlita sig på tjänsten:

- Aktivera den gemensamma konfigurationen nedan i den valda pilotdriften efter
  granskad migration av eventuella befintliga ID:n.
- Installera appversionen med separat spärrkod. Den tidigare appversionen kan
  inte spara koden och spärra direkt när verifieraren är avstängd.
- Provkör SQS/SES med rätt kontaktbindning och säkerställ att operatören tar emot
  vidarebefordrade studsar/klagomål. `ACCEPTED` är inte leveransbevis.
- Ändamålsenlig separat kontaktkontroll; verifierad e-postadress bevisar inte ensam
  att adressen tillhör den passkontrollerade personen.
- Sammanhängande tester av SAML/OIDC, befintliga sessioner, nattstopp och återstart
  mot den driftsatta auktoriteten. Övervakning och operativ felhantering.

API:t begränsas till 0,1 anrop/sekund med burst 5. Lambda har två samtidiga
körningar per funktion och tabellen max fem läs-/skrivenheter per sekund.
Det begränsar resursanvändning men är ingen garanterad fakturagräns och kan
begränsa tillgänglighet vid missbruk. Inga request-body-loggar skapas. CloudWatch
standardmätvärden finns; egna diagnostikloggar och larm återstår.

## Koppla verifierare, brygga och app

`configured_wallet` används av `serve.py`, `saml_bridge.py` och `wallet_cli.py`.
Sätt `OPENID_CONTINUITY_CONFIG` till en absolut, vanlig fil med mode 0600:

```json
{"version":1,"region":"eu-north-1","backendFunction":"arn:aws:lambda:eu-north-1:123456789012:function:your-backend"}
```

Använd `deployment/continuity-compose.yaml` tillsammans med `beta-compose.yaml`.
Sätt också `OPENID_NOTICE_QUEUE_URL` till stackens `NoticeQueueUrl`. Serverrollen
behöver endast `lambda:InvokeFunction` för backendfunktionen och `sqs:SendMessage`
för den kön. Den får inte skriva kontakt- eller aktiveringsposter i DynamoDB.
Notifieringsexportören går på testservern; kökonsumenten går separat i Lambda.
En ännu ej exporterad utkorgspost väntar till nästa serverstart. Vid ordnad
avstängning måste utkorgen därför tömmas och eventuella fel hanteras före stopp.

En migrerad wallet får en `wallet.continuity-required`-markör. Gamla lokala
kommandon utan konfiguration vägrar öppna den. Driftkonfigurationen måste också
bevaras separat från databasbackuper; markören ersätter inte det kravet.

Operatören förbereder en kontakt med `continuity_operator.py`, separat IAM-
behörighet till de två tabellerna och flaggan `--independently-verified-contact`.
E-post läses från stdin, inte kommandoraden. Granskningsreferensen ska motsvara
en verkligt genomförd separat kontroll. Verktyget aktiverar aldrig ett ID.
Remote registrering använder villkorade, atomiska skrivningar. Om ett svar
försvinner jämförs oföränderliga poster; inga spärrar eller kontakter skrivs över.
Därefter görs det vanliga manuella aktiveringsbeslutet med `wallet_cli.py`.

Spärrhemligheten lagras krypterad med befintligt AES-GCM-bibliotek och egen
AAD-domän i wallet. Endast dess hash går till spärrtabellen. Efter separat
kontaktbindning lämnas koden ut i en enhetssignerad snapshot. Den nya iPhone-
appen binder koden till registrerings-ID och publik betaorigin, lagrar den i
icke-synkroniserad Keychain och kan spärra direkt över HTTPS efter lokal
användarverifiering. HTTP-omdirigeringar tillåts inte. Privat serverkonfiguration
och privata ID:n flyttas aldrig automatiskt till den publika tjänsten.

`GET /revoke` visar ett enkelt formulär utan skript eller spårning. POST kräver
spärrkod och uttrycklig bekräftelse. Koden får inte läggas i länkar. Appen låter
innehavaren spara den utanför telefonen för användning vid förlorad enhet.

Källor: [DynamoDB konsistens](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.ReadConsistency.html),
[villkorade uppdateringar](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateItem.html),
[SES testläge](https://docs.aws.amazon.com/ses/latest/dg/request-production-access.html).

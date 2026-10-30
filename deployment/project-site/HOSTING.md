# Fristående projektsida

Filerna i `deployment/project-site/`, `index.html` och `beta.css`, lagras i en privat S3-bucket och levereras via
CloudFront. Projektsidan kräver inte att pilotens EC2-instans är igång.
Ladda endast upp dessa två publika filer, aldrig hela arbetskatalogen.

## Routning

| Sökväg | Ursprung | Cache |
| --- | --- | --- |
| `/` | S3, omskriven till `/index.html` av en CloudFront Function | 300 sekunder |
| `/beta.css` | S3 | 300 sekunder |
| `/.well-known/acme-challenge/*` | Pilotens HTTP-port | Avstängd |
| Övriga sökvägar | Pilotens HTTPS-port | Avstängd |

Pilotens ursprungsadress är `idp.openid.tensetti.io`, som fortsätter peka
direkt på EC2. CloudFront skickar besökarens Host-header vidare, så att
nginx väljer serverblocket för `openid.tensetti.io`. Befintliga SAML- och
OIDC-adresser, cookies, formulär och appens sessionskontroller behålls. Testflödena
ska inte kräva ett gemensamt betalösenord. Alla headers,
cookies och frågeparametrar vidarebefordras till piloten. Använd aldrig
statisk cachepolicy för dessa anrop. Fel från piloten ska inte lagras.

HTTP-utmaningar vidarebefordras separat så att förnyelse av pilotens
befintliga Let's Encrypt-certifikat fortsätter fungera efter DNS-bytet.
CloudFronts certifikat hanteras av ACM i `us-east-1`. Dess DNS-post måste
finnas kvar för automatisk förnyelse.

S3 blockerar offentlig åtkomst. En bucketpolicy tillåter endast läsning
från den valda CloudFront-distributionen med signerade ursprungsanrop
(Origin Access Control). HTTPS krävs för sidan, med säkerhetsheaders och
en CSP som tillåter den egna stilmallen och formulär till testtjänsten.
Åtkomstloggning är avstängd.

## Publicering och kontroll

1. Kontrollera HTML/CSS och ladda upp de två filerna med rätt innehållstyp
   och `Cache-Control: public,max-age=300`.
2. Vänta ut cachetiden eller invalidera `/` och `/beta.css`.
3. Kontrollera att HTTPS-svaren matchar de publicerade filerna och att
   båda testlänkarna öppnas utan betalösenord när piloten är igång. Kontrollera
   även att en ny besökare kan nå appens godkännandesida och att personuppgifter
   och testresultat inte lämnas ut utan rätt session.
4. Prova oberoendet från pilotinstansen i en separat testmiljö eller under
   ett beslutat driftprov. Den delade betan ska inte stoppas för detta utan
   samordning. Testsidan följer [driftplanen](../README.md#betans-öppettider):
   dygnet runt till 1 december 2026 kl. 00.00 svensk tid.

Vid återställning kan de två tidigare filerna laddas upp igen. För att
återgå till den tidigare driften kan `openid` återställas till pilotens
A-post; `idp.openid` och `api.openid` ska inte ändras.

## Kostnad

Ingen extra virtuell server behövs. CloudFront och S3 debiteras enligt aktuell
regional prislista och faktisk användning. Kontrollera kontoavtal och eventuell
fri nivå i kostnadsunderlaget; dessa är inga beständiga egenskaper i koden. Budgetlarm är inte en hård utgiftsspärr. Behåll pilotens
beslutade slutstopp och kontrollera prognosen innan mer trafik eller fler
AWS-tjänster aktiveras.

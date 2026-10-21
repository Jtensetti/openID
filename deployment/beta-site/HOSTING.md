# Fristående projektsida

`index.html` och `beta.css` lagras i en privat S3-bucket och levereras via
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
OIDC-adresser, cookies, formulär och inloggningsskydd behålls. Alla headers,
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
   båda testlänkarna fortfarande kräver inloggning när piloten är igång.
4. Kontrollera sidan även med pilotinstansen stoppad. Testsidan har
   fortfarande pilotens öppettider, vilket anges på projektsidan.

Vid återställning kan de två tidigare filerna laddas upp igen. För att
återgå till den tidigare driften kan `openid` återställas till pilotens
A-post; `idp.openid` och `api.openid` ska inte ändras.

## Kostnad

Ingen extra virtuell server behövs. CloudFront använder ordinarie
förbrukningspriser med den månatliga fria trafiknivån; S3 debiterar lagring
och hämtningar. Budgetlarm är inte en hård utgiftsspärr. Behåll pilotens
driftschema och kontrollera prognosen innan mer trafik eller fler
AWS-tjänster aktiveras.

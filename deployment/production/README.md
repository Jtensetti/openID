# Sammanhängande driftplattform

Den här profilen samlar appens befintliga serverkedja i ett Compose-projekt,
`tjipp`. Den är under införande och håller nyregistrering stängd. Den använder
explicita tjänstenycklar i stället för labbinitiering. Det är en teknisk
driftdefinition, inte ett godkännande att utfärda e-legitimationer.

Profilen knyter för närvarande IdP:n till den egna kontotjänstens fasta
SAML-/OIDC-konfiguration. Den hämtar ännu inte Sweden Connects externa
motpartsmetadata. En separat runtimekonfiguration för federationens
ankare, krypteringsnyckel och testklienter återstår före externt anslutningsprov.
Det äldre `phone-sandbox-idp`-läget ska inte användas som reservväg med
produktionsnycklar.

## Ingående delar

| Process | Beständig åtkomst | Gränssnitt |
| --- | --- | --- |
| `verifier` | Register och verifieringskonfiguration | App-API på TLS/loopback 8767, privat profilnyckelsocket, separat spärrtjänst |
| `vault` | Endast profilnyckel | Avgränsad Unix-socket; lämnar inte ut rånyckeln |
| `bridge` | Register och konfiguration | Separata Unix-socketar för federation och avisering; samma spärrtjänst som API:t |
| `idp` | Egna TLS-/utfärdarnycklar och publikt SP-certifikat | SAML/OIDC på TLS/loopback 9443; federationens socket |
| `sp` | Egna TLS-/SP-nycklar och publikt IdP-certifikat | Kontotjänst, protokoll- och underskriftsprov på TLS/loopback 9444 |
| `notice-exporter` | Ingen register- eller nyckelmontering | Aviseringssocket och en uttryckligt vald SQS-kö |

Värden kör nginx enligt `nginx.conf.in`. `ingress.py` hämtar tre skilda
HTTPS-värdnamn ur konfigurationen. Ingressen kontrollerar varje bakomliggande
TLS-certifikat och döljer interna administrations-/hälsorutter.

De externa beroendena ingår i driftgränsen: separat spärr-API och privat
spärrfunktion, aktuellt DynamoDB-register, SQS/felkö, aviseringsleverans samt
operativ kontaktbindning. [Spärrtjänstens mall och instruktion](../continuity/README.md)
beskriver dem. Använd ett nytt, separat namn-/behörighetsutrymme med
`TestBeta=false`. Återanvänd inte ett avvecklat pilotregister. Saknad
spärrkonfiguration får inte ersättas med lokal status.

## Värd och säkerhetsgräns

Profilen kräver en ensam Linux x86_64-värd med Docker Compose, Landlock ABI 3
och seccomp. API och Java-tjänster binds till loopback. Endast ingressens
HTTPS och avsedd administration får nås utifrån. En 8 GiB-värd är utgångspunkt
för kapacitetsprov; verkliga mätningar avgör dimensioneringen.

Det finns ingen autoskalning eller kampanjstyrd avstängning. Register och
pågående NFC-sessioner stöder inte flera parallella verifierarrepliker.
En värd är en gemensam felpunkt. Backup, återställning, övervakning,
incidentberedskap och beslutad tillgänglighet måste införas och provas;
Compose skapar inte dessa kontroller.

Varje process har egen identitet och begränsade monteringar. Värdadministratören
kontrollerar fortfarande hela maskinen. SQLite-operatören kan fortfarande
fatta aktiveringsbeslut. Filsystemseparationen ger varken HSM-skydd eller
oberoende mänsklig motkontroll. Molnbehörigheter och nyckelförvaltning kräver
separat införd och verifierad kontroll.

## Privat konfiguration

Allt nedan ligger utanför repot i `$TJIPP_DIRECTORY`. Lägg aldrig privata
filer i ett byggarkiv, en PR eller ett publikt testresultat.

| Sökväg | Ägare/grupp | Läge |
| --- | --- | --- |
| `data`, `secrets` | 10001:20002 | 0700; privata filer 0600 |
| `runtime.json`, `continuity.json` | 10001:20002 | 0600 |
| `origins.json` | Administratör | Läsbar för tjänsterna; skrivbar endast av administratör |
| `vault/private` | 10005:20002 | 0700; `wallet.identity-key` 0600 |
| `vault/socket` | 10005:20002 | 2710 |
| `ipc/federation` | 10001:20001 | 2710 |
| `ipc/notice` | 10001:20003 | 2710 |
| `federation-idp` | 10002:20001 | 0700; alla filer 0600 |
| `federation-sp` | 10003:20001 | 0700; alla filer 0600 |

Utgå från `runtime.example.json` och `continuity.example.json`; ersätt
exempelvärdena med den verkliga miljön. `origins.json` innehåller endast
`idp` och `sp`, se [formatet](../pilot-origins.example.json).
`secrets` innehåller API:ts TLS-certifikat/-nyckel, privat kopplingskod,
kontrollerat CSCA-paket och aktuell CSCA-spärrlista. Tillitsankare ska komma
från en kontrollerad källa, aldrig från en inskickad passhandling.

Nyregistrering, publik registrering och utvecklings-App Attest är uttryckligen
avstängda. Posekontrollen ska vara `enforce`. Kopierade novemberflaggor och
`testBeta` godtas inte av profilkontrollen.

### Federationens nycklar

Provisionering ska ske separat med dokumenterat ägarskap och beslutad
nyckelhantering. `runtime-idp` och `runtime-sp` genererar inga ersättningsnycklar.
Saknade filer stoppar starten; de faller aldrig tillbaka till `phone-init`.

| Katalog | Exakt filuppsättning |
| --- | --- |
| `federation-idp` | `tls.p12`, `tls.password`, `idp.p12`, `idp.password`, `sp.crt`, `subject-secret` |
| `federation-sp` | `tls.p12`, `tls.password`, `sp.p12`, `sp.password`, `idp.crt` |

Varje PKCS#12-fil får innehålla exakt en privat nyckel, med alias `tls`,
`idp` respektive `sp`. Lösenordsfiler och `subject-secret` innehåller ett
separat slumpvärde om 43–128 URL-säkra tecken. Bevara `subject-secret` över
omstarter. Certifikat ska vara giltiga RSA-certifikat om minst 3072 bitar;
interna TLS-certifikat måste täcka `localhost` och `127.0.0.1`.
IdP och SP måste ha olika nycklar. Motpartens fil innehåller endast dess
publika certifikat. Extra filer, labbmarkörer, delade rättigheter och
symboliska länkar avvisas.

Till nginx exporteras endast respektive interna TLS-certifikat som
`/etc/nginx/tjipp-api-tls.crt`, `tjipp-idp-tls.crt` och `tjipp-sp-tls.crt`.
De är skilda från federationens signeringscertifikat. Publik HTTPS använder
certifikatkedja och nyckel under `/etc/letsencrypt/live/tjipp/`.

Den här credentialadaptern är filbaserad. HSM-stöd, nyckelceremoni,
nyckelrotation och verklig flerpersonkontroll är inte verifierade genom den.
Kontotjänstens dokumentunderskrift använder fortfarande test-CA och nycklar
i processminnet; [begränsningarna](../../docs/pdf-underskrift.md) gäller även här.
Autentiseringskontexten förblir privat pilotstatus och intygar ingen LoA 1–4.

## Kandidat, start och kontroll

1. Bygg och verifiera hela revisionen enligt [leveransinstruktionen](../build/README.md).
   Importera samma godkända imagepaket utan ombygge. Bevara Git-revision,
   byggkörning, manifestets verifierade SHA-256 och image-ID tillsammans med
   den aktuella driftkonfigurationen. Även denna profil omfattas av hela
   `assurance-gate`; en röd grind får inte hoppas över.
2. Provisionera nya privata filer och externa beroenden. Verifiera
   filrättigheter, behörigheter, certifikat, DNS, TLS-förnyelse och åtkomst.
3. Kontrollera inställningar, renderad Compose och nginx före start:

```sh
export TJIPP_DIRECTORY=/srv/tjipp
export TJIPP_IMAGE_ID=sha256:REPLACE_WITH_VERIFIED_IMAGE_ID
export TJIPP_NOTICE_QUEUE_URL=https://sqs.eu-north-1.amazonaws.com/ACCOUNT/QUEUE
python3 deployment/production/check.py settings --directory "$TJIPP_DIRECTORY"
docker compose -f deployment/production/compose.yaml config --format json |
  python3 deployment/production/check.py compose --image-id "$TJIPP_IMAGE_ID" --directory "$TJIPP_DIRECTORY"
python3 deployment/production/ingress.py --directory "$TJIPP_DIRECTORY" > /privat/tjipp-nginx.conf
```

Installera granskad ingresskonfiguration och verifiera den med `nginx -t`.
Ingressens statiska startsida ligger i `/var/www/tjipp`; ACME-katalogen är
`/var/www/tjipp-acme`. Säkerställ certifikatförnyelse innan miljön lämnas obevakad.

Efter beslutat påslag för den avgränsade granskningen:

```sh
docker compose -f deployment/production/compose.yaml up -d
docker compose -f deployment/production/compose.yaml ps
```

Kontrollera den faktiska imagen i alla sex processer och att interna portar
är otillgängliga utifrån. Verifiera stängd registrering, API/readiness,
SAML/OIDC med signerade syntetiska godkännanden och nekade felaktiga svar.
Prova omstart och oberoende spärr när huvudkedjan är stoppad. Aviseringskvittens
är inte bevis på leverans. Prova återställning med senare spärrar bevarade.
En grön hälsokontroll ersätter inte dessa prov eller ett fysiskt telefonprov.

## Automatiska prov

```sh
python3 -m unittest discover -s deployment/production -p 'test_*.py' -v
python3 deployment/test_beta_nginx.py --configuration deployment/production/nginx.conf.in
```

Compose-proven använder Docker Compose för att rendera den faktiska filen;
de hoppas över om verktyget saknas lokalt och körs obligatoriskt i CI.
Java-proven verifierar privata nyckelgränser, felaktiga credentialfiler,
publik OIDC-nyckelbindning och SP-start utan IdP:ns privata nyckel.
Ingressproven använder genererade certifikat och en syntetisk bakomliggande
tjänst. De provar varken verklig passkontroll, HSM eller en driftsatt miljö.

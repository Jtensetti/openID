# Versionslåst arkiv och mottagarkvittens

`store.py` kompletterar [journalexporten](../../docs/arkivexport.md) med S3
Object Lock, separat mottagning och senare läsbarhetskontroll. AWS-bibliotek,
hashlås och licenser återanvänds från [AWS-miljön](../aws/THIRD_PARTY.md).
Ingen stack driftsätts och ingen data skickas automatiskt av PR eller CI.

## Konton, roller och skydd

Utfärdare och arkivförvaltare ska använda olika AWS-konton. Klienten nekar
samma konto för båda och kräver den konfigurerade arkivförvaltarrollen för
bekräftelse och läsbarhetsprov. Kontoseparation styrker inte olika personers
eller företags faktiska oberoende; trust, mandat och bemanning ska granskas.

`template.py` genererar en CloudFormation-mall för arkivkontot: privat bucket,
BucketOwnerEnforced, SSE-S3/AES256, versionslagring, Object Lock COMPLIANCE,
TLS-krav och Retain vid borttagning/ersättning. Utfärdarrollen får skriva och
läsa överförda objekt men nekas radering och ändring av bucketens skydd.
Endast arkivförvaltarrollen får skriva kvittenser. Inga roller eller nycklar
skapas av generatorn. Rollerna ska finnas före driftsättning; obligatoriska
parametrar är `IssuerAccountId`, `IssuerRoleName` och `CustodianRoleName`.
Kontoförvaltarna ska ge rollerna motsvarande identitetsbehörighet, begränsad
till respektive Allow-statement och resurs i bucketpolicyn. Arkivrollens
trust ska inte ge utfärdaren rätt att anta den.

Klienten kräver Stockholm, rätt bucketägare, versionslagring och COMPLIANCE-
standard. Alla filer skickas med SHA-256, villkorad skapning, explicit
kryptering och bevarande. Exakt VersionId, innehåll, kryptering och skydd
läses tillbaka. Endpointöverskrivningar från AWS-profil/miljö ignoreras.

Bevarandet räknas från det senaste av leverans och giltighet/händelse/beslut
i uttaget. Fristen är 1827–3650 dagar med avrundningsmarginal för mottagning.
Registertid mer än 72 timmar framåt kräver granskning. Policyn nekar kortare
bevarande och mer än 3655 dagar per objekt. Verktyget förkortar eller
raderar aldrig ett bevarande. COMPLIANCE-lås binder även felaktiga uttag;
besluta dataklass och bevarande före driftsättning. Upprepade leveranser kan
ge extra lagringskostnad. Inga KMS-kundnycklar eller nya tjänster behövs.

## Körning

Installera `deployment/aws/requirements.lock` med `--require-hashes` i en
separat operatörsmiljö. Kopiera `config.example.json` utanför repot, ersätt
exempelvärdena med beslutade konton/bucket/roll och sätt läge 0600.
Autentisering använder SDK:s credentialkedja och valfri `--profile`;
hemligheter ska inte ligga i konfiguration eller processargument.

```sh
python deployment/archive/store.py deliver --profile issuer-archive \
  --config /private/archive-config.json --source /private/export \
  --manifest-sha256 SEPARAT_BEVARAD_SHA256 --output /private/delivery.json
```

Detta ger leveransunderlag, inte mottagarkvittens. Vid ofullständig leverans
ges ingen bekräftelse. Redan skrivna objekt är låsta och raderas inte.
Filer grupperas under unikt överförings-ID och manifestet skrivs sist.
Förmedla underlaget och separat förankrad digest till arkivförvaltaren:

```sh
python deployment/archive/store.py confirm --profile archive-custodian \
  --config /private/archive-config.json --source /private/delivery.json \
  --manifest-sha256 SEPARAT_BEVARAD_SHA256 --output /private/receipt.json
```

Mottagaren återläser exakt angivna versioner till privat temporär katalog,
verifierar hela uttaget offline och kontrollerar bevarande. Först därefter
skrivs en separat COMPLIANCE-låst kvittens som också återläses. Utfärdarens
profil kan inte utföra bekräftelsen eller skriva till kvittensprefixet.
Ett senare prov kräver varken ursprungligt register eller lokal export:

```sh
python deployment/archive/store.py check --profile archive-custodian \
  --config /private/archive-config.json --source /private/receipt.json \
  --manifest-sha256 SEPARAT_BEVARAD_SHA256 --output /private/check-20261025.json
```

Resultatet är `READABLE` med provtid och population. Fel ger exitkod 2 och
ingen resultatfil. Schemalägg provet i förvaltarens oberoende miljö med nytt
filnamn per körning och larm även vid utebliven körning. Befintliga resultat
skrivs aldrig över. Känsliga AWS-felsvar eller personposter loggas inte.

Kvittensen är ett versionslåst mottagningsregister under mottagarens
AWS-behörighet, inte en kvalificerad underskrift eller betrodd tidsstämpel.
Den kompletterar inte saknade utgivningsunderlag och attesterar inte att ett
ursprungligt identitetsbeslut var korrekt. Faktiska förvaltare, avtal, larm,
driftsättning och bevittnad mottagning krävs fortfarande.

## Prov och primärkällor

`test_store.py` använder inga live-credentials. Det provar hela kedjan och
nekar fel konto/roll, ändrad data/version, bristande bevarande/kryptering och
falsk kvittens efter fel. Botocore Stubber validerar S3-API-kontrakt och
svarsmodeller. Mallens resurs- och policygränser provas, och CI kör cfn-guard.
Detta är offline-/kontraktsprov, inte bevis för en driftsatt S3-miljö.

Kontrollerat 2026-10-24:
[Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html),
[skydd och bevarandegränser](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-managing.html),
[PutObject](https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/put_object.html)
och [GetObject](https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/get_object.html).

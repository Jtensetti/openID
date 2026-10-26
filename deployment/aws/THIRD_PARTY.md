# AWS-testets beroenden

Samma låsta AWS SDK-graf används av den separata
[arkivklienten](../archive/README.md). Den för inga nya paket till
applikationens runtime och tar inga credentials från repot.

Kontrollerat 2026-10-20. `requirements.lock` låser AWS SDK och hela dess
installerade Python-graf med hjulhashar. `sbom.cdx.json` innehåller dessa
sju paket och CI-verktyget CloudFormation Guard. Fullständiga källrevisioner,
paketmetadata och daterade advisorysvar finns i `dependency-audit.json`.

| Komponent | Version | Licens |
|---|---|---|
| boto3 / botocore | 1.43.115 / 1.43.115 | Apache-2.0 |
| s3transfer | 0.19.3 | Apache-2.0 |
| jmespath | 1.1.0 | MIT |
| python-dateutil | 2.9.0.post0 | BSD-3-Clause; delar erbjuds även under Apache-2.0 |
| six | 1.17.0 | MIT |
| urllib3 | 2.8.0 | MIT |
| CloudFormation Guard | 3.2.1 | Apache-2.0 |

Boto-projekten underhålls av AWS och deras låsta versioner publicerades
2026-10-19. Inget granskat repository var arkiverat. Dateutil och six har
äldre releaser från 2024; senare repositoryaktivitet redovisas i registret.
Aktivitet är ingen garanti för kommande rättningar.

OSV och PyPI gav inga publicerade fynd för de sju Pythonversionerna vid
kontrollen. Guards offentliga GitHub-advisorylista var tom. Kontrollerna
omfattar inte egna kodfel, Rust-binärens hela beroendegraf eller OS-paket.
Licens- och NOTICE-filer från hjulen och Guards låsta källrevision finns
oförändrade i `licenses/`; installationen behåller även paketens egna filer.

Node 24.19.0 och OpenBao 2.7.1 återanvänds från
[befintligt komponentregister](../../verification/THIRD_PARTY.md).
`bootstrap.sh` kontrollerar deras publicerade Linux-artefakters SHA-256 och
AWS regionala CA-pakets SHA-256. CA-paketet kommer från
`https://truststore.pki.rds.amazonaws.com/eu-north-1/eu-north-1-bundle.pem`.
En ändrad distributionsfil måste granskas och låsas på nytt.

RDS-motorn är låst till PostgreSQL 18.6. Ubuntu 24.04-AMI anges som ett fast
ID för varje körning; installerade OS-paket och SSM-agenten förvaltas av
Ubuntu/AWS och ingår inte i Python-SBOM. Avvecklingsfunktionen använder
AWS Lambdas förvaltade Python 3.12 och medföljande boto3: dessa uppdateras av
AWS och omfattas inte av det lokala paketlåset. Funktionen är endast ett
extra avvecklingsskydd för engångsmiljön.

Beroendeändringar ska granskas av repots förvaltare och uppdatera lås,
licensfiler, SBOM och säkerhetsprov. Produktionsförvaltare är ännu inte utsedd;
se [projektets förvaltningsstatus](../../THIRD_PARTY.md#projektlicens-och-förvaltning).

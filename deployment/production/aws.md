# AWS-värd för Tjipp

[host.yaml](host.yaml) beskriver en varaktig värd för den samlade
[driftprofilen](README.md) i `eu-north-1`. Välj en Canonical Ubuntu 24.04 LTS
amd64-AMI med gp3 och kontrollera dess ägare `099720109477`, tillgänglighet
och rotenheten `/dev/sda1` före användning. Spara AMI-ID, zon och revision
tillsammans med CloudFormations förändringsplan.

Mallen väljer en `m7i-flex.large` med 8 GiB som utgångspunkt för kapacitetsprov.
Den samlade profilens deklarerade minnesgränser ryms inte på en 4 GiB-värd.
Krypterad gp3 lagrar 20 GiB på systemdisken
och 30 GiB på datadisken. En ny fast IPv4-adress ger utgående HTTPS till
Session Manager, Ubuntu och driftens externa beroenden. Det separata
undernätet har en internetgateway. `PublicIngress=false` håller inkommande
trafik stängd. HTTP för ACME och HTTPS kan öppnas genom ett granskat
byte av den parametern i en stackuppdatering. Administration sker via Session Manager.

Mallen behöver en tillåten operatörsroll för Session Manager. Avgränsa
operatörens behörighet till den aktuella instansen. Kontrollera att agenten
är online och att avsedd operatör kan öppna och avsluta en session. AWS
instansrollen använder IMDSv2 och Systems Manager-policyn. Parameter Store
läsning är uttryckligen nekad. När båda resurserna från den nya
[spärrstacken](../continuity/README.md) finns, ange dess `BackendFunction`
och könamnet från `NoticeQueueArn`. Då skapas två avgränsade klientroller:
`ContinuityClientRole` får endast `lambda:InvokeFunction` för den funktionen;
`NoticeClientRole` får endast `sqs:SendMessage` för den kön. Instansrollen
får endast anta dessa två roller, med fasta sessionsnamn och högst en timme.
Den behåller Systems Manager för värdadministration men får inga direkta
verksamhetsrättigheter eller provisionerings-/mutationsrättigheter.

Den enda appprocess som kan läsa instansrollen är den avgränsade rootrotatorn.
Den använder IMDSv2, verifierar källrollen och skriver atomiskt två separata
kortlivade sessioner med läge 0600 till respektive mottagar-UID. Övriga
containrar är icke-root och värdens nftables-filter nekar deras åtkomst till
båda metadataadresserna. Klienterna använder enbart sin credential-process;
de återfaller inte till miljönycklar, profiler eller IMDS. Se
[driftprofilen](README.md) för de exakta filgränserna. Verkligt AWS-IAM och
rotation på värden måste provas efter införd förändringsplan.
Värdens rootadministratör kan fortfarande nå värdens filer och processer.

## Förändringsplan

```sh
cfn-lint --regions eu-north-1 --template deployment/production/host.yaml
cfn-guard validate --rules deployment/production/host.guard \
  --data deployment/production/host.yaml --output-format json
aws cloudformation validate-template --region eu-north-1 \
  --template-body file://deployment/production/host.yaml
```

Använd en CREATE-förändringsplan för den nya stacken. Kontrollera aktuell
kontoplan och, om den är Free, instanstypens `free-tier-eligible`-värde,
kvarvarande krediter och planens slutdatum. Kontrollera instanstypens
tillgänglighet i vald zon. Tilldela `AmiId` det verifierade ID:t och använd
`CAPABILITY_IAM`. Läs samtliga ändringar
och valideringshändelser. Bevara planens ID, resurslista och parametrar.
Exekvering startar debitering för värd, volymer och adress. En stoppad värd
lämnar kostnaden för volymer och fast adress. Redovisa kvarvarande historiska
adresser separat fram till avveckling.

## Starta värden

1. Läs `InstanceId`, `DataVolumeId` och `PublicIPv4` från stacken. Kontrollera
   instansens faktiska AMI, metadataalternativ, gruppregler, volymer och
   SSM-status. Använd Canonicals signerade arkiv över HTTPS i
   `/etc/apt/sources.list.d/ubuntu.sources`. Behåll arkivens nyckelring.
   Läs in systemuppdateringar och installera Ubuntu-paketen `docker.io`, `docker-compose-v2`, `nginx`
   `nftables` och `certbot`. Anteckna exakta installerade versioner. Maska
   `docker.service` och `docker.socket` före installationen så att Docker
   börjar starta först med volym- och metadataisoleringen på plats.
2. Matcha `DataVolumeId` mot serienumret i `lsblk -o NAME,SERIAL,FSTYPE,SIZE,MOUNTPOINTS`.
   Första provisionering av en ny, tom volym använder ext4 på hela enheten.
   Verifiera enhet och befintliga signaturer före formatering. En bevarad
   volym monteras med sitt befintliga filsystem. Spara dess filsystems-UUID
   i `/etc/fstab` för `/srv/tjipp` med `nodev,nosuid,noexec,nofail` och
   `x-systemd.device-timeout=60s`. `nofail` låter värden starta och nås via
   SSM även om disken behöver åtgärdas.
3. Spara `DataVolumeId` som enda rad i `/etc/tjipp/data-volume-id` med
   ägare `root:root` och läge 0600. Installera [volymkontrollen](check-data-volume.sh)
   som `/usr/local/libexec/tjipp-check-data-volume` med ägare `root:root`
   och läge 0755. Installera [Docker-tillägget](docker-data-volume.conf)
   i `/etc/systemd/system/docker.service.d/40-tjipp-data-volume.conf`.
   Montera volymen, kör kontrollen och läs om systemd. Avmaska Docker och
   prova start. Under första värdprovet, med tjänsterna avstängda och utan
   skrivande processer, kontrollera att Docker nekar start med fel volym-ID.
   Återställ korrekt värde och kontrollera omstart med monterad datavolym.
   Monteringskravet gäller även containrar som Docker återstartar automatiskt.
4. Installera den granskade källrevisionen rootägd och inte skrivbar av
   appkonton under `/opt/tjipp/current`. Installera
   [tjipp-metadata.service](tjipp-metadata.service) i `/etc/systemd/system/`
   och [docker-metadata.conf](docker-metadata.conf) som
   `/etc/systemd/system/docker.service.d/41-tjipp-metadata.conf`.
   Kontrollera att ingen swap finns; avaktivera den beständigt före OpenBao.
   Läs om systemd och kör metadataenheten samt `check.py host` som root.
   Docker kräver enheten och gör även en ny filterkontroll vid varje start.
   Prova med tjänsterna stoppade att saknat/förändrat filter nekar Dockerstart;
   återinstallera och verifiera båda adressfamiljerna med tjänsternas UID:n.
   Ändra inte andra brandväggstabeller. Root och värdadministration är betrodda;
   en senare administrativ brandväggsändring kräver ny kontroll.
5. Förbered nya privata filer enligt driftprofilen. Kontrollera den separata
   spärrstacken och behörigheterna. Spara `HostRoleArn`,
   `ContinuityClientRoleArn` och `NoticeClientRoleArn` i rotatorns privata
   konfiguration. Importera det kompletta godkända leveranspaketet och jämför
   samtliga tre verifierade image-ID:n med konfigurationen före tjänstestart.
   Slutför och prova OpenBao-tokenförnyelse, unseal-beredskap och samordnad
   återställning innan miljön lämnas obevakad. Anslut DNS och certifikat när ingångarna är redo.
   Prova certifikatförnyelse, stängd registrering och verifierad spärr vid
   nedstängning av huvudkedjan. Spara resultaten för samma version.

## Övervakning och återställning

Knyt värdens faktiska `InstanceId` och båda volym-ID:n till den befintliga
[säkerhetsstacken](../security/README.md) om dess larm, trail och snapshotplan
införs. Kontrollera befintliga trails och kostnader före exekvering. Prova
larmleverans och kvittens med utsedda mottagare. Använd
[återställningsbindningen](../../docs/aterstallningsbindning.md) för en
konsekvent registerkopia och en isolerad återläsning med aktuell spärrtjänst.
DataDisk bevaras vid borttagning eller ersättning av stacken. Vid värdbyte
stoppar operatören processerna och avmonterar disken före frånkoppling.
Prova att återläsning bevarar senare spärrar. Styrk lagringsplats, kostnad,
bevarande och återställningstid innan backup räknas som införd.

Primärkällor för [Ubuntu-AMI](https://documentation.ubuntu.com/aws/aws-how-to/instances/find-ubuntu-images/),
[SSM-anslutning](https://docs.aws.amazon.com/systems-manager/latest/userguide/setup-create-vpc.html)
och [EBS-serienummer](https://docs.aws.amazon.com/ebs/latest/userguide/identify-nvme-ebs-device.html).

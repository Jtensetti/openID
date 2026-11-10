# AWS-värd för Tjipp

[host.yaml](host.yaml) beskriver en varaktig värd för den samlade
[driftprofilen](README.md) i `eu-north-1`. Välj en Canonical Ubuntu 24.04 LTS
amd64-AMI med gp3 och kontrollera dess ägare `099720109477`, tillgänglighet
och rotenheten `/dev/sda1` före användning. Spara AMI-ID, zon och revision
tillsammans med CloudFormations förändringsplan.

Mallen väljer en `t3.large` med 8 GiB som utgångspunkt för kapacitetsprov.
CPU-krediter körs i Standard-läge. Krypterad gp3 lagrar 20 GiB på systemdisken
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
och könamnet från `NoticeQueueArn`. Då tillkommer exakt `lambda:InvokeFunction`
för den funktionen och `sqs:SendMessage` för den kön i samma konto och region.
Processerna delar värdens instansroll. Värdens administratör kan nå
värdens filer och processer, vilket ingår i modellen för driftbehörighet.

## Förändringsplan

```sh
cfn-lint --regions eu-north-1 --template deployment/production/host.yaml
cfn-guard validate --rules deployment/production/host.guard \
  --data deployment/production/host.yaml --output-format json
aws cloudformation validate-template --region eu-north-1 \
  --template-body file://deployment/production/host.yaml
```

Använd en CREATE-förändringsplan för den nya stacken. Tilldela `AmiId` det
verifierade ID:t, välj zon och använd `CAPABILITY_IAM`. Läs samtliga ändringar
och valideringshändelser. Bevara planens ID, resurslista och parametrar.
Exekvering startar debitering för värd, volymer och adress. En stoppad värd
lämnar kostnaden för volymer och fast adress. Redovisa kvarvarande historiska
adresser separat fram till avveckling.

## Starta värden

1. Läs `InstanceId`, `DataVolumeId` och `PublicIPv4` från stacken. Kontrollera
   instansens faktiska AMI, metadataalternativ, gruppregler, volymer och
   SSM-status. Läs in systemuppdateringar från signerade Ubuntu-arkiv över
   HTTPS. Installera Ubuntu-paketen `docker.io`, `docker-compose-v2`, `nginx`
   och `certbot`. Anteckna exakta installerade versioner. Maska
   `docker.service` och `docker.socket` före installationen så att Docker
   börjar starta först med volymkontrollen på plats.
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
4. Förbered nya privata filer enligt driftprofilen. Kontrollera den separata
   spärrstacken och behörigheterna. Importera leveranspaketet och jämför dess
   verifierade image-ID med den deklarerade konfigurationen innan de sex
   processerna startas. Anslut DNS och certifikat när ingångarna är redo.
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

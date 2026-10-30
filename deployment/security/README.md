# Backup, revisionslogg och larm

`template.py` genererar en separat CloudFormation-stack. Den skapar ingen EC2,
Lambda, databas, bildanalys eller skanning av användarinnehåll. Ingen prenumeration
skapas automatiskt. Driftansvarig väljer och bekräftar larmmottagare separat.

## Omfattning

- En flerregions-CloudTrail för managementhändelser, med signerade kontrollfiler.
  Första managementkopian är normalt utan CloudTrail-händelseavgift; S3, KMS
  och CloudWatch debiteras enligt användning. Befintliga trails ska kontrolleras
  så att dubbla debiterbara kopior inte införs av misstag. Inga data events eller
  betalda Insights aktiveras.
- Privat S3 med versionshantering, KMS-kryptering och ett års föreslagen gallring.
  CloudWatch håller samma managementhändelser 90 dagar för larm. Nyckeln roteras.
  Detta är inte ett oberoende WORM-arkiv; kontoadministratören kan fortfarande
  ändra kontrollen. Projektets separata arkiv har en annan uppgift.
- Dagliga DLM-snapshots av den uttryckligen angivna instansens två volymer,
  inklusive rotvolym, 14 uppsättningar. Schemat är 17:00 UTC och körs inom AWS:s
  schemaläggningsfönster. Betan kör dygnet runt till kampanjslut: anta därför
  inte att den är stoppad vid kopiering. En volymsnapshot från körande server
  är kraschkonsekvent och ersätter inte appens konsekventa registerbackup
  eller en återställningsövning. Stoppa inte drift som bieffekt av detta paket.
- Sexton standardlarm för tre befintliga funktioners fel/throttling, köfördröjning,
  dead letters, instansfel, snapshotfel/utebliven kopia och fyra säkerhetshändelser.
  De läser befintliga mätvärden och CloudTrail-filter, utan nya beräkningsjobb.
  Ett krypterat SNS-topic används för leverans. Larmet för utebliven kopia börjar
  gälla först när backup aktiveras.

## Validering

```sh
python3 deployment/security/template.py > /privat/security-template.json
cfn-lint --format json --regions eu-north-1 --template /privat/security-template.json
cfn-guard validate --rules deployment/security/security.guard --data /privat/security-template.json --output-format json
GUARD_BIN=/sokvag/till/cfn-guard python3 -m unittest discover -s deployment/security -v
```

Negativa tester provar offentlig/okrypterad lagring, avstängd eller ofullständig
trail, raderbara loggar/nycklar, för bred snapshotbehörighet och tyst backupbortfall.
Reglerna nekar också extra beräkningsresurser, skanning, CloudTrail Insights och
data events. Att lägga till sådana tjänster kräver en uttrycklig ändring av
den granskade omfattningen och en ny kostnadsbedömning.
Använd verifierad Guard 3.2.1 enligt befintligt CI-jobb. Driftens parametrar,
konton, larmmottagare och bevis hör inte hemma i publika exempel.

## Införande i två steg

1. Verifiera konto, region, befintliga stackar/trails, instans och exakt två
   krypterade volymer. Ange faktiska namn på de tre funktionerna och två köerna.
   Matcha inte godtyckliga resurser på ett gemensamt projektnamn. Kontrollera
   kostnad och godkänd bevarandeperiod.
2. Generera mallen och validera syntax/schema, säkerhetsregler och IAM-policyer.
   Skapa en förändringsplan med `BackupState=DISABLED`; kontrollera dess resurser
   och valideringshändelser innan exekvering. Ingen befintlig stack ersätts.
3. Aktivera stackens raderingsskydd efter skapande. Tilldela endast den avsedda
   instansen taggen `openIDBackup=<stacknamn>`. Om instansen ägs av en annan
   CloudFormation-stack ska taggen även hanteras där, så att nästa uppdatering
   inte återställer konfigurationen. Granska detta som en separat förändring.
4. Kontrollera den nya rollens faktiska policy. Den får skapa kopior för en
   bestämd instans och två volymer; endast snapshots med både denna policys
   AWS-systemtagg och stackens backuptagg får raderas. Prova att andra kopior
   nekas. DLM:s trust är begränsad till konto/region och dess service; efter
   skapande kan SourceArn bindas till exakt policy-ID om rollens livscykel
   hanteras utan cirkulära CloudFormation-beroenden.
5. Uppdatera till `BackupState=ENABLED`. Prova en första snapshot och därefter
   den automatiska körningen. Verifiera varje volym, kryptering, privat delning,
   färdig status och senaste ålder. Ett summerat larm om två kopior kan inte
   ensamt styrka att rätt volymuppsättning går att återställa.
6. Anslut godkänd larmmottagare, bekräfta prenumeration och prova ett tydligt
   märkt syntetiskt driftlarm. Kontrollera leverans och kvittens samt återgång
   till OK. Utse reservmottagare och dokumentera beredskap. Bekräftelselänk ska
   hanteras av den avsedda mottagaren; ett topic utan bekräftad mottagare är
   inte färdig incidentberedskap.
7. Bevisa faktisk CloudTrail-leverans i S3 och CloudWatch, inte bara IsLogging.
   Prova positiva och negativa filterhändelser utan identitetsdata. Vid fel
   inspekteras LastDeliveryError/LatestCloudWatchLogsDeliveryError, IAM och KMS.
8. Gör en isolerad återställningsövning enligt överordnad driftinstruktion.
   Att en snapshot är `completed` innebär inte att F04 eller ISO-kontrollen
   är stängd. Bevara aktuell oberoende spärrstatus och raderingsbeslut.

## Kostnad och driftgränser

Snapshot debiteras för lagrade block, inte för antalet jobb. Ett konservativt
planeringsfall är två fulla volymer × antal kvarhållna dagar; faktisk kostnad
beror på använda och ändrade block. Beräkna med aktuell regional prislista,
antal larm/mätvärden, loggvolym, KMS/SNS/S3, skatt, valuta och tillfälligt
återställningsutrymme. Aktivera en kostnadsbudget med tidiga varningar; AWS
Budgets är fördröjd bevakning, inte ett automatiskt utgiftstak. Stäng inte
spärr eller radera nödvändiga backup-/revisionsbevis automatiskt vid en varning.

Backup är inom samma konto/region och inkluderar lokala nyckelfiler. Den är
inte separat nyckelförvaring eller skydd mot kapad kontoadministratör. För en
annan volym, kundhanterad EBS-nyckel eller ändrad serverarkitektur krävs ny
behörighets- och återställningsprövning; rättigheter ska inte breddas generellt.
Managementloggen täcker inte applikationens identitetsbeslut, nginx-trafik,
alla dataläsningar eller alla fel i externa beroenden. Larm för kampanjens
slutstopp och intern hälsa måste utformas utifrån verkligt driftlöfte.

## Primärkällor

Kontrollerade 2026-10-26:

- [CloudTrail i CloudFormation](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cloudtrail-trail.html)
- [CloudTrail till CloudWatch](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-required-policy-for-cloudwatch-logs.html)
- [CloudTrail KMS-policy](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-kms-key-policy-for-cloudtrail.html)
- [DLM-roller](https://docs.aws.amazon.com/ebs/latest/userguide/service-role.html)
- [DLM-mätvärden](https://docs.aws.amazon.com/ebs/latest/userguide/monitor-dlm-cw-metrics.html)
- [Krypterad SNS och tjänsteavsändare](https://docs.aws.amazon.com/sns/latest/dg/sns-key-management.html)
- [CloudWatch-larmens källbegränsning](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Notify_Users_Alarm_Changes.html)

Detta är operativa kontroller och testbar konfiguration, inte ett påstående om
certifiering, full ISO-efterlevnad eller Digg-godkännande.

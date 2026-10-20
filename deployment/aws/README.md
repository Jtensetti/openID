# RDS-kompatibilitetstest

Tillfällig miljö i `eu-north-1` för register-, behörighets-, TLS-, last- och
återställningsproven i `verification/test_cluster.py`. Den kör inga publika
e-id-tjänster och behandlar inga verkliga personuppgifter.

## Resurser och kostnad

PostgreSQL 18.6 körs på RDS `db.t4g.micro`, Single-AZ, med 20 GiB krypterad
gp3-lagring. Testmaskinen är `t3.small`, med 12 GiB krypterad gp3-disk och
CPU-krediter i standardläge. Databasen är privat. Testmaskinen har inga
inkommande nätregler; administration sker genom Systems Manager.
Databaslösenordet skapas av RDS och läses från Secrets Manager i testprocessen.

En EventBridge-regel anropar avvecklingsfunktionen var femte minut. Efter
fyra timmar från mallgenereringen tar den bort den märkta databasen och
avslutar testmaskinen. Funktionen finns innan dessa resurser skapas.
API-fel och tjänstefördröjningar kan försena avvecklingen: kontrollera alltid
slutläget och ta bort hela stacken efter testet. Inga snapshots sparas.

Mallen saknar NAT Gateway, lastbalanserare, databasproxy och automatisk
lagringsökning. Kontrollera aktuella regionala priser, kontoplan och saldo
före varje körning. AWS Free plan tillåter endast Single-AZ för RDS;
detta prov verifierar därför inte automatisk databasväxling mellan zoner.

## Förbered och granska

Python 3.12 och AWS CLI med behörighet att hantera teststacken behövs lokalt.
Lös upp Canonicals Ubuntu 24.04 x86_64-AMI i Stockholm och granska ID:t innan
det skickas till generatorn. Ett fast AMI-ID låser den aktuella körningen.

```sh
aws ssm get-parameter --region eu-north-1 \
  --name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id \
  --query Parameter.Value --output text
python3 deployment/aws/template.py --ami AMI_ID > /tmp/openid-rds-test.json
aws cloudformation validate-template --region eu-north-1 \
  --template-body file:///tmp/openid-rds-test.json
```

Välj ett unikt stacknamn med formen `openid-aws-check-` följt av tolv
hextecken. Använd CloudFormation change set med `CAPABILITY_IAM`, granska
resurslistan och valideringshändelserna, och verkställ sedan samma change set.
Sätt stacktaggarna `Environment=disposable-test` och `OpenIDTest=STACKNAMN`.
En mall vars sluttid har passerat ska genereras om, inte förlängas i Lambda.

## Kör och avveckla

Stackens outputs innehåller `RunnerId`, `DatabaseHost`, `DatabaseSecretArn`,
`ExpiryFunction` och `ExpiresAtEpoch`. Kontrollera att SSM visar maskinen
som Online, att avvecklingsregeln är aktiverad och att ett provanrop till
funktionen returnerar `WAITING` före sluttiden.

Överför en granskad källrevision till testmaskinen via SSM Run Command.
Hämta arkivet med full commit-SHA från GitHub och kontrollera dess SHA-256
innan uppackning. Kör som root, från den uppackade revisionen:

```sh
bash deployment/aws/bootstrap.sh DATABASE_HOST DATABASE_SECRET_ARN
```

Skriptet kontrollerar SHA-256 för Node, OpenBao, AWS CA-paket och Pythonhjul.
Det kräver en oanvänd databas med rätt testnamn och PostgreSQL 18. Rapporten
skrivs till `/var/tmp/openid-aws/capacity.json`. Testnycklar och hemligheter
ska inte kopieras till kommandotext, loggar eller testartefakter.

Samla resultatet och ta därefter bort stacken även om testet misslyckades:

```sh
aws cloudformation delete-stack --region eu-north-1 --stack-name STACKNAMN
aws cloudformation wait stack-delete-complete --region eu-north-1 --stack-name STACKNAMN
```

Kontrollera att RDS-instansen är borta och EC2-instansen avslutad, inklusive
dess disk. Faktureringsuppgifter kan vara fördröjda. En kvarvarande stack
eller misslyckad radering måste hanteras innan arbetet lämnas.

## Lokala tester

```sh
python3.12 -m venv /tmp/openid-aws-venv
/tmp/openid-aws-venv/bin/pip install --require-hashes --only-binary=:all: -r deployment/aws/requirements.lock
/tmp/openid-aws-venv/bin/python -m unittest discover -s deployment/aws -v
```

CI kör avvecklingens säkerhetsfall och CloudFormation Guard utan AWS-nycklar.
Mallens API-schema kontrollerades med `cfn-lint` 1.57.2; Guard 3.2.1 är
SHA-256-låst i workflowet. Beroenden och underhåll redovisas i
[THIRD_PARTY.md](THIRD_PARTY.md).

OpenBao körs i testläge för de vanliga registerproven; återställningsprovet
startar även en separat TLS-skyddad Raft-miljö. Mallen saknar redundans,
produktionsbackup, driftlarm och en beständig nyckeltjänst. Den ska inte
återanvändas som produktionsmiljö.

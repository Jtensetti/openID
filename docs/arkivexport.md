# Privat export av registerjournaler

`verification/audit_archive.py` exporterar en sammanhängande läsögonblicksbild
av befintliga registerjournaler. Format 1 och 2 är JSON Lines med fasta kolumner,
radantal, byteantal och SHA-256 per fil i ett manifest. Verktyget skriver
aldrig tillbaka till registret och anropar ingen nyckeltjänst.

För versionslåst lagring i ett annat AWS-konto, separat mottagarkvittens och
senare läsbarhetsprov finns [arkivklienten och infrastrukturen](../deployment/archive/README.md).
Leverans och mottagning är separata steg under olika konton/roller.

## Population och åtkomst

| Körläge | Innehåll |
|---|---|
| SQLite | Credentials: ID, publik nyckel, tillstånd, skapande, giltighet och beslutsreferens. Profilmetadata: credential, version, verifieringstid och dokumentets sista giltighet. Samtliga befintliga händelser. Format 2 inkluderar även gallringsjournalen. |
| PostgreSQL schema 2 | Samma tre populationer samt aktiveringsförslag med begärare/godkännare och operatörshändelser. Operatörstid bevaras i UTC med mikrosekunder. |

Alla rader som är synliga i ögonblicksbilden ingår; ingen tidsfiltrering eller
automatisk gallring görs. PostgreSQL använder `REPEATABLE READ READ ONLY` och
servercursor; SQLite använder en explicit lästransaktion. En samtidig spärr
får därmed inte blandas in i bara en av exportens tabeller.

Efter [SQLite-gallring](gallring-sqlite.md) inkluderar profilpopulationen även
bevarade metadata från `profile_evidence`, med samma kolumner och format.
Motstridiga levande/bevarade rader avvisas. Profilinnehållet återinförs inte.
SQLite med enbart gallringsschema exporteras som format 2. `retention_runs.jsonl`
ingår även när journalen är tom: körnings-ID, tid, deklarerad policyreferens,
policyhash, de två lagringstiderna och antal per gallringstabell. Journalens
typer, intervall, räknarfält och hash mot den deklarerade policyn kontrolleras
både vid export och offlineverifiering. Referensen eller hashen bevisar inte
att policyn är beslutad eller att journalens uppgifter är sanna.

Journal och profilmetadata läses i samma snapshot. Ett ofullständigt
gallringsschema eller vyer i stället för dess tabeller nekar exporten;
verktyget får inte tyst utelämna journalen. Äldre SQLite utan gallringsschema
och PostgreSQL schema 2 behåller format 1. Offlineverifieringen stöder båda
formaten samt format 3 nedan. Äldre verifierare nekar nya format och behöver uppdateras före mottagning.

Format 3 används för SQLite med samtyckestabeller och för PostgreSQL schema 3. Det inkluderar även `enrollment_policies`, `enrollment_consents` och `credential_consents`: exakt information, signerade val, enhetsnyckelns digest, serverns mottagningstid, eventuell återkallelsetid och credentialbindning. SQLite behåller gallringsjournalen. Ett delvis tillagt samtyckesschema nekas. Nya exporter kräver uppdaterad verifierare och PostgreSQLs utökade, läsande `archive-access.sql`. Äldre arkivformat kan fortfarande verifieras.

Personprofiler, bilder, person-/dokumenttaggar, pairwise subjects,
PIN-verifierare och sessionshemligheter exporteras inte. Exporten innehåller
ändå känsliga identifierare, händelser och operatörsnamn. Katalogen skapas
med läge 0700, filerna med 0600. Hantera den på ett skyddat, krypterat
arkivmedium utanför repot. Lägg aldrig exporten bland publika CI-artefakter.

## Export

SQLite kräver en befintlig databas, men ingen identitetsnyckel:

```sh
python verification/audit_archive.py export \
  --sqlite /private/wallet.sqlite \
  --destination /private/archive/register-20261024 \
  --revision FULLSTANDIG_40_TECKENS_COMMIT_SHA
```

För PostgreSQL tillämpas först `deployment/cluster/archive-access.sql` av
behörig databasägare. Skriptet kan köras igen och ger befintliga
`openid_auditor` läsrätt till de uttryckligen valda kolumnerna. Det ger ingen
läsrätt till profilers chiffertext, subjects, PIN-verifierare eller
sessionshemligheter, och ingen skriv-/aktiveringsrätt. Använd ett separat
personligt revisionskonto med denna roll; dela inte applikationens login.
Tillämpa åtkomsten separat även i en återställd databas. Ordinarie schema 2
och befintliga backupformat ändras inte.

```sh
python verification/audit_archive.py export \
  --postgres-file /private/auditor-db \
  --destination /private/archive/register-20261024 \
  --revision FULLSTANDIG_40_TECKENS_COMMIT_SHA
```

Anslutningsfilen ska vara en privat vanlig fil, läge 0600, med fullständig
libpq-anslutning inklusive `sslmode=verify-full` och betrott CA-certifikat.
Anslutningen läses ur filen och visas inte i processargument eller feltext.
Angiven kodrevision är operatörens uppgift och ska verifieras mot byggbevis;
formatkontrollen är ingen attest av vilken kod som faktiskt kördes.

Standardgränsen är 1 GiB totalt, högst en miljon rader per population,
högst 1 MiB per rad och fem minuters körtid. Lägre totalgräns kan väljas
med `--max-bytes`. Fel eller överskriden gräns tar bort det nya, ofullständiga
uttaget; befintlig destination skrivs aldrig över. Manifestet skapas sist,
efter slutförd lästransaktion, och resultatet innehåller dess SHA-256.

## Oberoende mottagning och läsbarhetsprov

1. Bevara resultatets `manifestSha256` separat i behörighetsstyrd journal
   eller hos arkivmottagaren. Kontrollsumman får inte hämtas från samma
   föränderliga exportkatalog vid verifieringen.
2. Överför uttaget till avsedd arkivförvaring och låt mottagaren verifiera
   mot den separat förmedlade kontrollsumman.
3. Dokumentera mottagare, tid, förvaringsreferens och kvittens med digest.
   Prova återkommande läsning och verifiering från arkivets egen kopia.

```sh
python verification/audit_archive.py verify \
  --source /private/received/register-20261024 \
  --manifest-sha256 SEPARAT_BEVARAD_SHA256
```

Offlineverifieringen använder endast Pythons standardbibliotek. Den nekar
ändrade/trunkerade filer, omskrivet manifest mot gammal kontrollsumma,
saknade/extra filer, avvikande kolumner/radantal, symlänkar, hårda länkar,
publikt läsbara filer och överskridna gränser. Kontrollsummor visar att bytes
överensstämmer med det förankrade uttaget. De ger ingen digital signatur,
betrodd tid, autenticitet hos databasens ursprung eller skydd mot att en
administratör ändrat registret före exporten.

Detta är ett läsbart uttag av befintliga journaler, inte ett fullständigt
utgivningsbevis eller en återställningsbackup. Uttaget innehåller inte
passunderlag, biometrisk prövning eller villkorsacceptans som registret inte
bevarar. Oberoende förvaring, beslutad bevarande-/gallringspolicy, faktisk
mottagarkvittens, larm vid uteblivet uttag och schemalagda läsbarhetsprov
behöver införas i driften. Verktyget ändrar ingen gallringsrutin.

Tekniskt stöd för ögonblicksbilder:
[PostgreSQL 18](https://www.postgresql.org/docs/18/transaction-iso.html#XACT-REPEATABLE-READ)
och [SQLite](https://www.sqlite.org/isolation.html).

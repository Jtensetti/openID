# Separat byggmiljö och serverleverans

Den samlade driftprofilen levereras nu med
[tre-image-paketet](../production/README.md#inventering-av-alla-tre-bilder).
Det återanvänder appverifieraren nedan men kräver även separata bedömningar
och importkontroller för PostgreSQL och OpenBao. Instruktionerna för
`deployment/image_bundle.py` gäller appens underpaket och äldre privat beta;
de räcker inte ensamma för den samlade driften.

`Private pilot runtime` bygger Linux/amd64-paketet på en ny GitHub-hostad
Ubuntu 24.04-maskin. Betavärden används inte för kompilering eller Dockerbyggen.
Jobbet får endast läsa repot och har inga AWS-behörigheter, Apple-nycklar,
betanycklar, personregister eller åtkomst till privata testnät.

Byggkontexten kommer från `git archive HEAD`: bara versionshanterade filer
följer med, utan Git-inloggning eller lokala filer. Dockerbaser, paket och
modeller använder befintliga versions- och hashlås. Ingen ny tredjepartsaction
eller utökad tokenbehörighet införs. Byggjobbet behöver internet för låsta
beroenden; verifierar- och protokollproven körs utan externt nät.

## Bygg och hämta

1. Merge till `main` startar hela `Assurance checks`. Serverjobbet bygger,
   provar, exporterar och återläser exakt samma image utan ett nytt bygge.
   PR-jobb provar också export/import. För PR:er från samma repository sparas
   det fullständiga paketet; externa fork-PR:er får inget sådant leveranspaket.
2. Hela körningen, inklusive `assurance-gate`, ska vara godkänd för vald
   revision. Ett tillgängligt imagepaket är inte ensamt ett godkännande:
   ett annat komponentjobb kan ha misslyckats efter att det laddades upp.
3. Hämta `production-image-<full revision>` från den verifierade körningen. Bevara
   körningslänk, försök, revision och manifestets SHA-256 från jobbsammanfattningen
   separat från det hämtade paketet. Artefakten sparas i GitHub i **sju dagar**;
   releasearkivet behöver egen bevaring. Byggdata använder Actions-lagringskvoten.
4. Ett separat ombygge kan startas med **Run workflow** i `Private pilot runtime`
   för en vald branch/tagg. Manifestets `source.revision` anger det faktiskt
   byggda HEAD. Kräv också en passerad helhetskörning på samma källträd och
   dokumentera kopplingen. En manuell serverkörning ersätter inte den grinden.

Appens underpaket i `application/` innehåller `image.tar.gz`, `source.tar.gz`, `manifest.json`,
`python-packages.json`, syntetiska `protocol-results.json` och elva `os-*`-filer:
OS-bedömning, Trivy-rapport, CycloneDX, dpkg-lista, databasmetadata,
skannerlås, skanner-SBOM, tillämplighetspolicy, runtimeprov, komponentadvisories
och tillämplighetsresultat. Manifestet binder filernas storlekar och SHA-256
till Git-revision/träd, image-ID, plattform och byggkörning. Exporten nekar
ofullständig, gammal eller underkänd OS-skanning, fel image-ID/revision och
paketlistor som inte stämmer. Källarkivet innehåller också låsfiler, SBOM,
licenser och motsvarande källkod. SAML-bryggan, federationsmodulen och
hälsoproben ingår i imagen; betans Compose-filer monterar ingen programkod.
Övriga komponenters test- och advisoryartefakter bevaras separat från samma
helhetskörning enligt [releaseinstruktionen](../../docs/releasekandidat.md).

Kontrollsumman måste hämtas via den betrodda GitHub-körningen, inte enbart
räknas fram från ett okänt paket. Den ger integritetskontroll relativt den
valda körningen, ingen oberoende byggattest eller garanti mot en komprometterad
repoägare, byggmiljö eller Actions-tjänst. Paketet är inte produktionsgodkänt.

## Importera utan att bygga eller starta tjänster

Använd Python 3.9+ och en granskad checkout av den valda kodrevisionen.
`deployment/image_bundle.py` använder även hjälparna under `deployment/build/`.
Hämta koden genom den betrodda kodkanalen, inte genom
att först köra okänd kod ur ett overifierat paket. Packa upp Actions ZIP i
en egen privat katalog. Behåll image- och källarkiven i paketet som filer.

```sh
python3 deployment/image_bundle.py verify \
  --directory /privat/kandidat \
  --expected-revision FULL_COMMIT_SHA \
  --expected-manifest-sha256 SHA256_FRAN_GITHUB_KORNINGEN

python3 deployment/image_bundle.py import \
  --directory /privat/kandidat \
  --expected-revision FULL_COMMIT_SHA \
  --expected-manifest-sha256 SHA256_FRAN_GITHUB_KORNINGEN
```

Import kräver en lokal Linux/amd64-Dockerdaemon och läsbart Docker-datalager.
Fritt utrymme i det lagret måste vara minst två gånger image-storleken plus
512 MiB, utöver det nedladdade paketets plats. Skriptet avvisar fel revision,
manifest, filhash, saknad fil, symlänk, plattform, ofullständiga
protokollresultat eller OS-bevis innan Docker ändras. OS-skanningens aktualitet
kontrolleras mot **paketeringstiden**, men tillämplighetspolicyn måste även
vara giltig vid import. En utgången bedömning stoppar alltså också ett äldre
återgångspaket tills en ny granskad kandidat finns.
Efter laddning måste image-ID och plattform stämma. Ingen container startas
eller ersätts; inga data återläses.
Operatören måste skydda paketkatalogen mot samtidiga ändringar under import.

Om utrymmet inte räcker: välj större lagring eller arkivera/ta bort enbart
identifierade, oanvända byggartefakter enligt en granskad åtgärd. Kör inte
`docker system prune`, radera inte register och bygg inte om på betavärden.

## Installera i den privata betan

Följ [kandidat och återgång](../../docs/releasekandidat.md). Registrera aktuell
konfiguration och image-ID för varje tjänst. Vid övergång från äldre
uppsättningar ska deras kodmonteringar tas bort genom samma granskade
Compose-byte; imagebyte ensamt tar inte bort dem.
Bevara register, nycklar, spärrar, privata miljövärden och aktuella volymer.
Sätt `OPENID_BETA_IMAGE_ID` till manifestets fullständiga `sha256:...` efter
verifiering. Både `beta-compose.yaml` och `continuity-compose.yaml` kräver
variabeln. Kontrollera den sammanslagna konfigurationen före ett godkänt byte:

```sh
docker compose -f deployment/beta-compose.yaml -f deployment/continuity-compose.yaml \
  config --format json | python3 deployment/image_bundle.py check-beta-compose \
  --image-id "$OPENID_BETA_IMAGE_ID"
```

Kontrollen kräver samma fullständiga image-ID för alla sex tjänster,
skrivskyddad rot och exakt tjänstens data-/konfigurationsmonteringar under
`/srv/openid`. Den kräver även separata processidentiteter, avgränsade grupper
och nyckel-/aviseringssocket enligt [betans isolering](../README.md#processer-och-nycklar-i-betan).
Övriga volymer, configs/secrets/volumes_from och tmpfs utanför
`/tmp` nekas. Ingen image byggs eller tjänst startas av kontrollen.
Använd `up -d --no-build --pull never` med
rätt Compose-projekt. Efteråt kan samma verifierade paket användas för en
läsande driftkontroll:

```sh
python3 deployment/image_bundle.py check-beta \
  --directory /privat/kandidat \
  --expected-revision FULL_COMMIT_SHA \
  --expected-manifest-sha256 SHA256_FRAN_GITHUB_KORNINGEN
```

Kontrollen nekar saknad, stoppad, extra eller felaktig container, rörlig
tagg, skrivbar rot och monteringar utanför samma data-/konfigurationsgräns.
Även en skrivskyddad kodmontering nekas eftersom den ersätter imagens kod.
[Docker beskriver att bindmonteringar skymmer befintliga filer](https://docs.docker.com/engine/storage/bind-mounts/#bind-mounting-over-existing-data).
Docker-metadatan läses utan att ändra tjänster eller läsa privata filer.
Kontrollen verifierar inte datainnehåll, värd-OS, hela runtimekonfigurationen
eller efterföljande ändringar av en betrodd Dockeradministratör.
Kontrollera readiness, åtkomstskydd och färska telefonflöden efter bytet.

Betavärden behöver fortsatt Docker för drift. Dess operatör kan fortfarande
tekniskt starta ett bygge: denna separation är ett leveransflöde, inte en
oberoende administrativ spärr mot värdens administratör. Sådan rollseparation
och produktionsbeslut hanteras separat. iPhone-distributionssignering sker
fortsatt i den privata Xcode-miljön; inga Apple-certifikat flyttas till CI.

Ett äldre app-/serverpar får inte ersättas genom ett blint imagebyte.
Kontrollera registreringspolicy, aktuell CSCA-CRL, appens stöd för
registreringskvitton, ingressens klientadresshuvud och värdens Landlock-stöd.
Saknade förutsättningar måste ordnas före bytet; stäng inte av kontroller
eller fabricera tidigare deltagares samtycke för att få starten att passera.

## Systempaket och säkerhetsunderlag

Pilot- och registerjobben kör `.github/scripts/audit_image_os.py` mot det
exakta byggda image-ID:t. Trivy kontrollerar alla Debianpaket, alla
allvarlighetsgrader och även fynd utan rättning. Paketlistan måste stämma
exakt med dpkg. Rårapporten sparas ofiltrerad; ingen ignore-fil används.

[Runtimepolicyn](runtime-policy.json) skiljer råa paketträffar från faktisk
påverkan i dessa två Linux/amd64-images. Varje beslut anger CVE, paketversion,
underlag och obligatoriska kontroller. Oanvända paketdelar tas bort fysiskt,
med filhashar i `removal.json`; dpkg-metadata och licenser bevaras. Därför kan
en borttagen komponent fortfarande ge en rå paketträff. Glibcs DNS-söklista
begränsas med tom `LOCALDOMAIN`, även vid Pythonstart. Inga DNS-suffix läggs
till automatiskt; konfigurera tjänster med fullständiga namn. Compose- och
driftkontrollen nekar att skyddet ersätts.

`runtime_evidence.py` provar den färdiga imagen: borttagna filer/moduler,
Base64-avvisning, temporärkataloger, DNS-initiering med lång sökdomän,
SQLite och native-symboler. Ett separat C++-prov testar allokeringsgränsen.
PyTorchs medlevererade testprogram tas bort. FFmpegs videobakände är
avstängd och ett explicit öppningsförsök ska nekas; JPEG/JP2-avkodningen
provas separat. Databasklienten kräver TLS/SCRAM och nekar GSS/Kerberos.
De få kvarvarande native-anropen kräver exakt bibliotekshash och dessa
körningsskydd. Statisk symbolfrånvaro är stöd för den dokumenterade anropsanalysen,
inte ensam bevisning för att all kod är oåtkomlig.

Python/Expat följs dessutom med Chainguards aktuella komponentfeed och
CNA-poster från CVE-programmet. Detta är kompletterande upstreambevakning,
inte ett påstående att Wolfi-paket finns i imagen. Nya/ändrade poster kräver
ny bedömning. Granskade upstreamfynd behåller sina körningskontroller även
när Wolfi backportar en fix; det ändrar inte vår installerade runtime.
Python är 3.12.16, med inbäddad Expat 2.9.0. De öppna
Expat-fynden bedöms mot JSON-gränserna, de låsta AWS-klienterna och Python-API:t;
Java-SAML använder en annan parser. Det är inget generellt friskintyg för Expat.

De interna HTTP-klienterna för OpenBao och övervakning använder strikt
`Content-Length`/chunk-framing i `verification/http_transport.py`. Kontrolltecken
nekas innan URL-normalisering och namnuppslagning. Slutimagen provar felaktiga
längder, chunk-storlekar och nulltecken. AWS-klienterna använder tre fasta
HTTPS-endpoints i eu-north-1, verifierad TLS och inga miljöstyrda HTTP-proxyer.
De tar inte emot destinationsadresser från publika anrop och förmedlar inte
HTTP-framing vidare. Modellhämtning är ett byggsteg med fasta URL:er och hashkontroll.
Bedömningen av CVE-2026-103995 och CVE-2026-116566 gäller dessa anropsgränser;
den underliggande CPython-versionen är inte patchad och ska inte anges som fri
från fynden för generell användning. Nya nätverksanrop kräver ny bedömning.

Snapshotåterställning nekar vyer, triggers och virtuella SQLite-tabeller före
integritetskontrollen. Separata WAL-/journalfiler får inte importeras.
Negativa prov körs även i slutimagen. Locale är låst till C.UTF-8 och tom
LANGUAGE, så att HTTP-anrop inte kan välja meddelandekataloger.
Nya GCC-fynd i kompilatorns headerfiler skiljs från installerade runtimebibliotek;
den bedömningen intygar inte separat kompilerad kod i Pythonhjul.
Samtliga berörda CNA-poster är hashbundna till granskningen.

Grinden kräver noll **obearbetade eller tillämpliga** fynd. Nya CVE:er,
nya versioner, ändrad runtimekod, saknade prov och utgånget granskningsdatum
stoppar bygget. Besluten gäller till datumet i policyn, längst till betans slut.
Vid kod- eller beroendeändring måste berörda dataflöden omprövas innan
`sourceSHA256` uppdateras. Att bara byta hash är inte en säkerhetsgranskning.
Import/export räknar om besluten från rådata och kräver policyn från den
betrodda checkouten. Bedömningar är inte oberoende attestation eller riskacceptans.

STS-förnyaren ingår i appimages och använder den låsta SDK:ns Query/XML-protokoll.
Bedömningen får inte utgå från att XML saknas.
`metadata_client()` registrerar en kontroll på `before-parse.sts` för både
lyckade svar och API-fel, innan SDK:ns XML-parser skapas. Den kräver UTF-8,
nekar DTD/entitetsdeklarationer, nulltecken och annan deklarerad kodning samt
nekar parserindata över 64 KiB. SDK:n har redan buffrat kroppen vid denna
punkt; gränsen begränsar parsningen, inte hämtningens minnesåtgång.

`runtime_evidence.check_sts_transport()` provar samma klient och låsta SDK
med syntetiska wire-svar. Vanlig GetCallerIdentity, AssumeRole och API-fel
ska nå den riktiga parsern; förbjudna kroppar ska avvisas innan parsern
skapas. Nätanslutningar nekas och endast genererade metadata-credentials
används. Pilotens SDK-prov kör också denna kontroll från den färdiga imagen.
För lokala prov i en utvecklingsmiljö med SDK-låset installerat:

```sh
PYTHONPATH=verification:deployment/build python3 -m unittest -v test_aws_credentials
```

Tre JSON-klienter är inte längre underlag för påståendet att XML saknas.
Den gamla markören `python_xml_not_exposed` lämnas inte som godkänt bevis.
De tre Expat-besluten kräver nu enkeldokumentprov, granskad källkod och samtliga
STS-kontroller. Gränserna prövas mot parser-reset, DTD-expansion respektive
orimligt stora attributmängder. Övriga XML-konsumenter måste bedömas separat.
SPAR:s kundtestmodul är inte kopplad till utfärdande och följer inte med i
runtimebilderna; dess separata tester finns kvar. AST-gränsen för direkta
XML-importer behålls. Källhashen binder den dokumenterade ändringsgranskningen;
okända eller kvarvarande GCC-/glibc-/OpenSSL-fynd blockerar fortfarande.

Skanner och upstream-SBOM verifieras mot [trivy.lock.json](trivy.lock.json).
Databasen och komponentfeedens index/arkiv får vara högst 24 timmar gamla.
Ofullständighet och verktygsfel stoppar exporten. `pilot-image-inventory` och
`cluster-os-inventory` behåller rådata, inventering, källor, prov och beslut
i 90 dagar även vid fel. Kopierad Node/Temurin, inbäddade hjulbibliotek,
andra tjänsteimages och värd-OS behöver fortsatt egen kontroll.

### Färdig image och rättigheter

`image_surface.py` inventerar paketfiler, kända komponenter och SQLite-motorn
utan att köra administrativa verktyg eller läsa register. `--whole-image`
läser fysiska kataloger utom `/dev`, `/proc` och `/sys`; symlänkar följs inte.
Läsfel och mål utanför omfånget ger ofullständigt resultat. Rapporten binder
image-ID, revision, insamlarhash och kontrollprocessens privilegier. Namnsökning
täcker inte omdöpt eller inbäddad kod och utgör inget sårbarhetsundantag.

`file_privileges.py` tar bort setuid/setgid från reguljära filer efter
installation, utan att ändra innehåll, ägare eller katalogers setgid.
Före-/efterrättigheter och filhashar sparas. CI nekar nya privilegierade
filer, ändrat innehåll och ofullständig läsning. Inspektionen körs nätlöst
med skrivskyddad rot och enbart `DAC_READ_SEARCH`; tjänsterna behåller UID
10001. Filcapabilities, volymer och värd-OS ingår inte i denna kontroll.
`no-new-privileges`, `cap_drop` och separat driftverifiering behövs fortsatt.

### Låst runtime

Pilot och register använder samma officiella Debianbaserade
`python:3.12.16-slim-trixie`, låst med indexdigest och amd64-manifest i
[python-runtime.lock.json](python-runtime.lock.json). Projektet kompilerar
inte egen Python eller egna Debianpaket och har ingen alternativ runtimebas.
Ursprung, receptrevision och licenser finns i [komponentregistret](../../THIRD_PARTY.md).

Byt digest först efter upstream-/licens-/advisorykontroll. Kör hela CI och
ompröva tillämplighetspolicyn mot den nya slutimagen; installera inte paket
vid serverstart. Debianmetadata beskriver den ursprungliga installationen,
med dokumenterad borttagning av oanvänd kod. Licenserna bevaras.

Applikationshjul hämtas via BuildKits `ADD --checksum` från
[python-wheels.lock.json](python-wheels.lock.json), som matchar verifierarens
requirements-lås. BuildKit med stöd för Dockerfile 1.6+ krävs. Pip installeras
från ett verifierat hjul och körs utan nät eller paketindex. Efter installation
tas pip, dess inbäddade paket, ensurepip bort från runtime. `pip-removal.json` anger borttagna filer och deras hash.
dpkg-databasen och basens metadata bevaras oförändrade: de beskriver installerade
paket före den dokumenterade borttagningen. Filsysteminventeringen visar
faktiskt kvarvarande kod. CI verifierar
borttagningen och den faktiska paketlistan. Byggverktygets advisories och
historiska lager omfattas inte av denna runtimehärdning.

Node och Temurin kommer från digest-/hashlåsta officiella distributioner.
Versioner, upstream-SBOM och biblioteksdata registreras i byggartefakterna;
se [komponentregistret](../../THIRD_PARTY.md). Versionsbyte kräver nya lås,
licens-/advisorykontroll och full CI. Ingen ombyggnad eller paketinstallation
ska göras på betavärden.

`sqlite_transition.py` skapar ett syntetiskt register och en äldre backup
med den tidigare, låsta Bookworm-basen. Den nya imagen måste läsa registret
och återställa backupen med bevarad spärr och registreringskarantän. Den
äldre imagen används endast som testverktyg och levereras inte.

## Prov av leverans och paketkontroll

`python3 -m unittest discover -s deployment -p test_image_bundle.py -v`
provar skadade filer, fel revision/manifest/plattform, saknade filer,
symlänkar, misslyckade/dubbla/ofullständiga protokollresultat, utrymmesstopp
och fel inläst image-ID. Actions provar dessutom verklig export, borttagning
av byggtaggar, återinläsning och Java-start utan nät från det inlästa paketet.
Monteringsproven avvisar ersatt kod, saknade datamonteringar, skrivbara
konfigurationsfiler och överlagring via tmpfs. CI startar dessutom bildens
faktiska SAML-brygga som vanlig användare med tom privat tmpfs-lagring,
kontrollerar rätt/fel audience och socketstädning efter SIGTERM.
Protokollproven importerar bildens federationsmodul utan en värdmonterad kopia.

`python3 .github/scripts/test_audit_image_os.py -v` provar fel image/verktyg/OS,
saknade/extra/dubbla paket, ändrade versioner, gammal/framtida databas,
dolda/felaktiga fynd, korrupta distributionsfiler, skadliga arkivmedlemmar
och att tidigare resultat eller skannerfel inte kan ge godkänt.
Linux-jobbet provar dessutom verklig paketinstallation och skanning av sin image.

Bildproven körs också i den faktiskt byggda serverimagen med avstängt nät
och skrivskyddat filsystem: JPEG/JP2/rå JPEG 2000, andra format, korrupta
bilder och YuNet/SFace. `runtime-components.json` inkluderar OpenCV:s
byggkonfiguration, upstream-SBOM och hash för binären och de medlevererade
delade biblioteken. Se verifierarens [licens- och komponentregister](../../verification/THIRD_PARTY.md)
för de kvarvarande inbäddade biblioteksfynd som OS- och PyPI-skanning inte täcker.

Registerjobbets tidsgräns är 30 minuter för källbygget och de efterföljande
integrationsproven; det inför inget nytt jobb, schema eller molnbehörighet.

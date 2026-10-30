# Separat byggmiljö och serverleverans

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
   PR-jobb provar också export/import, men lagrar inte det stora imagepaketet.
2. Hela körningen, inklusive `assurance-gate`, ska vara godkänd för vald
   revision. Ett tillgängligt imagepaket är inte ensamt ett godkännande:
   ett annat komponentjobb kan ha misslyckats efter att det laddades upp.
3. Hämta `pilot-image-<full revision>` från den verifierade körningen. Bevara
   körningslänk, försök, revision och manifestets SHA-256 från jobbsammanfattningen
   separat från det hämtade paketet. Artefakten sparas i GitHub i **sju dagar**;
   releasearkivet behöver egen bevaring. Byggdata använder Actions-lagringskvoten.
4. Ett separat ombygge kan startas med **Run workflow** i `Private pilot runtime`
   för en vald branch/tagg. Manifestets `source.revision` anger det faktiskt
   byggda HEAD. Kräv också en passerad helhetskörning på samma källträd och
   dokumentera kopplingen. En manuell serverkörning ersätter inte den grinden.

Paketet innehåller `image.tar.gz`, `source.tar.gz`, `manifest.json`,
`python-packages.json`, syntetiska `protocol-results.json` och åtta `os-*`-filer:
OS-bedömning, Trivy-rapport, CycloneDX, APK-lista, databasmetadata,
skannerlås, skanner-SBOM och Wolfis leverantörsadvisories. Manifestet binder filernas storlekar och SHA-256
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
`deployment/image_bundle.py` använder även `deployment/build/wolfi_advisories.py`.
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
kontrolleras mot **paketeringstiden**; ett äldre paket kan fortfarande behövas
för återgång, medan en ny release kräver ett aktuellt säkerhetsbeslut.
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

Kontrollen kräver samma fullständiga image-ID för alla fem tjänster,
skrivskyddad rot och exakt tjänstens data-/konfigurationsmonteringar under
`/srv/openid`. Övriga volymer, configs/secrets/volumes_from och tmpfs utanför
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

## Systempaket och säkerhetsunderlag

Pilot- och registerjobben kör `.github/scripts/audit_image_os.py` mot det
exakta byggda image-ID:t. Trivy jämför Wolfi-paketen med en säkerhetsdatabas
som får vara högst 24 timmar gammal. Hela paketlistan måste stämma mot
APK-databasen `/usr/lib/apk/db/installed`. Okänt OS, saknad täckning, fel image-ID, verktygsfel och fynd
stoppar komponentjobbet, leveransexporten och `assurance-gate`.

Wolfis Trivy-integration utvärderar intervall med rättade versioner. Därför
läser `wolfi_advisories.py` också leverantörens fullständiga OSV v2-feed:
index och arkiv ska vara högst 24 timmar gamla, innehålla samma poster och
ha överensstämmande ändringstider. Indexets millisekunder jämförs på sekundnivå
eftersom v2-posterna trunkerar denna precision. Öppna intervall och statusarna
`detection`, `true_positive_determination`, `pending_upstream_fix` och
`fix_not_planned` blockerar. Okända scheman/statusar stoppar kontrollen.
Denna komplettering ersätter inte Trivys jämförelse av rättade APK-versioner.

Alla rapporterade fynd, även låg/okänd allvarlighetsgrad och fynd utan
publicerad rättning, stoppar exporten. Ingen ignore-fil, statusfiltrering
eller automatisk riskacceptans används. Det är projektets konservativa
releasekontroll, inte ett krav på noll skannerfynd i ISO 27001. Bedöm faktisk
påverkan separat; ett källpakets advisory bevisar inte att varje binär eller
funktion är exploaterbar. En källkodsmerge stänger inga kvarvarande fynd.

Trivy och dess upstream-SBOM hämtas från officiell release och verifieras mot
[trivy.lock.json](trivy.lock.json). Verktyget körs på byggmaskinen utan
molnbehörigheter eller verksamhetsdata och installeras inte i serverimagen.
Skanningen sker lokalt med avstängd telemetri. Internet behövs för
verktygsdistribution och aktuell databas.

`pilot-image-inventory` och `cluster-os-inventory` sparar paketlistor,
Trivy-rapport, Wolfi-poster, CycloneDX, databasdatum/hash, verktygslås/SBOM och bedömning i
90 dagar, även vid fynd. Bevara underlagen från vald revision separat inför
release. Python och dess systembibliotek omfattas av APK-kontrollen. Kopierad Node,
Temurin, OpenCV:s inbäddade bibliotek, modeller, andra images och värd-OS behöver separat bedömning.
OSV-kontrollen av applikationslåsen är ett separat komplement.

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

Pilot och register använder samma minimala Wolfi-bas, byggd med apko från
[wolfi-runtime.yaml](wolfi-runtime.yaml) och det fullständiga paketlåset
[wolfi-runtime.lock.json](wolfi-runtime.lock.json). Alla 31 paket har exakt
version och kontrollsumma, även transitiva beroenden. Python är distributionens
3.12.16-r1; projektet kompilerar inte en egen Python eller egna OS-paket.
Det färdiga filsystemet kopieras till `scratch`, utan skal eller pakethanterare.

Apko 1.4.13 hämtas med SHA-256 från officiell release. Lås och källrevisioner
finns i [runtime-tools.lock.json](runtime-tools.lock.json). Verktyget och
Debian-byggmiljön stannar i byggsteget. APK-metadata, basens SPDX/CycloneDX,
konfiguration, lås och apko-licens sparas under `/usr/share/doc/openid-runtime/`.
Paketens medlevererade licenser bevaras. SBOM anger licensuttryck och källor;
fullständiga komponentlicenser och motsvarande källor behöver säkerställas
före extern distribution, se [komponentregistret](../../THIRD_PARTY.md).

Uppdatera låset med samma verifierade apko-version i isolerad byggmiljö:

```sh
apko lock deployment/build/wolfi-runtime.yaml --arch x86_64 \
  --lockfile deployment/build/wolfi-runtime.lock.json
```

Granska hela paketdiffen, ursprung, licenser och advisories före incheckning.
Låsfilen ska behålla den konfigurationschecksumma som apko genererar.
Kör sedan hela CI; byt inte till rörliga taggar eller uppdateringar vid serverstart.

Applikationshjul hämtas via BuildKits `ADD --checksum` från
[python-wheels.lock.json](python-wheels.lock.json), som matchar verifierarens
requirements-lås. BuildKit med stöd för Dockerfile 1.6+ krävs. Pip installeras
från ett verifierat hjul och körs utan nät eller paketindex. Efter installation
tas pip, dess inbäddade paket, ensurepip och distributionens installeringshjul
bort från runtime. `pip-removal.json` anger borttagna filer och deras hash.
APK-databasen och bas-SBOM bevaras oförändrade: de beskriver installerade
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

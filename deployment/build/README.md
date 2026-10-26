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
`python-packages.json` och syntetiska `protocol-results.json`. Manifestet
binder filernas storlekar och SHA-256 till Git-revision/träd, image-ID,
plattform och byggkörning. Källarkivet innehåller också låsfiler, SBOM,
licenser och de källfiler som betans befintliga Compose-konfiguration monterar.
Övriga komponenters test- och advisoryartefakter bevaras separat från samma
helhetskörning enligt [releaseinstruktionen](../../docs/releasekandidat.md).

Kontrollsumman måste hämtas via den betrodda GitHub-körningen, inte enbart
räknas fram från ett okänt paket. Den ger integritetskontroll relativt den
valda körningen, ingen oberoende byggattest eller garanti mot en komprometterad
repoägare, byggmiljö eller Actions-tjänst. Paketet är inte produktionsgodkänt.

## Importera utan att bygga eller starta tjänster

Använd Python 3.9+ och ett granskat `deployment/image_bundle.py` från den
valda kodrevisionen. Hämta skriptet genom den betrodda kodkanalen, inte genom
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
manifest, filhash, saknad fil, symlänk, plattform eller ofullständiga
protokollresultat innan Docker ändras. Efter laddning måste image-ID och
plattform stämma. Ingen container startas eller ersätts; inga data återläses.
Operatören måste skydda paketkatalogen mot samtidiga ändringar under import.

Om utrymmet inte räcker: välj större lagring eller arkivera/ta bort enbart
identifierade, oanvända byggartefakter enligt en granskad åtgärd. Kör inte
`docker system prune`, radera inte register och bygg inte om på betavärden.

## Installera i den privata betan

Följ [kandidat och återgång](../../docs/releasekandidat.md). Registrera aktuell
konfiguration och image-ID för varje tjänst. Verifiera att monterade kodfiler
kommer från samma revision; imagebyte ensamt byter inte bind-mountade filer.
Bevara register, nycklar, spärrar, privata miljövärden och aktuella volymer.
Ändra image-referenser till manifestets fullständiga `sha256:...` i den valda
konfigurationen och använd `up -d --no-build --pull never` med rätt Compose-projekt.
Kontrollera readiness, åtkomstskydd och färska telefonflöden efter bytet.

Betavärden behöver fortsatt Docker för drift. Dess operatör kan fortfarande
tekniskt starta ett bygge: denna separation är ett leveransflöde, inte en
oberoende administrativ spärr mot värdens administratör. Sådan rollseparation
och produktionsbeslut hanteras separat. iPhone-distributionssignering sker
fortsatt i den privata Xcode-miljön; inga Apple-certifikat flyttas till CI.

## Systempaket och säkerhetsunderlag

Pilotjobbet kör `.github/scripts/audit_image_os.py` mot det **exakta image-ID**
som byggts och provats. En nätlös engångscontainer läser installerade Debian-paket
med `dpkg-query`. Trivy jämför dem med säkerhetsdatabasen; namn, version och
arkitektur för samtliga paket måste också stämma mellan de två inventeringarna.
Okänt OS, saknad täckning, fel image-ID, verktygsfel och en databas äldre än
24 timmar nekar kontrollen. Ingen gammal lyckad rapport återanvänds.

Alla rapporterade fynd, även låg/okänd allvarlighetsgrad och fynd utan publicerad
rättning, stoppar exporten och den gemensamma grinden. Ingen ignore-fil,
statusfiltrering eller automatisk riskacceptans används. Fynd behöver rättas
eller utredas med ett separat granskat beslutsunderlag; detta är en konservativ
releasekontroll, inte ett påstående att ISO 27001 kräver noll skannerfynd.
Bedöm faktisk påverkan: en advisory mot ett källpaket bevisar inte att varje
binärpaket eller tjänstefunktion är exploaterbar.

Trivy **0.76.1** och dess upstream-SBOM hämtas från officiella releasen och
verifieras mot [trivy.lock.json](trivy.lock.json). Verktyget körs endast på
byggmaskinen, med samma läsbehörighet som jobbet, utan molnbehörigheter eller
åtkomst till betans data. Inga nya jobb eller scheman tillkommer. Internet
behövs för distributionsfiler och aktuell säkerhetsdatabas; skanning sker
lokalt med avstängd telemetri. Skannern installeras inte i serverimagen.

`pilot-image-inventory` sparar även vid fynd paketlistan, full Trivy-rapport,
CycloneDX för OS-paketen, databasdatum och databasens SHA-256, verktygslås/SBOM
och `assessment.json` med filhashar och täckningsgränser i 90 dagar. Behåll
denna artefakt från samma godkända helhetskörning tillsammans med releasebevisen.
Python-listan, runtime-versionerna och komponentversioner från Node, Python
(OpenSSL/SQLite/Expat) och Temurins releasefil finns i samma artefakt. OS-kontrollen
granskar **inte** separat byggda/kopierade Python-, Node- och Temurin-runtime,
deras inbäddade bibliotek, modeller, värd-OS eller andra images. Den befintliga
OSV-kontrollen av applikationslåsen kvarstår; hela leveranskedjan är ännu inte täckt.

Python-basen är låst till en uppdaterad digest för samma 3.12.15/Bookworm-release.
[bookworm-updates.lock.json](bookworm-updates.lock.json) låser ytterligare
OpenSSL-/tzdata-paket med Debian-version, ursprung och SHA-256. Byggskriptet
kontrollerar alla nedladdningar och paketidentiteter före installation, nekar
nedgradering och kontrollerar installerad slutversion. Inga extra beroenden
hämtas automatiskt. Både pilot och registerimage använder dessa rättningar;
den fullständiga OS-grinden körs tills vidare bara för piloten.
Paketsteget kräver **Linux/amd64 och Debian Bookworm** och får bara köras inne
i det isolerade imagebygget. Det ska inte köras direkt på en driftvärd.

Node 24.22.1 används i images och motsvarande CI-prov. Python/Temurin har
nyare publicerade säkerhetsreleaser som behöver införas separat; OS-grinden
bevisar inte att dessa runtime-komponenter är aktuella.

Versionsbyten kräver ny käll-, licens- och advisorykontroll samt nya hashlås
och hela CI-körningen. Förvaltningen följer repots beroendeprocess; namngiven
produktionsförvaltare och oberoende releasebeslut återstår.

## Prov av leverans och paketkontroll

`python3 -m unittest discover -s deployment -p test_image_bundle.py -v`
provar skadade filer, fel revision/manifest/plattform, saknade filer,
symlänkar, misslyckade/dubbla/ofullständiga protokollresultat, utrymmesstopp
och fel inläst image-ID. Actions provar dessutom verklig export, borttagning
av byggtaggar, återinläsning och Java-start utan nät från det inlästa paketet.

`python3 .github/scripts/test_audit_image_os.py -v` provar fel image/verktyg/OS,
saknade/extra/dubbla paket, ändrade versioner, gammal/framtida databas,
dolda/felaktiga fynd, korrupta distributionsfiler, skadliga arkivmedlemmar
och att tidigare resultat eller skannerfel inte kan ge godkänt.
Linux-jobbet provar dessutom verklig paketinstallation och skanning av sin image.

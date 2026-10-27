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

`image-surface.json` kompletterar advisorybedömningen med paketens fillistor,
hashar/rättigheter för kända administrativa komponenter och avlästa privilegier
för en separat nätlös, skrivskyddad CI-process. Bild-ID, revision och insamlarens
hash följer med. Saknade läsrättigheter och länkar utanför undersökta kodkataloger
redovisas som ofullständig täckning. Verktygen exekveras inte. Detta är inte
driftkonfiguration, full kodnåbarhetsanalys, VEX eller ett sårbarhetsundantag.
Den ordinarie OS-grinden påverkas inte av inventeringens innehåll.

Pilot- och registerbygget tar bort setuid/setgid från reguljära filer efter
installationerna. Tjänsterna behöver inga filbaserade byten till root eller
andra användare/grupper. Filinnehåll, ägare och övriga rättigheter bevaras;
paket, licenser och advisories finns kvar. `/dev`, `/proc` och `/sys` undantas,
symlänkar följs inte och katalogers setgid ändras inte. Byggningen sparar
före-/efterrättigheter och filhashar i `file-privileges.json`.

CI kontrollerar den färdiga pilotimagen, registerimagen och OpenCV-kandidaten:
inga reguljära filer inom detta omfång får ha setuid/setgid, och ändrade filer
måste matcha byggrapporten. Läsfel, nya privilegierade filer eller förändrat
innehåll stoppar provet. Kontrollen använder root enbart för att läsa hela
imagefilsystemet, med avstängt nät, skrivskydd och borttagna capabilities.
Imagernas förvalda driftanvändare behåller UID 10001. Filcapabilities, volymer, historiska lager
och värdsystemet ingår inte i denna kontroll; `no-new-privileges`, `cap_drop`
och separat driftverifiering behövs fortfarande. Det är härdning, ingen
rättning av de rapporterade paketfynden.

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

Pilotens och registertjänstens Python-bas använder **Debian 13/Trixie** med
versions- och hashlås i [debian-runtime.lock.json](debian-runtime.lock.json).
OpenSSL-/SQLite-versionerna kontrolleras före och efter den extra, hashlåsta
tzdata-uppdateringen. Inga extra beroenden hämtas automatiskt, och
byggsteget nekar nedgradering eller delvis installerade paket.
Det får bara köras inne i det isolerade Linux/amd64-imagebygget.

OS-grinden accepterar endast Debian 13 och jämför fortfarande varje
installerat paket mot skannerns fullständiga inventering. Den accepterar
inte en återgång till Debian 12, ett okänt OS eller rapporterad slutad
support. Inga nya sårbarhetsundantag tillkommer. Hela OS-grinden omfattar
tills vidare pilotimagen; registerimagen har egna funktionsprov.

`sqlite_transition.py` är ett **CI-prov med genererade data**. Det skapar
Wallet-register och äldre backup med den tidigare, låsta basens SQLite
3.40.1 utan nät. Den byggda Trixie-imagen läser registret och återställer
kopian med SQLite 3.46.1. Spärrar, avbrutna förfrågningar, integritet och
nekad återaktivering måste bestå. Proven mot den nya imagen omfattar också
Wallet, verkliga signaturer och krypterad återställning. Resultatet sparas som
`sqlite-transition.json` i samma inventeringsartefakt. Testet ändrar inga
verkliga register och ersätter inte en bevittnad återställningsövning.

Detta är ett byte av containerbas. Produktionsvärdens OS, databasfiler,
konfiguration och monterade volymer uppgraderas inte av byggsteget.
Införande och återgång kräver fortfarande granskning, backup och faktisk
kontroll på avsedd miljö enligt releaseinstruktionen.

Node 24.22.1 används i images och motsvarande CI-prov. Pilotens JDK/JRE och
serverproven använder Temurin 21.0.13+9. Dess officiella Linux x64-arkiv låses
med SHA-256 före extraktion; Java byggs på samma Debian-bas som pilotens runtime.
JRE:s licensfiler bevaras, och upstream-SBOM finns både i imagen och i
`pilot-image-inventory`. SBOM beskriver upstreambygget, inte hela serverimagen.
BuildKit med stöd för `ADD --checksum` (Dockerfile 1.6+) krävs.

Python **3.12.16** byggs från ett hashlåst officiellt källarkiv i en separat,
digestlåst byggcontainer. Källarkiv och upstream-SPDX verifieras av BuildKit
före användning. `build_python.sh` bygger med delat libpython, PGO och LTO,
utan Tk, och kräver passerade upstream-prov för TLS, hashning, SQLite, XML,
tar, temporära kataloger och cookies. Kompilering/prov sker utan externt nät.
Installation sker i en tom stagingkatalog och ersätter hela basens äldre
Python-installation. Python 3.12.16 och inbäddad Expat 2.9.0 kontrolleras
också i den färdiga imagen innan paketinstallationen fortsätter.

En avgränsad teständring hämtar upstreams accepterade avbrottsfel för
`test_pha_required_nocert`. Testet kräver fortfarande att servern nekar
anslutningen utan klientcertifikat. Inget TLS-beteende ändras och inget prov
hoppas över. Originalfil, patchad fil och upstreamreferens har separata
hashvärden i `python-runtime.lock.json` och `tls-test-patch.json`.

`install_build_pip.py` installerar det hashlåsta pip 26.2.2-hjulet utan nät
eller index, direkt från hjulfilen. Installation får inte felaktigt använda
byggcontainerns redan installerade pip. Applikationspaketen har fortsatt
hashkrav och endast binära hjul tillåts.

Alla applikationshjul hämtas i ett separat `scratch`-steg av BuildKit med
`ADD --checksum`, från de officiella filadresserna i
[python-wheels.lock.json](python-wheels.lock.json). Låset hänvisar till samma
versioner och SHA-256 som komponenternas befintliga requirements-filer.
Pilotprofilen har 21 paket; registerprofilen har sex och hämtar inga
biometriska beroenden. Paketinstallation körs med `RUN --network=none`,
`--no-index`, lokal `--find-links`, hashkrav och oförändrad beroendelösning.
Hjulen monteras skrivskyddat från nedladdningssteget och kopieras inte till
driftfilsystemet. Inget pip-anrop i dessa två imagebyggen behöver nätåtkomst.

`test_python_wheels.py` nekar ändrade krav/hashar, saknade eller extra hjul,
andra ursprung och förlorad nätisolering. CI bygger sedan de riktiga Linux-
images och jämför installerade paket samt pips installationsrapport med
profilens namn, versioner, lokala filadresser och SHA-256. Lås och rapport
bevaras under Python-underlaget; deras hashvärden finns i paketinventeringen.
Förändrat ursprung kräver samma granskning som övriga beroendeändringar.

Efter installation tas pip, dess inbäddade paket, startprogram och hela
`ensurepip` inklusive gammalt bootstrap-hjul bort från driftfilsystemet.
Tjänsten installerar inte paket under körning; uppdatering kräver en ny image.
Båda imagernas CI verifierar att pip/ensurepip inte går att importera och att
paketförteckningen beskriver de verkligt installerade applikationspaketen.
`python-packages.json` använder `openid-python-inventory-v1`, framtaget med
standardbibliotekets metadata. Detta tar inte bort historiska bygglager.

Pips bygglicenser, upstream-SBOM och borttagningsbevis bevaras under
Python-underlaget. Pip 26.2.2 har fortfarande advisoryfynd i medlevererad
urllib3 och andra komponenter; borttagningen begränsar runtime, men ersätter
inte bedömning av byggverktygets exponering. Nätisoleringen av pip begränsar
dess exponering för proxy- och HTTP-svar under dessa imagebyggen. BuildKits
nedladdare, andra verktygs nätåtkomst och pip på CI-värden omfattas inte av
denna åtgärd. Den rättar inte pips bundlade källkod och är inget generellt
sårbarhetsundantag. Pythonkällans ursprungliga SPDX
ska inte läsas som en förteckning över det färdiga driftfilsystemet.

Käll-SPDX, licenser, bygglås och upstream-testlogg sparas under
`/usr/share/doc/openid-python/` och i inventeringsartefakten. Runtime-rapporten
anger deras relevanta hashvärden samt interpreterfilens SHA-256. Detta är
spårbarhet inom bygget, inte oberoende attest eller bevis för bitidentiska
ombyggen. Den färdiga imagen måste dessutom passera openID:s faktiska
bild-, signatur-, Wallet-, återställnings- och protokollprov.

Den separata driftimagen i `ops/` får också Temurin 21.0.13+9, med egen
byggkontext och utan e-id-tjänst. Noble-systempaketen och övriga runtime-
beroenden behöver fortsatt granskning. OS-grinden täcker inte sådana luckor.

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

Bildproven körs också i den faktiskt byggda serverimagen med avstängt nät
och skrivskyddat filsystem: JPEG/JP2/rå JPEG 2000, andra format, korrupta
bilder och YuNet/SFace. `runtime-components.json` inkluderar OpenCV:s
byggkonfiguration, upstream-SBOM och hash för binären och de medlevererade
delade biblioteken. Se verifierarens [licens- och komponentregister](../../verification/THIRD_PARTY.md)
för de kvarvarande inbäddade biblioteksfynd som OS- och PyPI-skanning inte täcker.

Registerjobbets tidsgräns är 30 minuter för källbygget och de efterföljande
integrationsproven; det inför inget nytt jobb, schema eller molnbehörighet.

## Kandidat för färre inbäddade bildbibliotek

[OpenCV-provbygget](opencv/README.md) är ett uttryckligt separat byggmål.
Det befintliga pilotjobbet jämför det med standardimagen och sparar käll-,
licens-, modell- och binärbevis. Standardmålet använder fortsatt det låsta
upstreamhjulet. Ett godkänt jämförelseprov medger inte automatiskt byte
eller release: full integration och slutimagets egna kontroller återstår.

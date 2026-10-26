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

## Prov

`python3 -m unittest discover -s deployment -p test_image_bundle.py -v`
provar skadade filer, fel revision/manifest/plattform, saknade filer,
symlänkar, misslyckade/dubbla/ofullständiga protokollresultat, utrymmesstopp
och fel inläst image-ID. Actions provar dessutom verklig export, borttagning
av byggtaggar, återinläsning och Java-start utan nät från det inlästa paketet.

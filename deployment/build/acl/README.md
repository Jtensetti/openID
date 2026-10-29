# Isolerad ACL-paketkandidat

Bygger ACL 2.4.0 med Debian-paketering 2.4.0-1 mot samma låsta Trixie-
byggmiljö som pilotimagen. Lokal utvärderingsversion är `2.4.0-1openid1`.
Syftet är att pröva en möjlig åtgärd för CVE-2026-54369/54370 utan att
blanda in binärpaket byggda mot en nyare glibc. Kandidatbygget installerar
inget i appimagen. Ett separat manuellt prov får uppgradera en disponibel
appbild; det utgör inget införande- eller tillitsgodkännande.

## Källor och byggkedja

`candidate.lock.json` låser basimage, Debian-snapshot, åtta direkta
byggpaket, fyra källindata, signerare och relevanta licens-/paketeringsfiler.
Den gemensamma `util_linux/bootstrap.py` verifierar arkivsignatur, exakt
Release-text och paketindex. Alla nya transitiva paketnedladdningar
kontrolleras mot samma index innan byggverktygen installeras i den
tillfälliga byggimagen. Faktisk paketlista och hämtade paket sparas.

`candidate.py` kräver Debian-utvecklarnyckelringen från denna snapshot,
en giltig `.dsc`-signatur med låst fullständigt primärfingeravtryck och
exakta signerade checksummor för hela källgruppen. Upstreamnyckelns byte
och tre tillåtna publika primärnycklar förankras i denna paketering.
Signaturen över det komprimerade upstreamarkivet måste vara giltig och
komma från den särskilt låsta signeraren. Källarkiven får bara innehålla
vanliga filer och kataloger. Signaturverifierarens sju verkliga,
genererade regressionsfall körs före källberedningen med byggmiljöns GnuPG.

Endast Debians changelog får en daterad lokal utvärderingspost. Källkod,
patchserie, Linux-tester och `hardening=+all` bevaras. Den låsta dpkg-
versionen bygger utan root som standard; inga fakeroot-/sudo-rättigheter
tillkommer. Källbygge och prov körs utan nät, med skrivskyddad rot,
vanlig användare, inga capabilities och `no-new-privileges`.
Upstreams `runwrapper` skapar ett temporärt hjälpbibliotek som testsviten
laddar med `LD_PRELOAD`. `TMPDIR` pekar därför på en egen katalog i den
skrivbara byggvolymen; den tillfälliga `/tmp`-mountens körskydd ändras inte.
Upstreamsviten körs sekventiellt i kandidaten. Den isolerade
byggcontainern har en ändlig gräns på 512 processer; testfel förblir
fatala. CI #92 gav tio `PASS`, fyra root-`SKIP` och två NFS-`XFAIL`.

`Dockerfile.dockerignore` gäller byggkontexten `deployment/build`. Den
tillåter exakt byggfilerna och de åtta publika signaturfixturerna från
util-linux-kandidaten. Föräldrakatalogerna återutesluts innan enskilda
filer tillåts, så nya filer under dem inte följer med automatiskt.

## Prov och bevis

Alla 16 förväntade upstreamresultat måste finnas. Tio ordinarie testfiler
måste ge `PASS`; fyra root- och två NFS-fall får redovisas som `SKIP` eller
`XFAIL`, men aldrig döljas som lyckade tester. `FAIL`, `ERROR`, `XPASS`,
saknade, länkade eller tvetydiga resultat stoppar kandidaten. Debian-
byggets testfel maskeras inte på Linux. Råa `.log`-/`.trs`-filer sparas.

De färdiga `acl`, `libacl1` och `libacl1-dev` måste ha exakt lokal version,
källidentitet och amd64-arkitektur. Deras byte omhashas och extraheras
utan installation eller maintainer-skript. `compatibility.py` provar:

- färdigpaketerat bibliotek och headers med genererade access-/default-ACL;
- avslag för läsning/skrivning genom en sista symbolisk länk när
  `AT_SYMLINK_NOFOLLOW` används;
- att den äldre länkmöjligheten med flaggor `0` fortfarande finns;
- att `setfacl -P --restore` accepterar en vanlig fil men nekar en
  genererad länk utan att ändra målets ACL;
- att befintlig `tar` 1.35+dfsg-3.1 laddar just kandidatbiblioteket och
  bevarar access-/default-ACL, filinnehåll och länk vid arkivering/återläsning.

Detta är vanliga användarfall, inte ett bevis mot samtidiga races eller
fullständig ABI-, kernel-, root- eller NFS-täckning. Tar-provet avser den
befintliga binären. Det löser inte Debians separata rapport om att samma
tar-version inte kan kompileras mot de nya ACL-headerfilerna.

Bevisartefakten innehåller provutfall, hashmanifest, byggverktygsinventering,
byggskript/fixturer, autentiserade källchecksummor, licenser, beredd
motsvarande källkod före kompilering, tre kandidatpaket och en avgränsad
CycloneDX-lista. Debugpaket och installerarens `.udeb` exporteras inte;
`.changes`/`.buildinfo` kan därför hänvisa till fler byggresultat än de tre
sparade paketen. Byggfel och käll-/testloggar sparas också, när de hunnit
skapas. SBOM:en är ingen full inventering av applikation eller inbäddad kod.

## Körning

Lokala avvisningsprov installerar inget:

```sh
python3 -m unittest discover -s deployment/build/acl -p 'test_*.py' -v
```

Det befintliga `pilot / container`-jobbet exporterar endast spårad kod,
hämtar de låsta källindata och bygger kandidaten utan installation. Bevis
sparas i 30 dagar. Föregående OS-fynd gör fortfarande jobbet rött.

Manuell `workflow_dispatch` med `acl_candidate: true` kör ett eget jobb.
Det validerar den signerade kandidatens råartefakt och alla manifestförda
evidensfiler (81 i CI #92). Endast det redan installerade `libacl1` läggs i
en separat appbild; de övriga två paketen behålls som byggbevis. Provbilden byggs
utan nät, binds till referensbildens exakta lager, behåller appens runtime-
konfiguration och kontrollerar paketövergången samt skyddade app-/JDK-filer.
En kort ACL-/tar-probe, bild- och protokollprov och en strikt OS-skanning
körs mot provbildens image-ID. Installerade paket och resultaten sparas
som separat artefakt även när OS-grinden blir röd. Provet skapar ingen
AWS-resurs. Ett lyckat byggprov eller bildprov stänger inte ett CVE-fynd.

## Licens och återstående införande

Upstream kommer från Savannahs ACL-projekt, distribuerat här via signerad
Debian-källa. Copyright omfattar bland andra Silicon Graphics och Andreas
Gruenbacher. Standardvillkor är GPL-2.0-or-later; bibliotek och flera
hjälpfiler har LGPL-2.1-or-later. Debians etikett `LGPL-2+` följs av en
granttext för 2.1 eller senare; använd filernas egna villkor. Exempel,
testverktyg och medföljande byggstöd har ytterligare filspecifika notiser.
Alla huvuden/notiser bevaras i källkopian, tillsammans med full GPL-2- och
LGPL-2.1-text och Debians copyright. Nytt `libattr1-dev` används endast i
byggmiljön; dess och `libattr1`:s copyright sparas också. Attrs headers
och bibliotek har LGPL-2.1-or-later enligt granttexten; övrig standardkod
GPL-2.0-or-later. Inget attr-binärpaket exporteras med kandidaten.

Repoförvaltaren ansvarar för säkerhetsbevakning, nycklars aktuella status,
licenser, uppdateringar och omprov. Låsta nyckelringar upptäcker inte
senare spärrar. Före införande återstår bland annat komplett relevans-
och kompatibilitetsbedömning, godkända nya OS-resultat och oberoende
releasebeslut. Den separata paketövergången och app-/protokollproven måste
bindas till exakt provad revision; tidigare resultat för en separat
provimage styrker inte en senare sammansatt leverans.
En ny biblioteksversion gör inte gamla anrop som följer länkar säkra.
[Primärkällor](../../../docs/SOURCES.md#acl-kandidat-2026-10-28).

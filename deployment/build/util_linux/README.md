# Util-linux: separat paketkandidat

Kandidatbygget tar fram hela Debians paketserie för util-linux som ett steg
mot en sammanhängande uppdatering av systempaketen. CI provinstallerar de nio
runtimepaketen i en separat avbildning av den testade pilotimagen. Ordinarie
pilot, register och drift använder fortsatt de befintliga runtimepaketen.
Referensens OS-fynd och imageexport hålls skilda från provinstallationens.

`candidate.lock.json` låser upstream **2.41.6**, Debians paketering
**2.41.5-0+deb13u1** och underhållsrevision
`56e83de535ae1df9228d3b1cbf978b3e36b5d959`. Uppföljningen är inte en utgiven
Debian-säkerhetsuppdatering. Den lokala paketversionen är `2.41.6-0openid1`.
Nyare färdiga util-linux-binärer kräver en annan glibc; enstaka biblioteksbyten
bryter dessutom nuvarande exakta paketberoenden.

## Låsning och källkontroll

Verktygen installeras endast i en engångsimage från en digestlåst Trixie-bas.
De 39 direkt valda paketen har exakta versioner. APT använder bara Debian-
snapshoten `20261027T000000Z`. Dess signerade InRelease och hela amd64-index
har låsta SHA-256. Varje transitiv nedladdning måste matcha indexets identitet
och hash före installation. Extra paketkällor, ändrade index, nedgraderingsflaggor
och ignorerade signaturfel tillåts inte. Alla installerade byggpaket inventeras.

Trixie-basens befintliga `sqv` verifierar InRelease före paketinstallation.
Även den autentiserade Release-texten måste matcha sitt hashlås. APT gör
sedan sin ordinarie arkivkontroll. `gpgv` installeras uttryckligen med låst
version genom denna kedja; det förutsätts inte finnas i basimagen.
Hashlåset avser `sqv`-utmatningen: det sista radslutet före signaturblocket
är en formatseparator och ingår inte i klartexten enligt RFC 9580 §7.1.
Vår kontroll normaliserar inga bytes. Även extra radslut, mellanslag eller
CRLF i verifierarens utmatning ger därför avslag. Storlek och faktisk hash
loggas för att ett avvikande resultat ska kunna undersökas.

Källfilerna har storleks- och hashlås. GnuPG ska verifiera Debians `.dsc` mot
byggmiljöns versionslåsta Debian-keyring innan paketeringen används.
Den signerade filen binder paketeringens bytes. Upstreams nyckel i paketeringen
har eget hashlås och förankrar det fullständiga primärfingeravtrycket.
Den äldre nyckelkopian saknar förnyad giltighet. En uppdaterad publik kopia
har hämtats med samma fullständiga fingeravtryck från Ubuntus nyckelserver.
`upstream-signing-key-refreshed.asc` bevarar dessa publika bytes i repot;
ursprungsadressen, storleken och SHA-256 finns kvar i låset. Bygget kontrollerar
kopian innan den förs till indata och igen före signaturverifieringen.
Saknad, länkad eller ändrad kopia stoppar bygget utan nätfallback. Inga bytes
normaliseras och inget hashlås ändras. Övriga källfiler hämtas fortfarande
över HTTPS och måste matcha sina lås. Faktisk storlek och hash loggas vid fel.
GnuPG måste visa exakt en publik
primärnyckel med samma fingeravtryck i båda kopiorna. Nyckelservern är endast
distributionskanal. GnuPG verifierar signaturen över det okomprimerade
källarkivet med den uppdaterade nyckeln, och signeraren måste matcha låset.
Utgångna/spärrade signaturer och saknad entydig `VALIDSIG` nekar beredning.
`gpgv` kan returnera noll även för en utgången eller spärrad nyckel; vår
befintliga statuskontroll måste därför också lyckas. Sju regressioner med
genererade publika nycklar och verkliga signaturer provar giltigt fall,
utgången/spärrad nyckel, utgången signatur, ändrat innehåll, saknad nyckel
och oväntad signerare. De körs med byggmiljöns låsta GnuPG före källberedningen;
saknade verktyg eller ett underkänt prov stoppar bygget. `signature-policy.log`
sparar resultatet. Fixturerna innehåller inga privata nycklar och tillförs
aldrig nyckelringarna som används för att verifiera källorna.
Byggkontextens tillåtelselista omfattar testmodulen och exakt de åtta publika
fixturfilerna; övriga tester och lokala filer ingår inte i byggkontexten.
Föräldrakatalogerna öppnas för traversering, deras innehåll utesluts på nytt
och endast de namngivna filerna återinkluderas.
Detta avser status i den versionsbundna nyckelkopian; ett nätlöst bygge
upptäcker inte senare publicerade spärrcertifikat. Repoförvaltaren ska därför
kontrollera aktuell upstreamnyckel och säkerhetsinformation före införande,
bevara daterat underlag och granska varje nyckeländring separat. Om den
kontrollen saknas eller indikerar spärr får kandidaten inte införas.
Nyckeln är offentlig verifieringsdata, inte en privat signeringsnyckel.
Den senare upstreamdiffen är separat revisions-/hashlåst; releasesignaturen
täcker inte diffen. Detta är ingen oberoende bygg- eller releaseattest.

Två Debianpatchar utelämnas efter kontroll att de redan ingår upstream.
Debians maskning av ett känt hardlink-testfel tas bort, så felet blir fatalt.
Övriga paketeringspatchar bevaras. `dpkg-source` applicerar serien, varefter
de nio filerna från uppföljningen måste matcha låsta upstreamhashar.
Debians hardening-val ändras till `+all`; changelog och byggrapport beskriver
ändringarna. Licenstexter och källfilernas notiser bevaras.

## Körning och bevis

`dpkg-buildpackage` körs som vanlig användare, utan nät och capabilities,
med skrivskyddad containerrot och begränsad CPU, minne och processmängd.
Byggberoendekontroll, paketering och upstream-regressioner måste lyckas.
Inget `nocheck` eller `continue-on-error` sätts. Upstreams eget antal
”PASSED” kan inkludera överhoppade prov; rålogg och skip-rader sparas.
Kärn-/namespaceprov som kräver extra privilegier får inte tillskrivas miljön.

`util-linux-build-candidate` sparas i 30 dagar, även vid fel: verktygsinventering,
signatur-/patch-/byggloggar, lås, licenser, motsvarande beredd källkod och
hashmanifest. Vid lyckat bygge sparas en avgränsad CycloneDX-förteckning,
de nio runtimepaketen och metadata om
alla byggda deb-paket. Övriga binärpaket och arbetskatalogen laddas inte upp.
Installerpaket av typen `udeb` representeras endast av checksumrader i
`.buildinfo`/`.changes`; de ingår inte i `.deb`-förteckningen, dess SBOM
eller runtimeexporten.
Alla pakethuvuden måste ha exakt käll-/binärversion, arkitektur och filnamn;
Debians historiska versionsprefix för `bsdutils` och `login` bevaras.
Saknade eller dubbla runtimepaket nekar hela exporten innan något kopieras.
Källarkivet tas före kompilering och följer med kandidatpaketen. Förteckningen
omfattar källindata, byggda paket och byggmiljöns dpkg-paket; den är ingen
fullständig inventering av inbäddad kod eller av applikationens runtime.

Steget har högst 25 minuter inom pilotjobbets befintliga 55-minutersgräns.
Det ligger före de stora applikationsbyggena, så förberedelsefel stoppar
pilotjobbet tidigt. Vid fel saknas senare image-/OS-prov för revisionen;
de får inte tillskrivas ett resultat från en tidigare körning. Paketbygget
kan inte upphäva OS-fynd eller andra fel.
Inga nya jobb, actions, behörigheter eller AWS-resurser införs. Byggminuter
och artefakter använder GitHub-kvoten. Repoförvaltaren ansvarar för
versionsbevakning, licenser och omprov.

## Provinstallation i CI

`prepare_trial.py` kräver ett lyckat paketbygge för exakt testad revision och
samma käll-/verktygslås. Alla manifestfiler kontrolleras, även sådana som inte
kopieras till Docker-kontexten. Länkade sökvägar, ändrade bytes, saknade/extra
runtimepaket och en befintlig målkatalog nekas. Kontexten innehåller endast
paketen, deras byggbedömning, låset och installationshjälparna.

`Trial.Dockerfile` utgår från referensens verifierade image-ID. Installation
körs som root under ett isolerat bygge utan nät, med förbud mot nedladdning,
paketborttagning och tjänstestart. De nio verifierade paketen kopieras till en
ny tillfällig APT-cache och omhashas där före simulering/installation.
APT:s cachefilnamn behåller versionsepoken med kodningen `%3a`; de skiljer sig
från dpkg-byggexportens filnamn. `--no-download` förutsätter denna förberedelse
även när lokala deb-filer anges. Inga befintliga arkiv eller paketindex används;
källista och källkatalog är tomma för båda APT-anropen. Cachemappningen sparas
i installationsrapporten och den tillfälliga katalogen tas bort efteråt.
APT-plan, verkliga pakethuvuden och slutlig
dpkg-inventering måste visa exakt de nio uppgraderingarna. Övriga paket och
applikations-/Python-/Java-träden måste bevaras; filjämförelsen omfattar inte
utökade attribut. Nya setuid/setgid-bitar tas bort och kontrolleras med samma
hjälpare som för referensen. Fil-capabilities ingår inte i den inventeringen;
runtimeproven använder capability-drop och no-new-privileges.

APT:s simulering kan lägga till hakparenteser med tillfälliga beroendetillstånd
efter en `Inst`-rad. De ändrar inte det valda paketets namn/version. Parsern
accepterar detta dokumenterade format men nekar extra/dubbla installationer,
borttagning, fel version och `Conf ... broken`. Den verkliga slutliga
paketövergången och `dpkg --audit` kontrolleras fortfarande. Vid fel sparas
begränsade APT-loggslut i Docker-byggloggen eftersom ett misslyckat bygglager
inte exporteras.

Efter bygget jämförs lagerkedja och runtimekonfiguration mot referensen.
Prov körs mot det oföränderliga kandidat-ID:t: paketstatus, sju kommandons
versioner, laddning av fem bibliotek, bild-/processisolering, livscykel,
återställning, SAML och OIDC. Körningarna har skrivskyddad rot, avstängt nät,
resursgränser och inga capabilities. Bildprovens testfiler monteras var för
sig bredvid applikationen så att deras relativa modellsökväg pekar på imagens
egna modeller; inga modeller monteras från värddatorn. Endast
filprivilegieinventeringen körs som root med `DAC_READ_SEARCH`;
protokollprovet använder CI-användarens UID
för sin skrivbara beviskatalog. Biblioteksladdning är inte fullständig
ABI-verifiering, och privilegierade mount-/namespace-/kärnprov utförs inte.

Kandidatens installerade systempaket får en egen OS-skanning. Dess fynd
undantas inte från säkerhetsgrinden. `util-linux-installation-evidence`
sparar imagebindning, kontextmanifest, installationsrapport, biblioteks-
och testresultat samt OS-bedömning i 30 dagar, även vid fel. Byggfel kan ge
endast kontext och bygglogg; uteblivna senare prov räknas inte som lyckade.
Provinstallationen har högst fem minuter och runtimeproven sju minuter inom
det befintliga jobbets tidsgräns. Ingen kandidat publiceras som runtimeimage.
Aktuell CVE-bedömning, full kompatibilitetsbedömning och oberoende granskning
krävs före införande. Inga CVE-fynd stängs av ett lyckat bygge eller prov.

Lokala prov kräver Python 3 samt `gpg` och `gpgv`. De omfattar verklig
signaturverifiering av genererade fixturer, men utför inget Linux-bygge
och ersätter inte verifieringen av källutgåvans signatur:

```sh
python3 -m unittest discover -s deployment/build/util_linux -p 'test_*.py' -v
```

Primärkällor kontrollerade 2026-10-27–28:

- [Upstreams källutgåva och signatur](https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/v2.41/)
- [Låst uppföljning](https://github.com/util-linux/util-linux/compare/02822c9374fc72d38baf8a1f859eb0813970bf3f...56e83de535ae1df9228d3b1cbf978b3e36b5d959)
- [Debians paket- och säkerhetsstatus](https://security-tracker.debian.org/tracker/source-package/util-linux)
- [Debians daterade arkiv](https://snapshot.debian.org/archive/debian/20261027T000000Z/)
- [Debians arkivautentisering](https://manpages.debian.org/trixie/apt/apt-secure.8.en.html)
- [APT 3.0.3: simulerade paketoperationer och beroendeannoteringar](https://sources.debian.org/src/apt/3.0.3/apt-pkg/algorithms.cc/)
- [APT 3.0.3: cachefilnamn och kontroll av redan hämtade paket](https://github.com/Debian/apt/blob/3.0.3/apt-pkg/acquire-item.cc)
- [APT-konfiguration: separata källor, index och arkivcache](https://manpages.debian.org/trixie/apt/apt.conf.5.en.html)
- [Sequoias signaturverifierare i Trixie](https://manpages.debian.org/trixie/sqv/sqv.1.en.html)
- [Kernel.org: signatur över okomprimerat arkiv](https://www.kernel.org/signature.html)
- [GnuPG: gpgv, nyckeltillit och maskinläsbar status](https://www.gnupg.org/documentation/manuals/gnupg/gpgv.html)
- [Docker: byggkontext och ordnade dockerignore-undantag](https://docs.docker.com/build/concepts/context/#dockerignore-files)

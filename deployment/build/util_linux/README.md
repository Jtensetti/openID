# Util-linux: separat paketkandidat

Kandidatbygget tar fram hela Debians paketserie för util-linux som ett steg
mot en sammanhängande uppdatering av systempaketen. Paketen installeras ännu
inte i pilot, register eller drift. OS-skannerns fyndlista och ordinarie
imageexport använder fortsatt de befintliga runtimepaketen.

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
har eget hashlås och används för signaturen över det okomprimerade källarkivet.
Utgångna/spärrade signaturer och saknad entydig `VALIDSIG` nekar beredning.
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

Efter ett lyckat bygge återstår provinstallation av hela beroendegruppen,
ABI/paketkonsistens, applikationens säkerhets-/protokollprov, aktuell
sårbarhetsbedömning och oberoende granskning. Inga CVE-fynd stängs av bygget.

Lokala negativa prov; de utför inte Linux-bygge eller verklig GnuPG-verifiering:

```sh
python3 deployment/build/util_linux/test_candidate.py -v
```

Primärkällor kontrollerade 2026-10-27:

- [Upstreams källutgåva och signatur](https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/v2.41/)
- [Låst uppföljning](https://github.com/util-linux/util-linux/compare/02822c9374fc72d38baf8a1f859eb0813970bf3f...56e83de535ae1df9228d3b1cbf978b3e36b5d959)
- [Debians paket- och säkerhetsstatus](https://security-tracker.debian.org/tracker/source-package/util-linux)
- [Debians daterade arkiv](https://snapshot.debian.org/archive/debian/20261027T000000Z/)
- [Debians arkivautentisering](https://manpages.debian.org/trixie/apt/apt-secure.8.en.html)
- [Sequoias signaturverifierare i Trixie](https://manpages.debian.org/trixie/sqv/sqv.1.en.html)
- [Kernel.org: signatur över okomprimerat arkiv](https://www.kernel.org/signature.html)

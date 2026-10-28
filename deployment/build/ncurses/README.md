# Isolerad ncurses-kandidat

Den här kandidaten utvärderar ncurses 6.6+20260608 med Debians signerade
paketering 6.6+20260608-2 mot den låsta Trixie-miljön. Lokal version är
`6.6+20260608-2openid1`. Den är inte en officiell Debianuppdatering och
installeras inte i ordinarie app- eller registerimage av detta flöde.

## Bygggräns

`candidate.lock.json` låser exakt källgrupp, Debian-/upstreamsignerare,
nyckelring från autentiserad snapshot, byggpaket, licens-/paketeringsfiler
och basimage. Verktygsstarten verifierar Debians arkivsignatur, oförändrade
Release-bytes och paketindex. Hämtade transitiva deb kontrolleras mot indexet.
Källberedningen kräver två faktiska giltiga signaturer, fullständiga
fingeravtryck och signerade checksummor. Upstreamarkivet får bara innehålla
vanliga filer och kataloger. Debians sex interna symbolfilslänkar tillåts
endast med granskade namn och mål. Endast en lokal changelogpost tillförs;
Debianpatchar och upstreamkod bevaras. Källkod och notiser sparas.

Debians profil `nobiarch` hoppar över sekundära 32-/64-bitarsbyggen.
Nativebibliotek, verktyg, fristående paket och exempel ska fortfarande
byggas. Buildern kör som vanlig användare utan nät, capabilities eller
skrivbar rot. Inga paketskript körs vid efterföljande extraktion.

## Avgränsade prov

Enhetstester nekar annan käll-/paketidentitet, fel checksummegrupp,
oväntad nyckel och osäkra symbolfilslänkar. Det isolerade Linux-bygget
måste producera nio namngivna Debianpaket med exakt lokal version och
arkitektur. `compatibility.py` extraherar färdiga deb och kontrollerar
`libtic.so.6`/`libtinfo.so.6`/`libncursesw.so.6`, SONAME, att de nya
`tic`/`infocmp` verkligen länkar kandidatens bibliotek, genererade terminfo-/termcapfall
med 2048 tecken samt indataformerna i de ursprungliga rapporterna om
CVE-2025-6141 och CVE-2025-69720. Licenser, verktygsinventering,
byggloggar, paket och en
avgränsad CycloneDX-lista bevaras för granskning.
Paketidentitet, de fyra runtime-paketen och bygginventeringen sparas redan
före kompatibilitetsprovet, så ett underkänt prov lämnar granskbara byte
men fortfarande `passed: false` och inget införandegodkännande.
[Termcaprapporten](https://lists.gnu.org/archive/html/bug-ncurses/2025-03/msg00107.html)
och [SGR-rapporten](https://github.com/Cao-Wuhui/CVE-2025-69720)
anger de genererade indataformerna. Debian markerar Trixies ncurses-version
som sårbar för [CVE-2025-6141](https://security-tracker.debian.org/tracker/CVE-2025-6141)
och [CVE-2025-69720](https://security-tracker.debian.org/tracker/CVE-2025-69720).

Gränsproven ger inget fuzz-/sanitizerbevis och inte full ABI-/terminal-
eller appkompatibilitet. En härdad binär som inte kraschar bevisar inte
minnessäkerhet. Fynden förblir öppna. Det manuella CI-jobbet provar därför
en separat appbild: det kontrollerar hashade byggbevis och exakt fyra
runtime-deb, installerar dem nätfritt i en kopia av referensbilden,
jämför paketläge och skyddade app-/JDK-filer, kontrollerar bibliotek,
filprivilegier och fysisk filyta och kör om bild-, säkerhets- och
protokollproven. Slutbildens Debianpaket skannas med den strikta OS-grinden.
Detta är ett föreslaget prov tills CI har körts på ändringen. Licens- och
nyckelaktualitet samt oberoende införandebeslut krävs innan paketen får
användas. En versionsetikett eller lyckad kompilering stänger inga fynd.

## Lokal kontroll

```sh
python3 -m unittest discover -s deployment/build/ncurses -p 'test_*.py' -v
```

Detta kommando installerar ingenting. Ett faktiskt Linux-bygge kräver den
spårade Docker-kontexten `deployment/build`, den låsta Trixie-snapshoten
och en separat körning med bevarad råartefakt. Bygggränsen skapar ingen
AWS-resurs.

## Separat appbildsprov

`prepare_trial.py` avvisar fel revision, ofullständiga bevis, ändrade eller
länkade paketfiler och annan käll-/paketidentitet. `Trial.Dockerfile` utgår
från exakt referensimage-ID och monterar de fyra paketen endast under ett
nätfritt byggsteg. `trial_install.py` kräver att alla fyra redan finns i
referensen, att endast deras versioner ändras och att `/app`, `/usr/local`
och JDK-trädet behåller filer, lägen och ägare. `probe_trial.py` kontrollerar
slutlig dpkg-identitet, `tic`/`infocmp`, biblioteksladdning och Python curses.
Ingen kandidatdeb kopieras in i bildens filsystem. Provet kör inga privilegierade
exploitfall, fuzzning eller full ABI-kontroll. Underkänd OS-skanning förblir
ett underkänt jobb även om installationen lyckas.

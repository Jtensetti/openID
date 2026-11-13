# Isolerade leverantörskandidater

Byggrecepten här är kandidater. De ändrar inte `vendor-images.lock.json`,
startar inga tjänster och ger inget produktionsgodkännande. Kör i en
isolerad Linux/amd64-byggmiljö utan driftuppgifter:

```sh
python3 deployment/production/vendor-builds/candidates.py --output /tmp/vendor-candidates
```

PostgreSQL 18.7 behåller den officiella, digestlåsta Alpine-bilden och tar
bort `gosu`. Den kanoniska profilen kör redan `postgres`/`initdb` direkt som
70:70 och använder inte leverantörens root-entrypoint.

OpenBao utgår från revision `9e0a0d3c3504a0a00b45e61355afac5e35c78379`
(2.7.2). Det är en **modifierad Tjipp-version**, inte en ny upstream-release.
Go 1.27.4, go-jose/v4 4.1.9, CAP 0.15.0, x/crypto 0.59.0 och x/net 0.62.0
med sina låsta transitiva uppdateringar byggs med CGO avstängt. Okta MFA
avlägsnas och dess verifieringsfunktion nekar alltid; den gamla Okta v2-
klienten drog annars in den underhållsfria go-jose/v3. Inget annat MFA-fall
ändras. Gränstestet kräver nekande även med tom konfiguration. Transit,
tokenförnyelse och omstart måste sedan provas i hela driftprofilen innan
bilden får väljas för leverans.

`sources.lock.json` binder upstream-arkiv, Go-distribution och ursprungliga
respektive ändrade källfiler med SHA-256. Ändrade OpenBao-filer är MPL-2.0;
originallicensen finns i `OPENBAO-LICENSE`. Build-steget samlar även
beroendenas LICENSE/NOTICE-filer, Go-licensen, modullista och de ändrade
källfilerna i `/usr/share/doc/tjipp-openbao`. go-jose är Apache-2.0, CAP
MPL-2.0 och Go/x-moduler BSD-3-Clause. Go:s modulsummor verifieras innan
kompilering. `vendor_builder.py` använder en separat `docker-container`-byggare
med digestlåst BuildKit 0.33.1 och exporterar ett Docker-arkiv med
`rewrite-timestamp=true`. Docker Engines vanliga Moby-export får inte användas
för detta. Arkivet läses sedan in i Docker; lagrens filtidsstämplar normaliseras
till det fasta SOURCE_DATE_EPOCH-värdet. Kandidatprovet bygger båda bilderna på nytt
i separata, tomma byggare och kräver samma bild-ID. Enbart bildens skapandetid räcker inte;
en separat ombyggnad måste visa detta innan ett ID låses.

Reedsolomon 1.0.0 saknar licensfil i Go-arkivet. Upstreams enda efterföljande
commit `c5f4bc9af094852b52e593a5f964647c43028c51` tillför MIT-licensen utan
kodändringar. Den licensfilen bevaras separat med källa och SHA-256 i
`supplemental-licenses/lock.json`; andra saknade licenser stoppar bygget.

OpenBao-bilden tar bort de oanvända APK-verktygen och deras zlib-beroende
genom pakethanteraren. Paketregistret bevaras. APK:s byggtransaktionslogg
stängs av med dess dokumenterade `--logfile=no`; annars bäddas byggögonblicket
in i filinnehållet även när lagertiderna normaliseras. CI behåller kommandots
utdata och granskar det verkliga paketregistret. Detta påverkar inte OpenBaos
maskade revisionslogg i drift. Efter bygget sparas faktisk
paketlista, samtliga OS-/Go-fynd, CycloneDX-SBOM, bild-ID och byggreceptets
hash. Noll paketfynd ersätter inte funktionstest eller oberoende granskning.

Go anger den lokalt byggda huvudmodulen som `(devel)`. Därför binder
`sourceGoModules` just denna modul till OpenBaos låsta upstream-version.
Leveransgranskningen frågar OSV om både den exakta modulversionen och
upstream-commiten. Råa svar, samtliga sidfrågor och resultaten sparas i
`source-advisories.json` och spelas om vid importkontrollen. Saknade svar,
ändrad frågetäckning eller ett enda fynd stoppar leveransen. Dessa fynd får
inte undantas med hänvisning till våra beroendeändringar. Bildskanningen
kontrollerar samtidigt de faktiskt kompilerade beroendena. OSV:s ofullständiga
datatäckning ersätter inte oberoende granskning av upstream eller vår ändring.

Den kanoniska profilen väljer uttryckligen bilder genom det överordnade
`vendor-images.lock.json`. Kandidatskanningen ändrar inte detta lås.
`vendor_images.py` verifierar samtliga angivna byggindata och basens ID,
bygger utan driftuppgifter och nekar ett annat utbilds-ID. Det kompletta
runtimeprovet och separata, färska paketbedömningar måste därefter passera.
Driftimporten använder det exporterade paketet och bygger ingenting.

BuildKit är ett byggverktyg enbart i isolerad CI, utan driftuppgifter.
Det körs inte på driftvärden eller i levererade tjänster. Version 0.33.1
([officiell release](https://github.com/moby/buildkit/releases/tag/v0.33.1))
och dess linux/amd64-manifest låses i `vendor_builder.py` och bildlåset.
Verktyget är Apache-2.0; dess licenser stannar i den officiella verktygsbilden.
Se [Docker-exporten](https://docs.docker.com/build/exporters/oci-docker/)
och [containerdrivrutinen](https://docs.docker.com/build/builders/drivers/docker-container/).

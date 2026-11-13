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
kompilering. Den fasta tidsstämpeln gör repeterbara bild-ID:n möjliga;
en separat ombyggnad måste visa detta innan ett ID låses.

OpenBao-bilden tar bort de oanvända APK-verktygen och deras zlib-beroende
genom pakethanteraren. Paketregistret bevaras. Efter bygget sparas faktisk
paketlista, samtliga OS-/Go-fynd, CycloneDX-SBOM, bild-ID och byggreceptets
hash. Noll paketfynd ersätter inte funktionstest eller oberoende granskning.

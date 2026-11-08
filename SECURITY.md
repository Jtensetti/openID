# Säkerhet

Tjipp saknar produktionsrelease, Digg-godkännande och oberoende
säkerhetsgranskning. SAML har separata testflöden med syntetiska identiteter och
[appgodkännande](deployment/sweden-connect-app/README.md).

## Rapportera problem

Mejla [Jonatan@tensetti.se](mailto:Jonatan@tensetti.se) med berörd revision,
förutsättningar, konsekvens och steg för att återskapa felet. Be om en säker
överföringsväg för känsliga bilagor. Publicera inte sårbarhetsdetaljer,
passuppgifter, biometrik, nycklar eller sessionsvärden i öppna ärenden.

Det finns ingen bemannad beredskap eller garanterad svarstid. Kontaktadressen
ersätter inte användarens spärrfunktion.

## Miljöer

| Miljö | Identitet och avgränsning |
| --- | --- |
| Lokal protokollabb (`start`, `start-web`) | Genererade identiteter. `start-web` använder WebAuthn; `start` simulerar godkännandet. Ska köras lokalt utan publik tunnel eller proxy. |
| Sweden Connect-sandbox | Separat syntetisk IdP, testnycklar och simulerad autentiseringskontext. Ingen tillitsnivå 3. |
| Telefonpilot (`phone-idp`, `phone-sp`) | Pass- och ansiktskontroll med appens enhetsnyckel. Separat register och konfiguration. |
| Underskriftsprov | Test-CA och signeringsnycklar i processminnet; ingen HSM, betrodd tid eller långtidsvalidering. |

Utveckling, sandbox och produktion ska ha separata nycklar, ankare,
behörigheter och data. Testnycklar får inte bli produktionsankare.

## Data och hemligheter

CI använder genererade identiteter. Verkliga pass, bilder, personakter,
privata nycklar och driftdata ska förvaras utanför repo och publika artefakter.
En publicerad hemlighet måste återkallas eller roteras; radering av filen räcker inte.

Pilotregistret lagrar profil och förminskat passfoto krypterat. Rå chipdata,
kamerabilder och ansiktsmallar lagras inte i registret. Databas och nyckelfil
måste skyddas separat. Läs [arkitekturen](docs/arkitektur.md) för dataflöden
och [raderingsinstruktionen](docs/radering-rattighetsarende.md) för rättighetsärenden.

Återställ med `recovery.py restore` eller klusterlägets återställningsverktyg.
De spärrar återställda nycklar och stänger nyregistrering och biometrisk
analys i minst 24 timmar. En äldre backup får inte återaktivera spärrade ID:n
eller nollställa försöksbudgeten. Se [återställningsbindning](docs/aterstallningsbindning.md).

## Kända begränsningar

| Område | Kvarstående kontroll |
| --- | --- |
| Biometri och kamera | Kalibrerad felacceptans/felavvisning, PAD, bildinjektion och fysisk kamerakedja. App Attest bevisar inte bildernas fysiska ursprung. |
| NFC och pass | Bredare enhetsprov och reläangrepp. Dokumentsignerarens spärrkontroll kräver aktuell CSCA-spärrlista. |
| Identitetsregister | Verklig registeradapter för passförnyelse och registerkontroll saknas. |
| Nycklar och behörighet | SQLite-pilotens serverkonto kan både läsa profilnyckeln och aktivera credentials. Rollseparation och HSM-förvaltning återstår. |
| Drift och återställning | Prov med faktisk backup, nyckelförvaring, övervakning och kontinuitet. |
| Federation | Extern OIDC-verifiering, produktionsanslutning och granskning av avsedd profil. |
| Underskrift | Betrodd certifikatkedja, tidsstämpling och långtidsvalidering. Testerna styrker inte QES. |

WebAuthn-labben använder attestering `none`; den styrker inte fabrikat,
hårdvaruskydd eller frånvaro av nyckelsynkronisering. Klusterläget har andra
nyckel- och databasroller än SQLite-piloten, se [klusterdrift](deployment/cluster/README.md).

## Test och release

[Testöversikten](docs/testning.md) anger vad automatiska tester täcker och vad
som kräver fysisk eller operativ verifiering. OS-paketfynd bedöms enligt
[bygginstruktionen](deployment/build/README.md#systempaket-och-säkerhetsunderlag);
råa fynd och versionsbundna beslut ska bevaras.

Följ [utvecklings- och releasekraven](docs/utveckling.md). En merge visar inte
vad som är driftsatt. Produktionsutgivning kräver oberoende granskning och
beslut av en behörig människa. Projektet har inte visats uppfylla ISO 27001
eller Diggs tillitskrav.

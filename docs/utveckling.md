# Utveckling

## Byggmiljöer

| Del | Miljö och källa till versioner |
|---|---|
| Verifierare och SAML | Linux x86_64. [Installation](../verification/README.md) och [serverworkflow](../.github/workflows/prototype.yml). |
| iPhone | macOS och Xcode. [Projekt, signering och tester](../ios/README.md); CI-versionen anges i [ios.yml](../.github/workflows/ios.yml). |
| WebAuthn-labb | JDK och Chromium. [Bygginstruktion](../prototype/README.md); låsta beroenden i POM och package-lock. |
| Containers | Docker. [Bygg och verifierad import](../deployment/build/README.md); versioner och digests anges i Dockerfilerna. |

Låsfiler, projektgenerator och workflows är källor för byggversioner.
Uppdatera komponentens instruktion när verktyg eller kommandon ändras.
Verifierarens Python-lås gäller Linux x86_64; ändra inte hashkraven för att
installera paket på en annan plattform.

## Ändringar

1. Utgå från aktuell `main` och använd en separat branch. Samla ändringen i
   en PR, om inte repoägaren uttryckligen begärt en direktpush.
2. Uppdatera berörd kod, relevanta tester och komponentens körinstruktion.
   Dokumentera beteende och begränsningar där funktionen beskrivs.
3. Kör kontroller enligt [testöversikten](testning.md). Ange revision,
   kommandon, resultat och ej körda delar i PR:n eller commitunderlaget.
4. Vid beroendeändringar: kontrollera ursprung, licens och advisories;
   uppdatera lås, SBOM och attribution tillsammans med ändringen.
5. Följ [kandidat och återgång](releasekandidat.md) före installation.
   Merge, byggresultat och driftsättning är skilda steg.

Behåll instruktioner som behövs för att förstå, bygga, testa och driva
programvaran. Undvik upprepade statuslistor och daterade arbetsloggar i
README-filer. Historiska körresultat hör till GitHub Actions och den aktuella
PR:n; driftunderlag och verkliga användarprov förvaras privat.

## Obligatoriska kontroller och repoägarskap

[Assurance checks](../.github/workflows/assurance.yml) kör alla komponenter
för varje PR och för `main`. `assurance-gate` kräver godkända jobb för
server/protokoll, register, pilotcontainer, iPhone, driftcontainer,
infrastruktur och beroenden. Avbrott, fel och överhoppade jobb är inte
godkännande. Jobben använder syntetiska data och läsbehörighet till koden.

Repots synlighet och verkställda skyddsregler hanteras i
[GitHubs inställningar](https://github.com/Jtensetti/openID/settings/rules).
[branch-protection.json](../.github/branch-protection.json) är ett förslag
för granskad förvaltning, inte ett bevis på de aktuella inställningarna.
Repoägaren har begärt upplåsning av `main` för sammanföringen. Det ändrar
inte testresultat eller villkoren för produktionsutgivning.

GitHub tillåter inte att PR-författaren godkänner sin egen PR. Före
produktion krävs oberoende säkerhetsgranskning och ett behörigt mänskligt
beslut; en kodagent kan inte attestera sin egen produktionsrelease.

För en ny installation kan skyddsförslaget granskas med
`python3 .github/scripts/configure_repository.py`. `--apply` kräver en
behörig GitHub CLI-session och ett separat beslut om konfigurationen.
Skriptet ersätter inte befintligt branchskydd. Lägg ingen administratörstoken i CI.

## Säkerhetsbevakning

[Dependency advisory monitoring](../.github/workflows/dependencies.yml)
kontrollerar Maven-, Python- och npm-lås samt Swift- och actionrevisioner
mot OSV. Fel och ofullständiga svar ger felstatus. Rapporten anger datum,
revision, manifesthashar och täckningsgränser. Det finns inga automatiska
undantag för fynd.

Dependabot föreslår uppdateringar enligt [konfigurationen](../.github/dependabot.yml).
En föreslagen version behöver granskas och provas innan den förs in.
OSV:s täckning omfattar inte alla OS-lager, modeller och byggverktyg; se
[säkerhetsinformationen](../SECURITY.md#kända-begränsningar-och-separata-utkast).

CI-artefakter har begränsad retention och är inte långtidsarkiv.
Bevara nödvändiga leveransunderlag separat. Undvik dubbla omkörningar;
privata repositories omfattas av kontots Actions-kvot och debitering.

# Utveckling

## Byggmiljöer

| Del | Verktyg och instruktioner |
|---|---|
| Verifierare och SAML | Linux x86_64, Python 3.12, Node 24.19.0, Temurin 21.0.12.1+1 och Maven 3.9.11. [Start och tester](../verification/README.md). |
| iPhone | macOS och iOS 16+. CI: Xcode 16.4; bygge 106: Xcode 27.1. [Projekt och signering](../ios/README.md). |
| WebAuthn-labb | JDK 21 och Chromium; låst Playwright 1.62.1. [Start och tester](../prototype/README.md). |
| Driftcontainer | Docker med digestlåst Temurin. [Körning](../ops/README.md). |

Pass- och bilddata ska ligga utanför repot. Testfixturer genereras vid körning.
Verifierarens Python-lås gäller Linux x86_64; ändra inte hashkraven för att
tyst installera på en annan plattform.

## Ändringar

1. Utgå från aktuell `main` och arbeta på en separat branch. Rikta PR:n mot
   `main`. En PR som bygger på en annan branch behöver föras hela vägen till
   `main` efter att beroendet mergats.
2. Uppdatera berörda [krav](krav.md), API-/startinstruktioner och negativa
   testfall tillsammans med ändringen. Dokumentera fungerande beteende och
   begränsningar där läsaren behöver dem.
3. Kör relevanta tester enligt [testöversikten](testning.md). Ange revision,
   resultat och ej körda delar i PR:n; återanvänd inte gamla antal som nytt bevis.
4. För beroendeändringar: granska ursprung, licens, underhåll och advisories;
   uppdatera lås, SBOM och komponentregister. Behåll attribution och NOTICE.

Publik dokumentation ska beskriva programvaran, API:er, driftkrav och
designbeslut. Affärskalkyler, kontaktutkast och intern korrespondens hanteras
separat. Lokala IDE-layouter och driftsinventarier ingår inte i kodbasen.
Versionshantera delade bygginställningar och tekniska instruktioner. Kommentarer i kod ska förklara en avsikt eller begränsning som inte
framgår av koden. Tillfälliga arbetsloggar hör hemma i PR:n.

## Nästa tekniska arbete

| Område | Acceptansprov |
|---|---|
| Fysisk iPhone | Signerat bygge på enheten: NFC, App Attest, Secure Enclave, avbrott, ny registrering, inloggning och spärr. |
| Biometri och fotografering | Kalibrerade trösklar samt mätning av felacceptans/felavvisning, presentationer, injektion och relä. |
| Pass och personregister | Spärrinformation, länkcertifikat, registerkontroll och ersättning efter passförnyelse. |
| Nycklar och återställning | Operativ rotation, gallring och PostgreSQL-/nyckelåterläsning på vald driftmiljö. |
| Extern integration | Fastställd profil, metadata, attribut och kontrollerad motpart med negativa protokollprov. |
| Drift | Operativa roller, redundant databas/nyckeltjänst, ingress, kapacitet och larmmottagning på vald driftmiljö. |

Produktionsöppning kräver oberoende säkerhetsgranskning och ett behörigt
mänskligt beslut om utgivning, dataskydd, drift och nyckelhantering.
Digg-godkännande och anslutningsavtal är separata beslut för sådan användning.
Kodändringar eller passerad CI ändrar inte dessa tillstånd. Se [SECURITY.md](../SECURITY.md).

## Obligatoriska kontroller och repoägarskap

`Assurance checks` kör alla komponenter för varje PR och för `main`, utan
sökvägsfilter. Den återanvänder komponenternas workflows från samma revision.
`assurance-gate` blir grön först när server/protokoll, delat register,
pilotcontainer, iPhone, driftcontainer, infrastrukturprov och aktuell
beroendekontroll har passerat. Fel, avbrott och överhoppade jobb nekar grinden.
Komponentprov kan även startas manuellt. Inga produktionshemligheter skickas
till dessa jobb; jobben har enbart läsbehörighet till koden.

Repoägaren behöver aktivera `.github/branch-protection.json` för `main` och
verifiera inställningen i GitHub. Den binder kontrollen till GitHub Actions,
kräver aktuell branch, en granskare och godkännande efter senaste push,
avfärdar gamla godkännanden, omfattar administratörer och förbjuder force-push
och borttagning. CODEOWNERS anger ansvarig förvaltare; det utgör inte en
oberoende säkerhetsgranskning. En sådan granskare måste utses och ges en
beslutad roll. Kodägargodkännande är inte aktiverat i förslaget eftersom en
ensam ägare inte kan godkänna sin egen PR.

Med repoägarens befintliga GitHub CLI-session kan förslaget granskas och
tillämpas med:

```sh
python3 .github/scripts/configure_repository.py
python3 .github/scripts/configure_repository.py --apply
```

Skriptet ersätter inte ett befintligt branchskydd. Det kontrollerar svaret
efter ändringen och aktiverar därefter GitHubs privata sårbarhetsrapportering.
Filen och skriptet innebär inte att dessa inställningar redan är aktiverade.
Lägg inte en administratörstoken i CI för att köra detta.

## Säkerhetsbevakning

Den dagliga `Dependency advisory monitoring` kontrollerar Maven-, Python-
och npm-låsen samt Swift- och actionrevisioner mot OSV. Samma kontroll ingår
i PR-grinden. Paginerade svar följs per fråga; ofullständiga svar, fel och
otillgänglig tjänst ger felstatus. Rapporten innehåller datum, kodrevision,
manifesthashar och täckningsgränser. Fynd kräver bedömning och rättning innan
grinden passerar. Det finns inga automatiska undantag.

Dependabot föreslår varje vecka uppdateringar för actions, Maven, npm och
Docker. Förslag behöver licens-/advisorygranskning, nya lås och passerad CI.
OSV:s register är inte heltäckande; särskilt OS-lager, JDK/Node, PostgreSQL,
OpenBao, modeller och driftkonfiguration behöver separat bevakning av
driftägaren. Swift-commitfrågor ersätter inte bevakning av inbäddade OpenSSL.
Verifiera dagliga körningar och en mottagare för fel efter aktivering på
`main`. GitHub-artefakterna med 90 dagars retention är inte långtidsarkiv
för utgivningsbevis.

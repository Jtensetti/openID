# Utveckling

## Byggmiljöer

| Del | Verktyg och instruktioner |
|---|---|
| Verifierare och SAML | Linux x86_64, Python 3.12, Node 24.19.0, Temurin 21.0.12.1+1 och Maven 3.9.11. [Start och tester](../verification/README.md). |
| iPhone | macOS, Xcode 16.4 och iOS 16+. [Projekt och signering](../ios/README.md). |
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
separat. Kommentarer i kod ska förklara en avsikt eller begränsning som inte
framgår av koden. Tillfälliga arbetsloggar hör hemma i PR:n.

## Nästa tekniska arbete

| Område | Acceptansprov |
|---|---|
| Fysisk iPhone | Signerat bygge på enheten: NFC, App Attest, Secure Enclave, avbrott, ny registrering, inloggning och spärr. |
| Biometri och fångst | Kalibrerade trösklar samt mätning av felacceptans/felavvisning, presentationer, injektion och relä. |
| Pass och personregister | Spärrinformation, länkcertifikat, registerkontroll och ersättning efter passförnyelse. |
| Nycklar och återställning | Rotation, gallring och restore som inte återupplivar spärrade nycklar. |
| Extern integration | Fastställd profil, metadata, attribut och kontrollerad motpart med negativa protokollprov. |
| Drift | Rollseparation, servernyckelskydd, kapacitet, övervakning och övad återställning. |

Produktionsöppning kräver oberoende säkerhetsgranskning och ett behörigt
mänskligt beslut om utgivning, dataskydd, drift och nyckelhantering.
Digg-godkännande och anslutningsavtal är separata beslut för sådan användning.
Kodändringar eller passerad CI ändrar inte dessa tillstånd. Se [SECURITY.md](../SECURITY.md).

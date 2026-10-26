# Tredjepartskomponenter

Versioner och licenser kontrollerades 2026-10-19, med kompletteringen
2026-10-20 i [verifierarens register](verification/THIRD_PARTY.md).
Underhålls- och sårbarhetsuppgifter nedan avser dessa kontrolltillfällen.

## Lås och licensfiler

Maven-grafen innehåller **192 JAR-artefakter**, låsta med version och SHA-256 i
[dependencies.lock.json](prototype/dependencies.lock.json).
[CycloneDX-SBOM](prototype/evidence/bom.json) innehåller paket och deklarerade
licenser; [OSV-resultatet](prototype/evidence/osv.json) innehåller den daterade
sårbarhetskontrollen. npm-paketen låses med integritetshash i respektive
`package-lock.json`. Python- och Swift-lås beskrivs i
[verification/THIRD_PARTY.md](verification/THIRD_PARTY.md).

AWS-testets SDK, CI-verktyg och licenser finns i
[deployment/aws/THIRD_PARTY.md](deployment/aws/THIRD_PARTY.md).
Samma hash-låsta SDK och SBOM används nu också av pilotcontainerns
spärrklient och aviseringskö samt av den separata Lambda-tjänstens SDK-layer.
Inga SDK-versioner eller transitiva beroenden ändras genom denna återanvändning.

| Komponent | Låst version / full källrevision | Användning och licens |
|---|---|---|
| [Spring Authentication Server](https://github.com/swedenconnect/spring-authentication-server) | 1.0.3 / `dd49df31aa250eaacbd3a27466a05ec331b6dddc` | Parent-POM, SAML-/OIDC-starter och provider-API. Apache-2.0. |
| [Credentials Support](https://github.com/swedenconnect/credentials-support) | 2.2.1 / `831d82d890ade02ee6fed81198996e3b7ef55e96` | PKCS12, OpenSAML-adapter och Spring-integration. Apache-2.0. |
| [Sweden Connect Test Client](https://github.com/swedenconnect/sweden-connect-test-client) | 1.0.19 / `87aac956a762928b11a640e30382f7e5ca5fef1b` | Enbart adaptern `CustomResponseProcessor.java`. Apache-2.0. |
| [SQLite JDBC](https://github.com/xerial/sqlite-jdbc) | 3.53.4.0 / `cab7981c19ce04d691f0675f0b2586afc2bbf803` | Java-labbens register. Apache-2.0 och Zentus BSD-2-Clause; SQLite 3.53.4 är public domain. |
| [Yubico Java WebAuthn Server](https://github.com/Yubico/java-webauthn-server) | 2.10.1 / `6c1b6cc19beae08cd6a310a40db1acee3673b98d` | `webauthn-server-core` och `yubico-util`. BSD-2-Clause samt Google-kod under BSD-3-Clause. |
| [Maven Wrapper](https://github.com/apache/maven-wrapper) | 3.3.4 / `524486aff97d0748926a977665d5befb3251ff17` | Officiella only-script-filer. Apache-2.0. Maven 3.9.11 har fast distributions-SHA-256. |
| [Apache PDFBox](https://pdfbox.apache.org/) | 3.0.8 (pdfbox, pdfbox-io, fontbox), Maven Central 2026-07-08 | Demodokument och PAdES-B-B-signatur i kontotjänstens underskriftstest. Apache-2.0; NOTICE och bundna tredjepartslicenser (Adobe AFM/glyflistor, Unicode, TwelveMonkeys) i [licenses/PDFBox-3.0.8-NOTICE.txt](prototype/licenses/PDFBox-3.0.8-NOTICE.txt) och [-LICENSE.txt](prototype/licenses/PDFBox-3.0.8-LICENSE.txt). |
| [Playwright](https://github.com/microsoft/playwright) | 1.62.1, inklusive playwright-core | Webbläsartester, Apache-2.0. Valfritt macOS-beroende fsevents 2.3.2 är MIT. |

Delade SAML-funktioner kommer från Sweden Connect `opensaml-addons` 2.2.1,
`opensaml-security-ext` 4.2.1, `opensaml-swedish-eid` 2.3.1 och OpenSAML 5.2.1.
Pass-, NFC-, App Attest-, QR- och modellkomponenter redovisas i
[verifierarens register](verification/THIRD_PARTY.md).

## Anpassad källkod

`prototype/src/main/java/lab/LabResponseProcessor.java` bygger på G05-adaptern.
Ursprung, källfil och revision finns i [ATTRIBUTION.md](prototype/licenses/ATTRIBUTION.md).
Copyright, författare och licenshuvud har bevarats. Anpassningen kräver
signerade och krypterade assertioner, explicit RSA-SHA256/SHA256-validering
och ett symmetriskt femsekunders svarsfönster. Resten av testklienten används inte.

[Apache-2.0](prototype/licenses/Apache-2.0.txt),
[Maven Wrappers NOTICE](prototype/licenses/Maven-Wrapper-NOTICE.txt),
[Zentus licens](prototype/licenses/sqlite-jdbc-LICENSE.zentus) och
[Yubicos COPYING](prototype/licenses/Yubico-COPYING.txt) bevaras i repot.
Ingen NOTICE hittades i de granskade G01/G05-källträden. Inbäddade JAR:er
behåller sina egna licens- och NOTICE-resurser vid paketering.

## WebAuthn

Yubicos API utför protokollvalideringen och JCA utför kryptografin.
Labben tillåter ES256/RS256, kräver användarverifiering och använder
attestering `none`. En kompletterande policy nekar `crossOrigin=true` och
förekomst av `topOrigin`; dessa fält kontrolleras inte av Yubicos
`CollectedClientData` vid den låsta revisionen. Jackson läser fälten och
avvisar duplicerade nycklar.

Guava **33.7.2-jre**, `failureaccess` **1.0.3**, `j2objc-annotations` **3.1**
och Jackson CBOR/JDK8 **2.21.7** förenar beroendegraferna utan avstängd
convergence-kontroll. De deklarerar Apache-2.0.

CBOR **4.5.6** låses tillsammans med Numbers **1.8.2** och DataUtilities
**1.1.0**. CBOR:s POM och LICENSE anger Unlicense; de två andra anger
public domain/CC0 i käll-JAR:erna. Versionsintervallet i Yubicos parent
ersätts med ett exakt val. Ingen matchande Git-tagg hittades för CBOR 4.5.6;
publicerad käll-JAR och artefaktchecksumma används för spårning.
Käll-JAR:ens SHA-256 är
`05384f450f77728579caba69c79a9c7752826356e14610927b11e75de05b652e`.

## Underhåll och säkerhetskontroll

Vid kontrollen var G01, G03, G05, SQLite JDBC och Yubico inte arkiverade.
Senaste push var 2026-10-19, 2026-04-24, 2026-10-15, 2026-10-15 respektive
2026-10-13. G02 anger G01 som ersättare och används inte. CBOR, Numbers och
DataUtilities var inte arkiverade; senaste push var 2026-06-04, 2026-04-20
respektive 2025-08-11. Aktivitet innebär inget underhålls- eller SLA-löfte.

Spring Boot **4.1.1** och Java **21** kombineras med Tomcat **11.0.26**,
Jackson **2.21.7/3.1.7** och jsoup **1.23.2** (test). Parentens ursprungliga
versioner gav OSV-träffar och överstyrs med Maven-koordinater/BOM:er.
Den låsta grafen gav inga publicerade OSV-fynd vid kontrolltillfället.
SQLite-advisoryn [CVE-2023-32697](https://github.com/xerial/sqlite-jdbc/security/advisories/GHSA-6phf-6h5g-97j2)
är rättad i 3.41.2.2, före den använda versionen.

Kontrollen omfattar inte egna kodfel, JDK, OS, webbläsare eller byggpluginernas
hela graf. Den ersätter inte oberoende säkerhetsgranskning.

## Transitiva licenser

SBOM hämtar licensdeklarationer från Maven-POM:er. Filgranskningen fann:

- `stax2-api` 4.2.1 deklareras som BSD-4-Clause i SBOM, men
  `META-INF/LICENSE` anger Simplified BSD/2-clause. Originaldeklarationen
  finns kvar i SBOM; filuppgiften behövs vid distributionsgranskning.
- Bouncy Castle 1.86 anger ”Bouncy Castle Licence”; JAR:ens LICENSE innehåller
  MIT-text med The Legion of the Bouncy Castle som rättighetshavare.
  Samma redan låsta `bcpkix`/`bcprov` används för den syntetiska
  dokumentunderskriftens CMS och X.509; inga nya Java-beroenden tillkommer.
  OpenSSL är en separat testvalidator från testmiljön. Exakt version
  sparas i `openssl-results.json`; den är inte en produktionskomponent
  eller ett betrott certifikatutfärdarregister. Uppdateringsansvaret följer
  labbens befintliga beroendegranskning.
- Logback 1.5.38 deklarerar EPL-2.0/LGPL-2.1; Jakarta Annotation/Servlet
  EPL-2.0/GPL med Classpath Exception; Cryptacular 1.3.0 Apache-2.0/LGPL.
  Biblioteken är oförändrade. JUnit 6.0.3 är EPL-2.0 och används endast i test.

## Driftimage

`ops/Dockerfile` låser Temurin **21.0.12.1+1** på Ubuntu Noble med image-digests.
Docker Hubs official-images-manifest kopplade taggarna till
[adoptium/containers@511f9356dc4d50932a0a5f8cfb0f87ed1aef4f07](https://github.com/adoptium/containers/tree/511f9356dc4d50932a0a5f8cfb0f87ed1aef4f07).
Dockerfile-källan är Apache-2.0. JDK/JRE har GPL-2.0 med Classpath Exception
och separata licenser i `legal/`; Ubuntu-paketens licenser finns i
`/usr/share/doc`. Dessa bevaras i basimagen och täcks inte av Maven-SBOM.

Imagen bygger endast `ops/src/SealedEnvironment.java`. Verifierare,
Sweden Connect, identitetsdatabas och testnycklar ingår inte.

## Apples systemramverk

iOS-kamerans fångstguide använder Apples systemramverk Vision: ansiktsrutor
revision 3 och fångstkvalitet revision 2. Inget nytt paket eller modellvikter
distribueras. Ramverket följer iOS och Apples SDK-villkor; Xcode är låst till
16.4 i CI. API-underlaget kontrollerades 2026-10-20:
[ansiktsrutor](https://developer.apple.com/documentation/vision/vndetectfacerectanglesrequest),
[huvudvinkel](https://developer.apple.com/documentation/vision/vnfaceobservation/yaw) och
[fångstkvalitet](https://developer.apple.com/documentation/vision/vndetectfacecapturequalityrequest).

## Byggkontroll av systempaket

Trivy **0.76.1**, källrevision
`e713f67f7d54decdcd9b3132c9751833dcced698`, används endast i det isolerade
pilotbygget. Ursprung är [Aqua Securitys officiella repo](https://github.com/aquasecurity/trivy).
Distribution och upstream-SBOM låses med SHA-256 i
[trivy.lock.json](deployment/build/trivy.lock.json). Projektet är aktivt
underhållet vid kontrollen 2026-10-26; releasen publicerades 2026-10-21.
[Apache-2.0](deployment/build/licenses/Trivy-LICENSE.txt) och
[NOTICE](deployment/build/licenses/Trivy-NOTICE.txt) bevaras oförändrade.
Verktyget eller dess Go-beroenden distribueras inte med appen/serverimagen.
Upstream-SBOM har 458 komponentposter och sparas i CI-artefakten; den saknar
licensdeklarationer per komponent och utgör inte en fullständig licensrevision.
Vid eventuell egen distribution av verktyget krävs separat transitiv licensgranskning.

Python **3.12.15-slim-bookworm** använder nu indexdigest
`sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70`.
Docker Official Images anger
[docker-library/python@2a3b794c223ab067d122719541cdd54a068732a5](https://github.com/docker-library/python/tree/2a3b794c223ab067d122719541cdd54a068732a5/3.12/slim-bookworm)
som källa för amd64-manifestet. Uppdateringen bevarar Python-versionen och
tar in Debian-paketet `ca-certificates` 20250419~deb12u2.
Ytterligare rättningar för `libssl3`/`openssl` 3.0.22-1~deb12u2 och `tzdata`
2026e-0+deb12u1 hämtas från Debian Security med versions- och hashlås i
[bookworm-updates.lock.json](deployment/build/bookworm-updates.lock.json).
Befintliga paketlicenser och copyright-filer i `/usr/share/doc` bevaras
genom Debians paketinstallation. Python- och Temurin-versionerna ändras inte av OS-rättningen.
Node uppdateras separat till 24.22.1 enligt följande avsnitt.

Den daterade OS-inventeringen och CycloneDX sparas för varje byggd pilotimage.
Den är skild från Maven-/Python-SBOM och omfattar inte de kopierade runtime-
binärerna. Resultat, täckning och stoppvillkor beskrivs i
[bygginstruktionen](deployment/build/README.md#systempaket-och-säkerhetsunderlag).

## Node-säkerhetsuppdatering 2026-10-26

Node **24.22.1** ersätter 24.19.0 i serverimages, server-/register-/iPhone-CI
samt det separata AWS-testets installationsskript. Inga sådana AWS-jobb körs
av ändringen. [Officiell säkerhetsrelease](https://nodejs.org/en/blog/release/v24.22.1)
beskriver bland annat TLS-/DNS-/Brotli-rättningar, CA-uppdatering och OpenSSL 3.5.9.
Dockerimagen är låst till
`sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205`;
amd64-källan anges som
[nodejs/docker-node@80f02a542da739e6a662451d1db66456a0dea253](https://github.com/nodejs/docker-node/tree/80f02a542da739e6a662451d1db66456a0dea253/24/bookworm-slim).
Linux x64-distributionen har SHA-256
`6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6`
enligt Node-projektets SHASUMS256.txt.

Node är MIT med separata licenser för inbäddade delar. Releasefilen LICENSE
har kontrollerats och innehåller dessa texter; den kopieras fortsatt till
serverimagen från den officiella Node-distributionen. Ingen Node-källkod
kopieras till projektet. `runtime-components.json` inventerar den faktiska
Node-binärens komponentversioner samt Python/OpenSSL/SQLite/Expat och
Temurins releaseuppgifter. Det är inventering, inte full advisorytäckning
eller oberoende SBOM-attest. Testa protokoll och CryptoKit-interoperabilitet
med den nya runtime-versionen före införande.

## Projektlicens och förvaltning

**Projektets egen licens är inte beslutad.** POM/SBOM använder `NOASSERTION`
så att parentens Apache-licens inte ärvs som projektbeslut. Före distribution
behövs beslut om projektlicens, bidragsvillkor och tillämpliga
attributions- och källkodskrav. Tredjepartslicenserna gäller sina respektive filer.

Formellt uppdateringsansvar och produktionsförvaltare är inte utsedda.
Beroendeändringar ska uppdatera lås, SBOM, licens-/advisorykontroll och
berörda tester enligt [utvecklingsinstruktionerna](docs/utveckling.md).

## OIDC-komplettering 2026-10-21

Samma upstream-release 1.0.3 används för OIDC-starter och OIDC-modulen.
Nimbus OAuth2/OIDC SDK 11.38.2 och JOSE/JWT 10.10 används för meddelanden
och tokenvalidering. Nya transitiva komponenter är content-type 2.3,
lang-tag 1.7, jcip-annotations 1.0-1, oidc-sweden-nimbus 1.0.0,
Sweden Connect OIDF common 1.0.0 och credentials-support-nimbus 2.2.1.
Samtliga nya komponenter deklarerar Apache-2.0 i hämtade Maven-underlag;
JAR-innehållens licens- och NOTICE-filer bevaras. Inga upstream-källfiler
har kopierats till OIDC-adaptern.

Låset innehåller 189 artefakter med SHA-256. Tre tidigare testberoenden
(json-smart, accessors-smart och ASM) ingår nu vid körning; deras versioner
och checksummor är oförändrade. CycloneDX-SBOM och daterad OSV-kontroll
är uppdaterade. OSV gav inga matchande fynd för de 189 koordinaterna;
det är inte bevis för frånvaro av sårbarheter. Nya integrationen är
begränsad till privat pilot. Produktionsförvaltare och oberoende granskare
återstår enligt förvaltningsavsnittet ovan.

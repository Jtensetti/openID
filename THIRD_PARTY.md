# Tredjepartskomponenter

Versioner och licenser kontrollerades 2026-10-19, med kompletteringen
2026-10-20 i [verifierarens register](verification/THIRD_PARTY.md).
Underhålls- och sårbarhetsuppgifter nedan avser dessa kontrolltillfällen.

## Lås och licensfiler

Maven-grafens JAR-artefakter är låsta med version och SHA-256 i
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

`ops/Dockerfile` använder Temurin **21.0.13+9** från samma kontrollerade
Linux x64-arkiv och SBOM som beskrivs nedan. Hela JDK-/JRE-katalogen ersätts;
den tidigare Java-installationen används inte av den slutliga containern.
Ubuntu Noble-lagren är fortsatt låsta till de tidigare image-digests som
levererades med Temurin 21.0.12.1+1. Detta är inte en full OS-uppdatering.
Docker Hubs official-images-manifest kopplade taggarna till
[adoptium/containers@511f9356dc4d50932a0a5f8cfb0f87ed1aef4f07](https://github.com/adoptium/containers/tree/511f9356dc4d50932a0a5f8cfb0f87ed1aef4f07).
Dockerfile-källan är Apache-2.0. JDK/JRE har GPL-2.0 med Classpath Exception
och separata licenser i `legal/`; Ubuntu-paketens licenser finns i
`/usr/share/doc`. De nya JRE-licenserna och OS-licenserna bevaras och täcks
inte av Maven-SBOM. Kandidaten är begränsad till Linux/amd64; Compose väljer
den plattformen även på Apple Silicon.

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
`e713f67f7d54decdcd9b3132c9751833dcced698`, används endast i de isolerade
pilot- och registerbyggena. Ursprung är [Aqua Securitys officiella repo](https://github.com/aquasecurity/trivy).
Distribution och upstream-SBOM låses med SHA-256 i
[trivy.lock.json](deployment/build/trivy.lock.json). Projektet är aktivt
underhållet vid kontrollen 2026-10-26; releasen publicerades 2026-10-21.
[Apache-2.0](deployment/build/licenses/Trivy-LICENSE.txt) och
[NOTICE](deployment/build/licenses/Trivy-NOTICE.txt) bevaras oförändrade.
Verktyget eller dess Go-beroenden distribueras inte med appen/serverimagen.
Upstream-SBOM har 458 komponentposter och sparas i CI-artefakten; den saknar
licensdeklarationer per komponent och utgör inte en fullständig licensrevision.
Vid eventuell egen distribution av verktyget krävs separat transitiv licensgranskning.

### Wolfi-bas och apko, kontrollerat 2026-10-30

Pilot och register byggs från offentliga [Wolfi-paket](https://packages.wolfi.dev/os/).
De 32 exakta paketversionerna och deras kontrollsummor finns i
[wolfi-runtime.lock.json](deployment/build/wolfi-runtime.lock.json).
Receptkällan är [wolfi-dev/os@65e46148155ff624c83ce3c02321614adc4d23b1](https://github.com/wolfi-dev/os/tree/65e46148155ff624c83ce3c02321614adc4d23b1).
Basen omfattar bland annat glibc 2.44-r11, OpenSSL 4.0.3-r8,
SQLite 3.54.1-r0, Expat 2.9.0-r0 och Python 3.12.16-r1.
Paketens egna licenser gäller, bland annat LGPL-2.1-or-later (glibc),
Apache-2.0 (OpenSSL), MIT (Expat), PSF-2.0 (Python) och GCC:s runtimeundantag.
SQLite anges som public domain. SPDX/CycloneDX från varje bygge bevarar
paketidentiteter, deklarerade licenser och källreferenser. Paketens medlevererade
licensfiler raderas inte. Wolfi-paketen innehåller inte fullständiga licenstexter
för alla komponenter: komplett licens- och källleverans måste säkerställas
före extern distribution. Paketlåset och SBOM utgör inte ett sådant godkännande.

[Apko 1.4.13](https://github.com/chainguard-dev/apko/releases/tag/v1.4.13),
commit `217f25a71fd6f18f00fb1024f9b251dc7127bfd5`, sammanställer basen utan
att kompilera om paketen. Linux amd64-arkivets SHA-256 är
`2377cd4a2efed58905da580f835fbdf2a6ed4ad0f10ff541827153a42d491cee`.
[Apache-2.0-licensen](deployment/build/licenses/Apko-LICENSE.txt) bevaras.
Verktygets Go-beroenden levereras inte i runtime. Verktygslås, paketlås,
konfiguration och bas-SBOM sparas i imagen och CI-underlaget.

Byggverktygssteget använder fortsatt digestlåst Python 3.12.15-slim-trixie,
`sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704`.
Dess [MIT-licens](deployment/build/licenses/docker-library-python-LICENSE.txt)
bevaras i repot. Debian-filsystemet följer inte med till slutimagen.
CI använder dessutom den tidigare Bookworm-basen enbart för syntetiska
SQLite-fixturer. Återläsningsproven kräver bevarad spärr och karantän.

Trivy kompletteras med [Wolfis fullständiga OSV-feed](https://advisories.cgr.dev/chainguard/v2/osv/all.json)
för öppna ärenden som saknar rättad version. Den kompletteringen krävs för
att ett byte av distribution inte ska ge falskt godkänt resultat. Inventeringen
2026-10-30 hade nio öppna leverantörsposter för Python/Expat. Expat hade dessutom
[en ny upstreamrättning](https://github.com/libexpat/libexpat/pull/1450)
för CVE-2026-118370 som ännu inte ingick i den låsta paketversionen.
Bytet gör därför inte kandidaten fri från kända fynd.
Aktuella resultat och stoppvillkor hör till den exakta CI-revisionen;
se [bygginstruktionen](deployment/build/README.md#systempaket-och-säkerhetsunderlag).
Förvaltaren ansvarar för låsuppdatering och ny licens-/advisorykontroll.

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

## Temurin-säkerhetsuppdatering 2026-10-26

Pilotens JDK/JRE och serverproven använder **Temurin 21.0.13+9-LTS**, den
officiella [releasen](https://github.com/adoptium/temurin21-binaries/releases/tag/jdk-21.0.13%2B9)
från Eclipse Adoptium. Projektet är aktivt underhållet; release publicerades
2026-10-22. Linux x64-arkiven hämtas oförändrade från denna release. Byggningen
nekar fel SHA-256 före extraktion, fel arkitektur eller annan runtime-version.
Ingen äldre Java-distribution kopieras till pilotimagen.

| Underlag | SHA-256 |
|---|---|
| `OpenJDK21U-jdk_x64_linux_hotspot_21.0.13_9.tar.gz` | `d7f5d5cf865a2902b70ff549b97586a7d3f234e016f041ab447ea740c7d66d1c` |
| `OpenJDK21U-jre_x64_linux_hotspot_21.0.13_9.tar.gz` | `a535a1df9c6284d9618872984e026ae0352d1f7e9e0605425c0e6114f47351dd` |
| `OpenJDK21U-sbom_x64_linux_hotspot_21.0.13_9.json` | `5431b6d3ad286a41d9e20b9b0d37355f430046e333b4954c0814a8c3014bd4f4` |

Upstream-SBOM binder JDK- och JRE-arkiven till källrevision
[`2ab10ca20c191701c3a9f3153bfc6e93d63714c1`](https://github.com/adoptium/jdk21u/commit/2ab10ca20c191701c3a9f3153bfc6e93d63714c1)
och byggrevision
[`1cf43d7a3e77886bfea7d550a902e151a87d724d`](https://github.com/adoptium/temurin-build/commit/1cf43d7a3e77886bfea7d550a902e151a87d724d).
JRE:s separata release-metadata binder dess arkivhash till samma version och
byggrevision. Arkivens `legal/` och releasefil bevaras; GPL-2.0 med Classpath
Exception och komponenternas egna licenser gäller fortsatt. Ingen Java-källkod
ändras. Källkods- och attributionskrav ska uppfyllas före extern distribution.
SBOM sparas i imagen och CI-artefakten. Den har fem distributionskomponenter
(JDK, JRE, statiska bibliotek, debug- och testimage), byggverktyg och byggmetadata,
men saknar licensdeklaration per komponent och full inventering av inbäddade
bibliotek. Den ersätter inte OS-rapporten, Maven-SBOM eller sådan bedömning.

Kompatibilitet provas med serverns Java-, signatur- och passprov samt pilotens
SAML/OIDC-prov mot den paketerade JRE:n. Aktuella resultat hör till PR:n och
exakt CI-revision. Byte av version ersätter inte oberoende granskning.
Även `ops/` använder nu dessa Java-arkiv, men behåller sina tidigare Noble-
systempaket. Uppdateringsansvaret följer förvaltningen nedan.

## Python 3.12.16 och installationsverktyg

Runtime använder Wolfis Python 3.12.16-r1. Upstream är den officiella
[säkerhetsutgåvan](https://www.python.org/downloads/release/python-31216/),
commit `2c2462afc5d978d31f3d073001fc202d269917ff`, tillsammans med
[distributionens recept och patchar](https://github.com/wolfi-dev/os/blob/65e46148155ff624c83ce3c02321614adc4d23b1/python-3.12.yaml).
Paketet länkar mot distributionens OpenSSL, SQLite och Expat. Projektets
privata Python-kompilering och dess testpatch har tagits bort.
Paketlås, bas-SBOM och Python-paketets licens följer med. Kompatibilitet
provas i slutimagen med verifierare, nyckeltjänst, bildarbetare, återställning,
SAML och OIDC. En ny bas är inte godkänd innan dessa prov passerar.

Pip **26.2.2** används endast för paketinstallation under bygget. Hjulet har
SHA-256 `fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70`;
inbäddad CycloneDX har SHA-256
`7be976001ba70fe6b38530af13063bea96e1bd894c271c4e57908c737079ef93`.
Körningen startar från det verifierade hjulet utan nät och kräver en faktisk
installation även om byggmiljön redan har pip. Inga runtimefiler i ensurepip
modifieras. Efter paketinstallationen tas både pip och hela ensurepip bort
ur det färdiga driftfilsystemet. Separat inventering verifierar borttagningen.
Historiska bygglager omfattas inte av denna borttagningskontroll.

Pips MIT-licens och transitiva licens-/attributionsfiler kopieras till
`/usr/share/doc/openid-python/pip-licenses/` före borttagning: bland annat
Apache-2.0, BSD, ISC, PSF och certifis MPL-2.0. Inbäddad SBOM bevaras också.
Basens SBOM beskriver även installeringshjulet `py3-pip-wheel`. Detta hjul
tas bort tillsammans med pip och ensurepip. Borttagna filers hash sparas i
`pip-removal.json`; APK-metadata och SBOM behålls som proveniens.
Ingen licens för hela projektet härleds från detta.

Pips version ingår i OSV-kontrollen. Separat kontroll av dess bundlade
komponenter gav fynd för urllib3, msgpack och setuptools. De kräver bedömning
av faktisk medlevererad kod och bygganvändning; inga undantag eller påståenden
om fullständig rättning följer av versionsbytet. Borttagning ur runtime
ersätter inte granskning av byggverktyget.
Pilot- och registerbyggen installerar nu applikationshjulen från ett lokalt,
skrivskyddat BuildKit-steg utan nätåtkomst. Filadresserna kommer från PyPI:s
officiella distributionsmetadata respektive PyTorchs CPU-index, som för
det låsta torch-hjulet hänvisar till `download-r2.pytorch.org`.
`deployment/build/python-wheels.lock.json` binder ursprung till befintliga
paketversioner och hashkrav; inga nya paket, versioner eller licenser införs.
Installationsrapport och verklig paketlista kontrolleras i båda images.
Åtgärden begränsar pips nätverksexponering under imagebygget; värdens CI-pip,
BuildKit och andra nedladdare behöver fortsatt egen bedömning. Existerande
komponentregister, licenser och SBOM kvarstår; hjullåset ersätter dem inte.
Förvaltaren ansvarar för versions-, licens- och advisorybevakning och uppdatering av den låsta Wolfi-basen. Oberoende
granskning, integrationstester och behörigt releasebeslut krävs fortsatt.

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

Vid OIDC-införandet omfattade låset 189 artefakter. Det aktuella innehållet
styrs av `prototype/dependencies.lock.json`. Tre tidigare testberoenden
(json-smart, accessors-smart och ASM) ingår nu vid körning; deras versioner
och checksummor är oförändrade. CycloneDX-SBOM och daterad OSV-kontroll
är uppdaterade. OSV gav inga matchande fynd för de 189 koordinaterna;
det är inte bevis för frånvaro av sårbarheter. Nya integrationen är
begränsad till privat pilot. Produktionsförvaltare och oberoende granskare
återstår enligt förvaltningsavsnittet ovan.

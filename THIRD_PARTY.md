# Tredjepartsmaterial och licensbeslut

Kontrolldatum: 2026-10-19.

## Vad som faktiskt finns här

Förstudien, arkitekturförslaget, kravmatrisen, agentinstruktionerna och projektets övriga nytillkomna Markdown-filer är projektspecifika originaltexter. De hänvisar till primärkällor och återger korta faktasammanfattningar. De utgör inte officiella Digg-dokument.

G1-prototypen använder nedanstående låsta bibliotek och en avgränsad källkodsadapter. Inga myndighetslogotyper, verkliga certifikatuppsättningar eller fullständiga avtalskopior har importerats. Kandidatregistret längre ned är det ursprungliga förstudieunderlaget; det är inte ett påstående om färdig produktdistribution.

## Faktiskt införda komponenter i G1

Kontrollerat 2026-10-19 mot officiella GitHub-repositoryn, Maven-artefakter, LICENSE-filer och versionsbundna källfiler. Full Maven-graf med JAR-checksummor: [dependencies.lock.json](prototype/dependencies.lock.json). Licensdeklarationer, paketversioner och fler hashvärden: [CycloneDX SBOM](prototype/evidence/bom.json). Testverktygen i npm är låsta med integritetshash i `prototype/package-lock.json`.

| Ursprung | Låst release och full commit | Faktisk användning och licens |
|---|---|---|
| [G01 Spring Authentication Server](https://github.com/swedenconnect/spring-authentication-server) | 1.0.3, `dd49df31aa250eaacbd3a27466a05ec331b6dddc` | Parent-POM och SAML-starter med transitive moduler. Apache-2.0, LICENSE läst. Ingen egen fork eller kopiering av referensserverns UI/CI. |
| [G03 Credentials Support](https://github.com/swedenconnect/credentials-support) | 2.2.1-release, `831d82d890ade02ee6fed81198996e3b7ef55e96` | PKCS12-credentials, OpenSAML-adapter och Spring-integration. Apache-2.0, LICENSE läst vid denna commit. |
| [G05 Sweden Connect Test Client](https://github.com/swedenconnect/sweden-connect-test-client) | 1.0.19, `87aac956a762928b11a640e30382f7e5ca5fef1b` | Enbart `CustomResponseProcessor.java`, anpassad till `prototype/src/main/java/lab/LabResponseProcessor.java`. Apache-2.0; original copyright/author/licenshuvud bibehållna. Se attribution nedan. |
| [Apache Maven Wrapper](https://github.com/apache/maven-wrapper) | 3.3.4, `524486aff97d0748926a977665d5befb3251ff17` | Officiella only-script-filer, Apache-2.0. Maven 3.9.11 med fast distributions-SHA-256 i wrapper-properties. |
| [Microsoft Playwright](https://github.com/microsoft/playwright) | 1.62.1, exakt npm-version inklusive playwright-core 1.62.1 | Endast utvecklings-/webbläsartestverktyg, Apache-2.0. Inte del av Java-applikationen. Valfritt macOS-beroende fsevents 2.3.2 är MIT. |

G05-länken och källfilens exakta URL ska läsas tillsammans med revisionen i [attributionsfilen](prototype/licenses/ATTRIBUTION.md). Hela testklienten används inte: dess öppna val av identiteter, tillitsnivåer och metadata passar inte labbens fasta gränser. Delade protokollfunktioner kommer från Sweden Connect `opensaml-addons` 2.2.1, `opensaml-security-ext` 4.2.1, `opensaml-swedish-eid` 2.3.1 och OpenSAML 5.2.1; inga egna kryptografiska primitiver eller SAML-validatorer har skrivits.

Lokala ändringar i G05-adaptern: namn/paket, obligatoriskt signerade och krypterade assertioner, explicit RSA-SHA256/SHA256-validering och symmetriskt femsekunders svarsfönster. Licenstexten finns i [Apache-2.0.txt](prototype/licenses/Apache-2.0.txt). Ingen NOTICE hittades i de granskade G01/G05-källträden. Maven Wrappers NOTICE har bevarats i [Maven-Wrapper-NOTICE.txt](prototype/licenses/Maven-Wrapper-NOTICE.txt). Inbäddade beroende-JAR:er behåller sina egna licens-/NOTICE-resurser vid lokal paketering.

### Underhåll, säkerhet och kompatibilitet

G01 och G05 var inte arkiverade. Senaste push enligt GitHub var 2026-10-19 respektive 2026-10-15; de valda releaserna publicerades 2026-10-13 respektive 2026-10-15. G03 var inte arkiverat (push 2026-04-24). G02 `saml-identity-provider` anger fortfarande G01 som ersättare och används inte. G04 SignService var inte arkiverat (push 2026-03-31); taggen `1.2.0-release` pekade på `9714f3783bb7af862a4bfbd39ef8e87e569ff9ea`, LICENSE är Apache-2.0. G04 införs inte eftersom dokumentunderskrift ligger utanför denna autentiseringsetapp. Aktivitet är inte en garanti om SLA eller fortsatt underhåll.

G01:s låsta parent kombineras med Spring Boot 4.1.1, Java 21 och säkerhetspatchar: Tomcat 11.0.26, Jackson 2.21.7/3.1.7 samt jsoup 1.23.2 (test). Parentens ursprungliga versioner gav OSV-träffar och används därför inte oförändrade. Beroendehanteringen överstyr faktiska Maven-koordinater/BOM:er; enbart egenskaper i POM räcker inte när Boot-BOM importeras av parenten. Den uppdaterade grafen är verifierad i testerna.

De offentliga GitHub-advisorylistorna för G01/G03/G04/G05 var tomma vid kontroll. OSV-kontroll av de slutliga 170 Maven-paketen gav inga träffar vid kontrolltillfället; [maskinläsbart resultat](prototype/evidence/osv.json). Det omfattar inte egna kodfel, JDK, operativsystem, byggpluginernas hela graf eller en oberoende revision. Upptäckt färskhetsavvikelse i `opensaml-addons` och övriga återstående begränsningar står i [verifieringsrapporten](prototype/evidence/verification.md).

### Transitiva licenser och distributionsgräns

SBOM:s licensdata kommer från Maven-POM:er och är deklarationer, inte en juridisk kompatibilitetsattest. De 170 komponenterna deklarerar Apache-2.0, MIT, BSD-varianter, EPL-2.0 samt alternativ med LGPL/GPL med Classpath Exception. Inga EUPL-komponenter från kandidatlistan har införts. Särskilt granskade avvikelser:

- `stax2-api` 4.2.1 får **BSD-4-Clause** i genererad SBOM, medan dess faktiska `META-INF/LICENSE` uttryckligen anger Simplified BSD/2-clause. Originaldeklarationen har inte dolts eller skrivits om i SBOM; filnivåuppgiften ska styra fortsatt distributionsgranskning.
- Bouncy Castle 1.86 deklarerar “Bouncy Castle Licence”; JAR:ens `META-INF/LICENSE.md` innehåller MIT-text med The Legion of the Bouncy Castle som rättighetshavare.
- Logback 1.5.38 deklarerar EPL-2.0/LGPL-2.1; Jakarta Annotation/Servlet deklarerar EPL-2.0/GPL med Classpath Exception. Cryptacular 1.3.0 deklarerar Apache-2.0/LGPL. Dessa bibliotek har inte modifierats. JUnit 6.0.3 är EPL-2.0 och används enbart i test.

Denna PR inför källkod för en intern lokal labb och publicerar ingen binär release. Innan vidare distribution krävs ägarens val av projektlicens och granskning av tillämpliga tredjepartsalternativ, attribution och eventuella källkodserbjudanden. POM/SBOM markerar egen projektlicens som `NOASSERTION` så att parentens Apache-licens inte felaktigt ärvs som projektbeslut.

Föreslagen uppdateringsägare för labben är repositoryägaren **Jtensetti**, att bekräfta vid granskning; ingen produktionsförvaltare eller oberoende säkerhetsgranskare är ännu utsedd. Uppdateringar ska innehålla ändrad låsfil/SBOM, ny advisory-/licenskontroll och samma negativa flödes- och paketeringstester. Beslutet här är **labbunderlag för granskning**, inte godkänd produktion.

## Tillägg: beständig labbdrift och stängd driftgrund, 2026-10-19

- **Xerial SQLite JDBC 3.53.4.0**, release 2026-08-26, commit
  `cab7981c19ce04d691f0675f0b2586afc2bbf803` i
  [xerial/sqlite-jdbc](https://github.com/xerial/sqlite-jdbc/tree/cab7981c19ce04d691f0675f0b2586afc2bbf803).
  Projektet var inte arkiverat, senast pushat 2026-10-15. Apache-2.0 samt
  inbäddad Zentus-kod under BSD-2-Clause; den faktiska JAR-filens
  [LICENSE.zentus](prototype/licenses/sqlite-jdbc-LICENSE.zentus) bevaras här.
  SQLite-motorn är 3.53.4 och har [public domain-dedikation](https://sqlite.org/copyright.html).
  Ingen fork eller modifiering av biblioteket. Används enbart i syntetisk labb.
  Den publicerade advisoryn [CVE-2023-32697](https://github.com/xerial/sqlite-jdbc/security/advisories/GHSA-6phf-6h5g-97j2)
  granskades: rättad i 3.41.2.2, äldre än vår låsta version. JDBC-adressen
  konstrueras enbart från en lokal privat katalog; ingen nätverksklient väljer den.
- Den uppdaterade Maven-grafen är **171 JAR-artefakter**, alla låsta med SHA-256.
  Uppdaterad SBOM och OSV-kontroll finns i `prototype/evidence/`; kontrollen
  gav **0 träffar** 2026-10-19. Detta ersätter det tidigare antalet 170 ovan.
- **Eclipse Temurin 21.0.12.1+1**, officiella JDK/JRE-containrar på Ubuntu Noble,
  för `ops/`. Fulla image-index-digests finns i Dockerfile; de hämtades från
  Docker Hubs officiella `library/eclipse-temurin`-register 2026-10-19.
  [Official-images-manifestet](https://github.com/docker-library/official-images/blob/master/library/eclipse-temurin)
  kopplade båda taggarna till Dockerfile-källan
  [adoptium/containers@511f9356dc4d50932a0a5f8cfb0f87ed1aef4f07](https://github.com/adoptium/containers/tree/511f9356dc4d50932a0a5f8cfb0f87ed1aef4f07).
  Dockerfile-källan är Apache-2.0. JDK/JRE har GPL-2.0 med Classpath Exception
  och separata tredjepartslicenser i `legal/`, vilket bevaras i basimagen.
  Ubuntu-paket har egna licenser i `/usr/share/doc`; deras kompletta
  sårbarhets-/licensinventering är **inte** täckt av Maven-SBOM/OSV-kontrollen.
  Ingen publik binär release eller generell distributionslicens för egen kod
  har utfärdats. Ägarens projektlicensbeslut kvarstår.

Den stängda driftimagen byggs enbart från `ops/src/SealedEnvironment.java`.
Sweden Connect, SQLite, prototypens JAR och testnycklar ingår inte. Blueprinten
låser region och stänger automatiska releaser. CI har endast `contents: read`
och inga Render-nycklar eller produktionshemligheter.

## Tillägg: WebAuthn och webbklient, 2026-10-19

- **Yubico Java WebAuthn Server 2.10.1** (`webauthn-server-core` och
  `yubico-util`), release 2026-10-09, commit
  `6c1b6cc19beae08cd6a310a40db1acee3673b98d` i
  [Yubico/java-webauthn-server](https://github.com/Yubico/java-webauthn-server/tree/6c1b6cc19beae08cd6a310a40db1acee3673b98d).
  Oförändrade Maven-artefakter; ingen kopierad validator eller egen fork.
  `COPYING`, `SECURITY.md`, releaseanteckningar och relevanta API-källfiler
  lästa. BSD-2-Clause samt Google-kod under BSD-3-Clause; hela
  [COPYING](prototype/licenses/Yubico-COPYING.txt) bevaras. GitHub-repot var
  inte arkiverat, senast pushat 2026-10-13, och listan över publicerade
  repository-advisories var tom. Detta är underhållsindikatorer, ingen SLA.
- Yubicos API sköter WebAuthn-valideringen och JCA kryptografin. Labben
  tillåter ES256/RS256, kräver användarverifiering och använder attestering
  `none`. Ingen attesteringsmodul, FIDO-metadatahämtare eller molntjänst
  införs. En kompletterande lokal policy nekar `crossOrigin=true` och
  förekomst av `topOrigin`; dessa Level 3-fält kontrolleras inte av Yubicos
  `CollectedClientData` vid den låsta revisionen. Jackson används för
  fältläsning, inklusive avvisning av duplicerade fält. Detta är ingen ny
  signatur- eller protokollvalidator.
- **Guava 33.7.2-jre** (Apache-2.0) låses uttryckligen i dependency management
  för att förena Yubicos och Sweden Connects beroendegrafer. Ingen
  dependency-convergence-kontroll har stängts av. Även `failureaccess` 1.0.3
  och `j2objc-annotations` 3.1 uppdateras. Jackson CBOR/JDK8 2.21.7 är
  Apache-2.0 och följer den redan låsta Jackson-BOM:en.
- **CBOR 4.5.6** låses uttryckligen i dependency management, tillsammans med
  transitiva Numbers **1.8.2** och DataUtilities **1.1.0**, utan lokala ändringar.
  CBOR:s POM och upstream `LICENSE.md` anger Unlicense. Numbers
  och DataUtilities anger public domain/CC0 i de publicerade versionernas
  käll-JAR:er. CBOR:s och Numbers repositoryn var inte arkiverade, med
  senaste push 2026-06-04 respektive 2026-04-20. DataUtilities var inte
  arkiverat, senast pushat 2025-08-11; den äldre publicerade versionens
  källhuvud användes för licenskontrollen. Yubicos parent anger intervallet
  `[4.5.1,5)`, som Maven först upplöste till **5.0.0-alpha2**. Den
  förhandsversionen har ersatts med den senaste publicerade stabila
  4.5-versionen vid kontrollen, **4.5.6**, inom upstreams intervall. Guava
  och CBOR väljs nu exakt i vår POM; övriga intervall styrs av låsta BOM:er.
  Ingen matchande Git-tagg hittades för CBOR 4.5.6; Maven-artefaktens
  checksumma och publicerade käll-JAR används för versionsspårningen.
  Käll-JAR:ens SHA-256 är
  `05384f450f77728579caba69c79a9c7752826356e14610927b11e75de05b652e`.
- Den upplösta grafen är nu **177 JAR-artefakter**. Alla är versions-/SHA-256-låsta;
  uppdaterad CycloneDX-SBOM och OSV-resultat finns i `prototype/evidence/`.
  OSV gav **0 publicerade fynd** vid kontrollen 2026-10-19. Det är ingen
  garanti om frånvaro av sårbarheter, och omfattar inte webbläsaren, JDK,
  OS eller byggpluginernas hela graf.
- HTML, CSS, JavaScript, service worker, SVG-ikon och applikationsintegration
  är projektspecifik kod. Inga CDN-skript, frontendramverk, externa typsnitt,
  analys-SDK:er eller appbutiks-SDK:er införs. Playwright används bara i test.

Uppdateringsägare föreslås fortsatt vara Jtensetti, att bekräfta vid granskning.
Egen projektlicens och oberoende granskning återstår. Den nya koden publiceras
som källkod för granskning i en separat PR, utan produktionsdriftsättning.

## Kandidater och kontrollstatus

| Kandidat | Nu känd licensuppgift | Kvar före eventuell införsel |
|---|---|---|
| Sweden Connect Spring Authentication Server, G01 | Apache-2.0 enligt README. | Läs LICENSE/NOTICE, lås release, granska beroenden och distribution. |
| Äldre SAML Identity Provider, G02 | Apache-2.0 enligt README; ersatt projekt. | Ingen nyutveckling planerad här. Vid eventuell referenskopiering krävs separat filgranskning. |
| Credentials Support, G03 | Apache-2.0 enligt README. | Fullständig fil-/beroendegranskning och ansvar för uppdateringar. |
| SignService, G04 | Apache-2.0 enligt README. | Fullständig licens- och beroendegranskning samt avgränsad produktanvändning. |
| Sweden Connect Test Client, G05 | Apache-2.0 enligt README; uttalat testverktyg. | Verifiera licens och begränsa till egen/godkänd testmiljö. |
| Diggs Open Source Project Template, G06 | Lästa README-filen är CC0-1.0. | Kontrollera varje mallfil, SPDX/REUSE och eventuella separata villkor. |
| REST API-profil Lint Processor, G07 | README CC0-1.0; kod EUPL-1.2 enligt projektuppgifter. | Separera text, verktyg och produktkod; pröva licenskonsekvenser för faktisk användning. |
| Wallet Account, G08 | EUPL-1.2 enligt repositorysidan. | Läs licensfil och aktuell revision; ingen implementation vald. |
| Ena-samverkansplattform, G09 | Inte verifierad för kopiering. | Länka som referens; kopiera inte förrän villkor är klarlagda. |

Exakta repositorylänkar och lästa dokumentversioner finns i `docs/SOURCES.md`. En README-etikett är en första uppgift, inte en fullständig licensrevision.

## Införselkontroll

Före kopiering, paketering, inlänkning eller distribution ska ändringen innehålla:

```text
Ursprunglig URL och fullständig revision:
Filer/paket som faktiskt används:
Kod, dokumentation, bild eller verktyg:
Licens och filnivåundantag:
Nödvändig attribution/NOTICE:
Lokala ändringar:
Transitiva komponenter:
Distribution/drift och licensbedömning:
Granskare och uppdateringsägare:
```

Behåll ursprunglig attribution där licensen kräver det. Skriv inte om copyright-rader så att projektet ser ut att ha skapat någon annans kod. Använd inte myndighetsnamn, kvalitetsmärken eller logotyper som ett påstående om rekommendation eller godkännande.

## Projektets egen licens

**Projektlicensen är ännu inte beslutad eller tillagd.** Ambitionen är öppen källkod, men denna dokumentationsleverans har inte fattat ett fullständigt licensbeslut för framtida kod och bidrag.

Apache-2.0 kan utredas för egen kod med hänsyn till de primära kandidaterna; dokumentationens licens och hantering av eventuella EUPL-komponenter behöver bedömas separat. Detta är ett förslag, inte en juridisk kompatibilitetsgaranti eller en redan utfärdad licens.

Före externa kodbidrag eller första distribution ska ägaren besluta licens, lägga till rätt LICENSE-/NOTICE-filer och dokumentera bidragsvillkor. Skapa inga licens-/REUSE-badges som antyder att detta redan är klart.

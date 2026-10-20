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

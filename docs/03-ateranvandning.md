# Återanvändning: Sweden Connect, Digg och Ena

Kontrollerat 2026-10-19. Käll-ID och lästa README-versioner finns i [SOURCES.md](SOURCES.md). **Tabellen nedan är den ursprungliga dokumentationsinventeringen.** Den efterföljande G1-implementationens faktiska val, kompilerade versioner och lästa licenser finns i [THIRD_PARTY.md](../THIRD_PARTY.md) och [verifieringsrapporten](../prototype/evidence/verification.md). Ingen komponent är godkänd för produktion genom denna labb.

## 1. Rekommenderad riktning

Utred Sweden Connects aktuella **Spring Authentication Server** som protokollgrund. Lägg vår egen identitetslivscykel och verkliga autentisering bakom dess integrationspunkter. Utred separat nyckelhantering och underskrift. Börja inte med att skriva en egen SAML-, OIDC- eller kryptografisk implementation.

Detta är ett föreslaget arkitekturbeslut, inte ett konstaterande att komponenterna redan uppfyller våra samlade produktkrav. Versionsval återstår.

## 2. Inventering

| Källa / repository | Vad den lästa dokumentationen visar | Licensuppgift och kontrollnivå | Föreslagen användning |
|---|---|---|---|
| G01: `swedenconnect/spring-authentication-server` | Gemensam autentiseringsgrund med SAML och OIDC. Referensservern använder simulerad autentisering. | README anger Apache-2.0. Fullständiga licensfiler, release och beroendekedja återstår. | **Primär kandidat** för federationslagret; ersätt inte verklig utgivning med referensens simulering. |
| G02: `swedenconnect/saml-identity-provider` | README anger uttryckligen att G01 har ersatt projektet och avråder från nyutveckling här. | README anger Apache-2.0. | **Historisk referens**, inte grund för ny produkt. |
| G03: `swedenconnect/credentials-support` | PKI-abstraktioner, PKCS#11/HSM samt integration med andra Java-bibliotek. | README anger Apache-2.0; relevanta avsnitt lästa. | Kandidat för serverns nyckelhantering. Biblioteket är inte en HSM och löser inte nyckelceremonier eller organisation. |
| G04: `swedenconnect/signservice` | Komponenter för svensk underskriftstjänst, bland annat autentisering, nycklar, protokoll och revisionslogg. | README anger Apache-2.0. | Separat underskriftsutredning; verifiera den fullständiga beviskedjan innan produktbeslut. |
| G05: `swedenconnect/sweden-connect-test-client` | SAML SP/OIDC RP för test. Kan avsiktligt skapa felaktiga protokollmeddelanden. | README anger Apache-2.0 och tydliga testverktygsbegränsningar. | Egen isolerad testmotpart för positiva och negativa fall. Inte kundprodukt eller produktionskomponent. |
| G06: `diggsweden/open-source-project-template` | Mallar för projektstyrning, säkerhet, bidrag, licenshantering och arbetsflöden. | Lästa README-filen är märkt CC0-1.0; alla mallfiler får inte antas ha samma licens. | Inspiration och senare selektiv återanvändning efter kontroll av varje fil. |
| G07: `diggsweden/rest-api-profil-lint-processor` | Validerar OpenAPI mot svenska REST API-profilen med Spectral. | README är CC0-1.0; projektets kodlicens anges som EUPL-1.2. | Möjligt lokalt utvecklingsverktyg för egna administrations-API:er; inte ett säkerhetsintyg. |
| G08: `diggsweden/wallet-account` | Java-tjänst för plånbokskonton och API-first-utveckling. | Repositorysidan anger EUPL-1.2; README-avsnitt lästa, licensfil och kod ej fullgranskade. | Senare referens för kontomodell. Ingen grund för att påstå att en plånbokstjänst är en svensk e-id-utfärdare. |
| G09: `diggsweden/ena-samverkansplattform-os` | Arbetsyta för utforskande samverkan om öppen programvara; README beskriver `no-code` och arbetsdokument. | Licens för eventuell kopiering är inte verifierad. | Läs som bakgrund till samverkan, inte som installerbar e-id-komponent. |

## 3. Vad Ena kan och inte kan ge oss

Ena-materialet i G09 handlar här om samverkan och öppen programvara. Det ska inte förväxlas med en sammanhängande e-id-produkt. Vi kan använda dess erfarenheter för förvaltning och samarbete, men den konkreta tekniska återanvändningen i denna inventering finns framför allt hos Sweden Connect.

Vår praktiska fördel är därför inte att ett färdigt BankID-alternativ ligger och väntar. Fördelen är att protokoll, nyckelgränssnitt, underskriftskomponenter och testmotparter inte behöver uppfinnas från grunden.

## 4. Första tekniska undersökningen

### Steg A: verifiera upstream innan beroendet väljs

För varje kandidat dokumenteras:

```text
repository:
roll i vår produkt:
underhållsstatus kontrollerad:
vald release/tag:
fullständig commit-SHA för vald revision:
artefaktkoordinat och checksumma:
licensfiler och eventuella NOTICE-filer:
transitiva beroenden och licenser:
publicerade säkerhetsmeddelanden kontrollerade:
JDK-/ramverkskrav:
lokalt bygg- och testresultat:
ansvarig för framtida uppdateringar:
beslut och kvarvarande risker:
```

En README-blob-SHA i källregistret är inte en versionslåsning av biblioteket. En etikett `latest`, en grön badge eller frånvaro av kända sårbarheter är heller inte ett godkännande.

### Steg B: bygg en sluten protokoll-labb

Använd en vald, granskad version av G01 och en egen instans av G05. Börja med simulerade, tydligt märkta testidentiteter och separata certifikat. Visa endast protokollinteroperabilitet. Registrera resultat för lyckad inloggning, fel mottagare, fel nyckel, gammal begäran, återspelning och avbrutet flöde.

SAML är ett föreslaget första avgränsat testspår. Det innebär inte att OIDC är otillgängligt: G01 stödjer båda och T01 listar separata profiler. Fastställ med Digg vilket konkret utförande som accepteras för vår anslutning och ersättningsmodell.

### Steg C: separera produktfunktioner från demofunktioner

Inventera alla exempelkonton, simulerade autentiseringssteg, självsignerade testankare, felsökningsutskrifter och inbyggda testnycklar. Dokumentera vilka som aldrig får följa med till produktion. Att demon fungerar ger inte status `IMPLEMENTED` för verklig utgivning.

### Steg D: utred underskrifter och HSM var för sig

Testa G03 mot en isolerad utvecklingsmiljö först. SoftHSM kan användas för gränssnittstester, inte som påstående om produktionsmässigt nyckelskydd. Utred G04 med syntetiska dokument och en explicit modell för användaravsikt, signerat innehåll och validering.

## 5. Licens- och leveranskedjestrategi

Föreslagen princip: använd officiella versionslåsta bibliotek framför onödiga kopior. Forka först när en dokumenterad brist motiverar underhållsansvaret. Behåll obligatorisk attribution och licensinformation när kod faktiskt förs in.

EUPL-licensierade kandidater ska bedömas separat från Apache-komponenter. Ett fristående lintverktyg och inlänkad produktkod är olika tekniska situationer, men licenskonsekvenser ska prövas – inte gissas. Även mallrepo kan ha olika licenser för kod, text och bilder.

Granska importerade CI-arbetsflöden lika noga som källkod: behörigheter, hemligheter, nätverksåtkomst, externa actions och versionslåsning. Kopiera aldrig ett upstream-workflow med produktionsbehörighet bara för att avsändaren är en myndighet.

Projektets egna agent-skills är nyskrivna instruktioner med källhänvisningar. De är inte kopierade från Digg och innebär inte att Digg har granskat arbetssättet. Se [THIRD_PARTY.md](../THIRD_PARTY.md).

## 6. Återstående kunskapsluckor

Ingen release är ännu vald. Ingen kompabilitetsmatris, SBOM, fullständig licenskontroll, sårbarhetsrevision eller prestandamätning är genomförd. Inga driftsgarantier från upstream har verifierats. Dessa luckor är uppgifter i genomförandeplanen, inte små detaljer som kan hoppas över när prototypen börjar fungera.

# Tekniska krav och verifieringsluckor

SIG-01/02: test-PDF:en har ett [synligt underskriftskvitto](pdf-underskrift.md)
i det riktiga signaturfältet. Kvittot omfattas av samma signerade revision.
Rendering, ändrat kvitto och bildkopiering provas separat från certifikattillit.
Testutfärdaren är fortsatt ej betrodd och formell kravstatus ändras inte.

Krav-ID:n behålls för spårbarhet till tester och tidigare granskningar.
Tabellen beskriver teknisk täckning; formell kravstatus är fortsatt `OPEN`.
Källhänvisningar avser inventeringen och daterade omkontroller i [SOURCES.md](SOURCES.md).
Aktuell originaltext behöver kontrolleras inför en formell bedömning.

[iPhone-underlaget](iphone-sakerhet.md) delar upp appens tekniska kontroller,
installationsbevis och återstående fysiska/organisatoriska bevis. APP-01–08
är delpunkter; de ersätter inte de överordnade kravens formella status.

## Identitet och nycklar

| ID | Område / källa | Implementation och prov | Kvarstående kontroll |
|---|---|---|---|
| ID-01 | Utgivningspolicy, D08 K5.1–K5.3 | Privat registrering med separat operatörsaktivering; valbart [TestFlight-testläge](testflight-beta.md) med automatisk testaktivering utan e-post. Ingen formell utgivningsstatus höjs. | Fastställd utgivningspolicy och användarvillkor. |
| ID-02 | Identitets-/registerkontroll, D08 K5.7–K5.9 | Autentiserade uppgifter ur passets DG1. SQLite-adapterkontraktet vidarebefordrar ett befintligt personnummer utan sekelgissning och nekar avvikande registeridentitet även vid läsning av äldre bindningar. | Verklig registeradapter/åtkomst, avvikelser och skyddade identiteter. Testadapter är inte registerbevis. |
| ID-03/04 | Utgivningsmetod, D08 K5.10–K5.13; D09 | Passbaserat appflöde. | Bedömning av metoden. Nyutgivning via befintlig e-id saknas. |
| ID-05 | Fjärrkontroll, D08 K5.13; D09 | Serverstyrd JMRTD PACE/CA med signerad DG14 och färsk MAC-kontrollerad läsning. `ChipAuthenticationTest` provar även kopierade data utan privat chipnyckel, replay och ändrad MAC. Lokal Vision-guide provas i `CaptureGuideTests`. Biometriarbetaren återanvänder detektioner och passets featurevektor inom samma försök; regressionstest jämför med parvis inferens. SQLite och PostgreSQL debiterar högst fem analyser per verifierad handling och rullande 24 timmar atomärt före inferens, även vid modellfel. Parallella instanser, omstart, saknad HMAC-nyckel och COPY-återläsning provas. Stödd återläsning spärrar automatiskt ny registrering och analys i 24 timmar. | Sammanhängande fysisk provning, passets spärrstatus hos utgivaren, drift av certifikatspärr, kalibrerad biometri/PAD samt oberoende injektions-/reläprov. Kameraguiden är inget verifierat liveness-bevis. |
| ID-06 | Innehavarregister, D08 K5.14 | `test_identity` och `test_cluster`: krypterad personprofil, dokumentreferens, enhetsbindning och atomisk ersättning. | Registeravstämning och oberoende utgivningskontroll. |
| ID-07 | Faktorer/nyckelskydd, D08 K6.1–K6.2 | Secure Enclave/Keychain i iOS-koden; CryptoKit/server-interoperabilitet testad. | Fysiskt enhetstest och verifierad hårdvarubindning på servern. WebAuthn-labben använder attestering `none`. |
| ID-08 | Återställning, D08 K6.3 | Nyregistrering för samma pass ersätter nyckeln; spärrad nyckel kan inte aktiveras igen. iPhone behåller möjlighet att fortsätta avbruten registrering efter statusfel och kräver bekräftad spärr före lokal nyckelborttagning, även vid utgång. Lagringsfel och UI-flödet provas med syntetiska data. Stödd återläsning spärrar gamla nycklar, annullerar väntande anrop och pausar registrering i 24 timmar. SQLite-backup och återläsning bevarar kravet på oberoende spärr; driftåterläsning kräver detta även för äldre kopior. | Förlorad telefon utan självbetjäning, nytt pass, operativ kontroll av aktuellt spärrankare och återställningsövning. |
| ID-09 | Bindning/giltighet, D08 K6.4–K6.7 | Signerade engångsoperationer, utgång och samtidiga beslut testas i Python och XCTest. | Oberoende avisering och komplett utgivningsprocess. |
| ID-10 | Spärr, D03 §8.6 | App, operatörs-CLI och separat spärrtjänst i den publika betan; aktuell status kontrolleras vid godkännande, konsumtion och skyddad SP-läsning. | Sammanhängande telefonprov, schemalagd återstart, bemanning och oberoende granskning. |
| ID-11 | Bevarande/avveckling, D08 K2.7–K2.8, K5.5 | Råunderlag lagras inte; PostgreSQL-läget har begränsad gallring, Transit-omkryptering och ett bevarandegolv på 1827 dagar för händelser och aktiveringsbeslut. | Fastställda lagringstider, avveckling och gallring av administrativa loggar/personlänkar. |

## Protokoll och säkerhet

| ID | Område / källa | Implementation och prov | Kvarstående kontroll |
|---|---|---|---|
| SEC-01 | Kanaler, D08 K4.2; T01–T03 | HTTPS, fasta motparter, signaturer, CSRF/Origin och sessionsbindning. Negativa Java-/browserprov. | Extern interoperabilitet och driftgränser. |
| SEC-02 | Servernycklar, D08 K4.3 | Lokala testnycklar samt separat OpenBao Transit med profilrotation och avgränsade tjänstekonton. | HSM, operativ flerpersonskontroll, indexnyckelbyte och övad nyckelåterställning. |
| SEC-03 | Beroenden, D08 K4.4 | Versions-/hashlås, SBOM, daglig OSV-kontroll och samma kontroll i PR-grinden. Ofullständiga svar, fel och oavslutad paginering nekar kontrollen. Filelock och setuptools är uppdaterade med licensunderlag. Dependabot föreslår uppdateringar. Separat GitHub-byggmiljö exporterar provat serverpaket med revisions- och hashkontroll samt provad återinläsning; se [leveransflödet](../deployment/build/README.md). | Ansvarig larmmottagare, hela byggkedjan/OS, oberoende byggattest, administrativ rollseparation och oberoende revision. |
| GOV-07 | Befogenheter, D08 K3.4 | PostgreSQL-funktioner kräver två olika operatörsinloggningar; tjänstekonton saknar aktiveringsrätt. Schemainstallation och återställning stöder administratör utan superuser. Negativa tester nekar tjänste- och operatörskonton ägarmedlemskap och rollbyte. | Verklig personseparation, kontroll av ägar-/administratörsåtkomst och oberoende granskning. |
| FED-01 | Federationsprofil, D03 §8.4; T01–T03 | Sweden Connect SAML med lokal metadata och egen autentiseringskontext. | Full profilmappning och accepterad extern anslutning. |
| FED-02 | Mottagare/avsikt, D03 §§8.2–8.3 | Appen visar och signerar tjänst, syfte och kod. `test_identity`, XCTest och federationsprovet testar byte av bindningar och replay. | Närhets-/reläskydd och externa motparter. |
| FED-05 | GrandID som integrationsmål; projektkrav, GID-01–03 | [Anslutningsprofil och acceptanskriterier](grandid-integration.md) dokumenterade. Befintlig SAML/OIDC-kod använder fasta pilotmotparter. | Bekräftad leverantörsprofil, extern motpartskonfiguration, minimerade verifierade attribut, mottagarbindning och prov mot GrandID. Status OPEN. |
| SIG-01/02 | Dokumentunderskrift, T01, T05–T08 | Syntetisk WebAuthn-labb visar exakt text och kräver separat underskriftsavsikt. CMS-signering och certifikatbindning provas med Bouncy Castle och OpenSSL. SignMessage, SAD, separat underskriftsåtgärd och PAdES-testkedja körs mot både SQLite och PostgreSQL. Kodnivå, textbindning, avbrott, replay och spärr provas. PostgreSQL nekar tjänsten att ändra fasta bindningar eller direkt läsa/återställa PIN-verifierare. | Vald produktionsprofil, verklig identitet, CA/HSM, betrodd tid, långtidsbevis och extern granskning. Se [prövningsunderlaget](provningsunderlag.md). |
| TEST-01 | Testmiljö, D03 §8.9 | Genererade pass/nycklar, lokala motparter och automatiserad CI. | Extern acceptanstestmiljö och fysiska enheter. |

## Drift och rapportering

| ID | Implementation | Återstående arbete |
|---|---|---|
| OPS-01/02 | Gunicorn/TLS med hälsokontroller, kapacitetsgränser, isolerad bildanalys, resursbegränsad container och lokala belastningsprov. PostgreSQL-läge med flera TLS-workers, instansbortfallsprov och separata mät-/larmfunktioner. Separat stängd Render-container. | Tillgänglighets-/svarstidsmål enligt D03 §8.5.1 är inte verifierade. Redundans och mätning på avsedd produktionsmiljö saknas. |
| OPS-03/04/05 | Privat sårbarhetsrapportering är aktiverad via GitHub; se SECURITY.md. Ingen verifierad operativ support-, incident- eller ändringsprocess. | Bemannad mottagning, incidentövning och kompatibel uppgradering enligt D03 §§8.7, 8.12–8.14. |
| OPS-06 | Begränsade sessioner, meddelandestorlekar och engångsvärden. | Driftanpassad missbruksdetektion och granskad utredningsprocess. |
| OPS-09 | [Förberedd konfiguration](../deployment/security/README.md) för managementlogg, begränsad EBS-backup och larm utan nya beräkningsjobb. Schema- och negativa säkerhetsprov; backup är avstängd som standard. | Driftsättning, budgetbevakning, bekräftad larmmottagare, faktisk loggleverans, kontrollerad kopia av varje volym och återställningsövning. Konfiguration är inte bevis på verksam kontroll. |
| OPS-08 | Privat, skrivskyddad export av befintliga registerjournaler i SQLite och PostgreSQL. Sammanhängande ögonblicksbild, fasta kolumner, minimerade fält och offlineverifiering mot separat förankrad SHA-256. Samtidighets- och negativa fil-/behörighetsprov. Klient och mall för COMPLIANCE-låst S3 i separat konto, mottagarkvittens under egen roll och senare läsbarhetsprov; offline- och AWS-kontraktsprov. Se [arkivexport](arkivexport.md). | Fullständiga utgivningsbevis, verklig oberoende förvaltare, driftsättning och bevittnad mottagning, godkänd bevarandeplan, schemaläggning och operativa läsbarhetsprov. Uttaget ändrar ingen gallringsrutin. |
| OPS-07 | Java-/SQLite-återläsning samt PostgreSQL-registerbackup, sluten återställning och spärr av alla gamla nycklar. CI provar återläst OpenBao-snapshot, gamla/saknade profilnycklar, Raft-ledarbortfall och nyregistrering efter återläsning. En beständig 24-timmarsspärr skyddar försöksbudgeten; tjänster kan inte nollställa eller skugga den. | Övning på vald driftplattform, extern backupförvaring, återställningstider och operativ nyckelceremoni. |
| FIN-01/02/03/04 | `OfflineReportTest` provar klassificering och deduplicering i Java-labben. Ersättningsgrundande antal är alltid noll och ingen rapport skickas. | Produktionsrapportering är inte implementerad; format, avtal, kvittenser och rättelser behöver verifieras mot D03–D05. |

## Projektregler

| ID | Regel |
|---|---|
| INT-01 | Ingen generativ modell fattar identitets-, autentiserings- eller underskriftsbeslut. Biometriska modellvärden är underlag i ett separat verifieringsflöde. |
| INT-02 | CI och publika exempel använder genererade identiteter och testnycklar. Verkliga handlingar hålls utanför repot och används bara i uttryckligen vald privat testmiljö. |
| INT-03 | Testtrafik får inte ge ersättningsanspråk. |
| INT-04/05 | Säkerhetskritisk produktionsrelease kräver oberoende granskning och behörigt mänskligt beslut. |
| INT-06 | Tredjepartsmaterial kräver dokumenterad version, licens, attribution och uppdateringsansvar. |

Verifiering redovisas med revision, kommando, resultat och begränsning i
[testöversikten](testning.md) eller PR:n. Formell acceptans kräver beslutsfattare,
datum och omfattning. Känsliga underlag lagras utanför det publika repot.

### Privat telefonprov: inmatning och diagnos

ID-05/INT-02: Kamerans TD3-text används endast för att fylla i chipets
åtkomstuppgifter, efter kontrollsiffror och datumvalidering. Den ersätter
inte identitetskontroll. OCR-bilder lagras inte. Fysisk kameraläsning återstår.
OPS-01/02: Fast stegkod vid avvisad passkontroll möjliggör felsökning utan
passuppgifter eller godtycklig undantagstext i loggen. Formell status är oförändrad.

ID-05: Certifikatinläsning och PKIX använder den låsta Bouncy Castle-providern
för stöd för explicita EC-parametrar. Ett genererat Brainpool-prov täcker
betrodd kedja, obetrodd kedja och ändrad datagrupp. Detta ändrar inte
kraven på tillitsankare eller den kvarstående kontrollen av certifikatspärr.

ID-05: Registrering av en verifierad identitet kräver nu ett aktuellt
`CHECKED_CRL`-resultat. Status och sista giltighetstid följer med från Java
till registreringen; utgång under fångst eller lagring avvisas och rullas
tillbaka. Även spärrat CSCA-ankare och listor med otillåten omfattning nekas.
Syntetiska negativa prov täcker båda databaslägena. Driftens provisionering,
färskhållning, skydd vid helsystems-återställning och passets egen spärrstatus
återstår; detta är inget tillitsgodkännande.

ID-05/OPS-07: `crl_maintenance.py` verifierar kandidat och installerad CRL
med samma Java-bibliotek som passkontrollen. Äldre version, ändrat innehåll
med återanvänt nummer, förlorad utfärdartäckning och ogiltig signatur nekas.
Filbyte är låst och atomärt, med negativa felprov och utgångsvarning.
Verktyget hämtar inget och installerar ingen schemaläggning. Kontrollen
ersätter inte oberoende aktuell information efter återläsning av hela värden.

ID-05: Aktuell riktningsguide, fångsttrösklar och lokalt kameraprov beskrivs i
[iPhone-dokumentationen](../ios/README.md#fotografering). Guiden är inte ett liveness-bevis.

ID-05/INT-02: Biometriarbetaren rapporterar endast fasta steg och tillåtna orsakskoder. Huvudprocessen validerar koderna igen och skiljer modell-/arbetarfel från avvisad bildanalys. Inga bilder, poäng eller godtyckliga undantagstexter loggas. Diagnostik ändrar inte experimentella gränser eller formell status.

ID-05: YuNet-detektor använder två helbildsskalor för högupplösta kamerabilder. Fleransiktsfall och motstridiga detektioner avvisas; originalbild används för ansiktsjämförelse och PAD. Bildfel returneras som fast kod med bildnummer 1–3, utan råpoäng eller bilddata. Testar skalåterföring och negativa fall; ingen ändrad formell status.

### Felåterkoppling för legitimering

ID-09, ID-10 och FED-02: appen skiljer statushämtning från godkännande,
nekande och spärr. Testsidan skiljer känt nekande, avbrott och utgången
begäran från ett okänt anslutnings-/kontrollfel. Okänd orsak presenteras inte
som bekräftad spärr eller bekräftat nekande. Avslutade QR-begäranden döljs
och en länk erbjuder en ny inloggning. Status får återhämtas automatiskt;
godkännanden skickas aldrig om automatiskt. Formell kravstatus ändras inte.

ID-09/TEST-01: appens nekandeval ligger utanför det rullbara innehållet i
alla begäransvarianter, inklusive underskrift och säkerhetskod. UI-prov
täcker synlighet utan rullning, stor text, öppet tangentbord och utgång.
Ett nekande kräver fortfarande ett separat signerat beslut; att stänga
vyn är inte ett serverbekräftat avbrott.

### OIDC och tillitsnivåer i privat beta

FED-03 (T03): Authorization Code med S256 PKCE, `state`, `nonce`,
`private_key_jwt` och fast motpart/redirect. Samma signerade enhetsgodkännande
som SAML. Servern får bara intyga den privata autentiseringskontexten;
begärd nivå får inte kopieras till utfärdat resultat. Tekniska tester är
inte fullständig Sweden Connect-profilöverensstämmelse eller anslutning.

FED-04 (D08, D09, T04): Tillitsnivå är en policy för hela utfärdande- och
livscykelprocessen. Betan utfärdar inte LoA 1–4. Diggs tillitsramverk omfattar
nivå 2–4; att identifierarregistret även innehåller LoA1 innebär inget godkännande.
Stöd för högre nivåer kräver styrkt identitetskontroll, nyckelskydd,
återställning, spärr, organisation, drift och tillämplig granskning.
LoA4 förutsätter en särskild utfärdande- och autentiseringslösning;
nuvarande pass-/kameraflöde är inte tillräckligt bevis.

GOV-08 (D08, D09, D14): Luckor kvarstår för dokumenterad tillitspolicy,
behörighetsseparation, revision, personuppgiftsbehandling och gallring,
incidenthantering, kontinuerligt spärrstöd, ekonomiska/organisatoriska krav
samt avtal och formellt godkännande. Manuell aktivering kvarstår men utgör
inte ensam bevis för att kraven är uppfyllda.

INT-03 (EU01–EU03): SDG:s gränsöverskridande förfaranden och eIDAS-erkännande
är skilda från stöd för att läsa andra länders pass. Återanvändning av bevis
via OOTS är ytterligare en integration. Tillämpningsbedömning, konsoliderad
EU-rätt och fullständig profilmappning återstår. Ingen formell status höjs.


### Registerbindning och ersättning i SQLite-piloten

ID-02/ID-08–10: `registry_binding.py` separerar registerbevis från passprofil,
nyckel och session. Svar binds till engångsfråga, credential, profilversion och
dokumentreferens; skyddade uppgifter, tvetydighet, konflikt, utgång och
återspelning stoppas. En registerkontrollerad ersättning av pass bevarar
personkopplingen men byter profilversion och spärrar äldre nycklar atomiskt.
Ersatta dokument kan inte användas för nyregistrering. Återläsning spärrar
alla nycklar och kasserar registerbindningar.

`test_registry_binding` använder en syntetisk adapter och provar även
samtidighet, rollback, sessionsspärr och schemaövergång från befintlig pilot.
Ingen verklig registeradapter, automatisk aktivering, ny HTTP-endpoint eller
nationella identitetsattribut i federation införs. PostgreSQL-stöd och
operativ återställning återstår. Separat spärr i SQLite-betan beskrivs i
[avisering och spärr](avisering-och-sparr.md). Formell status: OPEN.
Se [flöde, befogenheter och begränsningar](registerbindning.md).


## Personnummer från signerade passuppgifter

D08 K5.7 kräver nationell identitetsbeteckning; K5.8 kräver jämförelse mot
officiellt register. D09 accepterar även registeruppgifter via mellanhand.
K5.9 medger alternativa kontroller för skyddade uppgifter. D09 K5.14
rekommenderar uppdatering varje helgfri vardag. Passbaserad fjärridentifiering
enligt K5.13 ersätter inte registerkontrollen. Ingen särskild leverantör
föreskrivs. Uppgifterna på chipet och registeruppgifternas aktualitet är två
skilda bevis. Ingen anslutning beställs med stöd av denna inventering.

Uppdaterad implementation: efter signatur-, certifikatkedje- och hashkontroll
läser servern DG1:s personal-number-fält för utfärdarland SWE. Tomt fält ger
ingen identitetsbeteckning. 10 eller 12 ASCII-siffror med giltigt datum och
Luhn-kontroll bevaras exakt; sekel gissas inte. Dag över 60 behandlas som
samordningsnummer vid datumkontrollen. Andra länders optional-data tolkas inte
som svenska identitetsbeteckningar. Felaktigt svenskt fält avvisas.

`passportPersonalNumber` lagras i den krypterade passprofilen och visas i
ägarens app med upplysning om att folkbokföringskontroll saknas. Fältet används
inte som registerbevis eller för automatisk sammanfogning av personposter.
Federationsgränsen lämnar endast de befintliga visningsfälten namn,
MRZ-födelsedatum och porträtt; personnumret lämnas inte genom SAML/OIDC.
`PassportVerifierTest`, `test_identity` och `WalletSecurityTests` täcker
signerade testdata, manipulation, format, äldre profiler och attributgränsen.

Fältets förekomst och visning har bekräftats vid ett privat telefonprov.
Detta styrker inte uppgifternas aktualitet i ett officiellt register. ID-02 förblir OPEN eftersom
registerkontroll och hantering av skyddade uppgifter återstår.


## Automatisk anslutning i sluten TestFlight-beta

Nya appinstallationer använder den fasta publika HTTPS-adressen utan VPN
eller inbyggd kopplingshemlighet. Sparade serverbindningar bevaras.
`publicEnrollment` är avstängd som standard och får endast aktiveras för
betans kanoniska adress med produktions-App Attest. Den öppnar endast
befintliga registrerings- och signerade plånboksrutter; metrics och
administration kräver fortsatt separat behörighet. Origin, storleksgränser,
frekvensbegränsning och begränsat antal sessioner gäller även utan kopplingskod.
App Attest samt chip-, pass- och bildkontroller kvarstår. Aktivering följer
valt läge: manuell i standardläget, automatisk endast i det uttryckliga
[TestFlight-testläget](testflight-beta.md).
TestFlight-inbjudan är distributionskontroll, inte identitetsbevis.
`RuntimeTests` provar åtkomstgränserna, och `WalletSecurityTests` provar
standardanslutning och bevarad privat serverbindning.

OPS-01/02: bakom betans nginx skiljer ett explicit loopbackproxyläge
klienternas trafikräknare åt. Nginx ersätter inkommande adressuppgifter;
runtime nekar förfalskade, saknade och tvetydiga värden och normaliserar
motsvarande IP-skrivsätt. `test_ingress_client`, `RuntimeTests` och det
riktiga nginx-provet täcker dessa gränser. Införande och kapacitetsmål i
betan återstår; NAT-klienter delar räknare och lokala processer är betrodda.

## Underskrift, testkonsol, biometri och spärrlista 2026-10-24

SIG-01/02, FED-01 (D03 §8.4; T02 §7; SAP): telefonprovidern visar SignMessage i
appen och intygar `signMessageDigest` samt SAD (`scal2`). Registret binder texten
till en separat `sign`-åtgärd och IdP:n kontrollerar textens SHA-256 vid
konsumtion. Text som inte kan visas, SAD utan text och underskrift från en
tjänst utan `sigservice` hanteras enligt DP 1.9 §7. Avbryt och neka ger status
`cancel` till tjänsten (§6.4). Kontotjänstens testkonsol kör tio SAML-fall mot
verklig IdP och registret; underskriftsfallet ger en PAdES-B-B-PDF från en ej
betrodd test-CA. Formell status oförändrad: OPEN.

ID-05 (D08 K5.13): serverstyrd ordning för huvudvridning och kontroll av
landmärkesparallax på servern, beständig gräns på fem underkända biometriska
beslut per pass och dygn, och inga råa poäng till klienten. Valfri spärrkontroll
av passets dokumentsignerare mot CSCA:ns spärrlista (provad mot Polismyndighetens
publicerade CSCA-nycklar och `SWE.crl`). Gränserna är okalibrerade; PAD-, injektions-
och reläprov återstår. Formell status oförändrad: OPEN.

## Säkerhetskod för stora åtaganden 2026-10-24

ID-07/09, K6.1 (två faktorer): tjänsten kan per transaktion kräva en servertestad
säkerhetskod med sex siffror utöver enhetsnyckeln, via kontexten
`urn:openid:authn:passport-native:pin:v1`. Fel kod räknas på servern, fem fel
spärrar koden permanent, och koden lagras endast som HMAC med den separata
identitetsnyckeln. Provas i `test_security_code`, `SignatureRequestPolicyTest`,
testkonsolens kodfall och `WalletSecurityTests`. Formell status oförändrad: OPEN.

## Nyckelfiler och kravspårning 2026-10-22

SEC-02/K4.3: lokal profilnyckel måste vara en vanlig fil med en hårdlänk,
privata rättigheter och utan exekveringsrätt. Öppning utan följning av symlänk
och utan blockering stoppar FIFO före läsning. Kontrollen avser det öppnade
filobjektet. Detta ersätter inte HSM, skydd mot tjänstekontot eller
administrativ flerpersonskontroll. `test_identity_key` provar avvisning av
FIFO, katalog, symlänk, hårdlänk, breda rättigheter och fel längd.

Se [40-punktsmatrisen](digg-kravmatris.md) och
[avisering och spärr](avisering-och-sparr.md). Formell status
förblir OPEN; dokumenten är ännu inte fastställda eller operativt verifierade.

## Automatisk iOS-fångst

ID-05/INT-02: ansiktsguiden visar geometrisk närhet, väljer högsta fångstkvalitet
i ett kort godtagbart bildfönster och bevarar serverns ordning. Förlorad
kontinuitet rensar bilderna; UI-färg används inte som serverbevis.
Passguiden kontrollerar hela sidans kanter och läser MRZ från en lokal
stillbild före ifyllnad. Bilden sparas eller skickas inte.
`CaptureGuideTests` provar bildval, riktning, pauser och rensning.
`PassportPhotoTests` kör Vision på syntetiska sidbilder och provar avklippt,
tom och avvikande handling. UI-prov kontrollerar instruktioner, stor text
och passram. Fysisk kalibrering, fångsttid och attackprov återstår.
Formell status är oförändrad; TrueDepth är ett separat undersökningsspår.

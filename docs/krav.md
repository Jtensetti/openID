# Tekniska krav och verifieringsluckor

Krav-ID:n behålls för spårbarhet till tester och tidigare granskningar.
Tabellen beskriver teknisk täckning; formell kravstatus är fortsatt `OPEN`.
Källhänvisningar avser inventeringen 2026-10-19 i [SOURCES.md](SOURCES.md).
Aktuell originaltext behöver kontrolleras inför en formell bedömning.

## Identitet och nycklar

| ID | Område / källa | Implementation och prov | Kvarstående kontroll |
|---|---|---|---|
| ID-01 | Utgivningspolicy, D08 K5.1–K5.3 | Privat registrering med separat operatörsaktivering. | Fastställd utgivningspolicy och användarvillkor. |
| ID-02 | Identitets-/registerkontroll, D08 K5.7–K5.9 | Autentiserade uppgifter ur passets DG1. | Registeråtkomst, avvikelser och skyddade identiteter. |
| ID-03/04 | Utgivningsmetod, D08 K5.10–K5.13; D09 | Passbaserat appflöde. | Bedömning av metoden. Nyutgivning via befintlig e-id saknas. |
| ID-05 | Fjärrkontroll, D08 K5.13; D09 | Serverstyrd JMRTD PACE/CA med signerad DG14 och färsk MAC-kontrollerad läsning. `ChipAuthenticationTest` provar även kopierade data utan privat chipnyckel, replay och ändrad MAC. Lokal Vision-guide kräver tre huvudpositioner, bildkvalitet och stabilitet; `CaptureGuideTests` provar fångstvillkoren. | Fysisk NFC/App Attest, certifikatspärr, kalibrerad biometri/PAD samt oberoende injektions-/reläprov. Kameraguiden är inget verifierat liveness-bevis. |
| ID-06 | Innehavarregister, D08 K5.14 | `test_identity` och `test_cluster`: krypterad personprofil, dokumentreferens, enhetsbindning och atomisk ersättning. | Registeravstämning och oberoende utgivningskontroll. |
| ID-07 | Faktorer/nyckelskydd, D08 K6.1–K6.2 | Secure Enclave/Keychain i iOS-koden; CryptoKit/server-interoperabilitet testad. | Fysiskt enhetstest och verifierad hårdvarubindning på servern. WebAuthn-labben använder attestering `none`. |
| ID-08 | Återställning, D08 K6.3 | Nyregistrering för samma pass ersätter nyckeln; spärrad nyckel kan inte aktiveras igen. | Förlorad telefon utan självbetjäning, nytt pass och skydd mot gammal databasåterläsning. |
| ID-09 | Bindning/giltighet, D08 K6.4–K6.7 | Signerade engångsoperationer, utgång och samtidiga beslut testas i Python och XCTest. | Oberoende avisering och komplett utgivningsprocess. |
| ID-10 | Spärr, D03 §8.6 | App eller operatörs-CLI; spärr kontrolleras vid godkännande, konsumtion och skyddad SP-läsning. | Åtkomlig spärrkanal dygnet runt, bemanning och distribuerad drift. |
| ID-11 | Bevarande/avveckling, D08 K2.7–K2.8, K5.5 | Råunderlag lagras inte; PostgreSQL-läget har begränsad gallring och Transit-omkryptering. | Fastställda lagringstider, avveckling och gallring av administrativa loggar/personlänkar. |

## Protokoll och säkerhet

| ID | Område / källa | Implementation och prov | Kvarstående kontroll |
|---|---|---|---|
| SEC-01 | Kanaler, D08 K4.2; T01–T03 | HTTPS, fasta motparter, signaturer, CSRF/Origin och sessionsbindning. Negativa Java-/browserprov. | Extern interoperabilitet och driftgränser. |
| SEC-02 | Servernycklar, D08 K4.3 | Lokala testnycklar samt separat OpenBao Transit med profilrotation och avgränsade tjänstekonton. | HSM, operativ flerpersonskontroll, indexnyckelbyte och övad nyckelåterställning. |
| SEC-03 | Beroenden, D08 K4.4 | Versions-/hashlås, SBOM och daterade advisorykontroller. | Löpande bevakning, full byggkedja/OS och oberoende revision. |
| GOV-07 | Befogenheter, D08 K3.4 | PostgreSQL-funktioner kräver två olika operatörsinloggningar; tjänstekonton saknar aktiveringsrätt. Schemainstallation och återställning stöder administratör utan superuser. Negativa tester nekar tjänste- och operatörskonton ägarmedlemskap och rollbyte. | Verklig personseparation, kontroll av ägar-/administratörsåtkomst och oberoende granskning. |
| FED-01 | Federationsprofil, D03 §8.4; T01–T03 | Sweden Connect SAML med lokal metadata och egen autentiseringskontext. | Full profilmappning och accepterad extern anslutning. |
| FED-02 | Mottagare/avsikt, D03 §§8.2–8.3 | Appen visar och signerar tjänst, syfte och kod. `test_identity`, XCTest och federationsprovet testar byte av bindningar och replay. | Närhets-/reläskydd och externa motparter. |
| SIG-01/02 | Dokumentunderskrift, T01 | Ingen implementation. | Dokumentpresentation, innehållsbindning, signering och oberoende valideringskedja. |
| TEST-01 | Testmiljö, D03 §8.9 | Genererade pass/nycklar, lokala motparter och automatiserad CI. | Extern acceptanstestmiljö och fysiska enheter. |

## Drift och rapportering

| ID | Implementation | Återstående arbete |
|---|---|---|
| OPS-01/02 | Gunicorn/TLS med hälsokontroller, kapacitetsgränser, isolerad bildanalys, resursbegränsad container och lokala belastningsprov. PostgreSQL-läge med flera TLS-workers, instansbortfallsprov och separata mät-/larmfunktioner. Separat stängd Render-container. | Tillgänglighets-/svarstidsmål enligt D03 §8.5.1 är inte verifierade. Redundans och mätning på avsedd produktionsmiljö saknas. |
| OPS-03/04/05 | Ingen operativ support-, incident- eller ändringsprocess. | Kontaktvägar, bemanning, incidentövning och kompatibel uppgradering enligt D03 §§8.7, 8.12–8.14. |
| OPS-06 | Begränsade sessioner, meddelandestorlekar och engångsvärden. | Driftanpassad missbruksdetektion och granskad utredningsprocess. |
| OPS-07 | Java-/SQLite-återläsning samt PostgreSQL-registerbackup, sluten återställning och spärr av alla gamla nycklar. CI provar återläst OpenBao-snapshot, gamla/saknade profilnycklar, Raft-ledarbortfall och nyregistrering efter återläsning. | Övning på vald driftplattform, extern backupförvaring, återställningstider och operativ nyckelceremoni. |
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

ID-05: Kameraguiden visar ansiktsram, separata fångstindikatorer och korrigering direkt i förhandsbilden. För liten/stor sidovridning skiljs åt. Fångstgränserna är oförändrade; fysisk användbarhet och sidofångst behöver verifieras på telefon.

ID-05: Fångstguidens tolerans för små rörelser, centrering och lutning har ökats och hålltid kortats till 0,45 s/minst fyra observationer. Syntetiska prov täcker naturlig variation och fortsatt avvisning av stora rörelser. Serverns identitetskontroller och tre skilda huvudpositioner ändras inte. Fysisk användbarhet behöver bekräftas.

ID-05: Riktningsguide framåt/höger/vänster med separat fångstbekräftelse. Begränsad pausbudget utan tillgodoräknad avbrottstid provas med syntetiska mätserier, inklusive upprepade avbrott och fel sida. Fysiskt prov av speglad riktning och användbarhet återstår.

ID-05/INT-02: Biometriarbetaren rapporterar endast fasta steg och tillåtna orsakskoder. Huvudprocessen validerar koderna igen och skiljer modell-/arbetarfel från avvisad bildanalys. Inga bilder, poäng eller godtyckliga undantagstexter loggas. Diagnostik ändrar inte experimentella gränser eller formell status.

ID-05: YuNet-detektor använder två helbildsskalor för högupplösta kamerabilder. Fleransiktsfall och motstridiga detektioner avvisas; originalbild används för ansiktsjämförelse och PAD. Bildfel returneras som fast kod med bildnummer 1–3, utan råpoäng eller bilddata. Testar skalåterföring och negativa fall; ingen ändrad formell status.

### Felåterkoppling för legitimering

ID-09, ID-10 och FED-02: appen skiljer statushämtning från godkännande,
nekande och spärr. Testsidan skiljer känt nekande, avbrott och utgången
begäran från ett okänt anslutnings-/kontrollfel. Okänd orsak presenteras inte
som bekräftad spärr eller bekräftat nekande. Avslutade QR-begäranden döljs
och en länk erbjuder en ny inloggning. Status får återhämtas automatiskt;
godkännanden skickas aldrig om automatiskt. Formell kravstatus ändras inte.

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
operativ återställning/spärrkanal återstår. Formell status: OPEN.
Se [flöde, befogenheter och begränsningar](registerbindning.md).


## Kontroll av passfält och registerkrav 2026-10-21

ID-02 är fortsatt OPEN. Kodgranskning av revision a7ffe976 visar att appen
läser DG1, DG2, DG14 och SOD. Servern autentiserar datagruppernas hashvärden
mot signerad SOD. Identitetsmodellen tar ut namn, MRZ-födelsedatum,
nationalitet, utfärdarland, dokumentnummer och utgångsdatum. DG1:s
optional-data/personnummerfält tas inte ut; DG11 läses inte. Den sparade
profilen saknar därför nationell identitetsbeteckning. Rå DG1 bevaras inte
av det granskade flödet, så en tidigare privat läsning bevisar inte vilket
innehåll detta fält hade. Ingen privat personakt har öppnats i denna kontroll.

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

Fältets förekomst i det privata svenska passet återstår att bekräfta vid en
ny läsning. Inga tidigare råa passdata återskapas. ID-02 förblir OPEN eftersom
registerkontroll och hantering av skyddade uppgifter återstår.


## Automatisk anslutning i sluten TestFlight-beta

Nya appinstallationer använder den fasta publika HTTPS-adressen utan VPN
eller inbyggd kopplingshemlighet. Sparade serverbindningar bevaras.
`publicEnrollment` är avstängd som standard och får endast aktiveras för
betans kanoniska adress med produktions-App Attest. Den öppnar endast
befintliga registrerings- och signerade plånboksrutter; metrics och
administration kräver fortsatt separat behörighet. Origin, storleksgränser,
frekvensbegränsning och begränsat antal sessioner gäller även utan kopplingskod.
App Attest, chip-/pass-/bildkontroll och manuell aktivering kvarstår.
TestFlight-inbjudan är distributionskontroll, inte identitetsbevis.
`RuntimeTests` provar åtkomstgränserna, och `WalletSecurityTests` provar
standardanslutning och bevarad privat serverbindning.

## Nyckelfiler och kravspårning 2026-10-22

SEC-02/K4.3: lokal profilnyckel måste vara en vanlig fil med en hårdlänk,
privata rättigheter och utan exekveringsrätt. Öppning utan följning av symlänk
och utan blockering stoppar FIFO före läsning. Kontrollen avser det öppnade
filobjektet. Detta ersätter inte HSM, skydd mot tjänstekontot eller
administrativ flerpersonskontroll. `test_identity_key` provar avvisning av
FIFO, katalog, symlänk, hårdlänk, breda rättigheter och fel längd.

Se [40-punktsmatrisen](digg-kravmatris.md), [rutinförslag](styrningsrutiner.md)
och [design för avisering/spärr](avisering-och-sparr.md). Formell status
förblir OPEN; dokumenten är ännu inte fastställda eller operativt verifierade.

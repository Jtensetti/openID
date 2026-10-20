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
| GOV-07 | Befogenheter, D08 K3.4 | PostgreSQL-funktioner kräver två olika operatörsinloggningar; tjänstekonton saknar aktiveringsrätt. | Verklig personseparation, kontroll av ägar-/administratörsåtkomst och oberoende granskning. |
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

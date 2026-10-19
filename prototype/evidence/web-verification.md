# Faktisk verifiering: WebAuthn och webbklient

Kontrollerat 2026-10-19 på `feat/g2-open-web-authentication`, byggt vidare på
G2-revision `a86c5937f1298dc716109a6a0edc71763908453a`. Detta är en isolerad
teknisk etapp, inte en säkerhetsgodkänd release eller en accepterad grind.

## Vad som fungerar

`start-web` kör en lokal webbklient med registrering av testnyckel och
WebAuthn-inloggning till samma lokala SAML-testtjänst som tidigare. Sweden
Connect/OpenSAML sköter federation; Yubico Java WebAuthn Server 2.10.1 sköter
nyckelbevis och WebAuthn-validering. JCA och autentiseraren sköter kryptografin.
Ingen egen kryptografisk primitiv eller biometrisk motor har införts.

Webbklienten kräver ingen appbutik, frontend-CDN, extern attesteringsserver
eller inloggning hos ett visst molnföretag. Användarverifiering är obligatorisk;
externa FIDO2-nycklar och plattformsnycklar tillåts utan fabrikatslista.
PWA-installation är valfri. Service workern cachar ingenting och visar endast
en anonym 503-sida vid frånkoppling.

Publik nyckel, slumpmässigt användarhandtag, credential-ID, signaturräknare och
backupflaggor sparas atomiskt med revisionshändelsen. Privat nyckel, PIN och
biometri lagras inte av servern. Schema 1 migreras till 2 utan att radera
spärrar. Normal omstart bevarar nyckel och räknare. En gammal backup eller
okontrollerad avstängning återaktiverar aldrig nyckeln.

Challenges är engångsvärden med 60 sekunders giltighet, bundna till
webbläsarsession och rätt SAML-flöde. Misslyckad verifiering förbrukar också
challengen. Exakt HTTPS-ursprung och RP-ID kontrolleras. En lokal policy
förbjuder inbäddade ceremonier via `crossOrigin`/`topOrigin` eftersom Yubicos
låsta version inte själv kontrollerar dessa nyare fält. CSRF och Origin krävs
för formulären; CSP förbjuder inramning och externa skript. Spärr kontrolleras
vid nyckelbeslutet och på nytt före SAML-signering.

Det äldre `start`-läget finns kvar för explicit simulerade protokollprov men
kan inte öppna ett register med testnycklar. HTTP-godkännande utan WebAuthn
nekas i webbläget. Ingen e-poståterställning, nyckelöverskrivning eller dold
simulerad reservväg har lagts till.

## Körda tester

Verktyg: Temurin **21.0.12.1+1**, Maven **3.9.11**, Node **24.19.0**,
Playwright **1.62.1** med dess Chromium headless shell **151.0.7922.34**
(revision 1234, kontrollerad mot Playwright-manifestet). Linux/POSIX.

| Körning | Resultat |
|---|---|
| `./mvnw -B -ntp verify dependency:list -DoutputAbsoluteArtifactFilename=true -DoutputFile=target/dependencies.txt` | **132 JUnit-fall**, 0 fel, 0 överhoppade: 45 befintliga HTTPS/SAML, 13 livscykel, 20 lagring, 6 rapportering, 40 WebAuthn-servicefall och 8 nya HTTPS/WebAuthn/SAML-fall. |
| `python3 scripts/dependencies.py` | **177** låsta versioner och JAR-checksummor verifierade; dependency convergence aktiverad. |
| `npm run test:browser` | Äldre browserflödet samt nyckelregistrering och full SAML-inloggning med både virtuell USB- och plattformsautentiserare. Utloggning, spärrad aktiv session, nekad ny inloggning, mobil bredd 390 px, manifest utan parse-/installerbarhetsfel enligt Chromium, aktiv service worker, tom cache och offline-503 passerar. Inga externa sidförfrågningar eller JavaScript-undantag observerades. |
| `python3 scripts/smoke.py` | Paketerat init/start, exakt TLS-tillit och komplett syntetiskt SAML-flöde passerar. |
| `python3 scripts/recovery-smoke.py` | Separata JVM-starter, beständig spärr, gammal backup, faktisk SIGKILL och stängd autentisering efter osäker återstart passerar. |
| `python3 -m unittest discover -s ops/tests -v` | 6 befintliga HTTP-/processtester för den stängda driftgrunden passerar. Ingen driftkod ändrad. |
| CycloneDX 2.9.1 / OSV | SBOM för 177 artefakter genererad. OSV gav 0 publicerade fynd för den exakta grafen vid kontrolltillfället. |

[Maskinläsbara JUnit-resultat](web-test-results.json),
[beroendelås](../dependencies.lock.json), [SBOM](bom.json), [OSV](osv.json).
Det lokala Maven-anropet använde samma pinnade Maven/JDK med arbetsmiljöns
proxy och betrodda CA-katalog; TLS-verifiering stängdes inte av vid hämtning.

Negativa WebAuthn-fall omfattar fel ursprung/port/subdomän/protokoll,
RP-ID-hash, challenge, operationstyp, crossOrigin/topOrigin, saknad UP/UV,
ogiltiga backupflaggor, ändrad backupbehörighet, fel signatur inklusive
korrekt kodad signatur från en annan privat nyckel, fel credential-ID och
användarhandtag, upprepad nyckelregistrering, nyckel-ID hos annan identitet,
deadline, parallell konsumtion, återspelning, session-/SAML-förväxling,
felaktig/stor JSON, CSRF/Origin, simulerad nedgradering, spärr och utgång
under pågående flöde. Räknarlösa synkroniserbara nycklar provas separat;
en icke-nollräknare får inte upprepas eller gå bakåt.

Lagringsfallen omfattar verkligt WebAuthn-genererat publikt material över
omstart, schemauppgradering med bevarad spärr, injicerat auditfel som rullar
tillbaka registrering och gammal nyckelbackup som återställs spärrad.
Testautentiseraren använder JCA/CBOR för syntetiska fixtures, ingen egen
kryptografisk primitiv. Chromium-proven använder webbläsarens riktiga
`navigator.credentials` med virtuella CTAP2-enheter.

Under arbetet upptäcktes och rättades saknad CSP på upstreams `/lab`-kedja.
Maven upptäckte också olika Guava-versioner; de förenades uttryckligen till
Yubicos 33.7.2-jre och hela SAML-/WebAuthn-sviten kördes med den grafen.

## Scope, krav och kvarstående gränser

Lästa projektskills: `eid-lifecycle-security`,
`sweden-connect-integration`, `supply-chain-and-release` och
`eid-economics-and-reporting`. AGENTS.md, README, SECURITY, THIRD_PARTY och
berörd dokumentation i docs lästes före implementation. Källversioner:
W01/WebAuthn, Yubico 2.10.1 vid full revision i THIRD_PARTY; tidigare låsta
Sweden Connect-versioner behålls.

| Krav | Visad del och återstående bevis |
|---|---|
| ID-06/07/09/10 | Nyckelbevis med användarverifiering, begäransbindning, beständig nyckel/spärr och spärrade sessioner. Verklig personbindning och granskad bärare saknas. |
| ID-08 | Ny registrering kan inte skriva över tidigare nyckel; restore kan inte återuppliva den. Full mänsklig spärr-/återutgivningsprocess saknas. |
| FED-01/02, SEC-01, TEST-01 | Befintligt signerat/krypterat SAML-flöde med nya negativa WebAuthn- och HTTP-fall. Komplett federationsprofil, extern interoperabilitet och oberoende angreppstest saknas. |
| SEC-03, INT-01–06 | Låsta bibliotek, licenser, SBOM, tester och isolerad källkodsleverans. Oberoende releasegranskning, produktionsförvaltning och full leveranskedjerevision saknas. |

Identitetskontroll, tilldelning av SYNTHETIC-alice och lokal spärrkanal är
**simulerade**. Nyckelbeviset är tekniskt verkligt, men attestering `none` bevisar
inte fabrikat, hårdvaruskydd, enhetsbundenhet eller verklig persons identitet.
Ingen Digg-tillitsnivå påstås; labbkontexten är fortsatt `urn:openid:lab:simulated`.
Alla ersättningsgrundande transaktioner är fortsatt 0.

**Inte körda:** fysiska FIDO2-nycklar, verkliga Android-/iOS-/Linux-enheter,
Safari/Firefox, faktisk installation via operativsystemets dialog, pass-NFC,
dokument-/ansiktskontroll, extern federation, belastning/HA och oberoende
säkerhetsgranskning. Den tillgängliga miljön gav Chromium och virtuella
autentiserare; det räcker inte som fälttest eller certifiering.

CBOR 5.0.0-alpha2 är en uttrycklig transitive beroenderisk; se THIRD_PARTY.
Egen projektlicens är inte beslutad (förslag: Apache-2.0 för egen kod).
Databas-/OS-ägaren är betrodd och kan ändra program eller register. Robust
missbruksbegränsning, verifierad utgivning, HSM, full återställningskanal,
distribuerad spärr, driftansvar och behöriga produktionsbeslut återstår.
Ingen kravstatus har höjts till ACCEPTED. Inget autentiseringsflöde har
driftsatts på Render och ingen PR har slagits ihop i denna etapp.

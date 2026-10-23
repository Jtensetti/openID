# Säkerhet

## Status

Projektet saknar produktionsrelease, Digg-godkännande och oberoende
säkerhetsgranskning.

- `prototype/` med `start`/`start-web`: SAML/WebAuthn-labb med genererade identiteter och
  simulerad identitetskontroll. Normal omstart bevarar spärrar och publika
  nycklar. Krasch och återläsning spärrar alla credentials.
- `verification/` och `ios/`: passverifiering, ansiktsjämförelse, RGB-PAD,
  NFC-fångst och enhetsautentisering för sluten beta och privata telefonprov. Registrering
  kräver separat operatörsaktivering. `phone-idp` och `phone-sp` kopplar
  detta register till separata SAML-/OIDC-testtjänster.

`start-web` innehåller även en syntetisk dokumentunderskriftslabb med
separat WebAuthn-godkännande och tillfällig test-CA. Ingen verklig handling
kan laddas upp. Signeringsnycklarna ligger i JVM-minnet, inte i HSM, och
labben erbjuder varken kvalificerad underskrift eller långtidsvalidering.
Rutter för detta flöde aktiveras inte av `phone-idp`/telefonpiloten.
Federerade SignMessage-/SAD-begäranden avvisas av inloggningsproviderna.
- `deployment/continuity/`: separat spärrtjänst och köad avisering för den publika
  betan. Privata ID:n är inte automatiskt migrerade. Se
  [drift och begränsningar](deployment/continuity/README.md).
- `ops/`: driftcontainer i Render, utan e-id-funktioner.

Privata telefonprov har bekräftat passläsning och SAML-inloggning. Bredare
enhetsprov, modellernas felgrader, bildinjektion och certifikatspärr återstår. Se [verifierarens begränsningar](verification/README.md#begränsningar)
och [testöversikten](docs/testning.md).
De lokala labblägena ska inte exponeras via tunnel eller proxy. Den publika
betan har separat ingress och konfiguration; labbkommandon öppnar inte en
säker publik tjänst.

WebAuthn kräver användarverifiering, engångschallenge, exakt ursprung och
sessionsbindning. Attestering `none` ger ingen garanti om fabrikat,
hårdvaruskydd eller frånvaro av nyckelsynkronisering. Webbklienterna sparar
inga autentiseringssvar eller identiteter offline.

## Data och hemligheter

Följande får inte publiceras i repo, issues, PR:er, loggar eller bilagor:

- Verkliga ID-handlingar, bilder, biometriska underlag, personakter eller autentiseringshistorik.
- Privata nycklar, lösenord, API-nycklar, sessionsvärden eller åtkomstuppgifter.
- Känsliga revisionsbilagor eller exploateringsunderlag för andras system.

CI använder genererade testdata. Använd interna test-ID:n, inte slumpade
personnummer som kan tillhöra någon. Verkliga pass får bara användas i
användarens uttryckligen valda privata testmiljö. Externa testidentiteter
hanteras enligt respektive miljös villkor.

Pilotregistret sparar passets personprofil och förminskade foto krypterat.
Databas och nyckelfil måste skyddas separat från repot. Samma serverkonto
kan läsa nyckeln och aktivera credentials. Använd endast
`recovery.py restore` för återläsning av pilotdatabasen: den spärrar alla
återställda nycklar och kräver ny registrering. Manuell återläsning som
bevarar aktiva nycklar kan förlora senare spärrar och stöds inte.
SAML-/OIDC-tjänsterna nekar åtkomst om spärrkontrollen inte kan nås. Se
[lagring och nycklar](verification/README.md#spärr-och-lagring).

En publicerad hemlighet ska betraktas som röjd: stoppa exponeringen,
återkalla eller rotera den och utred användningen. Borttagning ur senaste
commit räcker inte. Historikändring kräver separat beslut.

## Rapportera problem

En privat säkerhetskanal är ännu inte konfigurerad. Publicera inte känsliga
sårbarhetsdetaljer i öppna issues; be projektägaren om en privat kontaktväg.
Inför pilot- eller produktionsrelease behövs ansvarig mottagare och en
dokumenterad process för triage och kommunikation.

## Test och release

Testa bara egna miljöer eller uttryckligen godkända mål. Utveckling, extern
testanslutning och produktion ska ha separata nycklar, ankare, behörigheter
och data. Testnycklar får inte användas som produktionsankare.

Följ [releasekraven](docs/utveckling.md).
Utgivning, rollseparation, nyckelhantering, spärr, återställning, dataskydd,
incidenthantering, kontinuitet och avtal behöver ansvariga och granskningsunderlag.
En kodagent får inte godkänna sin egen produktionsrelease.

Branch protection, CODEOWNERS, CI och privat rapportering måste verifieras
i GitHubs inställningar. Ingen egen kryptografisk primitiv eller generativ
modell får avgöra identitets- eller underskriftsbeslut.

Se [AGENTS.md](AGENTS.md), [arkitekturen](docs/arkitektur.md) och
[komponentregistret](THIRD_PARTY.md).

# Säkerhet

## Status

Projektet saknar produktionsrelease, Digg-godkännande och oberoende
säkerhetsgranskning.

- `prototype/` med `start`/`start-web`: SAML/WebAuthn-labb med genererade identiteter och
  simulerad identitetskontroll. Normal omstart bevarar spärrar och publika
  nycklar. Krasch och återläsning spärrar alla credentials.
- `verification/` och `ios/`: passverifiering, ansiktsjämförelse, RGB-PAD,
  NFC-fångst och enhetsautentisering för en privat pilot. Registrering
  kräver separat operatörsaktivering. `phone-idp` och `phone-sp` kopplar
  detta register till en separat lokal SAML-tjänst.
- `ops/`: driftcontainer i Render, utan e-id-funktioner.

Fysisk NFC/App Attest, modellernas felgrader, bildinjektion och certifikatspärr
återstår att utvärdera. Se [verifierarens begränsningar](verification/README.md#begränsningar)
och [testöversikten](docs/testning.md).
Labben och testtjänsten ska inte exponeras via tunnel eller proxy.

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
kan läsa nyckeln och aktivera credentials. Gamla kopior av pilotdatabasen
får inte återläsas: skydd mot återställd spärrstatus saknas i detta register.
SAML-tjänsten nekar åtkomst om spärrkontrollen inte kan nås. Se
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

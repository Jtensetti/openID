# Säkerhet

## Status

Privata registerjournaler kan tas ut med [arkivexportören](docs/arkivexport.md).
Exporten innehåller känsliga ID:n och operatörsuppgifter och ska förvaras
utanför repot och publika CI-artefakter. Verifiering kräver en separat
bevarad manifestkontrollsumma. Detta ger integritetskontroll av ett uttag,
inte en attest av det ursprungliga identitetsbeslutet.

Projektet saknar produktionsrelease, Digg-godkännande och oberoende
säkerhetsgranskning.

- `prototype/` med `start`/`start-web`: SAML/WebAuthn-labb med genererade identiteter och
  simulerad identitetskontroll. Normal omstart bevarar spärrar och publika
  nycklar. Krasch och återläsning spärrar alla credentials.
- `verification/` och `ios/`: passverifiering, ansiktsjämförelse, RGB-PAD,
  NFC-fångst och enhetsautentisering för sluten beta och privata telefonprov. Registrering
  kräver separat operatörsaktivering i standardläget. Det uttryckligen valda
  [TestFlight-testläget](docs/testflight-beta.md) aktiverar efter godkända
  kontroller utan e-post och avslutar giltigheten vid betans slut. `phone-idp` och `phone-sp` kopplar
  detta register till separata SAML-/OIDC-testtjänster.

`start-web` innehåller även en syntetisk dokumentunderskriftslabb med
separat WebAuthn-godkännande och tillfällig test-CA. Ingen verklig handling
kan laddas upp. Signeringsnycklarna ligger i JVM-minnet, inte i HSM, och
labben erbjuder varken kvalificerad underskrift eller långtidsvalidering.
Rutter för detta flöde aktiveras inte av `phone-idp`/telefonpiloten.
- `phone-idp`/`phone-sp`: federerad underskrift med SignMessage och SAD.
  Appen visar texten och kräver en separat underskriftsåtgärd; kontotjänstens
  testkonsol skapar en PAdES-signerad PDF med certifikat från en tillfällig,
  ej betrodd test-CA i processminnet. Ingen HSM, betrodd tid eller
  långtidsvalidering. Testkedjan styrker inte en kvalificerad underskrift eller
  en verklig innehavares identitet.
- `deployment/continuity/`: separat spärrtjänst och köad avisering för den publika
  betan. Privata ID:n är inte automatiskt migrerade. Se
  [drift och begränsningar](deployment/continuity/README.md).
- `ops/`: driftcontainer i Render, utan e-id-funktioner.

Privata telefonprov har bekräftat passläsning och SAML-inloggning. Bredare
enhetsprov, modellernas felgrader och bildinjektion återstår. Spärrkontroll av
passets dokumentsignerare kräver att operatören konfigurerar CSCA:ns spärrlista. Se [verifierarens begränsningar](verification/README.md#begränsningar)
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
återställda nycklar och spärrar ny registrering och biometrisk analys i
minst 24 timmar. Samma beständiga spärr finns i PostgreSQL-återställningen,
så att en äldre backup inte återöppnar en förbrukad försöksbudget. Därefter
krävs ny registrering. Manuell återläsning som
bevarar aktiva nycklar kan förlora senare spärrar och stöds inte.
SAML-/OIDC-tjänsterna nekar åtkomst om spärrkontrollen inte kan nås. Se
[lagring och nycklar](verification/README.md#spärr-och-lagring).

En publicerad hemlighet ska betraktas som röjd: stoppa exponeringen,
återkalla eller rotera den och utred användningen. Borttagning ur senaste
commit räcker inte. Historikändring kräver separat beslut.

## Rapportera problem

Rapportera säkerhetsproblem till
[Jonatan@tensetti.se](mailto:Jonatan@tensetti.se). Ange berörd version,
förutsättningar, konsekvens och en kort beskrivning. Skicka inte pass,
biometrik, personakter, privata nycklar eller lösenord. Be om en överenskommen
säker överföringsväg för känsliga tekniska bilagor. Publicera inte känsliga
sårbarhetsdetaljer i öppna kanaler.

Bemannad beredskap och garanterad svarstid är inte fastställda.
Kontaktadressen ersätter inte användarens separata spärrfunktion.

## Kända begränsningar

Källkoden innehåller [versionsbunden registreringsinformation och kvitton](docs/registreringsinformation.md),
[personutdrag](docs/personuppgiftsutdrag.md), [beslutad radering](docs/radering-rattighetsarende.md)
och [isolerade bildarbetare](docs/bildarbetare.md). Dessa kräver rätt
serverkonfiguration, databasversion och kompatibel app innan införande.
En merge innebär inte att skydden är driftsatta eller att tidigare
registreringar har giltiga kvitton.

[OS-paketkontrollen](deployment/build/README.md#systempaket-och-säkerhetsunderlag)
stoppar leverans vid fynd eller ofullständiga underlag. De kvarvarande
OS-/biblioteksfynden behöver åtgärdas eller bedömas med granskat underlag;
en mindre Wolfi-bas innebär inte att fynden är stängda. Öppna leverantörsärenden
för Python och Expat kvarstår i paketlåset från 2026-10-30. Kontrollen omfattar
även leverantörsstatusar som Trivys Wolfi-feed inte rapporterar. Se
[komponentregistret](THIRD_PARTY.md#wolfi-bas-och-apko-kontrollerat-2026-10-30).

Fysisk biometri-/PAD-kalibrering, injektion/relä, operativ återställning,
nyckelförvaltning och oberoende säkerhetsgranskning återstår. Projektet har
inte visats uppfylla ISO 27001-nivå eller Diggs tillitskrav. Organisations-
och juridiska beslut hanteras utanför kodbasen.

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

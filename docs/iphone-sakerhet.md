# iPhone: säkerhetskontroller och kvarstående bevis

Omfattningen är `ios/`, dess privata API och den separata spärrtjänsten.
Målet är passbaserad distansutgivning på tillitsnivå 3. Appen är en del av
utfärdarens ledningssystem; ISO/IEC 27001 avser ledningssystemet, inte en
fristående certifiering av en app. Detta är tekniskt granskningsunderlag,
inte en SoA, internrevision eller ett godkännandebeslut.

## Kontroller och stängningsvillkor

| Delpunkt | Införd kontroll och test | Återstår för överordnat krav |
|---|---|---|
| APP-01, SEC-01, K4.2: nätverk | Gemensam `WalletHTTP` för registrering, wallet och spärr. HTTPS, exakt svarsadress, inga omdirigeringar/cookies/diskcache, JSON, tidsgräns och begränsad strömning. `WalletHTTPTests` nekar osäker adress, annat svarsmål, HTML, omdirigering och för stora svar med/utan deklarerad längd. | Fysiskt nätverksbyte, TLS och verklig ingress; testdubblar bevisar inte drift. |
| APP-02, ID-07, K6.1–K6.2: enhetsnyckel | Secure Enclave, användarnärvaro och Keychain med `WhenPasscodeSetThisDeviceOnly`. Signerade bytes provas mot serverimplementationen. | Fysiska prov av borttagen enhetskod, biometribyte, återställning, ny telefon och hårdvarubindning. |
| APP-03, ID-09, K7.2: uttrycklig avsikt | Motpart, syfte, kod, underskriftstext och kodkrav binds till signaturen. Separat signeringsåtgärd. Negativa fall i `WalletSecurityTests`. | Oberoende relä-/injektionsprov och granskning av hela utgivningen. |
| APP-04, ID-07/09, K4.1: låsning | Låsning avbryter uppgifter och rensar profil, nyckelreferens, spärrkod, väntande länk och kodfel. Kodfält rensas vid låsning/stängning. Statusuppdatering efter PIN-spärr binds till samma upplåsning. Registrering avbryts mellan Apple-/NFC-steg. | Bevittnat avbrott under Face ID, första/andra NFC-läsning, kamera och nätverksanrop. Appväxlingsskydd förhindrar inte en användares avsiktliga skärmbild. |
| APP-05, ID-10, K6.8–K6.9: spärr | Sparad separat spärrkod, fast HTTPS-endpoint och lokalt godkännande; svar högst 4 KiB. Statusläsning får avbrytas för spärr, men inte ett obekräftat godkännande. | Fysisk kedja med stoppad verifierare, förlorad telefon, schemalagd återstart, bemanning och oberoende prov. Spärrkod måste hämtas innan avbrott. |
| APP-06, SEC-03, K4.4: reproducerbar leverans | Versions-/revisionslåsta paket, CI, Release utan simulatorfixturer, tydlig App Attest-miljö och faktisk version/byggnummer i Inställningar. | Signerat installationsbevis med exakt revision, IPA-hash, team/bundle/profil/entitlements samt oberoende releasegranskning. |
| APP-07, ID-01, K5.1–K5.3/K5.6: ansökan | Överföringsinformation och uttryckligt lokalt val före passläsning. | Beslutade villkor, utfärdardeklaration, rättslig grund/DPIA samt versionsbunden serverbevarad acceptans. Befintlig toggle är inte ett sådant bevis. |
| APP-08, ID-02/05, K5.7–K5.9/K5.13: grundidentifiering | Signerade passfält, chipkontroll, serverstyrd bildordning och beständig försöksbudget. | Auktoriserad register-/passstatuskontroll, skyddade identiteter, oberoende PAD-/biometriprov och beslutad metod. |

## Koppling till ISO-arbetet

Arbetsmappningen nedan ska kontrolleras mot organisationens licensierade
ISO/IEC 27001:2022 inklusive Amd 1:2024 och beslutad SoA. Den ersätter inte
bedömningen av samtliga 93 referenskontroller.

| Område | Relevanta referenser | Appens underlag | Öppen verksamhetsdel |
|---|---|---|---|
| Säkerhetskrav och livscykel | 6.1, 8.1; A.8.25–A.8.29 | Krav-ID, källkod, hotgränser och negativa tester | Beslutad riskmetod, riskägare, behandling och oberoende bedömning |
| Enhet och autentisering | A.8.1, A.8.5, A.8.24 | Enhetsnyckel, lokalt skydd, TLS och signerad avsikt | Stödd enhetsmatris och sammanhängande fysiska prov |
| Ändringar och sårbarheter | A.8.8, A.8.9, A.8.31–A.8.33 | Hashlås, CI, versionsnummer och separata testfixturer | Bemannat uppdateringsansvar, driftsatt konfiguration och godkänd release |
| Spårbarhet och integritet | A.5.34, A.8.15 | Minimerad diagnostik och registerhändelser | Rättslig grund, villkor, bevarande, åtkomstgranskning och journalernas fullständighet |
| Kontinuitet | A.5.30 | Separat spärrväg och säker återställningsdesign | Mål, schemalagd övervakning och övad återställning i vald miljö |

## Bevis för installation och prov

Registrera full Git-revision, version, byggnummer, byggverktyg, IPA-hash,
signeringsidentitetens team, bundle-ID, App Attest-miljö, debuggerbehörighet,
profilens giltighet och att avsedd telefon omfattas. Behåll privata
enhetsidentifierare utanför repot. Kontrollera installerad version efter
uppdateringen. En exporterad IPA är inte bevis på installation.

Använd [acceptansprotokollet](fysisk-acceptans.md) på samma revision. Appstart
och simulatorprov bevisar inte NFC, Apple-attestering eller identitetskontroll.
En installation får inte räknas som att alla APP-punkter eller deras Digg-/ISO-
referenser är stängda. Se [revisionsarbetssättet](revision.md) och
[hela kravmatrisen](digg-kravmatris.md).

# Tjipp

E-legitimation under utveckling för iPhone. Appen läser passets chip och
använder en enhetsnyckel för inloggning och underskrift. Servern kontrollerar
pass och ansiktsbilder samt hanterar godkännanden och spärr.

**SAML har testats i Sweden Connects sandbox den 4 november 2026**, med
syntetiska identiteter och extern testklient, inklusive Safari. Testet avser
[revision 2e4d8c9 i PR 62](https://github.com/Jtensetti/openID/pull/62).
Sandboxkoden är ännu inte mergad till `main`. Extern OIDC-verifiering,
oberoende säkerhetsgranskning och Digg-godkännande återstår.

## Börja här

| Uppgift | Instruktion |
| --- | --- |
| Förbered stöd i en e-tjänst | [Integration: SAML, testmiljö och exempel](integrations/README.md) |
| Kör ett lokalt test utan pass | [SAML/WebAuthn-labb](prototype/README.md) |
| Bygg iPhone-appen | [iOS](ios/README.md) |
| Förbered sandboxnycklar | [Certifikat och metadata](deployment/federation/README.md) |
| Kör servern | [Verifierare](verification/README.md), [drift](deployment/README.md) |
| Granska lösningen | [Arkitektur](docs/arkitektur.md), [säkerhet](SECURITY.md), [tester](docs/testning.md) |
| Arbeta med koden | [Utveckling](docs/utveckling.md), [beroenden och attribution](THIRD_PARTY.md) |

[Folkidentitet.se](https://folkidentitet.se) är projektets webbplats.
App, pilotserver och sandbox har separata versioner och driftsättningar.
[TestFlight-instruktionen](docs/testflight-beta.md) beskriver betans giltighet
och [driftinstruktionen](deployment/README.md) dess öppettider.

## Licens

Integrationsmaterial och exempel i `integrations/` är [MIT-licensierade](integrations/LICENSE):
gratis att använda och anpassa även kommersiellt, med bevarad namnangivelse.
Övrig egen kod får användas kostnadsfritt i oförändrad form enligt
[Tjipp Source-Available License 1.0](LICENSE). Kodändringar kräver tillstånd
enligt den licensen. Tredjepartskomponenter behåller sina egna villkor.

Kontakt: [Jonatan Tensetti](mailto:Jonatan@tensetti.se).
[Rapportera säkerhetsproblem privat](SECURITY.md#rapportera-problem).

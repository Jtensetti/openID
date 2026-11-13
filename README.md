# Tjipp

E-legitimation under utveckling för iPhone. Appen läser passets chip och
använder en enhetsnyckel för inloggning och underskrift. Servern kontrollerar
pass och ansiktsbilder samt hanterar godkännanden och spärr.

## Granska den sammanhängande leveransen

Utgå från telefonflödet: app och API, passverifiering, register,
användargodkännande, federation, underskrift och spärr. Komponenternas
samband och tillitsgränser beskrivs i [arkitekturen](docs/arkitektur.md).

| Del av leveransen | Huvudinstruktion |
| --- | --- |
| Bygg och identifiera samma serverartefakt | [Byggning och leverans](deployment/build/README.md) |
| Processer, konfiguration och driftprofiler | [Drift av Tjipp](deployment/README.md) |
| Verifiera kod och hela flöden | [Tester och deras avgränsning](docs/testning.md) |
| Säkerhetsgränser och rapportering | [Säkerhet](SECURITY.md) |

Ett granskningsunderlag ska ange källrevision, image-digest,
driftkonfiguration och genomförda kontroller för den aktuella kandidaten.
Källkoden i `main` och en installerad driftversion är separata objekt.
Extern OIDC-verifiering, oberoende granskning och Digg-godkännande återstår.

## Integration och utveckling

| Uppgift | Instruktion |
| --- | --- |
| Förbered stöd i en e-tjänst | [Integration: SAML, testmiljö och exempel](integrations/README.md) |
| Kör ett avgränsat protokollprov utan pass | [SAML/WebAuthn-labb](prototype/README.md) |
| Bygg iPhone-appen | [iOS](ios/README.md) |
| Förbered sandboxnycklar | [Certifikat och metadata](deployment/federation/README.md) |
| Kör servern | [Verifierare](verification/README.md), [drift](deployment/README.md) |
| Granska lösningen | [Arkitektur](docs/arkitektur.md), [säkerhet](SECURITY.md), [tester](docs/testning.md) |
| Arbeta med koden | [Utveckling](docs/utveckling.md), [beroenden och attribution](THIRD_PARTY.md) |

[Folkidentitet.se](https://folkidentitet.se) är projektets webbplats.
Sweden Connects sandbox är en extern federationsmiljö. Den
[syntetiska IdP:n](deployment/sweden-connect-sandbox/README.md) är ett
avgränsat protokollprov. Rotens `render.yaml` definierar en fristående
hälsokontrollcontainer. Dessa beskriver inte hela Tjipps driftleverans.

## Licens

Integrationsmaterial och exempel i `integrations/` är [MIT-licensierade](integrations/LICENSE):
gratis att använda och anpassa även kommersiellt, med bevarad namnangivelse.
Övrig egen kod får användas kostnadsfritt i oförändrad form enligt
[Tjipp Source-Available License 1.0](LICENSE). Kodändringar kräver tillstånd
enligt den licensen. Tredjepartskomponenter behåller sina egna villkor.

Kontakt: [Jonatan Tensetti](mailto:Jonatan@tensetti.se).
[Rapportera säkerhetsproblem privat](SECURITY.md#rapportera-problem).

# openID

Kodbas för en iPhone-app med passläsning, ansiktskontroll, enhetsnycklar och
SAML-/OIDC-inloggning. Servern binder passuppgifter till appens publika nyckel
och hanterar aktivering, godkännanden och spärr.

Projektet är under utveckling. Betans ID:n och underskriftscertifikat är
för test; projektet har inget Digg-godkännande och är inte anslutet till
Sweden Connect-federationen. Se [säkerhet och begränsningar](SECURITY.md).

## Börja här

| Uppgift | Instruktion |
|---|---|
| Bygg eller kör iPhone-appen | [iOS: Xcode, signering, funktioner och tester](ios/README.md) |
| Kör verifierare och testtjänst | [Linuxinstallation, API-flöden och tester](verification/README.md) |
| Prova SAML/WebAuthn med syntetiska identiteter | [Protokolllabben](prototype/README.md) |
| Bygg och leverera servern | [Isolerad byggmiljö](deployment/build/README.md), [drift och återställning](deployment/README.md) |
| Förstå komponenter och säkerhetsgränser | [Arkitektur](docs/arkitektur.md) |
| Ändra kod och verifiera resultatet | [Utveckling](docs/utveckling.md), [testöversikt](docs/testning.md) |

## Betan

[Projektsidan](https://openid.tensetti.io), [testkonsolen](https://openid.tensetti.io/test)
och [underskriftstestet](https://openid.tensetti.io/sign) har separat hosting.
En commit i repot uppdaterar inte automatiskt dessa tjänster eller telefonen.

- [Appens utgåvor](ios/README.md#utgåvor) skiljer TestFlight-piloten från utvecklingsbygget.
- [Betans öppettider och slutstopp](deployment/README.md#betans-öppettider) anger driftperioden.
- [TestFlight-läget](docs/testflight-beta.md) beskriver automatisk testaktivering och giltighet.
- [Avisering och spärr](docs/avisering-och-sparr.md) beskriver återstående åtkomst när huvudservern är avstängd.

Nya TestFlight-installationer ansluter utan VPN. Befintliga privata
serverbindningar behålls. Standardlägets manuella aktivering och
TestFlight-lägets automatiska aktivering är två skilda konfigurationer.

## Teknisk dokumentation

| Område | Dokument |
|---|---|
| Identitet | [Registerbindning](docs/registerbindning.md), [spärr och avisering](docs/avisering-och-sparr.md) |
| Registrering och data | [Information och kvitton](docs/registreringsinformation.md), [personutdrag](docs/personuppgiftsutdrag.md), [radering](docs/radering-rattighetsarende.md), [återställningsbindning](docs/aterstallningsbindning.md) |
| Protokoll | [OIDC](docs/oidc-pilot.md), [SAML-/OIDC- och underskriftsprov](docs/provningsunderlag.md), [PDF-signatur](docs/pdf-underskrift.md) |
| Drift | [PostgreSQL/OpenBao](deployment/cluster/README.md), [separat spärrtjänst](deployment/continuity/README.md), [journalexport](docs/arkivexport.md) |
| Leverans | [Kandidat och återgång](docs/releasekandidat.md), [prov på fysisk iPhone](docs/fysisk-acceptans.md) |
| Valfri infrastruktur | [AWS-kompatibilitetsprov](deployment/aws/README.md), [backup och loggning](deployment/security/README.md), [hälsokontrollcontainer utan e-id](ops/README.md) |
| Webbsida | [Källkod och publicering](deployment/project-site/HOSTING.md) |
| Beroenden | [Versioner och licenser](THIRD_PARTY.md), [tekniska källor](docs/SOURCES.md) |

Dokumentationen beskriver implementation och körning. Arbetsplaner,
organisationsdokument och historiska testrapporter förvaras utanför kodbasen.
Aktuella testresultat finns i [GitHub Actions](https://github.com/Jtensetti/openID/actions).
Äldre borttagna underlag finns kvar i Git-historiken.

Verkliga pass, personakter, privata nycklar och driftdata får inte läggas i
repot. Tester använder genererade identiteter. Kodagenter börjar i [AGENTS.md](AGENTS.md).
Projektets egen licens är ännu inte beslutad; tredjepartslicenser gäller respektive filer.
Namnet openID innebär ingen anknytning till OpenID Foundation eller Digg.

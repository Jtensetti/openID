# openID

Ett projekt för svensk e-legitimation. Repot innehåller en iPhone-app, en
pass- och ansiktsverifierare och en lokal autentiseringstjänst. Separat finns
en SAML/WebAuthn-labb som använder Sweden Connect.

Projektet är under utveckling och har inget Digg-godkännande. Tillitsnivå 3
är ett mål. Projektlicens, utgivningsvillkor och produktionsansvar återstår.

## Kör och utveckla

| Del | Innehåll |
|---|---|
| [iPhone-app](ios/README.md) | Xcode-projekt med passläsning, kamerafångst, enhetsnyckel, legitimering och spärr. |
| [Verifierare och testtjänst](verification/README.md) | Passkontroll, ansiktsjämförelse, liveness, pilotregister och QR-inloggning i webbläsaren. |
| [SAML/WebAuthn-labb](prototype/README.md) | Lokal IdP och SP, testnycklar och simulerad identitetskontroll. |
| [Driftpaket](ops/README.md) | Render-container med hälsokontroller. E-id-funktioner är avstängda. |

Tester använder genererade identiteter och nycklar. Verkliga pass används
endast i den överenskomna privata testmiljön; personuppgifter och hemligheter
får inte läggas i repot. Läs [säkerhetsinformationen](SECURITY.md) och
[komponentregistret](THIRD_PARTY.md).

## Underlag

- [Avtal och affärsmodell](docs/01-avtal-och-affarsmodell.md)
- [Kravmatris](docs/02-kravmatris.md)
- [Återanvändning](docs/03-ateranvandning.md)
- [Arkitektur och hotmodell](docs/04-arkitektur.md)
- [Genomförandeplan](docs/05-genomforande.md)
- [Frågor till Digg](docs/06-fragor-till-digg.md)
- [Källregister](docs/SOURCES.md)

Kodagenter börjar i [AGENTS.md](AGENTS.md), som hänvisar till projektets
arbetsinstruktioner i `.agents/skills/`.

Namnet openID innebär ingen anknytning till OpenID Foundation eller Digg.

# openID

Ett projekt för svensk e-legitimation. Repot innehåller en iPhone-app, en
pass- och ansiktsverifierare samt SAML- och OIDC-inloggning med Sweden Connect. Appens
nyckel knyts till personuppgifter från passet. En separat lokal tjänst
tar emot de uppgifter användaren godkänner att dela.

Projektet är under utveckling och har inget Digg-godkännande. Tillitsnivå 3
är ett mål. Projektlicens, utgivningsvillkor och produktionsansvar återstår.

## Kör och utveckla

| Del | Innehåll |
|---|---|
| [iPhone-app](ios/README.md) | Xcode-projekt med passläsning, fotografering, enhetsnyckel, legitimering och spärr. |
| [Verifierare och testtjänst](verification/README.md) | Passkontroll, ansiktsjämförelse, liveness, krypterat personregister och QR-inloggning med SAML. |
| [SAML/WebAuthn-labb](prototype/README.md) | Lokal IdP och SP, testnycklar och simulerad identitetskontroll. |
| [Privat pilotmiljö](deployment/README.md) | Containerpaket för appens verifierare och lokala testtjänst, med TLS, kapacitetsgränser och säker återställning. |
| [Delat register](deployment/cluster/README.md) | PostgreSQL, OpenBao, flera autentiseringsinstanser, operatörsroller och underhåll. |
| [AWS-kompatibilitetstest](deployment/aws/README.md) | Tidsbegränsat RDS-prov med privat databas och automatisk avveckling. |
| [Driftpaket](ops/README.md) | Render-container med hälsokontroller. E-id-funktioner är avstängda. |

Tester använder genererade identiteter och nycklar. Verkliga pass används
endast i en uttryckligen vald privat testmiljö; personuppgifter och hemligheter
får inte läggas i repot. Läs [säkerhetsinformationen](SECURITY.md) och
[komponentregistret](THIRD_PARTY.md).

## Dokumentation

- [Arkitektur](docs/arkitektur.md)
- [OIDC i den privata piloten](docs/oidc-pilot.md)
- [Tekniska krav och verifieringsluckor](docs/krav.md)
- [Utveckling](docs/utveckling.md)
- [Testning](docs/testning.md)
- [Källregister](docs/SOURCES.md)

Kodagenter börjar i [AGENTS.md](AGENTS.md), som hänvisar till projektets
arbetsinstruktioner i `.agents/skills/`.

Namnet openID innebär ingen anknytning till OpenID Foundation eller Digg.

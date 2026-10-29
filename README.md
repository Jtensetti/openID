# openID

Ett projekt för svensk e-legitimation. Repot innehåller en iPhone-app, en
pass- och ansiktsverifierare samt SAML- och OIDC-inloggning med bibliotek från Sweden Connect. Appens
nyckel knyts till personuppgifter från passet. En separat testtjänst
tar emot de uppgifter användaren godkänner att dela.

Projektet är under utveckling och har inget Digg-godkännande. Tillitsnivå 3
är ett mål. Projektlicens, utgivningsvillkor och produktionsansvar återstår.

## Sluten beta

[Projektsidan](https://openid.tensetti.io) är tillgänglig dygnet runt.
Registrering och SAML-/OIDC-legitimering är öppna varje dag **09–17 svensk tid**.
Nya TestFlight-installationer ansluts automatiskt utan VPN. Befintliga privata
serverbindningar behålls. Alla ID:n kräver **manuell aktivering**.

Den publika betan har en separat spärrtjänst och köad e-postavisering.
Spärr utanför öppettiden kräver att innehavaren har hämtat sin spärrkod;
äldre privata ID:n flyttas inte automatiskt. Se
[avisering och spärr](docs/avisering-och-sparr.md) för provade funktioner och begränsningar.
Projektet är inte anslutet till Sweden Connect-federationen.

## Kör och utveckla

| Del | Innehåll |
|---|---|
| [iPhone-app](ios/README.md) | Xcode-projekt med passläsning, fotografering, enhetsnyckel, legitimering och spärr. |
| [Verifierare och testtjänst](verification/README.md) | Passkontroll, ansiktsjämförelse, liveness, krypterat personregister och QR-inloggning med SAML och OIDC. |
| [SAML/WebAuthn-labb](prototype/README.md) | Lokal IdP och SP, testnycklar och simulerad identitetskontroll. |
| [Privat pilotmiljö](deployment/README.md) | Containerpaket för appens verifierare och lokala testtjänst, med TLS, kapacitetsgränser och säker återställning. |
| [Separat spärr och avisering](deployment/continuity/README.md) | Publik betaintegration, operatörens kontaktkontroll och drift utanför testserverns öppettid. |
| [Delat register](deployment/cluster/README.md) | PostgreSQL, OpenBao, flera autentiseringsinstanser, operatörsroller och underhåll. |
| [AWS-kompatibilitetstest](deployment/aws/README.md) | Tidsbegränsat RDS-prov med privat databas och automatisk avveckling. |
| [Driftpaket](ops/README.md) | Render-container med hälsokontroller. E-id-funktioner är avstängda. |

Tester använder genererade identiteter och nycklar. Verkliga pass används
endast i en uttryckligen vald privat testmiljö; personuppgifter och hemligheter
får inte läggas i repot. Läs [säkerhetsinformationen](SECURITY.md) och
[komponentregistret](THIRD_PARTY.md).

## Dokumentation

- [Arkitektur](docs/arkitektur.md)
- [OIDC i piloten](docs/oidc-pilot.md)
- [Anslutning till GrandID: integrationsmål och acceptans](docs/grandid-integration.md)
- [Prövningsunderlag: OIDC, SAML och dokumentunderskrift](docs/provningsunderlag.md)
- [Tekniska krav och verifieringsluckor](docs/krav.md)
- [Diggs 40 tillämpliga kravpunkter](docs/digg-kravmatris.md)
- [Utveckling](docs/utveckling.md)
- [Testning](docs/testning.md)
- [Revision av hela tjänsten](docs/revision.md)
- [Förutsättningar inför bredare utgivning](docs/infor-utgivning.md)
- [Protokoll för fysisk acceptans](docs/fysisk-acceptans.md)
- [iPhone: säkerhetskontroller och kvarstående bevis](docs/iphone-sakerhet.md)
- [Källregister](docs/SOURCES.md)

Kodagenter börjar i [AGENTS.md](AGENTS.md), som hänvisar till projektets
arbetsinstruktioner i `.agents/skills/`.

Namnet openID innebär ingen anknytning till OpenID Foundation eller Digg.

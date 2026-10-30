# openID

Ett projekt för svensk e-legitimation. Repot innehåller en iPhone-app, en
pass- och ansiktsverifierare samt SAML- och OIDC-inloggning med bibliotek från Sweden Connect. Appens
nyckel knyts till personuppgifter från passet. En separat testtjänst
tar emot de uppgifter användaren godkänner att dela.

Projektet är under utveckling och har inget Digg-godkännande. Tillitsnivå 3
är ett mål. Projektlicens, utgivningsvillkor och produktionsansvar återstår.

## Sluten beta

[Projektsidan](https://openid.tensetti.io) är tillgänglig dygnet runt.
Testservern för registrering och SAML-/OIDC-legitimering är öppen **dygnet runt
till och med 30 november 2026**. Den stängs av **1 december 2026 kl. 00.00
svensk tid**. Se [betans driftplan](deployment/README.md#betans-öppettider).
Nya TestFlight-installationer ansluts automatiskt utan VPN. Befintliga privata
serverbindningar behålls. Det valbara [TestFlight-testläget](docs/testflight-beta.md)
aktiverar test-ID:n efter godkända kontroller, utan e-postkrav, och behåller
dem till betans slut med passets giltighet som övre gräns. Standardläget
kräver manuell aktivering. Automatiken infördes i den publika betan den
29 oktober 2026. Äldre väntande eller utgångna ID:n aktiveras inte av en
statushämtning. Se [appens utgåvor](ios/README.md#utgåvor) för skillnaden
mellan TestFlight-piloten och nästa utvecklingsbygge.

Den publika betan har en separat spärrtjänst. Standardläget har köad
e-postavisering; det automatiska testläget visar aktiveringen i appen.
Spärr när testservern är avstängd kräver att innehavaren har hämtat sin spärrkod;
äldre privata ID:n flyttas inte automatiskt. Se
[avisering och spärr](docs/avisering-och-sparr.md) för provade funktioner och begränsningar.
Projektet är inte anslutet till Sweden Connect-federationen.

## Repository och åtkomst

Repot är privat sedan 30 oktober 2026. Projektsidan och betans testsida har
separat hosting; repoändringen publicerar eller stänger inte dessa tjänster.
GitHubs nuvarande plan verkställer inte skyddsregler i det privata repot.
PR och godkänd CI ska därför kontrolleras av förvaltaren före merge; se
[repoägarskap och kontroller](docs/utveckling.md#obligatoriska-kontroller-och-repoägarskap).

## Kör och utveckla

| Del | Innehåll |
|---|---|
| [iPhone-app](ios/README.md) | Xcode-projekt med passläsning, fotografering, enhetsnyckel, legitimering och spärr. |
| [Verifierare och testtjänst](verification/README.md) | Passkontroll, ansiktsjämförelse, liveness, krypterat personregister och QR-inloggning med SAML och OIDC. |
| [SAML/WebAuthn-labb](prototype/README.md) | Lokal IdP och SP, testnycklar och simulerad identitetskontroll. |
| [Privat pilotmiljö](deployment/README.md) | Containerpaket för appens verifierare och lokala testtjänst, med TLS, kapacitetsgränser och säker återställning. |
| [Separat spärr och avisering](deployment/continuity/README.md) | Publik betaintegration, operatörens kontaktkontroll och drift även när testservern är avstängd. |
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
- [Sammanföring, releasekandidat och återgång](docs/releasekandidat.md)
- [Revision av hela tjänsten](docs/revision.md)
- [Förutsättningar inför bredare utgivning](docs/infor-utgivning.md)
- [Protokoll för fysisk acceptans](docs/fysisk-acceptans.md)
- [iPhone: säkerhetskontroller och kvarstående bevis](docs/iphone-sakerhet.md)
- [Källregister](docs/SOURCES.md)

Kodagenter börjar i [AGENTS.md](AGENTS.md), som hänvisar till projektets
arbetsinstruktioner i `.agents/skills/`.

Namnet openID innebär ingen anknytning till OpenID Foundation eller Digg.

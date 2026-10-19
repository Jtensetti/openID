# Driftpaket: stängd produktionsgrund

Det här paketet kan etablera en separat container med HTTP-hälsokontroller.
**Det är inte en fungerande produktions-e-legitimation.** Det innehåller ingen
IdP, testnyckel, testidentitet, databas, personuppgift, adminfunktion eller
konfigurationsflagga som kan öppna e-id-utgivning. Autentiseringsprototypen
körs separat enligt [prototype/README.md](../prototype/README.md).

Status: lokala Java/HTTP-tester körda. Extern Render-resurs är ännu inte skapad.
Render-installationen är bekräftad, men anslutningens anropsverktyg har inte
exponerats i arbetssessionen. Ingen extern driftsättning, kostnad eller URL
påstås vara verifierad. Containerverifieringen körs dessutom i GitHub Actions.

## Köra lokalt

```sh
docker compose -f ops/compose.yaml up --build -d
curl --fail http://127.0.0.1:8080/health/live
curl -i http://127.0.0.1:8080/health/ready
docker compose -f ops/compose.yaml down
```

`/health/live` ger 200 när processen är igång, med `status=SEALED` och
`eidIssuanceEnabled=false`. `/health/ready`, `/login`, SAML/OIDC och alla andra
vägar ger **503**. Grön liveness betyder inte att e-id-tjänsten är redo.
Containern kör som UID/GID 10001, med skrivskyddat filsystem, begränsat minne,
antal processer och CPU, utan Linux capabilities och på ett internt nät.
Endast värddatorns loopback exponeras i Compose.

Direkta tester utan Docker, med JDK 21:

```sh
python3 -m unittest discover -s ops/tests -v
```

De startar en riktig HTTP-process och kontrollerar liveness/readiness,
förbjudna autentiseringsvägar, metoder, miljövariabler, konfigurationsfel och
frånvaro av requestinnehåll i loggen. `JAVA_HOME` måste vara satt.

## Render-konfiguration

[render.yaml](../render.yaml) definierar projekt `openID`, miljö `production`
och tjänst `openid-production-sealed` i Frankfurt. Byggkontexten är enbart
`ops/`; `.dockerignore` tillåter bara en Java-källfil och Dockerfile.
Automatiska deployer är avstängda. Välj exakt CI-verifierad commit för en
manuell bootstrap-deploy. Denna tjänst behöver inga hemligheter eller diskar.

Blueprinten använder `free` för att kunna etablera den stängda grunden utan
ett nytt betalåtagande. Det valet uppfyller inte tillgänglighets-/kapacitetskrav
för en riktig e-id-tjänst; driftplan, kostnadsram, bemanning och granskad
leverantörskedja måste beslutas innan en sådan tjänst öppnas. Regionvalet är
inte i sig ett bevis på fullständig datalokalisering eller avtalsefterlevnad.

Render terminerar extern TLS. Dess hälsokontroll ska använda `/health/live`;
e-id-readiness ska fortsatt mätas separat som 503. Compose-regler för read-only,
capabilities och nät är **inte** ett påstående om att Render tillämpar samma
inställningar. Verifiera leverantörens faktiska isolering separat.

Vid driftsättning ska tjänstens ID, region, konfiguration, commit, deploy-ID,
URL och verkliga HTTPS-resultat skrivas i ett separat evidensavsnitt här.
Återgång innebär manuell deploy av föregående verifierade **stängda** commit;
en lyckad kodrollback säger inget om återläsning av framtida identitetsdata.

## Produktionsöppning som återstår

AGENTS.md och `supply-chain-and-release` kräver ett mänskligt beslut med
oberoende granskningsunderlag för säkerhetskritisk e-id-produktionsrelease.
Den här bootstrap-containern kan inte kringgå det med en miljövariabel.

Före faktisk e-id-drift återstår bland annat verklig utgivning och
autentiseringsbärare, separerade befogenheter även i databas/CI, HSM och
nyckelceremonier, oberoende bevislagring, distribuerad spärr, underskrift,
kapacitets-/kontinuitetstester, incident/supportorganisation, projektlicens,
avtal och relevanta beslut. Se kravmatrisen; inget formellt kriterium
har självattesterats som ACCEPTED.

## Komponenter och underlag

Temurin 21.0.12.1+1 (JDK för bygge, JRE för drift) på Ubuntu Noble låses med
fulla image-digests i Dockerfile. Inga Maven- eller npm-beroenden används här.
Den officiella basimagen bevarar JRE:ns licenser och `legal/`; källor och
licensgränser redovisas i [THIRD_PARTY.md](../THIRD_PARTY.md).

Kontrollerade primärkällor 2026-10-19:

- [Render Blueprint-fält](https://render.com/docs/blueprint-spec)
- [Render hälsokontroller](https://render.com/docs/health-checks)
- [Docker runtime och resurser](https://docs.docker.com/engine/containers/run/)
- [Officiella Temurin-containrar](https://github.com/adoptium/containers)

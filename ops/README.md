# Driftpaket: stängd produktionsgrund

Det här paketet kan etablera en separat container med HTTP-hälsokontroller.
**Det är inte en fungerande produktions-e-legitimation.** Det innehåller ingen
IdP, testnyckel, testidentitet, databas, personuppgift, adminfunktion eller
konfigurationsflagga som kan öppna e-id-utgivning. Autentiseringsprototypen
körs separat enligt [prototype/README.md](../prototype/README.md).

Status 2026-10-19: driftsatt och `live` i Render. [Extern liveness](https://openid-production-sealed.onrender.com/health/live)
svarar 200/SEALED. Samtliga 13 externa HTTPS-kontroller passerade med
certifikatvalidering och utan redirects. Readiness och autentisering är
fortsatt stängda. Lokala tester och containerverifieringen i GitHub Actions
har också passerat; se evidensen nedan.

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
och tjänst `openid-production-sealed` i Frankfurt. Den driftsatta tjänsten
skapades direkt i arbetsytan **OpenID** via Render-anslutningen. Blueprinten
har inte synkats; projekt-/miljögrupperingen är därför inte etablerad eller
verifierad av denna driftsättning. Byggkontexten är enbart
`ops/`; `.dockerignore` tillåter bara en Java-källfil och Dockerfile.
Automatiska deployer är avstängda. Välj exakt CI-verifierad commit för en
manuell bootstrap-deploy. Denna tjänst behöver inga hemligheter eller diskar.

Blueprinten använder `free` för att kunna etablera den stängda grunden utan
ett nytt betalåtagande. Det valet uppfyller inte tillgänglighets-/kapacitetskrav
för en riktig e-id-tjänst; driftplan, kostnadsram, bemanning och granskad
leverantörskedja måste beslutas innan en sådan tjänst öppnas. Regionvalet är
inte i sig ett bevis på fullständig datalokalisering eller avtalsefterlevnad.

Render terminerar extern TLS. Blueprinten anger HTTP-kontroll på `/health/live`,
men anslutningens verktyg kan inte konfigurera detta fält. Den faktiska
tjänsten använder därför **TCP-hälsokontroll** (`healthCheckPath` är tom).
Separata HTTPS-kontroller verifierar 200/SEALED och e-id-readiness 503.
HTTP-kontrollen kan senare konfigureras via Render Dashboard/API eller en
granskad Blueprint-synk. Compose-regler för read-only,
capabilities och nät är **inte** ett påstående om att Render tillämpar samma
inställningar. Verifiera leverantörens faktiska isolering separat.

Återgång innebär manuell deploy av föregående verifierade **stängda** commit;
en lyckad kodrollback säger inget om återläsning av framtida identitetsdata.

## Faktisk driftsättning och verifiering

| Fält | Verifierat värde |
|---|---|
| Tjänst | `srv-dbb01e49v7es73a6bvr0` |
| Deploy | `dep-dbb01es9v7es73a6c2k0`, `live` sedan 2026-10-19 11:37:09 UTC |
| Källrevision | `0299d31b458fd72b2251dc2cc192858e66beab45` |
| Region/plan | Frankfurt, `free`, en instans |
| Automatiska deployer | `off` |
| HTTPS | `https://openid-production-sealed.onrender.com` |
| Render-vy | [Tjänstens dashboard](https://dashboard.render.com/web/srv-dbb01e49v7es73a6bvr0) |

[Provideruppgifter](evidence/render-deployment.json) bygger på Render API:s
tjänst-/deploysvar och startloggen. [HTTPS-resultaten](evidence/render-https.json)
visar 13 kontroller: 200 på exakt `GET /health/live`, 503 på readiness,
autentiseringsvägar, testmaterial, query-aktivering, POST och HEAD. JSON-status,
cacheförbud och säkerhetsheaders kontrollerades också. Mätningen är ett
funktionstest från en klient, ingen kapacitets- eller tillgänglighetsmätning.

Kör om kontrollen från repots rot med Python 3; inga extra paket krävs:

```sh
python3 ops/verify_https.py https://openid-production-sealed.onrender.com
```

Skriptet returnerar exitkod 0 bara när alla kontroller passerar. Inga
autentiseringsuppgifter skickas. Gratisplanens viloläge kan ge långsam första
respons; ett misslyckat prov ska undersökas, inte döljas som godkänt.

Den driftsatta revisionens [labb-CI](https://github.com/Jtensetti/openID/actions/runs/39244622805)
och [container-CI](https://github.com/Jtensetti/openID/actions/runs/39244622896)
passerade. Render byggde själv från samma revision; CI:s lokala image-ID är
inte en attestering av Render-imagens digest. Den här första driftsättningen
har ingen tidigare live-version att återgå till. Senare dokumentations- och
verifieringsskriptändringar uppdaterar inte tjänsten när auto-deploy är av.

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
- [Render gratisplanens driftbegränsningar](https://render.com/docs/free)
- [Docker runtime och resurser](https://docs.docker.com/engine/containers/run/)
- [Officiella Temurin-containrar](https://github.com/adoptium/containers)

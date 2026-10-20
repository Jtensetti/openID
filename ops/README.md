# Driftcontainer

Container med hälsokontroller, utan e-id-funktioner. Autentiseringslabben
körs separat enligt [prototype/README.md](../prototype/README.md).

## Kör lokalt

```sh
docker compose -f ops/compose.yaml up --build -d
curl --fail http://127.0.0.1:8080/health/live
curl -i http://127.0.0.1:8080/health/ready
docker compose -f ops/compose.yaml down
```

`GET /health/live` ger 200 med `status=SEALED` och
`eidIssuanceEnabled=false`. Readiness, autentisering och övriga routes
ger 503. Compose använder UID/GID 10001, skrivskyddat filsystem,
resursgränser, inga Linux capabilities och internt nät med loopbackport.

Med JDK 21 och `JAVA_HOME` satt:

```sh
python3 -m unittest discover -s ops/tests -v
```

Testerna provar hälsokontroller, nekade routes/metoder, miljövariabler,
konfigurationsfel och loggning över HTTP.

## Render

Senast dokumenterade driftsättning, 2026-10-19:

| Fält | Värde |
|---|---|
| Tjänst | `srv-dbb01e49v7es73a6bvr0` |
| Deploy | `dep-dbb01es9v7es73a6c2k0`, live sedan 11:37:09 UTC |
| Källrevision | `0299d31b458fd72b2251dc2cc192858e66beab45` |
| Region/plan | Frankfurt, free, en instans |
| Auto-deploy | Av |
| HTTPS | https://openid-production-sealed.onrender.com |
| Dashboard | https://dashboard.render.com/web/srv-dbb01e49v7es73a6bvr0 |

[render.yaml](../render.yaml) har inte synkats, så dess projekt- och
miljögruppering är inte etablerad. Byggkontexten är `ops/`;
`.dockerignore` släpper bara igenom Java-källfilen och Dockerfile.
Driftsättning görs manuellt från en CI-verifierad commit. Inga hemligheter
eller diskar behövs.

Render terminerar TLS. Den dokumenterade tjänsten använder TCP-hälsokontroll.
Blueprinten anger HTTP på `/health/live`; detta kräver separat synkning eller
konfiguration i Dashboard/API. Compose-reglerna för isolering är inte
verifierade i Render.

Gratisplanen täcker inte tillgänglighets- eller kapacitetskrav för e-id-drift.
Driftkrav och kvarstående kontroller finns i [kravöversikten](../docs/krav.md).

## Verifiering

[Provideruppgifter](evidence/render-deployment.json) och
[HTTPS-resultat](evidence/render-https.json) dokumenterar 13 godkända kontroller
med certifikatvalidering: exakt GET på liveness ger 200; readiness,
autentisering, testmaterial, query-aktivering, POST och HEAD ger 503.
Cacheförbud och säkerhetsheaders kontrolleras också.

Kör om från repots rot:

```sh
python3 ops/verify_https.py https://openid-production-sealed.onrender.com
```

Exitkod 0 kräver att alla kontroller passerar. Gratisplanens viloläge kan
fördröja första svaret.

[Labb-CI](https://github.com/Jtensetti/openID/actions/runs/39244622805) och
[container-CI](https://github.com/Jtensetti/openID/actions/runs/39244622896)
passerade på den driftsatta revisionen. Render byggde från samma commit;
dess image-digest har inte attesterats. Senare kodändringar driftsätts inte
automatiskt.

## Komponenter

Temurin 21.0.12.1+1 på Ubuntu Noble låses med image-digests i Dockerfile.
Basimagen bevarar JRE-licenserna. Inga Maven- eller npm-paket används.
Se [THIRD_PARTY.md](../THIRD_PARTY.md).

Releasekrav finns i [SECURITY.md](../SECURITY.md).

Källor kontrollerade 2026-10-19:
[Blueprint](https://render.com/docs/blueprint-spec),
[hälsokontroller](https://render.com/docs/health-checks),
[gratisplan](https://render.com/docs/free),
[Docker runtime](https://docs.docker.com/engine/containers/run/),
[Temurin](https://github.com/adoptium/containers).

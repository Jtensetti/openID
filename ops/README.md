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

[render.yaml](../render.yaml) beskriver driftcontainern. Byggkontexten är
`ops/`; `.dockerignore` släpper bara igenom Java-källfilen och Dockerfile.
Driftsätt från en CI-verifierad commit. Inga hemligheter eller diskar behövs.
Render terminerar TLS; konfigurera HTTP-hälsokontroll på `/health/live`.
Compose-reglerna för isolering gäller inte automatiskt hos en molnleverantör.
Kontrollera den valda driftmiljön separat.

## Verifiering

Kör mot den egna driftsättningens HTTPS-adress från repots rot:

```sh
python3 ops/verify_https.py https://your-service.example
```

Verifieraren kontrollerar certifikat, hälsosvar, nekade autentiseringsvägar,
cacheförbud och säkerhetsheaders. Exitkod 0 kräver att alla kontroller passerar.
Spara körresultat med revision och miljö som CI-artefakt eller i releaseärendet.
Aktuella tjänste-ID:n och drifthistorik hör till driftsättningens inventarium.

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

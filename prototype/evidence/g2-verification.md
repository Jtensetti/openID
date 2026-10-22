# Historisk verifiering: lagring och driftcontainer

Rapport från [PR #2](https://github.com/Jtensetti/openID/pull/2), 2026-10-19.
Omfattning och antal nedan gäller den revisionen. Aktuella körningar finns i
[testöversikten](../../docs/testning.md). Maskinrapporter och låsfiler kan ha
uppdaterats efter denna körning; äldre versioner finns i Git-historiken.

## Implementation

- `SyntheticRegistry` + `RegistryStore`: SQLite 3.53.4, privat katalog, exklusivt
  processlås, schema-/integritetskontroll, atomisk status/spärrversion/audit och
  stängd autentisering vid lagringsfel. Normal omstart behåller giltighet och
  spärrar; ingen automatisk reseed eller förlängning av giltighet.
- SQLite `VACUUM INTO` för konsekvent backup. Restore till ny katalog skapar
  nya testnycklar och spärrar samtliga återställda credentials. Även oordnad
  processavslutning leder till spärr före nästa autentisering.
- SP registrerar terminalt utfall med SHA-256-fingeravtryck av den slumpmässiga
  SAML-begärans ID, via JDK:s `MessageDigest`. Inga identitetsattribut, cookies,
  råa assertions eller dokument sparas i denna händelsetabell. Det är en
  referensfunktion, ingen egen kryptografisk primitiv eller signaturkedja.
- `OfflineReport`: dubblett-/konfliktkontroll och intern kalenderavstämning i
  Europe/Stockholm. Alla händelser är syntetiska och ger exakt noll
  ersättningsgrundande transaktioner. Ingen extern rapporteringskod finns.
- Separat `ops/`-container med enbart JDK/HTTP-kod. Liveness 200 och explicit
  SEALED; readiness och samtliga autentiseringsvägar 503. Den innehåller inte
  labbkod, syntetiska identiteter eller testnycklar. Render Blueprint finns.

## Körda kontroller

| Kontroll | Faktiskt resultat |
|---|---|
| Maven `clean verify` och slutlig `verify` | 80 JUnit-fall, 0 fel, 0 överhoppade: 45 HTTPS/SAML, 13 livscykel, 16 beständig lagring, 6 rapportering. |
| `scripts/dependencies.py` | 171 exakta versioner och JAR-SHA-256 verifierade. |
| Paketerad `scripts/smoke.py` | Start/init, verifierad TLS och komplett syntetiskt SAML-flöde godkänt. |
| `scripts/recovery-smoke.py` | Riktiga separata JVM-starter, beständig spärr, äldre backup, nya nycklar, faktisk SIGKILL och fail-closed återstart godkänt. Offline-rapport 1 genomförd testinloggning, 1 nekat svar, 0 ersättningsgrundande. |
| `npm run test:browser` | Chromium: inloggning, automatiskt POST-svar, Origin, utloggning, nekad credential och aktiv sessionsspärr godkänt. |
| `python3 -m unittest discover -s ops/tests -v` | 6 verkliga HTTP/processtester godkända. Negativa vägar, metoder, aktiveringsförsök via miljövariabler, fel port, loggkanariefågel och verifierad timeout för ofullständig request. |
| OSV | 171 Maven-artefakter, inga publicerade fynd vid kontrolltillfället; se `osv.json`. |
| Docker-image | Docker/Podman saknas på arbetsvärden. [GitHub Actions](https://github.com/Jtensetti/openID/actions/runs/39244622896) byggde och testade den driftsatta källrevisionen med nät avstängt, read-only, non-root och borttagna capabilities: godkänt. |
| Render-deploy | `dep-dbb01es9v7es73a6c2k0` blev `live` 2026-10-19 11:37:09 UTC, från revision `0299d31b458fd72b2251dc2cc192858e66beab45`. Frankfurt/free, auto-deploy av, TCP-hälsokontroll. [Faktisk konfiguration](https://github.com/Jtensetti/openID/blob/a20803b/ops/evidence/render-deployment.json). |
| Extern HTTPS | 13 kontroller godkända med certifikatvalidering och utan redirects: liveness 200/SEALED, readiness och autentiseringsvägar 503, testmaterial otillgängligt, aktivering via query/POST nekad, säkerhetsheaders bevarade. [Maskinläsbart resultat](https://github.com/Jtensetti/openID/blob/a20803b/ops/evidence/render-https.json), [omkörning](../../ops/README.md). |

Maskinläsbara JUnit-fall: [test-results.json](test-results.json). Nya tester
utökar den tidigare G1-körningen; äldre [verification.md](verification.md)
är en historisk rapport om den föregående etappen.

## Kravkoppling och återstående kriterier

| Krav/fall | Vad evidensen visar | Vad den inte visar |
|---|---|---|
| ID-06/09/10, NEG-04/05 | Giltighet, spärr och ersättning består över omstart; konkurrerande revoke är idempotent; ersättning och gammal spärr skrivs atomiskt. | Verklig innehavarbindning, distribuerad konsistens eller dygnet-runt-organisation. |
| ID-08, OPS-07 | Äldre backup och krasch kan inte återuppliva credentials; nytt testnyckelmaterial vid restore. | Full återställningskanal för en människa, återupptagen tillgänglighet med bibehållen säkerhet, RTO/RPO eller HA. |
| GOV-07, NEG-06 | Ingen nätverksväg för utgivning/reset; databasens vanliga UPDATE/DELETE kan inte ändra audit/utfall. | Oberoende roller: samma OS-/databasägare kan kringgå triggers och ändra kod. Därför är kravet öppet. |
| FIN-01/02, INT-03, NEG-09 | Syntetiska lyckade, felaktiga, avbrutna och duplicerade modellhändelser kan inte bli ersättningsanspråk. Fel period och årsskifte provas. | Digg-schema, offentlig motparts-/avtalsklassificering, underskrift, rättelse eller insändning. SP räknar avbrutna svar som FAILED; särskiljning är ännu inte implementerad. |
| FIN-03, NEG-10 | Ingen insändningsmöjlighet introduceras. | Lokal transportstub med timeout/kvittens är **inte implementerad eller körd**; endpoint, API-header och idempotens får inte gissas. |
| SEC-03, INT-06 | Låst SQLite-version, licens/underhållskontroll, uppdaterad JAR-graf/SBOM; pinnade Temurin-image-digests. | Full OS/JRE/container-sårbarhetsskanning eller oberoende leveranskedjegranskning. |
| INT-02/04, TEST-01 | Separat produktionsartefakt saknar IdP, testdata och aktiveringsflagga. Negativa HTTP-fall provas. | En öppnad produktions-e-id eller godkänd säkerhetskritisk release. |

Upstream-frågan om Response IssueInstant och audit-autokonfiguration kvarstår
från G1. Livscykelloggen är inte en ersättning för ett komplett,
oberoende skyddat säkerhetsloggningssystem. Oberoende granskare och
produktionsförvaltare är ännu inte utsedda.

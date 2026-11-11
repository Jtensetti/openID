# Sammanhängande driftplattform

Den här profilen är den enda kandidaten för Tjipps samlade drift. Den ersätter
den tidigare SQLite-/socket-vault-kompositionen med PostgreSQL och OpenBao
Transit. Nyregistrering är stängd. Profilen är under verifiering och har inget
tillstånd att utfärda e-legitimationer.

Samma version ska kunna granskas och senare importeras utan ombygge. Kod,
lokalt prov, CI-resultat, installerade image-ID:n och formellt driftbeslut är
skilda bevis. Röd leveransgrind stoppar driftsättning.

## Tjänster och gränser

| Tjänst | Identitet | Åtkomst |
| --- | --- | --- |
| postgres | 999:999 | Egen data och TLS/SCRAM-konfiguration; loopback 15432 |
| openbao | 10008:20008 | Egen Raft-data, maskad revisionslogg och TLS; loopback 18210/18211 |
| credential-rotator | 0:0, endast CHOWN | Instansroll till STS; två separata kortlivade sessioner; inga register-, profilnyckel- eller IPC-monteringar |
| verifier | 10001:20010, grupp 20004 | PG-utfärdanderoll, begränsad Transit-token och spärrsocket; stängt insamlings-API 8767 |
| wallet | 10006:20011, grupp 20004 | PG-plånboksroll, egen Transit-token och spärrsocket; appens autentiserings-API 8768 |
| bridge | 10009:20001, grupper 20003/20004 | Egen PG-inloggning/Transit-token; federations- och aviseringssocketar |
| continuity | 10007:20004 | PG-kontrollroll; endast den externa spärrfunktionen via egen AWS-session |
| idp | 10002:20001 | Egna TLS-/signerings-/krypteringsnycklar, separat metadatatillstånd; loopback 9443 |
| sp | 10003:20001 | Egna TLS-/SP-nycklar; loopback 9444 |
| notice-exporter | 10004:20003 | Endast opaka köhändelser via socket och egen SQS-session; inget register eller profilnyckel |

[compose.yaml](compose.yaml) är kördefinitionen. [contract.py](contract.py)
samlar kontrollerade identiteter, monteringar, kommandon och resursgränser.
Alla tre importerade image-ID:n måste vara fullständiga SHA-256-ID:n och
`pull_policy: never` gäller. Gemensam appimage används av åtta tjänster;
PostgreSQL 18.6 och OpenBao 2.7.1 har egna digestbundna källor. Ett komplett
leveranspaket och OS-bedömning för samtliga tre images återstår innan release;
den befintliga en-image-importören är inte ett sådant paket.

Varje tjänst har skrivskyddad rot, borttagna Linux-förmågor, skydd mot
privilegieförhöjning, begränsade resurser och avstängda minnesdumpar.
Endast rotationsprocessen behåller CHOWN för filöverlämning. Inga kodöverlägg,
delade datakataloger eller miljövariabler med permanenta AWS-nycklar ingår.

## Värd, ingress och externa beroenden

Profilen kräver en Linux x86_64-värd med Docker Compose, nftables,
Landlock ABI 3 och seccomp. Alla containrar använder värdens nät.
Nginx enligt [nginx.conf.in](nginx.conf.in) är den publika ingången:
tre olika HTTPS-värdnamn och verifierad TLS till varje bakomliggande tjänst.
Appens `/native/` går till verifieraren och `/wallet/` till plånboken.
Endast ingressens HTTPS och avsedd administration öppnas externt.
Nginx normaliserar appens klientadresshuvud.

[AWS-instruktionen](aws.md) beskriver Stockholm-värden, diskar, IAM och
startskydd. Instansrollen får anta exakt två klientroller. Endast continuity
får anropa den valda spärrfunktionen; endast notice-exporter får skicka till
den valda kön. SDK:n använder enbart respektive paketerade credential-process,
läser en ägarskyddad fil och förnyar den kortlivade sessionen före utgång.
Filbyte sker atomiskt i separata kataloger. Rotatorn läser endast IMDSv2.

Värdens [metadatafilter](metadata_guard.py) blockerar både
`169.254.169.254` och `fd00:ec2::254` för samtliga UID utom root.
[tjipp-metadata.service](tjipp-metadata.service) installerar filtret innan
Docker. [docker-metadata.conf](docker-metadata.conf) kräver enheten och
kontrollerar filtret på nytt vid varje Dockerstart. Värdens rootadministration
och rotator är betrodda. Filseparation och databasroller ersätter inte
oberoende mänsklig kontroll eller HSM.

Separat spärr-API, privat spärrfunktion, DynamoDB-ledger, SQS/felkö,
kontaktbindning och faktisk aviseringsleverans ingår i driftgränsen.
[Spärrstacken](../continuity/README.md) ska ha ett nytt namn-/behörighetsutrymme
med `TestBeta=false`. Återanvänd inte de avvecklade pilotregistren.
Saknad spärrtjänst får inte ersättas med lokal ACTIVE-status.

Den deklarerade summan av tjänsternas minnesgränser är 5248 MiB.
Värdkontrollen kräver ytterligare minst 1024 MiB för värden samt ingen swap.
En 8 GiB-värd är utgångspunkt; ett godkänt kapacitetsprov på verklig värd
återstår. Gränserna är inte en genomströmnings- eller tillgänglighetsgaranti.
En värd och en Raft-nod innebär gemensamma felpunkter. Autoskalning ingår inte;
NFC-/proofingprocessen har avsiktligt en arbetare.

## Privat konfiguration och nycklar

All privat konfiguration ligger utanför repot i `$TJIPP_DIRECTORY`.
`check.py settings` kontrollerar den exakta filuppsättningen, ägare, grupper,
lägen, fasta sökvägar och sammanhängande inställningar. Symboliska länkar,
delade roller, öppnad registrering och gamla beta-flaggor avvisas.

| Sökväg | Ägare och läge |
| --- | --- |
| services/{verifier,wallet,bridge,continuity,credential-rotator} | Respektive tjänsts UID:GID; katalog 0700, privata filer 0600 |
| postgres/config, postgres/data | 999:999, 0700; konfigurationsfiler 0600 |
| openbao/config, openbao/data, openbao/audit | 10008:20008, 0700; konfigurationsfiler 0600 |
| ipc/continuity | 10007:20004, 2710 |
| ipc/federation, ipc/notice | 10009:20001 respektive 10009:20003, 2710 |
| aws/continuity, aws/notices | root:20004 respektive root:20003, 2710 |
| aws/*/session.json | Mottagarens UID:GID, 0600; endast kortlivad STS-session |
| federation-idp, federation-sp | 10002:20001 respektive 10003:20001, 0700; filer 0600 |
| federation-state | 10002:20001, 0700; endast metadatatillstånd |
| origins.json, federation.json, public/{idp,sp}.pem | root:root, 0644 |

Tjänsternas exakta filnamn finns i `PRIVATE_FILES` i
[kontraktet](contract.py). Utgå från respektive `*.example.json`.
Databasens anslutningsfil innehåller tjänstens egen inloggning och
`sslmode=verify-full`. Schema och operatorinloggningar provisioneras separat
enligt [PG-instruktionen](../cluster/README.md); tjänsterna skapar dem inte.
Verifierare och plånbok behöver **samma appkopplingskod**, med var sin skyddad
filkopia. Metrics-hemligheter är separata. TLS-nycklar återanvänds inte.

OpenBao startas med TLS och beständig Raft, aldrig `-dev`. Initiering,
unseal, audit, Transit-nycklar och avgränsade tjänstetokens provisioneras
separat under beslutad nyckelhantering. Starten initierar eller låser inte
upp tjänsten och återfaller inte till rånyckelfil eller root-token.
OpenBao använder inte mlock; värdens swap ska vara avstängd och tjänstens
minnes- och swapgräns ska vara lika. Den gamla inställningen
`disable_mlock` används inte. Se [OpenBaos driftanvisning](https://openbao.org/docs/install/).

**Obevakad drift är ännu inte verifierad.** Inför och prova förnyelse av
OpenBao-tokens med ägarskyddat filbyte, utgång/återinloggning, planerad
unseal-beredskap, maskad loggrotation, nyckelceremoni och samordnad
PG-/Raft-återställning. De entimmes-tokens som genereras i det syntetiska
CI-provet är ingen varaktig driftlösning. Rotatorn för AWS-sessioner löser
en annan åtkomstkedja. Behöriga verkliga personer och mandat återstår.

### Federation

`federation.json` väljer `private` eller `sweden-connect-sandbox` och monteras
skrivskyddad i IdP, SP och bridge. Inget läge intygar en tillitsnivå.

| Katalog | Exakt filuppsättning |
| --- | --- |
| federation-idp | tls.p12, tls.password, idp.p12, idp.password, encryption.p12, encryption.password, sp.crt, subject-secret |
| federation-sp | tls.p12, tls.password, sp.p12, sp.password, idp.crt, idp-encryption.crt |

PKCS#12 innehåller exakt en privat nyckel med alias `tls`, `idp`,
`encryption` respektive `sp`. Separata lösenordsfiler och `subject-secret`
innehåller 43–128 slumpmässiga URL-säkra tecken. Bevara `subject-secret` över
omstart. Giltiga RSA-certifikat om minst 3072 bitar krävs; interna
TLS-certifikat täcker localhost och 127.0.0.1. TLS, IdP-signering,
IdP-kryptering och SP har olika nycklar. Saknade filer stoppar starten.

Till nginx exporteras endast interna TLS-certifikat:
`/etc/nginx/tjipp-api-tls.crt`, `tjipp-wallet-tls.crt`,
`tjipp-idp-tls.crt` och `tjipp-sp-tls.crt`. Publik HTTPS har separat kedja
och nyckel under `/etc/letsencrypt/live/tjipp/`.

Sandboxprofilen hämtar den fasta signerade SAML-SP-feeden från
`https://md.sandbox.swedenconnect.se/metadata/mdx/role/sp.xml` och verifierar
den med certifikatet i jar-filen, SHA-256
`86b5306355636b184de4b0e29c7c417429ece79164fb4680acf0b5f28b1cc0ea`.
Endast testsp1, testsp2 och test-signservice1 under
`https://testclient.sandbox.swedenconnect.se/` tillåts utöver egen SP.
Begäran och appgodkännande binds till exakt mottagare. SP2 får inget
personnummer. Foto, passnummer och interna register-ID:n lämnas inte ut.
Faktiskt externt anslutningsprov återstår. Sweden Connects OIDC-federation
ingår inte här; egen SP:s befintliga OIDC-flöde behålls.

Nyckeladaptern för federation är filbaserad. Kontotjänstens
dokumentunderskrift använder test-CA i processminnet; begränsningarna i
[PDF-instruktionen](../../docs/pdf-underskrift.md) gäller även här.
Detta ger ingen kvalificerad underskrift eller verifierad LoA 1–4.

## Granskad start

1. Slutför leveransgrinden, bedöm samtliga images och bevara källrevision,
   CI-körning, manifesthash, image-ID:n och godkänd konfiguration. Importera
   samma kompletta granskade leverans utan ombygge. Säkerhetskritisk release
   kräver oberoende granskning och behörigt mänskligt beslut.
2. Provisionera privata filer, PG-roller, OpenBao och externa beroenden.
   Inför värdens volym- och metadataenheter före Dockerstart enligt
   [värdinstruktionen](aws.md). Prova startfel och återhämtning.
3. Kontrollera faktiska filer, värden, Compose och ingress:

```sh
export TJIPP_DIRECTORY=/srv/tjipp
export TJIPP_IMAGE_ID=sha256:REPLACE_WITH_VERIFIED_APP_IMAGE_ID
export TJIPP_POSTGRES_IMAGE_ID=sha256:REPLACE_WITH_VERIFIED_POSTGRES_IMAGE_ID
export TJIPP_OPENBAO_IMAGE_ID=sha256:REPLACE_WITH_VERIFIED_OPENBAO_IMAGE_ID
export TJIPP_NOTICE_QUEUE_URL=https://sqs.eu-north-1.amazonaws.com/ACCOUNT/QUEUE
sudo python3 deployment/production/check.py host
sudo python3 deployment/production/check.py settings --directory "$TJIPP_DIRECTORY"
docker compose -f deployment/production/compose.yaml config --format json |
  python3 deployment/production/check.py compose --image-id "$TJIPP_IMAGE_ID" --directory "$TJIPP_DIRECTORY"
sudo python3 deployment/production/ingress.py --directory "$TJIPP_DIRECTORY" > /privat/tjipp-nginx.conf
```

Installera granskad nginxkonfiguration, kör `nginx -t` och prova
certifikatförnyelse. Vid beslutat påslag startas först PG/OpenBao;
behöriga personer låser upp OpenBao. Därefter:

```sh
docker compose -f deployment/production/compose.yaml up -d --wait
docker compose -f deployment/production/compose.yaml ps
```

Kontrollera faktiska image-ID:n, tjänsteidentiteter, rättigheter, blockerad
metadataåtkomst och stängda interna portar. Kör samma syntetiska
inloggnings-/underskrifts-/spärrprov genom ingressen. Prova aviseringsleverans
till en beslutad mottagare; SQS-kvittens bevisar bara kömottagning.
Prova återställning med senare spärrar bevarade och mät avbrottstid.
CI ersätter inte fysisk telefon, verklig registeranslutning, kapacitetsprov,
organisatorisk kontroll, oberoende granskning eller Diggs beslut.

## Automatiska prov

```sh
python3 -m unittest discover -s deployment/production -p 'test_*.py' -v
python3 deployment/test_beta_nginx.py --configuration deployment/production/nginx.conf.in
```

Compose-proven renderar den faktiska filen med Docker och körs obligatoriskt
i Linux-CI. De hoppas uttryckligen över lokalt när Docker saknas.

[runtime_probe.py](runtime_probe.py) kör endast på en disponibel Linux-runner
som root med GITHUB_ACTIONS=true. Det tillför tillfälliga lokala IMDS-adresser,
nftables-regler och syntetiska DNS-/TLS-rötter. **Kör inte på driftvärden eller
en vanlig utvecklingsdator.** Provet startar samma tio tjänster och den
renderade nginxkonfigurationen, kontrollerar verkliga UID/GID, monteringar,
förmågor, minne/swap och metadataisolering för IPv4/IPv6. AWS ersätts av en
lokal TLS-/SigV4-fixtur med endast synligt syntetiska sessioner; inga
AWS-kontoanrop görs. Operator- och identitetsuppgifter är syntetiska.

Rapporten anger faktiskt utfall för stängd registrering, separat API,
kontrollerad aktivering, transaktionell avisering, SAML/OIDC,
SignMessage/SAD/test-CA-PAdES, tjänsteomstart, förseglad OpenBao och extern
spärr utan lokal ACTIVE-reservväg. Ett grönt resultat gäller denna
komponentkedja och dessa felprov, inte leveransgrind, långvarig drift,
AWS-IAM i det verkliga kontot eller godkännande.

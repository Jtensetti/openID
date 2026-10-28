# Källregister

Bildarbetarnas fil-/systemanropspolicy: Linux
[Landlock](https://docs.kernel.org/userspace-api/landlock.html),
[seccomp-filter](https://www.kernel.org/doc/html/v6.12/userspace-api/seccomp_filter.html),
[Landlock UAPI](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/landlock.h)
och [x86-64-systemanrop](https://github.com/torvalds/linux/blob/v6.12/arch/x86/entry/syscalls/syscall_64.tbl),
lästa 2026-10-27. Policyn kräver ABI 3, kontrollerar seccomp-arkitekturen
och nekar nya/okända systemanrop. Egna register/layout-definitioner används
för anrop från Python; ingen Linux-implementation kopieras. Policyns
tillåtna filer/anrop är projektdesign och kräver separat kompatibilitets-
och säkerhetsgranskning. Se [bildarbetare](bildarbetare.md).

SQLite-gallring: [URI mode=ro/rw](https://sqlite.org/uri.html),
[secure_delete](https://sqlite.org/pragma.html#pragma_secure_delete) och
[transaktioner](https://sqlite.org/lang_transaction.html), kontrollerade
2026-10-27. Funktionens konfigurationsgränser är projektdesign, inte fastställda
lagringstider eller rättsligt beslut. Backup/WAL och avveckling bedöms separat.

Bildprocessernas begränsningar: Python 3.12
[subprocess](https://docs.python.org/3.12/library/subprocess.html) och
[resource](https://docs.python.org/3.12/library/resource.html), lästa 2026-10-27.
Pipe-utdata måste begränsas under läsningen; communicate-buffring ger ingen
minnesgräns. Processstart kan inte avbrytas på alla plattformar. Resursgränser
är operativsystemsberoende och utgör inte fil-/nätisolering.

Bildarbetarnas kraschdumpar: Linux man-pages
[core(5)](https://man7.org/linux/man-pages/man5/core.5.html),
[PR_SET_DUMPABLE](https://man7.org/linux/man-pages/man2/PR_SET_DUMPABLE.2const.html)
och [PR_GET_DUMPABLE](https://man7.org/linux/man-pages/man2/PR_GET_DUMPABLE.2const.html),
lästa 2026-10-27. RLIMIT_CORE=0 räcker inte vid en pipad kraschinsamlare.
Bildarbetarna sätter även dumpable=0 på Linux och kräver lyckad återläsning
innan de läser bilddata. Detta gäller arbetarnas vanliga kraschförlopp,
inte skydd mot en komprometterad kärna, administratör eller arbetarkod.

Containerhärdning: [Linux no_new_privs](https://docs.kernel.org/userspace-api/no_new_privs.html)
och [Docker Engine security](https://docs.docker.com/engine/security/), lästa
2026-10-27. `no_new_privs` hindrar exec från att ge nya set-ID-/filcapability-
privilegier men begränsar inte alla andra privilegieövergångar. Borttagna
setuid/setgid-filrättigheter i våra images är ett kompletterande designval,
inte ett påstående om att paketens sårbarheter är rättade.
Inspektionsbehörigheten följer [Docker: Linux capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities),
läst 2026-10-27: `DAC_READ_SEARCH` används bara i den skrivskyddade CI-kontrollen
för att läsa imagekataloger som ägs av andra systemkonton.

## Avgränsad klientadress genom betans ingress, 2026-10-26

[nginx proxy_set_header](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header)
och [remote_addr](https://nginx.org/en/docs/http/ngx_http_core_module.html#var_remote_addr)
ligger till grund för att ersätta klientens adresshuvud med anslutningens
adress. Inga `real_ip`-regler ingår. Eget proxyläge begränsas till explicit
loopbacklyssnare; det provas med förfalskade huvuden genom riktig nginx.

## OS-kontroll och Debian-rättningar, 2026-10-26

[Trivy 0.76.1](https://github.com/aquasecurity/trivy/releases/tag/v0.76.1),
officiella distributionshashar, källrevision, LICENSE, NOTICE och upstream-SBOM
kontrollerades. [Debian-täckningen](https://trivy.dev/docs/latest/coverage/os/debian/)
skiljer dpkg-paket från egenbyggda binärer och använder Debians säkerhetsbedömning.
[Databasdokumentationen](https://trivy.dev/docs/latest/configuration/db/)
anger officiell OCI-källa och uppdateringsflöde. Projektet kräver aktuell
databas och jämför hela dpkg-inventeringen med skannerns paketlista.

Komplettering 2026-10-27: [Trivys containerkällor](https://trivy.dev/docs/latest/target/container_image/)
beskriver den lokala Docker-källan. Båda applikationsimagernas OS-kontroll
begränsas till denna källa och validerar fullständigt image-ID.
[GitHubs statusuttryck](https://docs.github.com/en/actions/reference/workflows-and-actions/expressions#status-check-functions)
ligger till grund för registerskanning efter testfel med `!cancelled()` och
bevisuppladdning med `always()`. Skanningsfel får inte omvandlas till godkänt jobb.

[Debian Securitys Trixie-index](https://security.debian.org/debian-security/dists/trixie-security/main/binary-amd64/Packages.xz)
anger OpenSSL `3.5.7-1~deb13u3`.
[Trixie-updates](https://deb.debian.org/debian/dists/trixie-updates/main/binary-amd64/Packages.xz)
anger version, fil och SHA-256 för tzdata `2026e-0+deb13u1`; den hämtade
filens bytes har verifierats.
[CVE-2025-7458](https://security-tracker.debian.org/tracker/CVE-2025-7458)
är rättad i Trixies SQLite `3.46.1-7+deb13u2`, men kvar i Bookworm.
[Debian 13:s ändringar](https://www.debian.org/releases/trixie/release-notes/whats-new.en.html)
och [kända begränsningar](https://www.debian.org/releases/trixie/release-notes/issues.en.html)
har granskats för amd64-containerbasen; ingen värd-OS-uppgradering görs.
Docker Official Images-manifest och källfil för Python 3.12.15-slim-trixie
anger källrevision `2a3b794c223ab067d122719541cdd54a068732a5`.
Index-/amd64-digest finns i komponentregistret. Detta är upstream-proveniens,
ingen oberoende byggattest eller fullständig OS-säkerhetsbedömning.

## Runtime-uppföljning, 2026-10-26

[Node 24.22.1](https://nodejs.org/en/blog/release/v24.22.1) är en säkerhetsrelease.
Version, officiell distributionshash, Docker-digest och LICENSE kontrollerades.
Den nya runtime-versionen används även i protokoll- och signaturproven.
[Python 3.12.16](https://www.python.org/downloads/release/python-31216/)
och [Temurin 21.0.13+9](https://github.com/adoptium/temurin21-binaries/releases/tag/jdk-21.0.13%2B9)
är publicerade säkerhetsuppdateringar. Temurins officiella Linux x64-arkiv,
kontrollsummor, releaseuppgifter och CycloneDX kontrollerades. JDK/JRE används
nu i pilotbygget och serverproven enligt komponentregistret.
[Adoptiums arkivinstruktion](https://adoptium.net/installation/archives) och
[BuildKits checksum-kontroll](https://docs.docker.com/reference/dockerfile/#add---checksum)
ligger till grund för installationen, även i `ops/`-imagen.

Python 3.12.16:s officiella XZ-arkiv och
[käll-SPDX](https://www.python.org/ftp/python/3.12.16/Python-3.12.16.tar.xz.spdx.json)
har hämtats och hashkontrollerats. Taggen pekar på commit
`2c2462afc5d978d31f3d073001fc202d269917ff`. Utgåvan rättar bland annat
komprometterade CA-nycklar, Expat, tarfile och tempfile.
[Dockerprojektets byggrecept](https://github.com/docker-library/python/blob/2a3b794c223ab067d122719541cdd54a068732a5/3.12/trixie/Dockerfile)
och MIT-licens ligger till grund för det separata källbygget. Bygget behåller
Python-/komponentlicenser, SPDX och testresultat.
[Pips ändringslogg](https://pip.pypa.io/en/stable/news/) och PyPI:s officiella
hjul för 26.2.2 kontrollerades: uppdaterade CA-certifikat och tidigare
säkerhetsrättningar ingår. Hjulhash, MIT-licens, transitiva licenser och
inbäddad CycloneDX är dokumenterade i komponentregistret. Pips nya version
används som byggverktyg; pip och ensurepip tas sedan bort ur driftfilsystemet.
Ursprunglig Python-SPDX beskriver källutgåvan före denna paketering. Bevakning får inte stanna vid
systempaketlistan; andra inbäddade beroenden återstår.

[Upstreams TLS-testförväntan](https://github.com/python/cpython/blob/540b3d0a7fa7cd842f064f79b1410cbd6868bffa/Lib/test/test_ssl.py)
för avvisad post-handshake-autentisering utan certifikat används i ett
avgränsat testbackport. Referensen innehåller mönstret; den anges inte som
committen som introducerade det. Filhashar och teständring bevaras i bygglåset.
Runtime-TLS-koden ändras inte.

[BuildKits nätisolering](https://docs.docker.com/reference/dockerfile/#run---networknone),
[skrivskyddade byggmonteringar](https://docs.docker.com/reference/dockerfile/#run---mounttypebind)
och [pips lokala installation](https://pip.pypa.io/en/stable/cli/pip_install/#cmdoption-no-index)
ligger till grund för imagebyggens installation från hashlåsta hjul utan nät.
PyPI:s JSON-metadata och [PyTorchs officiella CPU-index](https://download.pytorch.org/whl/cpu/torch/)
identifierar de exakta befintliga hjulen. Metadataadress och dess SHA-256
finns i `python-wheels.lock.json`; själva filens befintliga hash verifieras
separat av BuildKit och pip. En metadatahash ensam verifierar inte hjulfilen.

## Separat byggmiljö, 2026-10-26

[GitHub-hosted runners](https://docs.github.com/en/actions/concepts/runners/github-hosted-runners)
beskriver nya virtuella maskiner för vanliga hostade jobb.
[Actions-artefakter](https://docs.github.com/en/actions/using-workflows/storing-workflow-data-as-artifacts)
beskriver filbevaring, retention och artefaktdigest. Projektets separata
manifest binder även image, källrevision och protokollbevis.
[Docker image load](https://docs.docker.com/reference/cli/docker/image/load/)
stödjer komprimerade arkiv och återställer images och taggar utan ombygge.
Importskriptet jämför därför även det faktiskt inlästa image-ID:t.

[nginx client_body_buffer_size](https://nginx.org/en/docs/http/ngx_http_core_module.html#client_body_buffer_size)
och [client_body_temp_path](https://nginx.org/en/docs/http/ngx_http_core_module.html#client_body_temp_path)
anger när request-body skrivs till temporär fil och var den placeras.
Betans begränsade SAML-POST ryms nu inom motsvarande minnesbuffert;
engångsprovet anger egna temporära sökvägar för samtliga nginx-moduler.

## CI:s Ubuntu-paketkälla, 2026-10-26

[Ubuntu Server: Install and manage packages](https://ubuntu.com/server/docs/how-to/software/package-management/)
anger `ubuntu.sources`, huvudarkivet och `Signed-By` för Ubuntu 24.04.
[Huvudarkivet via HTTPS](https://archive.ubuntu.com/ubuntu/) har kontrollerats.
[GitHubs runnerkonfiguration](https://github.com/actions/runner-images/blob/c74a28e5f8943ae6a39cac7c3701dd6bd0a2ea51/images/ubuntu/scripts/build/configure-apt-sources.sh)
pekar Ubuntu 24.04 på `mirror+file:/etc/apt/apt-mirrors.txt`, med Azure först.
CI ersätter både denna URI och direktadressen till Azure med huvudarkivets
HTTPS-adress. APT:s befintliga signaturkontroll, suites och komponenter behålls.

## Omkontroll för appens GAP-arbete, 2026-10-26

D08 har lästs på nytt mot den publicerade webbsidan (rubrikdatum
2022-10-04, sidfot 2024-12-20). [ISO/IEC 27001:2022](https://www.iso.org/standard/27001)
och [Amd 1:2024](https://www.iso.org/standard/88435.html) är underlag för
ledningssystemets avgränsning. Fullständig bedömning förutsätter licensierad
standardtext och beslutad SoA; appens tekniska mappning är inte en certifiering.

[Apple App Attest Environment](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.devicecheck.appattest-environment)
och [förberedelser för App Attest](https://developer.apple.com/documentation/devicecheck/preparing-to-use-the-app-attest-service)
kontrollerade 2026-10-26: utvecklings- och produktionsnycklar tillhör skilda
miljöer. Produktion kan väljas för lokal provning, och TestFlight använder
produktion. Appens signerade entitlement kontrolleras separat från byggläget.

## Synligt PDF-kvitto och tillit, omkontroll 2026-10-26

[Diggs valideringsbeskrivning](https://www.digg.se/digitala-tjanster/e-underskrift/valideringstjanst),
[Adobes AATL-beskrivning](https://www.adobe.com/security/approved-trust-list.html)
och [EU:s tillitsförteckningar](https://digital-strategy.ec.europa.eu/en/policies/eu-trusted-lists)
har kontrollerats för skillnaden mellan synlighet, integritet och tillit.
T05 och T06 nedan anger fortsatt version 1.7 respektive 1.3.
[PDFBox FAQ](https://pdfbox.apache.org/3.0/faq.html#how-can-i-check-signed-pdfs)
beskriver att parsing/rendering inte i sig validerar digitala underskrifter.
Den befintliga låsta PDFBox-versionen 3.0.8 används utan nytt beroende.

## Testkonsolens ingress och formuläråtergång, 2026-10-26

[nginx proxy_buffer_size](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_buffer_size)
beskriver gränsen för bakomliggande svarshuvuden även när response buffering
är avstängd. [CSP form-action](https://www.w3.org/TR/CSP3/#directive-form-action)
anger kontrollen av formulärnavigationer. Telefonsidans policy behöver tillåta
OIDC:s konfigurerade callback efter godkännandets POST, utan godtyckliga mål.

## Ursprunglig inventering

Referenser från inventeringen 2026-10-19. Kravnummer och avsnitt finns i
[kravöversikten](krav.md). Originaltexternas aktuella lydelse och
ikraftträdande behöver kontrolleras inför en formell bedömning.

## Myndighetskällor och tekniska profiler

| ID | Källa |
|---|---|
| D01 | [Leverera elektronisk identifiering](https://www.digg.se/digitala-tjanster/e-legitimering/bli-godkand-utfardare-av-svensk-e-legitimation/leverera-elektronisk-identifiering-inom-auktorisationssystemet) |
| D02 | [Administrativa föreskrifter](https://www.digg.se/digitala-tjanster/e-legitimering/bli-godkand-utfardare-av-svensk-e-legitimation/leverera-elektronisk-identifiering-inom-auktorisationssystemet/auktorisationssystem-for-elektronisk-identifiering---administrativa-foreskrifter) |
| D03 | [Anslutningsavtal, leverantör](https://www.digg.se/digitala-tjanster/e-legitimering/bli-godkand-utfardare-av-svensk-e-legitimation/leverera-elektronisk-identifiering-inom-auktorisationssystemet/auktorisationssystem-for-elektronisk-identifiering---administrativa-foreskrifter/anslutningsavtal-for-auktorisationssystem-for-elektronisk-identifiering---leverantor) |
| D04 | [Bilaga 1, ersättning och fakturering](https://www.digg.se/digitala-tjanster/e-legitimering/bli-godkand-utfardare-av-svensk-e-legitimation/leverera-elektronisk-identifiering-inom-auktorisationssystemet/auktorisationssystem-for-elektronisk-identifiering---administrativa-foreskrifter/anslutningsavtal-for-auktorisationssystem-for-elektronisk-identifiering---leverantor/bilaga-1---ersattning-berakning-och-fakturering) |
| D05 | [Bilaga 2, beräkningsdata](https://www.digg.se/digitala-tjanster/e-legitimering/bli-godkand-utfardare-av-svensk-e-legitimation/leverera-elektronisk-identifiering-inom-auktorisationssystemet/auktorisationssystem-for-elektronisk-identifiering---administrativa-foreskrifter/anslutningsavtal-for-auktorisationssystem-for-elektronisk-identifiering---leverantor/bilaga-2---teknisk-specifikation-for-berakningsdata) |
| D06 | [Rapporteringsrutin](https://www.digg.se/digitala-tjanster/e-legitimering/bli-godkand-utfardare-av-svensk-e-legitimation/leverera-elektronisk-identifiering-inom-auktorisationssystemet/rutin-for-rapportering-inom-auktorisationssystem-for-elektronisk-identifiering) |
| D07 | [Bli godkänd utfärdare](https://www.digg.se/digitala-tjanster/e-legitimering/bli-godkand-utfardare-av-svensk-e-legitimation) |
| D08 | [Tillitsramverket](https://www.digg.se/digitala-tjanster/e-legitimering/om-e-legitimering/tillitsnivaer-for-e-legitimering/tillitsramverk-for-svensk-e-legitimation) |
| D09 | [Vägledning för utfärdare](https://www.digg.se/digitala-tjanster/e-legitimering/om-e-legitimering/tillitsnivaer-for-e-legitimering/tillitsramverk-for-svensk-e-legitimation/vagledning-for-utfardare) |
| D10 | [Teknisk anslutning hos offentlig aktör](https://www.digg.se/digitala-tjanster/e-legitimering/erbjud-inloggning-med-svenska-e-legitimationer/teknisk-information-gallande-auktorisationssystem-for-elektronisk-identifiering) |
| D11 | [Erkännandeskyldigheten från december 2026](https://www.digg.se/digitala-tjanster/e-legitimering/om-e-legitimering/krav-pa-offentliga-aktorer-att-erkanna-flera-e-legitimationer) |
| D12 | [Samlad ersättningsöversikt](https://www.digg.se/digitala-tjanster/digital-post/digital-post-for-dig-som-offentlig-aktor/infor-anslutning/avgifter-och-ersattning-inom-auktorisationssystem-elektronisk-identifiering-och-digital-post) |
| D13 | [Myndigheternas införandedatum](https://www.digg.se/om-oss/nyheter/digital-identitet/nyheter/2026-04-02-krav-pa-fler-e-legitimationer-i-myndigheters-e-tjanster---nu-starker-vi-robustheten) |
| L01 | [Lag (2026:1358)](https://www.riksdagen.se/sv/dokument-och-lagar/dokument/svensk-forfattningssamling/lag-20261358-om-statlig-e-legitimation-och_sfs-2026-1358/) |
| L02 | [Förordning (2023:709)](https://www.riksdagen.se/sv/dokument-och-lagar/dokument/svensk-forfattningssamling/forordning-2023709-om-auktorisationssystem-i_sfs-2023-709/) |
| T01 | [Sweden Connect, specifikationsindex](https://docs.swedenconnect.se/technical-framework/) |
| T02 | [SAML Deployment Profile](https://docs.swedenconnect.se/technical-framework/latest/02_-_Deployment_Profile_for_the_Swedish_eID_Framework.html) |
| T03 | [OpenID Connect Profile for Sweden Connect](https://docs.swedenconnect.se/technical-framework/latest/OpenID_Connect_Profile_for_Sweden_Connect.html) |

T02 och T03 använder föränderliga `latest`-adresser. De är läshänvisningar;
fullständig profilmappning och extern interoperabilitet återstår.

## Granskningsbas för protokoll och underskrift, 2026-10-23

[protocol-sources.json](protocol-sources.json) låser versionsrubrik och
SHA-256 för den direkt hämtade HTML som lästs. T02 identifierades nu som
1.9 och T03 som 1.1, båda daterade 2026-10-21. Detta ersätter den äldre
tekniska inventeringens versionsuppgift, men fastställer inte tillämpligt
anslutningsavtal eller övergångsregler. Indexet länkar också till december
2024; sökindex kan fortfarande visa äldre dokumentversioner.

| ID | Primärkälla |
|---|---|
| T05 | [DSS Implementation Profile](https://docs.swedenconnect.se/technical-framework/latest/07_-_Implementation_Profile_for_using_DSS_in_Central_Signing_Services.html), direkt hämtad version 1.7, 2026-10-23. |
| T06 | [Certificate Profile for Central Signing Services](https://docs.swedenconnect.se/technical-framework/latest/08_-_Certificate_Profile_for_Central_Signing_Services.html), direkt hämtad version 1.3, 2026-10-21. |
| T07 | [Swedish OpenID Connect Profile](https://www.oidc.se/specifications/swedish-oidc-profile-1_0.html), 1.0, 2023-12-11. |
| T08 | [Signature Extension for OpenID Connect](https://www.oidc.se/specifications/oidc-signature-extension-1_2.html), direkt hämtad version 1.2, 2026-10-18. |
| T09 | [Sweden Connect Security Requirements](https://docs.swedenconnect.se/federation/security-requirements.html), 1.0. |
| T10 | [OIDC Metadata Requirements](https://docs.swedenconnect.se/federation/oidc-metadata-requirements.html), 1.0. |
| T11 | [OpenID Foundation, OP conformance testing](https://openid.net/certification/connect_op_testing/) och [submission](https://openid.net/certification/op_submission/). Interna testresultat är inte resultat från denna svit. |
| T12 | [OpenSSL CMS](https://docs.openssl.org/3.0/man1/openssl-cms/): `-verify`, `-binary`, `-cades` och explicit CA-fil används för separata syntetiska interoperabilitetsprov. |

T06:s certifikatprofil och T05:s DSS-protokoll implementeras inte av
den nya lokala CMS-labben. [SignService](https://github.com/swedenconnect/signservice)
är fortsatt en kandidat för en sådan integration, inte ett infört beroende.
Tillämpliga delar och kvarstående verifiering beskrivs i
[prövningsunderlaget](provningsunderlag.md).

## WebAuthn

W01 omfattar [W3C WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/) och
[Yubicos server-API](https://developers.yubico.com/java-webauthn-server/).
Den införda versionen, licensen och lokala policyn finns i
[komponentregistret](../THIRD_PARTY.md#webauthn).

## Sweden Connect

| ID | Projekt | Användning |
|---|---|---|
| G01 | [Spring Authentication Server](https://github.com/swedenconnect/spring-authentication-server) | SAML-starter och integrations-API. |
| G02 | [SAML Identity Provider](https://github.com/swedenconnect/saml-identity-provider) | Äldre projekt, ersatt av G01; används inte. |
| G03 | [Credentials Support](https://github.com/swedenconnect/credentials-support) | Nyckel- och certifikatintegration. |
| G04 | [SignService](https://github.com/swedenconnect/signservice) | Referens för framtida dokumentunderskrift; används inte. |
| G05 | [Sweden Connect Test Client](https://github.com/swedenconnect/sweden-connect-test-client) | Källa till adaptern `LabResponseProcessor`. |

Exakta revisioner, licenser och underhållskontroller finns i
[THIRD_PARTY.md](../THIRD_PARTY.md). Pass-, NFC- och modellkällor finns i
[verifierarens komponentregister](../verification/THIRD_PARTY.md).

## Komplettering 2026-10-21: OIDC, tillitsnivåer och EU

| ID | Primärkälla och avgränsning |
|---|---|
| T04 | [Sweden Connect identifierarregister](https://docs.swedenconnect.se/technical-framework/latest/03_-_Registry_for_Identifiers.html), §3.1.1. Identifierare är inte certifiering. |
| D14 | [Diggs författningssamling](https://www.digg.se/om-oss/forfattningssamling): MDFFS 2025:1 samt 2025:2/2025:3 med ändringar 2026:3/2026:4. Fullständig tillämpningsbedömning återstår. |
| EU01 | [eIDAS, förordning 910/2014](https://eur-lex.europa.eu/eli/reg/2014/910/oj), ändrad genom 2024/1183. |
| EU02 | [Genomförandeförordning 2015/1502](https://eur-lex.europa.eu/eli/reg_impl/2015/1502/oj), tillitsnivåer low/substantial/high. |
| EU03 | [SDG, förordning 2018/1724](https://eur-lex.europa.eu/eli/reg/2018/1724/oj), särskilt artikel 13. |

T03 identifierades som version 1.0, daterad 2024-12-04. Biblioteksrevisionen
är separat: Spring Authentication Server 1.0.3,
`dd49df31aa250eaacbd3a27466a05ec331b6dddc`. Ingen fullständig
profilcertifiering är utförd. Direktåtkomst till EUR-Lex blockerades vid
denna genomgång; EU-hänvisningarna ersätter inte läsning av konsoliderad
lydelse inför juridiskt ställningstagande.


## Certifikatspärr, kontrollerat 2026-10-26

- [Polismyndigheten: CSCA-certifikat](https://polisen.se/tjanster-tillstand/pass-och-nationellt-id-kort/giltiga-svenska-resehandlingar/kontroll-av-passnationellt-id-kort/csca-certifikat/)
  hänvisar till svenska CSCA-certifikat och publicerade spärrlistor.
- [ICAO Doc 9303, del 12, åttonde upplagan med ändring 1](https://www.icao.int/sites/default/files/publications/DocSeries/9303_p12_cons_en.pdf),
  avsnitt 4.1.4.3 och 4.1.5–4.1.5.1: nyckelbyte och certifikatspärr.
  Verifierarens stöd är avgränsat till kompletta direkta CRL:er. Kontrollen
  av certifikat är skild från den enskilda resehandlingens giltighetsstatus.
  CRL-profilen och Appendix B anger även ett icke-kritiskt CRL-nummer som
  icke-negativt heltal på högst 20 oktetter. Uppdateringsverktygets krav på
  stigande nummer och bevarad utfärdartäckning är dess dokumenterade policy.

## Registeridentifierare

- [Skatteverket: samordningsnummer](https://www.skatteverket.se/privat/folkbokforing/personnummerochsamordningsnummer/samordningsnummer.4.5c281c7015abecc2e201130b.html), kontrollerad 2026-10-21. Dagfältet ökas med 60; kontrollsiffra ingår. Formatkontroll är inte registerverifiering eller bevis på styrkt identitet.


### Omkontroll av passfält och ID-02, 2026-10-21

D08 (webbversion daterad 2022-10-04) och D09 (2025-03-14) har lästs på nytt,
särskilt K5.7–K5.9, K5.13 och K5.14. Ingen formell kravstatus ändras.
[ICAO Doc 9303, del 10, åttonde upplagan med ändringar](https://www.icao.int/publications/documents/9303_p10_cons_en.pdf),
tabell 72: DG11 kan innehålla personal number och fullständigt födelsedatum;
fälten är valfria. Detta bevisar inte förekomst i ett visst svenskt pass.

## Komplettering 2026-10-23: utgivning

- D08 K2.1–K2.3 och D09 vägledning till K5.13 har lästs på nytt för
  organisation, uthållighet, kontroll av handlingens status och oberoende
  provning. Detta ändrar inte formell kravstatus.
- D15: [Digg, bilaga D om biometriska uppgifter](https://www.digg.se/digitala-tjanster/e-legitimering/om-e-legitimering/tillitsnivaer-for-e-legitimering/tillitsramverk-for-svensk-e-legitimation/vagledning-for-utfardare/bilaga-d-dataskyddsforordningens-bestammelser-vid-behandling-av-biometriska-uppgifter),
  senast uppdaterad 2025-03-19. Avsnitt 3 och 5 är underlag för alternativ
  grundidentifiering vid samtycke respektive konsekvensbedömning.
- P01: [Polisen, kontroll av pass/nationellt id-kort](https://polisen.se/tjanster-tillstand/pass-och-nationellt-id-kort/giltiga-svenska-resehandlingar/kontroll-av-passnationellt-id-kort/),
  granskad 2025-02-27. Publik giltighetskontroll och CSCA-certifikat är
  skilda funktioner. Sidan dokumenterar inte ett API-avtal för OpenID.
- R01: [SPAR, Personsök](https://www.statenspersonadressregister.se/master/start/teknisk-info/personsoek/),
  beskriver SOAP/XML, version 2023.1 och klientcertifikat. Ingen anslutning
  eller behörighet följer av att dokumentationen är tillgänglig.
- R02: [SPAR, exempelfiler för avisering](https://www.statenspersonadressregister.se/master/start/teknisk-info/filtransport/filer-foer-aviseringar/).
  Två publicerade exempelidentifierare återanvänds enbart i lokala
  adaptertester; inga produktionsuppslag görs.

## Bildbibliotek 2026-10-26

- [OpenCV Python release 94](https://github.com/opencv/opencv-python/releases/tag/94),
  revision `2ba8bf62f2f1215ab620416b041c9659005fa25c`; FFmpeg 8.1.2 och
  rättningar i Pythonbindningarna.
- [OpenCV 4.14.0](https://github.com/opencv/opencv/releases/tag/4.14.0),
  revision `0654a42e19215ef25b1d367d822f3c630447e7c7`.
- [Officiella byggalternativ](https://docs.opencv.org/4.x/db/d05/tutorial_config_reference.html):
  separata flaggor för bildformat och beroenden; ett eget begränsat bygge
  är undersökt men inte infört.
- [PyPI 4.14.0.94](https://pypi.org/project/opencv-python-headless/4.14.0.94/):
  Linux/amd64-hjulets bytes, licenstexter och upstream-SBOM kontrollerade.
- [AlmaLinux ALSA-2026-85968](https://errata.almalinux.org/8/ALSA-2026-85968.html),
  2026-10-21: OpenSSL-fix `1.1.1k-18.el8_6`. Hjulets SBOM anger `-17`,
  så denna versionsmatchade lucka är fortfarande öppen.

## Util-linux-källbygge, 2026-10-27

[Officiell 2.41.6-källa/signatur](https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/v2.41/),
[Debians säkerhetsstatus](https://security-tracker.debian.org/tracker/source-package/util-linux)
och [låst underhållsrevision](https://github.com/util-linux/util-linux/commit/56e83de535ae1df9228d3b1cbf978b3e36b5d959)
ligger till grund för den separata paketkandidaten. Den senare diffen är inte
omfattad av releasesignaturen. [Kernel.orgs signaturbeskrivning](https://www.kernel.org/signature.html)
anger verifiering över okomprimerad tar; checksumme-autosigneringen ersätter
inte utvecklarens signatur. [Debian-snapshoten](https://snapshot.debian.org/archive/debian/20261027T000000Z/)
har separat lås för InRelease och paketindex. Aktuella hash-/licensuppgifter
finns i [kandidatlåset](../deployment/build/util_linux/candidate.lock.json).
[Trixies sqv](https://manpages.debian.org/trixie/sqv/sqv.1.en.html) verifierar
arkivets signerade klartext med basens Debian-nyckelring före installation;
den autentiserade texten har eget hashlås.
[APT:s arkivautentisering](https://manpages.debian.org/trixie/apt/apt-secure.8.en.html)
behålls när den versionslåsta GnuPG-verifieraren installeras.
[RFC 9580 §7.1](https://www.rfc-editor.org/rfc/rfc9580.html#section-7.1)
skiljer sista separatorradslutet från signerad klartext.
[Sequoia OpenPGP 2.0.0](https://crates.io/crates/sequoia-openpgp/2.0.0)
(`src/armor.rs`) tar bort detta radslut vid läsning; Trixies `sqv` 1.3.0
använder denna biblioteksversion enligt snapshotens `Built-Using`.
Release-textens hashlås gäller de utmatade byten, utan egen normalisering.

[GnuPG:s in-/utmatningsformat](https://www.gnupg.org/documentation/manuals/gnupg/GPG-Input-and-Output.html)
beskriver `--show-keys`, `--with-colons` och nyckeluppdateringar.
Den låsta Debian-paketeringen förankrar Karel Zaks fullständiga fingeravtryck
`B0C64D14301CC6EFAEDF60E4E4B71D5EEC39C284`, men dess nyckelkopias giltighet
löpte ut 2019. [Ubuntus nyckelserver](https://keyserver.ubuntu.com/)
distribuerar en uppdaterad publik kopia. Den behandlas som hashlåsta indata,
inte som ny tillitskälla: primärfingeravtrycken måste vara identiska och
GnuPG måste fortfarande godkänna källsignaturen utan utgången/spärrad status.
Kopian är versionsbunden i repot med ursprungsadress och oförändrat hashlås;
den jämfördes med ett nytt svar 2026-10-28 svensk tid. Statuskontrollen i ett
nätlöst bygge gäller kopians innehåll, inte senare spärrar. Kernel.orgs
signaturbeskrivning ovan beskriver nyckelspärr vid kompromettering.
Aktuell nyckel-/säkerhetskontroll krävs därför separat före införande.

[GnuPG:s gpgv-manual](https://www.gnupg.org/documentation/manuals/gnupg/gpgv.html),
kontrollerad 2026-10-28, beskriver att nyckelringens nycklar betraktas som
betrodda och att utgångna/spärrade nycklar inte i sig ger avslag. Verktyget
kan samtidigt lämna maskinläsbara statusrader. Vår verifierare kräver redan
godkänd exitkod, entydig `VALIDSIG`, rätt signerare och frånvaro av förbjuden
status. Verkliga genererade fixturer provar denna kombination; de ändrar
varken verifieringspolicyn eller källornas tillitsankare. Senare spärrar som
saknas i nyckelkopian omfattas fortfarande inte av ett nätlöst prov.

## APT:s lokala paketcache, 2026-10-28

[APT 3.0.3 `pkgAcqArchive`](https://github.com/Debian/apt/blob/3.0.3/apt-pkg/acquire-item.cc)
bildar cachefilnamnet av paketnamn, full version och arkitektur. Versionsepokens
kolon kodas som `%3a` enligt
[`QuoteString`](https://github.com/Debian/apt/blob/3.0.3/apt-pkg/contrib/strutl.cc).
En redan förberedd cachefil ger en absolut installationssökväg. APT:s egen
cachekontroll jämför storlek; vår kopiering kräver dessutom låst SHA-256.
[`--no-download`](https://manpages.debian.org/trixie/apt/apt-get.8.en.html)
ska användas med redan hämtade arkiv. Provinstallationen förbereder därför
en egen cache före båda APT-anropen, med tomma källor/index enligt
[`apt.conf`](https://manpages.debian.org/trixie/apt/apt.conf.5.en.html).
Detta är format-/beteendeunderlag, ingen kopierad APT-implementation och
inget undantag från nätisolering, paketlås eller efterkontroll.

## ACL-kandidat, 2026-10-28

[Savannahs ACL-projekt](https://savannah.nongnu.org/projects/acl/) är
upstream; [Debians officiella källpool](https://deb.debian.org/debian/pool/main/a/acl/)
distribuerar den signerade 2.4.0-1-källgruppen. `.dsc`, upstreamsignatur,
nyckeluppsättning, fullständiga fingeravtryck och exakta byte binds i
[kandidatlåset](../deployment/build/acl/candidate.lock.json).

Debians aktuella poster för [CVE-2026-54369](https://security-tracker.debian.org/tracker/CVE-2026-54369)
och [CVE-2026-54370](https://security-tracker.debian.org/tracker/CVE-2026-54370)
anger 2.4.0-1 som rättad unstable-version medan Trixie är sårbar.
[Upstreams säkerhetsmeddelande](https://www.openwall.com/lists/oss-security/2026/06/29/1)
beskriver nya `_at`-API:er, no-follow och kvarvarande länkbeteende i äldre
anrop. Biblioteksbyte ensamt bevisar därför inte säkert anroparbeteende.
[Debian #1141146](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1141146)
gäller namnkonflikt när tar 1.35+dfsg-3.1 byggs med de nya headerfilerna;
det är inte ett uppmätt fel i den befintliga tar-binären.

Den autentiserade källans `doc/COPYING`, `doc/COPYING.LGPL`, filhuvuden,
`debian/copyright`, patchserie och testlista styr licens-/byggbedömningen.
Libattr-byggberoendets copyright läses ur exakt hashlåst Debian-paket.
[Trixies dpkg-manual](https://manpages.debian.org/trixie/dpkg-dev/deb-src-control.5.en.html)
anger rootlöst standardbygge sedan 1.22.13; den låsta 1.22.22 omfattas.
Ingen extra fakeroot-inställning eller privilegieutökning behövs.

## Ncurses-kandidat, 2026-10-28

[Debians källpool](https://deb.debian.org/debian/pool/main/n/ncurses/)
distribuerar den signerade ncurses 6.6+20260608-2-källgruppen. `.dsc`,
upstreamsignatur, två fullständiga signerarfingeravtryck, licens-/paketerings-
filer och storlekar/hashar är låsta i
[kandidatfilen](../deployment/build/ncurses/candidate.lock.json). Debians
paketeringsarkiv har sex interna länkar till symbolfiler; just dessa namn
och mål tillåts vid extraktion. Den lokala changelogposten är inte en
officiell Debianrelease.

Debians säkerhetsspårning markerar Trixie-versionen som sårbar för
[CVE-2025-6141](https://security-tracker.debian.org/tracker/CVE-2025-6141)
och [CVE-2025-69720](https://security-tracker.debian.org/tracker/CVE-2025-69720),
med 6.6+20260608-2 markerad som rättad i forky/sid. [Upstreams NEWS](https://invisible-island.net/ncurses/NEWS.html)
beskriver gränskontrollerna. [Den ursprungliga `tic`-rapporten](https://lists.gnu.org/archive/html/bug-ncurses/2025-03/msg00107.html)
och [rapportörens `infocmp -i`-exempel](https://github.com/Cao-Wuhui/CVE-2025-69720)
ger de genererade gränsprovens indataformer. Proven ersätter inte
sanitizer-/appbevis eller oberoende sårbarhetsbedömning.

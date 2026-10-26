# Källregister

## OS-kontroll och Debian-rättningar, 2026-10-26

[Trivy 0.76.1](https://github.com/aquasecurity/trivy/releases/tag/v0.76.1),
officiella distributionshashar, källrevision, LICENSE, NOTICE och upstream-SBOM
kontrollerades. [Debian-täckningen](https://trivy.dev/docs/latest/coverage/os/debian/)
skiljer dpkg-paket från egenbyggda binärer och använder Debians säkerhetsbedömning.
[Databasdokumentationen](https://trivy.dev/docs/latest/configuration/db/)
anger officiell OCI-källa och uppdateringsflöde. Projektet kräver aktuell
databas och jämför hela dpkg-inventeringen med skannerns paketlista.

[Debian Securitys amd64-index](https://security.debian.org/debian-security/dists/bookworm-security/main/binary-amd64/Packages.xz)
anger version, fil och SHA-256 för de låsta Bookworm-rättningarna.
De hämtade `.deb`-filernas hash har kontrollerats mot detta index.
[CVE-2026-84782](https://security-tracker.debian.org/tracker/CVE-2026-84782)
anger OpenSSL 3.0.22-1~deb12u2 som rättad Bookworm-version.
Docker Official Images-manifestet för Python 3.12.15-slim-bookworm anger
amd64-källrevision `2a3b794c223ab067d122719541cdd54a068732a5` och ny indexdigest
enligt komponentregistret. Detta är upstream-proveniens, ingen egen byggattest.

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
ligger till grund för installationen. Python-uppdateringen och den separata
`ops/`-imagen återstår. Bevakning får inte stanna vid systempaketlistan.

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

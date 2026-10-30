# Tekniska källor

Referenser för implementation, protokolltester och byggkedja. Daterade
kontroller beskriver den lästa versionen, inte dagens driftstatus eller
ett formellt godkännande. Beroenden och licenser finns i
[THIRD_PARTY.md](../THIRD_PARTY.md).

## Avgränsad klientadress genom betans ingress, 2026-10-26

[nginx proxy_set_header](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header)
och [remote_addr](https://nginx.org/en/docs/http/ngx_http_core_module.html#var_remote_addr)
ligger till grund för att ersätta klientens adresshuvud med anslutningens
adress. Inga `real_ip`-regler ingår. Eget proxyläge begränsas till explicit
loopbacklyssnare; det provas med förfalskade huvuden genom riktig nginx.

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
CI byter endast URI för Azure-spegeln; APT:s befintliga signaturkontroll,
suites och komponenter behålls.

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

## Tekniska profiler

| ID | Källa |
|---|---|
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

## Protokollidentifierare

T04: [Sweden Connect identifierarregister](https://docs.swedenconnect.se/technical-framework/latest/03_-_Registry_for_Identifiers.html),
§3.1.1. Kodens testkontext är inte en godkänd tillitsnivå. Den versionsbundna
OIDC-/SAML-källan ovan gäller protokollproven; biblioteksversionen anges separat
i [THIRD_PARTY.md](../THIRD_PARTY.md).

## App Attest, kontrollerat 2026-10-26

[Apple App Attest Environment](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.devicecheck.appattest-environment)
och [förberedelser för App Attest](https://developer.apple.com/documentation/devicecheck/preparing-to-use-the-app-attest-service)
beskriver skilda utvecklings- och produktionsmiljöer. TestFlight använder
produktion. Den signerade appens entitlement kontrolleras separat från byggläget.

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

### Passfält, kontrollerat 2026-10-21

[ICAO Doc 9303, del 10, åttonde upplagan med ändringar](https://www.icao.int/publications/documents/9303_p10_cons_en.pdf),
tabell 72: DG11 kan innehålla personal number och fullständigt födelsedatum;
fälten är valfria. Detta bevisar inte förekomst i ett visst svenskt pass.

## Registeradapter, kontrollerat 2026-10-23

- P01: [Polisen, kontroll av pass/nationellt id-kort](https://polisen.se/tjanster-tillstand/pass-och-nationellt-id-kort/giltiga-svenska-resehandlingar/kontroll-av-passnationellt-id-kort/),
  granskad 2025-02-27. Publik giltighetskontroll och CSCA-certifikat är
  skilda funktioner. Sidan dokumenterar inte ett API-avtal för OpenID.
- R01: [SPAR, Personsök](https://www.statenspersonadressregister.se/master/start/teknisk-info/personsoek/),
  beskriver SOAP/XML, version 2023.1 och klientcertifikat. Ingen anslutning
  eller behörighet följer av att dokumentationen är tillgänglig.
- R02: [SPAR, exempelfiler för avisering](https://www.statenspersonadressregister.se/master/start/teknisk-info/filtransport/filer-foer-aviseringar/).
  Två publicerade exempelidentifierare återanvänds enbart i lokala
  adaptertester; inga produktionsuppslag görs.

# Källregister

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

## Komplettering 2026-10-21: leverantörsanslutning

D01–D09 har lästs på nytt för anslutningsanalysen. Separata krav och vårt
eget återstående arbete finns under GOV-09 och FED-05 i kravöversikten.

| ID | Källa, version och avgränsning |
|---|---|
| D15 | [MDFFS 2025:1](https://www.digg.se/om-oss/forfattningssamling/foreskrifter-om-krav-pa-leverantorers-ansokan-om-anslutning-till-auktorisationssystem-for-tjanster-for-elektronisk-identifiering-och-for-digital-post-mdffs-20251/foreskrifter-om-krav-pa-leverantorers-ansokan-om-anslutning-till-auktorisationssystem-for-tjanster-for-elektronisk-identifiering-och-for-digital-post-mdffs-20251), beslutad 2025-04-15, gäller från 2025-05-05. §§6–15 gäller leverantörens förutsättningar; tekniskt stöd är inte formellt godkännande. |
| T05 | [Tekniska anslutningsregler, SAML](https://docs.swedenconnect.se/technical-framework/Tekniska_anslutningsregler.html), kontrollerad 2026-10-21, särskilt §§1.3 och 3.6.4. Föränderlig webbsida. |
| T06 | [Security Requirements 1.0](https://docs.swedenconnect.se/federation/security-requirements.html), publicerad 2026-09-02. Algoritmer, nycklar och rotation för båda protokollen. |
| T07 | [OpenID Federation Rules and Policies 1.0 draft 01](https://docs.swedenconnect.se/federation/oidf-rules.html), publicerad 2026-10-14. Utkast; införandeversion ska bekräftas med Digg. |
| T08 | [OpenID Connect Metadata Requirements 1.0 draft 02](https://docs.swedenconnect.se/federation/oidc-metadata-requirements.html), publicerad 2026-10-12. Utkast; dokumentets status gäller framför indexets förkortade titel. |

Ingen anslutnings- eller tillitsmärkning får deklareras bara för att en
identifierare finns i dessa dokument. Organisation, avtal och godkännande
ska vara styrkta för den avsedda miljön.

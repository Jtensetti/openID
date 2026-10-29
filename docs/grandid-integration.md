# Anslutning till GrandID

## Integrationsmål

OpenID ska kunna anslutas som extern identitetsleverantör till Svensk
e-identitets GrandID/eID API. Målet är att en myndighet ska kunna använda
OpenID genom sin befintliga integrationsmäklare. Befintlig Sweden
Connect-stack används för SAML 2.0 och OpenID Connect; den konkreta
anslutningen får en separat, överenskommen motpartsprofil.

Svensk e-identitet beskriver anslutning av externa IdP:er via båda
protokollen och konfiguration genom sin leveransorganisation. OIDC-dokumentet
beskriver också hur en extern OIDC-IdP kan nås av kunder som använder
mäklarens API eller SAML. Se GID-01–03 i [källregistret](SOURCES.md).

`FederatedLogin` och `GetSession` är kundgränssnitt på mäklarens andra sida.
De är inte det protokoll OpenID behöver implementera för denna
IdP-anslutning. GrandID:s egna OIDC-adresser och klientexempel bestämmer
inte heller vilka klientnycklar, claims eller algoritmer mäklaren accepterar
när den ansluter till vår IdP.

Status: integrationsmål och acceptanskriterier. Ingen GrandID-anslutning
eller provning mot leverantören är genomförd. Kundspecifik IdP-anslutning
och att erbjuda OpenID som generell e-legitimationsmetod är skilda
omfattningar; den senare är inte bekräftad av de lästa källorna.

## Befintlig kod och nödvändiga anpassningar

| Del | Nuvarande implementation | Anpassning för extern motpart |
|---|---|---|
| OIDC | [PilotOidc](../prototype/src/main/java/lab/PilotOidc.java) registrerar en fast klient och callback. Code, S256 PKCE och `private_key_jwt` används. | Separat konfiguration av överenskommet klient-ID, exakta redirect-URI:er, klientautentisering och nycklar. Mäklarens stöd för dessa val behöver bekräftas. |
| SAML | [Lab](../prototype/src/main/java/lab/Lab.java) använder lokal metadata för pilotens kontotjänst och underskriftstjänst. | Registrerad SP, betrodda metadata, exakta ACS-adresser och bekräftade signerings-/krypteringskrav. |
| Attribut | [PhoneIdentity](../prototype/src/main/java/lab/phone/PhoneIdentity.java) använder sex pilotattribut: subjekt, credentialreferens, profilversion, namn, MRZ-födelsedatum och passporträtt. | En tillåten attributmängd per motpart och ändamål. Interna referenser och porträtt ska inte följa med som standard. |
| Nationell identifierare | Passprofilen kan innehålla `passportPersonalNumber`. [Registerbindningen](registerbindning.md) saknar verklig adapter och är inte kopplad till SAML/OIDC-utlämning. | Fastställ verifieringskälla, format och mottagarens faktiska behov. Saknat eller otillräckligt verifierat underlag ska ge ett definierat avslag eller ett överenskommet reducerat resultat. |
| Appens godkännande | [PhoneBridge](../prototype/src/main/java/lab/phone/PhoneBridge.java) har fast tjänstenamn och syfte. [FederationServer](../verification/federation.py) tillåter pilotens fasta audience. | Registrerad mottagare, syfte och attribututlämning ska bindas till samma transaktion som användaren godkänner. |
| Metadata och drift | [Betans ingress](../deployment/beta-nginx.conf) använder betakontoskydd; OIDC-tokenväxling har separat klientautentisering. | Överenskommen åtkomst till discovery/JWKS eller SAML-metadata, nyckelrotation och testmiljö med rätt tillgänglighet. |

Pilotens mottagarvalidering utgår från dess fasta attributuppsättning.
Ett externt attributurval behöver därför en egen profil med egna prov;
det räcker inte att byta klient-ID eller ta bort ett fält ur pilotens svar.

## Motpartsprofil som behöver fastställas

Detta är projektets anslutningsunderlag, inte ytterligare publicerade
krav från GrandID. Följande uppgifter behöver komma från eller bekräftas
av Svensk e-identitet före ett leverantörsprov:

| Uppgift | Vad anslutningen ska ange |
|---|---|
| Omfattning och protokoll | Kundspecifik anslutning eller gemensam e-legitimationsmetod; SAML eller OIDC för det första flödet; accepterad profilversion och separat testmiljö. |
| Motpart och tillit | OIDC-klient/redirect-URI/klientautentisering eller SAML-entityID/ACS; publika nycklar, algoritmer, betrodda metadata, rotation och spärr av motpart. |
| Identitetsuppgifter | Exakta attributnamn, format, källa, obligatoriska fält, hantering av skyddade uppgifter och om ett subjekt gäller per mäklare eller per bakomliggande tjänst. |
| Mottagare och avsikt | Hur den bakomliggande myndighetens identitet förmedlas och valideras, vad appen visar och vilka uppgifter respektive mottagare får. |
| Session och livscykel | Fel/avbrott, utgång, färsk autentisering, tillitskontext, spärr efter inloggning samt behov av UserInfo och utloggning. |
| Drift och prov | Åtkomst till metadata/nycklar, tidsgränser, kontakt för testfel och vilka testresultat leverantören accepterar. |

Om en mäklarklient används för flera myndigheter måste den bakomliggande
mottagaren kunna bestämmas från betrodd konfiguration eller verifierad
protokolldata. Ett fritt tjänstenamn från webbläsaren får inte styra
apptext, subjekt eller attribututlämning. En separat registrering per
mottagare är ett alternativ när protokollet inte förmedlar den uppgiften.

Appen ska visa den bekräftade mottagarrollen korrekt. Om endast mäklaren
är verifierad får gränssnittet inte påstå att en viss myndighet är
identifierad. Pilotens hårdkodade namn är inte tillräckligt för ett sådant flöde.

Nuvarande privata autentiseringskontexter behålls tills det finns stöd
för en annan utfärdad kontext. Begärd tillitsnivå får inte bli ett intygat
resultat genom attributmappning. GrandID-kompatibilitet, Digg-godkännande
och anslutning till Sweden Connect har separata verifieringsunderlag.

## Genomförande och acceptans

FED-05 är ett projektspecifikt integrationskrav. Arbetet genomförs i
följande ordning med befintliga bibliotek:

1. **Registrera motparten i en separat testprofil.** Bind konfigurationen
   till exakta adresser, nycklar och accepterad profilversion. Okänd
   motpart, ändrad callback/ACS, främmande metadata och otillåten algoritm
   ska avvisas. Nuvarande pilot ska fortsatt fungera med sin fasta profil.
2. **Inför mottagarstyrd attribututlämning.** Prova fältnamn, format,
   verifieringskälla, saknade obligatoriska uppgifter och att överflödiga
   attribut inte lämnas ut. Förmedla inte MRZ:s tvåsiffriga årtal som ett
   fullständigt födelsedatum eller ett härlett personnummer.
3. **Bind appens beslut till mottagare och syfte.** Prova ändrat
   tjänstenamn, byte mellan två myndigheter, ändrad attributmängd och
   att ett godkännande inte kan användas i en annan session eller hos
   en annan mottagare. Subjektens avgränsning ska följa vald profil.
   Prova att identifierare som ska vara beständiga, exempelvis OIDC `sub`,
   behålls vid återinloggning och omstart samt vid nyckel- eller passbyte
   enligt vald profil. SAML:s transienta NameID har separat semantik.
4. **Prova hela flödet mot en separat testmotpart.** Återanvänd relevanta
   fall från [OIDC-provet](../verification/oidc-negative-test.py) och
   [SAML-provet](../verification/saml-negative-test.py): lyckad inloggning,
   fel issuer/audience/signatur/tid, återspelning, nekande, avbrott,
   spärr och otillräcklig autentiseringskontext. Prova även nyckelrotation
   och hur mäklarens session påverkas av spärr och utloggning.
5. **Verifiera hos GrandID.** Kör det överenskomna flödet mot deras
   godkända testmiljö och kontrollera de attribut myndighetens testtjänst
   faktiskt får. Spara kodrevision, profilversion, konfigurationshash,
   test-ID, resultat och bekräftad omfattning utan personuppgifter eller
   hemligheter. Lokala simuleringar räknas som förberedande prov.

Godkänt integrationsresultat avser den provade motparten, protokollet och
profilen. Ett OIDC-prov bevisar inte SAML-kompatibilitet eller generell
tillgänglighet hos alla myndigheter. Nuvarande pilotklients lokala
spärrkontroll innebär inte automatiskt att en extern mäklare avslutar en
redan skapad session; den egenskapen måste avtalas och provas separat.

## Underskrift

Första integrationsmålet ovan gäller autentisering. Vår SAML-implementation
har SignMessage/SAD och en testtjänst för PDF-underskrift, se
[prövningsunderlaget](provningsunderlag.md). Det finns ännu inget verifierat
kontrakt för att använda dessa funktioner genom GrandID.

Leverantörens BankID-parametrar för underskrift och dess separata
avtalshanterings-API fastställer inte en signeringsprofil för OpenID.
Ett sådant flöde behöver egen mappning av visad text/dokument,
underskriftsavsikt, signaturformat, certifikatkedja och valideringsbevis
samt separat acceptans enligt SIG-01/02.

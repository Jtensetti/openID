# Åldersverifiering: avgränsad integration

Den separata verifierardelen kan koppla en ålderspresentation till en registrerad
webbplats och lämna ett engångsresultat med enbart `age_over_18: true` till dess
server. Detta är integrationskod för labb. Det är inte en färdig EU-plånbok,
certifierad åldersutfärdare eller verifierad produktionsinstallation.

## Roller och datagränser

| Roll | Uppgift och data |
|---|---|
| Avtalskund | Koncern eller annan kund som har en eller flera registrerade webbplatser. Kund-ID hör till konfigurationen, inte användarens bevis. |
| Utfärdare | Labben signerar syntetiska mdoc-bevis. Autentiserad utgivning från Tjipps passregister återstår. |
| Plånbok | Labben har en programvaruplånbok med engångsbevis och separata nycklar. Native-stöd för dessa bevis ingår ännu inte i Tjipp-appen. |
| Verifierare | Kontrollerar bevis, signaturer, utfärdartillit, tider och sessionsbindning. DC API använder OWF mdoc och HPKE; generisk OpenID4VP använder separat EU-verifierarmotor. |
| Webbplatsens server | Startar kontrollen med sin egen API-nyckel, binder den till sin webbläsarsession och konsumerar ett godkännande en gång. |

`age_gateway.py` har ingen koppling till identitetsdatabasen, SAML-subjekt,
personnummer, passporträtt eller Tjipp-enhetsnycklar. En koncern får registrera
flera sajter. Den här implementationen kräver skilda API-nycklar och exakta
HTTPS-origins per sajt. Det är vår gräns för kundisolering, inte ett påstående
om att OpenID4VP alltid kräver skilda `client_id` per domän.

Gatewayns minimala resultat innebär inte automatiskt kryptografisk
olänkbarhet. Återanvända mdoc-nycklar, bevisidentifierare, verifierarens råa
bevis eller nätmetadata kan medge korrelation. Det krävs ett separat genomfört
plånboks-/utfärdarflöde med vald EU-profil, engångsbevis respektive ZKP och
kontrollerad loggning innan ett starkare integritetslöfte kan lämnas. Utfärdaren
ska inte kontaktas för varje webbplatsbesök i den avsedda arkitekturen.

## Åldersunderlag hos en framtida utfärdare

`age_eligibility.eligible_over_18(profile, today=...)` är en separat policy för
en autentiserad lagrad passprofil. Den väljer den yngsta kalendergiltiga
födelsedag som matchar MRZ:s tvåsiffriga år och inte ligger i framtiden.
Endast om även den tolkningen innebär minst 18 år lämnas `True`.
Födelseårhundrade och faktisk ålder fastställs eller lämnas inte ut.
En person över 100 kan därför nekas när samma MRZ passar en minderårig.

Policyn kräver ett giltigt dokument med utgångsdatum efter dagens datum.
För 29 februari krävs 1 mars vid 18-årsgränsen under ett icke-skottår.
Det är en konservativ teknisk policy, inte en generell lagtolkning.
Felaktiga eller saknade fält avvisas; personnummer eller medskickade
`age_over_18`-påståenden får inte överstyra resultatet.

Funktionen är inte en bevisutfärdare och anropas inte från webbplatsens API.
En kommande utfärdare måste läsa profilen genom den skyddade profilfunktionen,
kontrollera aktiv credential och aktuell spärr-/verifieringsstatus, binda
utgivningen till plånbokens nyckel och använda betrodd servertid. Ingen
publik endpoint får ta emot födelsedatum och göra om dem till ett betrott bevis.

## mdoc och Digital Credentials API

`age_dc_backend.MdocDcBackend(signer_pem)` implementerar en separat verifierare
för `org-iso-mdoc`, ISO 18013-7 Annex C. Den gör riktig mdoc-/COSE-verifiering
och HPKE-dekryptering via låsta `@owf/mdoc` och `hpke`, med Node/OpenSSL som
kryptografiskt underlag. `EuAgeVerifierBackend` ändras inte till DC API-stöd.

```sh
cd verification/age_wallet
npm ci --ignore-scripts --omit=optional
npm test
npm run demo
```

Demonstrationen skapar en tillfällig syntetisk utfärdare, två åldersbevis och
två olika enhetsnycklar. Programvaruplånboken presenterar ett bevis vardera
för `https://a.example` och `https://b.example`; ett tredje försök nekas.
Inga riktiga personuppgifter, sparade testnycklar eller nätanrop behövs.

Använd `MdocDcBackend` i samma privata WSGI-sammansättning som nedan och välj
`method: "dc_api"`. PEM-konfigurationen måste innehålla i förväg betrodda,
exakta dokumentutfärdarcertifikat. Adaptern verifierar inte en allmän CA-kedja,
hämtar inte EU:s tillitslista och stöder inte ZKP. Denna begränsade tillitsmodell
är avsiktlig: ett webbsvar eller ett medskickat certifikat blir aldrig betrott
enbart genom att presenteras. Samma organisations utfärdarcertifikat ska
användas för många användare, inte ett personligt certifikat per individ.

En begäran får endast avse `eu.europa.ec.av.1/age_over_18` utan avsikt att lagra
attributet. Extra attribut, statusidentifierare, enhetsmetadata och
enhetssignerade attribut avvisas. Verifieraren kontrollerar dokumentets
signatur, digests, giltighet och enhetssignatur mot faktisk HTTPS-origin,
nonce och transaktionens färska krypteringsnyckel. Browserns origin måste
komma från plattformen; `approvedOrigin` i programvarulabben simulerar bara
användarens val och är inget eget skydd mot en manipulerad klient.

`OneUseAgeWallet` utfärdar högst 30 bevis i minnet och skapar en färsk P-256-nyckel
per bevis. Utfärdaren får bara publik nyckel. Importen kontrollerar signatur,
åldersprofil och bindning till rätt nyckel. Ett bevis tas bort före presentation,
även när presentationen misslyckas. Parallella försök kan inte dela bevis.
Det finns ingen export, backup eller återställning; omstart förlorar innehållet.
Detta är programvarunycklar i en testplånbok, inte Secure Enclave eller native-lagring.

Worker-anrop har begränsade indata, utdata, heap och körtid. Högst fyra körs
samtidigt och 64 transaktioner får finnas. Transaktionen förbrukas före
dekryptering, även vid fel. Utgång kontrolleras före och efter verifieringen;
utgångna poster rensas vid nästa start. Separata processer eller omstart delar
inte sessioner. Worker-fel lämnar aldrig ut råa bevis eller nycklar i loggar.
Processgränsen är inte en OS-sandbox. Ingen produktionsdrift kopplas in här.

Engångsnycklar minskar återanvändning men bevisar inte olänkbarhet. Utfärdarens
utgivningslogg, mdoc-signaturer, tidsstämplar och nätmetadata kan fortfarande
bidra till korrelation. ZKP och extern integritetsgranskning återstår.

## OpenID4VP-adapter och konfiguration

`age_backend.EuAgeVerifierBackend(base_url, issuer_chain, ca_file=...)` använder
EU:s verifierarmotors REST-API vid den revision som låses i
[tredjepartsregistret](../THIRD_PARTY.md#externt-api-för-åldersverifiering).
Konfigurera en fast HTTPS-adress och ett **icke tomt, förhandsbetrott PEM-underlag**
med de utfärdarankare labben ska lita på. Det får inte hämtas från browserns
bevis. `ca_file` gäller HTTPS-serverns CA, inte bevisutfärdarnas tillitsankare.

Adaptern skickar `issuer_chain` både när transaktionen skapas och när de
verifierade mdoc-attributen läses. Därmed används uttryckliga ankare även om
upstreams generella konfiguration annars skulle lita på alla utfärdare.
Använd strikt verifierarläge:

```text
VERIFIER_ALWAYSACCEPTWALLETRESPONSE=false
VERIFIER_MDOC_REDIRECTURICLIENTIDINDEVICEAUTHHANDOVER=false
```

Den andra inställningen avser den här adapterns generiska OpenID4VP-profil.
Verifierarmotorns klientidentitet, verifierarnyckel och publika wallet-rutter
måste vara korrekt konfigurerade. `/ui` och `/utilities` ska bara vara
tillgängliga för den betrodda serverdelen; exponera inte dess kontroll-API
som en publik testtjänst. Ingen medföljande demonyckel ger produktionstillit.

Flödet använder `/ui/presentations/v2`, `by_reference`, `direct_post.jwt`, en
färsk nonce och DCQL för endast `eu.europa.ec.av.1/age_over_18`. Efter ett
strikt accepterat sessionssvar används `/utilities/validations/msoMdoc/deviceResponse`
för strukturerade attribut. **Utility-endpointen ensam bevisar inte
sessions-/enhetsbindning** och får inte användas direkt med browserdata.
Svar från demonstrationslägets `trust_info` godtas inte som åldersbeslut.

Digital Credentials API är förberett i gatewayns kontrakt och browserhjälparen,
men avstängt i denna verkliga adapter (`supports_dc_api=False`). Den granskade
motorns vanliga OID4VP-session får inte felaktigt användas som DC API-session.
Ingen fallback tolkar mänskligt läsbara `pages/lines` som betrott resultat.

Detta är generisk OpenID4VP 1.0 med `openid4vp://` och refererad begäran.
Det är **inte** ett påstående om kompatibilitet med EU-appens särskilda
`av://`-profil eller dess senaste regler för begäranspaketering. Ingen signerad
begäran skrivs om till ett annat format för att simulera sådan kompatibilitet.

I detta redirect-flöde binds slutresultatet till sajten i gatewayn. Plånbokens
signerade begäran identifierar den gemensamma verifieraren; denna adapter
för inte in den slutliga sajtens origin i begäran. Plånboken kan därför inte
utifrån denna integration visa ett kryptografiskt bekräftat medgivande till
den slutliga sajten. Det måste lösas i det valda fullständiga presentationsflödet.

Exempel på sammansättning i en privat WSGI-konfigurationsmodul:

```python
import os
from pathlib import Path
from age_backend import EuAgeVerifierBackend
from age_gateway import AgeGateway, Site, Sites
from age_http import AgeApplication

backend = EuAgeVerifierBackend(
    "https://verifier.example",
    Path("/private/age/issuer-anchors.pem").read_text(),
)
sites = Sites([
    Site("example-group", "example-video", "https://video.example",
         os.environ["AGE_VIDEO_API_KEY_SHA256"]),
    Site("example-group", "example-community", "https://community.example",
         os.environ["AGE_COMMUNITY_API_KEY_SHA256"]),
])
application = AgeApplication(AgeGateway(sites, backend), "age.internal.example")
```

Hasharna är SHA-256 i hex av skilda slumpmässiga API-nycklar med minst 256 bitars
entropi (exempelvis `secrets.token_urlsafe(32)`). `.example` är platshållare.
Ingen verifierare, nyckel eller tillitskonfiguration levereras som runtime-standard.
WSGI-servern behöver repots `verification/` i sin importväg, verifierad TLS
och en process. Det här exemplet är inte kopplat till betans serverstart.

Browserdelen importerar `runDigitalPresentation` respektive
`openId4VpAuthorizationUri` från `verification/static/age-presentation.mjs`.
Förbered presentationen genom sajtens server och anropa DC-funktionen direkt
från ett användarklick. Ange `timeoutMs` högst den kvarvarande sessionstiden
och skicka det opaka svaret till sajtens server för verifiering. OID4VP-funktionen
returnerar endast en kontrollerad länk för ett uttryckligt klick. Ingen navigation,
lagring, nätbegäran till Tjipp eller automatisk fallback sker i hjälparen.

## Privat API och webbplatsens ansvar

`age_http.AgeApplication(gateway, host)` är en WSGI-applikation för ett separat
server-till-server-gränssnitt. Den kräver POST, HTTPS, exakt Host,
`Content-Type: application/json` och `Authorization: Bearer <sajtens nyckel>`.
Den avvisar Origin, query-parametrar, vidarebefordrade klienthuvuden,
duplicerade JSON-fält, okända fält och för stora kroppar. Ingen CORS öppnas.
TLS och begärans tids-/storleksgränser ska upprätthållas av värdservern.
WSGI-miljöns transportuppgifter måste komma från en betrodd installation,
aldrig direkt från en godtycklig `X-Forwarded-Proto`.

| Sökväg | JSON-fält utöver autentiseringshuvudet | Resultat |
|---|---|---|
| `/age/start` | `siteId`, `origin`, `method` (`openid4vp` eller `dc_api`) | `id`, hemlig `binding`, kvarvarande `expiresIn`, `presentation`. |
| `/age/poll` | `siteId`, `id`, `binding` | Sessionens `state`; OpenID4VP-resultat hämtas från verifieraren. |
| `/age/complete` | `siteId`, `id`, `binding`, `credential` | Skickar ett opakt DC API-svar till verifieraren. Ett browserpåstående om ålder godtas aldrig. |
| `/age/consume` | `siteId`, `id`, `binding` | Exakt `{"age_over_18":true}` en gång efter godkänd verifiering. |
| `/age/cancel` | `siteId`, `id`, `binding` | Avbryter även ett redan verifierat men okonsumerat godkännande. |

Webbplatsens server behåller **API-nyckeln och `binding`**. Den binder `id`
och `binding` till den webbläsarsession som startade flödet och använder sitt
ordinarie CSRF-skydd. Inget av dessa hemliga värden får läggas i URL, QR,
frontendkod, analysverktyg eller loggar. Endast presentationsbegäran och vid
behov det icke auktoriserande sessions-ID:t lämnas till webbläsaren.

Browserhjälparen är en transportadapter. Webbplatsen får inte öppna innehåll
för att `navigator.credentials.get()` lyckas, för att browsern skickar
`age_over_18`, eller för att UI visar `VERIFIED`. Serverns lyckade `/age/consume`
är auktorisationsbeslutet. Avbrott eller nekande får inte automatiskt växla
till ett svagare verifieringssätt.

## Livslängd, samtidighet och omstart

| Tillstånd | Tillåtna övergångar |
|---|---|
| `STARTING` | `PENDING`; fel tar bort den ännu opublicerade sessionen. |
| `PENDING` | `VERIFYING`, `CANCELLED`, `EXPIRED`. |
| `VERIFYING` | `PENDING` vid väntande OID4VP-svar, annars `VERIFIED`, `DENIED` eller `FAILED`; avbrott och utgång vinner över ett sent svar. |
| `VERIFIED` | `CONSUMED`, `CANCELLED`, `EXPIRED`. |
| Terminala tillstånd | Kan aldrig ge ett nytt godkännande. |

Ett godkänt bevis skapar ett engångsbeslut för samma sajt och bundna session.
Beslutet gäller högst 120 sekunder från transaktionens start. Konsumtion
upprepar inte bevisverifieringen och frågar inte efter aktuell spärrstatus
för pass eller Tjipp-enhet. Detta är en kontroll vid ett bestämt tillfälle,
inte en fortlöpande statuskontroll.

Samtidiga konsumtionsförsök kan ge högst ett lyckat resultat. Tillstånd hålls
i ett låst, begränsat minnesregister: högst 256 sessioner totalt och 32 per
sajt. En omstart förlorar alla godkännanden. Kör därför en process för denna
labb. Fler processer, återställningsbar lagring, fakturering och produktions-SLA
ingår inte. Kund-ID används inte för en gemensam besökshistorik.

## Tester

Från `verification/`, med Python 3.12 och Node enligt repots lås:

```sh
python3 -m unittest -v test_age_gateway test_age_http test_age_backend test_age_eligibility
python3 -m unittest -v test_age_dc_backend
node --test age-presentation-test.mjs
npm test --prefix age_wallet
```

De ursprungliga gateway-, HTTP- och browserproven använder testdubblar.
`test_age_dc_backend` provar därutöver HTTP → gateway → worker → faktisk
mdoc-/HPKE-verifiering, med syntetisk utfärdare och programvaruplånbok.
Node-proven kontrollerar kryptografi, enhetsnycklar och engångslivscykel.
Detta är inte ett oberoende interoperabilitetsprov mot EU-appen: samma OWF-bibliotek
används på båda sidor. Safari/Chrome, fysisk iPhone, EU-tillitslista och ZKP
är inte provade. Exakta körresultat och ej körda delar hör till PR:n och CI.

## Protokollkällor och kvarvarande integrationssteg

- [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html), inklusive DCQL och Appendix A om Digital Credentials API.
- [EU:s verifierarguide](https://ageverification.dev/Getting%20started/developer_guide_verifier/).
- [EU:s åldersprofil](https://docs.ageverification.dev/av-doc-technical-specification/docs/annexes/annex-A/annex-A-av-profile/).

Digital Credentials API och OpenID4VP över vanlig redirect använder olika
sessionsbindningar. En signerad OpenID4VP-begäran via DC API ska bland annat
ange `expected_origins`; svarets audience binds till faktisk origin med
prefixet `origin:`. Ett koncern-ID kan inte ersätta den bindningen.

Före ett sammanhängande Tjipp-prov behövs autentiserad utgivning med aktiv
pass-/enhetsstatus, attesterade bevisnycklar, native-plånbok och presentation,
faktisk utfärdartillit och prov mot en oberoende implementation. Det interna
syntetiska utfärdaranropet är inte en OpenID4VCI-endpoint. Produktionssteget kräver den
oberoende granskning och det behöriga mänskliga beslut som anges i `AGENTS.md`.
Denna kodändring installerar inga tjänster och ändrar inga externa avtal.

Apples [provider-instruktion](https://developer.apple.com/documentation/identitydocumentservices/implenting-as-an-identity-document-provider)
kräver dokumentregistrering, en separat Identity Document Provider-utökning
och entitlement för aktuella mdoc-typer. Dessa delar finns inte i Tjipps
befintliga iOS 16-mål och antas inte fungera i Xcode 16.4-CI. Befintlig
Secure Enclave-nyckel och App Attest ersätter inte dessa funktioner.

Den aktuella [EU-referensappen för iOS](https://ageverification.dev/av-app-ios-wallet-ui/)
anger iOS 26.2 och har separata AV-anpassade beroenden. Dess källkod får inte
kopieras in utan att EUPL-villkoren hanteras. En native-integration behöver
en separat byggbar target, kompatibelt SDK/CI, rätt provisioning och ett
fysiskt prov med betrodda testutfärdare innan den aktiveras för användare.

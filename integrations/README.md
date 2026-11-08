# Integrera Tjipp

Förbered en SAML-integration med syntetiska identiteter. Materialet i den här
katalogen är [MIT-licensierat](LICENSE), inklusive kodexemplen: gratis att
använda och anpassa även kommersiellt. Behåll upphovsrätts- och licensmeddelandet.

## Status

| Del | Verifierat |
| --- | --- |
| SAML | Extern inloggning i Sweden Connects testklient den 4 november 2026, inklusive Safari. |
| Negativa SAML-fall | 18 fall dokumenterade i [PR 62](https://github.com/Jtensetti/openID/pull/62), bland annat fel nyckel, återspelning, fel ACS och sessionsbindning. |
| OIDC | Implementerat för lokal pilot; extern federation och flöde återstår. |
| Produktion | Tjipp saknar Digg-godkännande och oberoende säkerhetsgranskning. |

SAML-resultatet gäller `2e4d8c9ef1784022559600a84487259e71a0666c`, en separat
sandboxrevision. PR:n är ännu inte mergad; containerkontroller i CI är röda.
Testet styrker protokollutbytet med simulerad autentisering, inte en verklig
persons identitet eller tillitsnivå 3.

## 1. Prova referensflödet

Öppna [Sweden Connects testklient](https://testclient.sandbox.swedenconnect.se/).
Välj SAML, en registrerad test-SP och Tjipps sandbox-IdP. Skicka en signerad
begäran med HTTP-Redirect, `ForceAuthn=true` och `IsPassive=false`.
Utelämna RequestedAuthnContext eller använd `urn:openid:lab:simulated`.

På IdP-sidan: bekräfta att identiteten är simulerad och välj testidentiteten
`TEST-CREDENTIAL-alice`. Ingen passläsning eller appinstallation behövs.
Kontrollera att testklienten godtar svaret. En begäran om LoA3 ska nekas.

## 2. Anslut er testtjänst

1. Använd ert befintliga SAML-bibliotek eller er inloggningsförmedlare.
2. Skapa separat SP-konfiguration med HTTPS-adress, exakt ACS-URL samt
   testnycklar för signering och dekryptering.
3. Följ [sandboxens registrering](https://sandbox.swedenconnect.se/home/register.html).
   Kontrollera er SP-metadata med [Metadata Validator](https://validator.swedenconnect.se/)
   och registrera den i [Metadata Service](https://md.sandbox.swedenconnect.se/mdreg/home).
4. Läs det signerade IdP-flödet och välj Tjipps entityID nedan. Kontrollera
   signaturen mot sandboxens officiella metadataankare och metadatafilens
   giltighet innan den används. Följ [metadatainstruktionen](https://sandbox.swedenconnect.se/home/saml.html).
5. Skicka signerade AuthnRequest med den simulerade kontexten. Validera
   svar, assertion, mottagare, tidsgränser och sessionsbindning i biblioteket.

| Inställning | Värde |
| --- | --- |
| Tjipps entityID | `https://tjipp-sweden-connect-sandbox.onrender.com/idp` |
| Tjipps metadata | `https://tjipp-sweden-connect-sandbox.onrender.com/saml2/metadata` |
| Federationens IdP-metadata | `https://md.sandbox.swedenconnect.se/metadata/mdx/role/idp.xml` |
| Autentiseringskontext | `urn:openid:lab:simulated` |
| Begäran / svar | HTTP-Redirect / HTTP-POST |
| Identitetsuppgifter | Syntetiskt subjekt; inga verifierade personnummer eller passuppgifter. |

Hämta metadata för inspektion:

```sh
curl --fail --silent --show-error --proto '=https' 'https://tjipp-sweden-connect-sandbox.onrender.com/saml2/metadata' --output tjipp-sandbox-metadata.xml
```

Kommandot hämtar filen; signatur och tillit ska kontrolleras av
SAML-biblioteket enligt steg 4. Låt biblioteket läsa SSO-adresser och
certifikat från validerad metadata. Kopiera inte ett tillfälligt certifikat
som permanent ankare.

## 3. Kontrollera er integration

| Prov | Förväntat resultat |
| --- | --- |
| Giltig inloggning | Testsession för rätt syntetiskt subjekt. |
| Användaren avbryter | Ingen ny session. |
| Fel signatur, issuer, audience, recipient eller InResponseTo | Svaret nekas. |
| Utgånget eller återspelat svar | Ingen ny session. |
| Annan webbläsarsession eller ändrad RelayState | Ingen ny session. |
| Begärd LoA3 | Nekat svar utan assertion. |

Kör manipulerade svar mot er egen SP i en isolerad testmiljö. Spara version,
konfiguration och resultat utan sessionsvärden eller privata nycklar.

Sandboxen kan starta långsamt efter vila. Vänta tills den svarar innan ni
skapar en tidsbegränsad begäran. Testcertifikat och metadata löper ut och kan
bytas; kontrollera giltigheten vid fel. Tillgänglighet och support har inget SLA.

## Nästa steg

Integrationsmaterialet är kostnadsfritt. Villkor och priser för framtida
produktionsanvändning är inte fastställda. Produktionsanslutning kräver
separata nycklar, metadata och avtal samt att nödvändiga godkännanden finns.

Kontakt: [Jonatan Tensetti](mailto:Jonatan@tensetti.se).

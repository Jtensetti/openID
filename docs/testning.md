# Testning

Kör testerna från den revision som ska byggas. Aktuella resultat och
loggar finns i [GitHub Actions](https://github.com/Jtensetti/openID/actions).
Testantal från äldre revisioner används inte som bevis för den aktuella.

## Kör lokalt

| Del | Kommandon och förutsättningar |
|---|---|
| Pass, modeller, register och federation | [Verifierarens tester](../verification/README.md#tester). Linux x86_64 och låsta beroenden. |
| SAML, WebAuthn och dokumentunderskrift | [Protokolllabbens tester](../prototype/README.md#tester-och-beroenden) och [protokollbevis](provningsunderlag.md). JDK, Node och Chromium. |
| iPhone | [Bygge och simulatorprov](../ios/README.md#bygg-och-testa). macOS och Xcode. |
| Pilotcontainer | [Drift- och kapacitetsprov](../deployment/README.md#drift-och-kapacitet) samt [export/import av image](../deployment/build/README.md). |
| PostgreSQL och OpenBao | [Registertester](../deployment/cluster/README.md#tester). Isolerade syntetiska register. |
| Nginx | `python3 deployment/test_beta_nginx.py`. Linux och nginx; egna temporära kataloger, ingen ändring av systemtjänsten. |
| AWS-mallar | [Kompatibilitetsprov](../deployment/aws/README.md), [arkiv](../deployment/archive/README.md) och [backup/loggning](../deployment/security/README.md). Lokala mallprov skapar inga AWS-resurser. |
| Hälsokontrollcontainer | [HTTP-prov](../ops/README.md#kör-lokalt). Inga e-id-funktioner. |

Unix-sockets krävs för federationens processprov. Pass, bilder, privata
nycklar och verkliga tokens får inte hamna i loggar eller testartefakter.
Installation av molninfrastruktur och tester mot delade miljöer är separata driftåtgärder.

## CI och bevis

[Assurance checks](../.github/workflows/assurance.yml) återanvänder
komponenternas workflows från samma revision och sammanfattar resultatet i
`assurance-gate`. Alla komponenter måste passera. En misslyckad uppladdning
av obligatoriska artefakter innebär en ofullständig körning även om enskilda
tester har passerat.

Protokollpaketen innehåller faktisk testrevision, källrevision, JAR-/filhashar,
syntetiska resultat och täckningsgränser. Nginx-artefakten anger också
nginx-version och konfigurationshash. Följ [protokollinstruktionen](provningsunderlag.md)
för reproduktion och [leveransinstruktionen](releasekandidat.md) för att
bevara underlagen. Beroendelås, licenser och SBOM behövs för reproducerbara
byggen och behålls i källträdet; gamla fristående testresultat gör det inte.

## Täckning och begränsningar

| Område | Automatiska kontroller | Separat verifiering |
|---|---|---|
| Pass och chip | SOD, kedja, datagruppshashar, PACE/CA, replay och skyddad läsning med syntetiskt chip. | Fysisk NFC, avsedda pass och reläangrepp. |
| Certifikatspärr | Signerade CRL:er, spärrad DSC, utgång, återgång och atomiska filbyten. Utgång under registrering ska stoppa aktivering. | Operativ källa, aktualitet och återställning i drift. |
| Biometri | Modellinferens, huvudordning, parallax, försöksbudget, fel och samtidighet. | Kalibrerad felacceptans/felavvisning, presentationer, injektion och fysisk kamerakedja. |
| iPhone | Nyckelflöde, nätverksgräns, avbrott, registreringsåterhämtning, kameraguide och UI-fixturer. | Secure Enclave, App Attest, NFC, Face ID och fysisk användbarhet. |
| Livscykel | Aktivering enligt valt läge, utgång, spärr, engångsbruk och nyckelbyte. | Aktuell serverkonfiguration och sammanhängande telefonprov. |
| SAML/OIDC | Signatur, mottagare, state, nonce, PKCE, klientintyg, tider, återspelning, nekande och spärr. | Oberoende interoperabilitet och federationsanslutning. |
| Webb/nginx | Stora SAML-svar, skydd mot för stora POST, HSTS, klient-IP och synliga slutlägen vid OIDC-återgång. | Den installerade ingressen och fysisk webbläsare/app. |
| PDF | Signerade bytes, synligt kvitto, förändrat innehåll och separat OpenSSL-validering. | Betrodd certifikatkedja, tid och långtidsvalidering. |
| Återställning | SQLite/PostgreSQL, nyckelbindning, karantän och bevarat spärrkrav med syntetiska data. | Faktisk backup, nyckelförvaring och driftövning. |
| Arkiv och infrastruktur | Export, manipulation, åtkomstroller, kvittenskontrakt och CloudFormation Guard. | Verklig mottagning, återläsning, larm och molnkonfiguration. |

En grön CI bevisar täckningen ovan, inte ISO 27001-nivå, Digg-godkännande
eller att alla beroenden saknar sårbarheter. Öppna begränsningar och
separata kodutkast beskrivs i [SECURITY.md](../SECURITY.md#kända-begränsningar-och-separata-utkast).

## Fysisk iPhone

Använd [körinstruktionen för fysisk acceptans](fysisk-acceptans.md) och
[appens utgåvor](../ios/README.md#utgåvor). Registrering, godkännande,
nekande, underskrift, nyckelborttagning efter spärr och återstart ska provas
mot samma app-/serverkombination. Kontrollera även mörkt/ljust läge,
stor text och VoiceOver. Simulatorn ersätter inte dessa prov.

Förvara resultatet privat med datum, versioner, konfiguration och faktisk
observation per testfall. En äldre lyckad delkontroll får inte räknas som
ett nytt helkedjeprov.

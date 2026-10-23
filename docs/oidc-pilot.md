# OIDC i den privata piloten

OIDC aktiveras endast när `phone-idp`/`phone-sp` får en explicit
`PilotOrigins`-konfiguration. Den ursprungliga lokala SAML-labben påverkas
inte. Båda protokollen använder samma manuellt aktiverade ID, signerade
enhetsgodkännande och aktuella spärrstatus. Appen är autentiseringsenhet;
OIDC-kod och token hanteras av testsidans server, aldrig av QR-koden.

Flödet använder Authorization Code, S256 PKCE, slumpmässigt `state` och
`nonce`, 30 sekunders kodlivslängd och `private_key_jwt` med fast registrerad
RSA-nyckel. Mottagaren verifierar signatur, RS256, issuer, audience,
nonce, tidsgränser och den egna autentiseringskontexten. `max_age=0`
begär färsk autentisering; mottagaren nekar saknad eller för gammal
`auth_time`. Kontexten begärs som essential claim utan samtidig
`acr_values`. Pending-state
konsumeras en gång; en skyddad session gäller högst fem minuter och kräver
fortsatt giltigt ID vid varje åtkomst. Ingen refresh token begärs eller lagras.

Fasta HTTPS-origins och redirect URI ersätter dynamisk discovery eller
klientregistrering. Den egna kontexten är
`urn:openid:authn:passport-native:v1`. LoA1–4 utfärdas inte. Begäran om en
sådan nivå i testvyn avslås. Denna avgränsade integration är inte ett
påstående om fullständig Sweden Connect-profilöverensstämmelse.

Testsidan begär samma privata identitetsattribut som SAML: interna
identitetsreferenser, namn, födelsedatum från MRZ och passporträtt.
Godkännandet i appen anger detta syfte. Attribut finns endast i kortlivade
serversessioner och överförs via verifierad TLS; inga token eller bilder
ska skrivas till åtkomstlogg eller webbläsarens lokala lagring. Ytterligare
minimering per extern tjänst krävs före sådan anslutning.

HTTPS-ingången kräver individuellt betakonto för webbsidor. Endast
`/oidc/token` undantas från webbläsarens Basic-inloggning; där krävs
protokollets signerade klientautentisering. Portarna för verifierare,
IdP och mottagare förblir bundna till loopback. Inga dynamiska motparter,
myndighetsmetadata eller produktionsnycklar tillåts i denna pilot.

Krav: FED-03, FED-04, FED-02 och ID-10. Fullständig extern
interoperabilitet, tillitsgodkännande och oberoende säkerhetsgranskning
återstår. Upstream och beroenden anges i THIRD_PARTY.md.

Versionsbunden profilmappning och CI-artefakter finns i
[prövningsunderlaget](provningsunderlag.md). Federerade underskriftsbegäranden
med SignMessage/SAD får inte använda den vanliga inloggningsbekräftelsen;
providerna avvisar dessa tills en särskild integration finns.

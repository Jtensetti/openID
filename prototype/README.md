# SAML/WebAuthn-labb

Lokal IdP och testtjänst med Sweden Connect. WebAuthn bevisar kontroll över
en testnyckel; identitetskontrollen är simulerad. Det äldre `start`-läget
simulerar även användarens godkännande.

Appens passbaserade flöde använder samma SAML-bibliotek med en separat
provider. Se [phone-idp och phone-sp](../verification/README.md#saml-inloggning-med-passets-identitet).

## Kör webbklienten

Kräver JDK 21, Linux/POSIX, portar 8443/8444 och en WebAuthn-webbläsare.
Använd en separat testprofil och en passkey eller FIDO2-nyckel som stöder
användarverifiering. En passkey kan synkroniseras av sin leverantör.

Från `prototype/`, med `JAVA_HOME` satt till JDK 21:

```sh
./scripts/lab.sh build
java -jar target/isolated-eid-lab.jar init .local/web-test
java -jar target/isolated-eid-lab.jar start-web .local/web-test
```

1. Använd en ny katalog; äldre certifikat kan sakna `localhost`.
   Inspektera certifikatet med
   `keytool -printcert -file .local/web-test/tls.crt` och betro det i
   testprofilen. WebAuthn kräver säker kontext.
2. Öppna <https://localhost:8443/wallet/>, bekräfta den simulerade kontrollen
   och välj **Registrera testnyckel**. Använd `localhost`, inte IP-adressen:
   WebAuthn RP-ID är ett domännamn.
3. Öppna <https://localhost:8444/> och välj **Starta testinloggning**.
   Kontrollera motparten och välj **Godkänn med testnyckel**.
   `/me` ska därefter visa `SYNTHETIC-alice`.
4. Prova utloggning och spärr från testplånboken. Spärr stoppar även aktiva
   SP-sessioner. Alice gäller i en timme från `init`.
5. Installation på hemskärmen är valfri. Utan kontakt med servern visas
   en 503-sida; inloggning fungerar inte offline.

`start-web` behåller publika nycklar och signaturräknare vid normal omstart.
En registrerad nyckel kan inte skrivas över. `start` vägrar använda ett
register med WebAuthn-nycklar. Schema 1 migreras atomiskt till 2.
Krasch och backupåterläsning spärrar alla credentials.

För Chromium på Linux kan tilliten begränsas till labbcertifikatets
publika nyckel. Kör i en andra terminal med OpenSSL installerat:

```sh
LAB_SPKI=$(openssl x509 -in .local/web-test/tls.crt -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | openssl base64 -A)
chromium --user-data-dir="$PWD/.local/web-browser" --ignore-certificate-errors-spki-list="$LAB_SPKI" https://localhost:8443/wallet/
curl --cacert .local/web-test/tls.crt https://localhost:8444/
```

Använd profilen enbart för labben. Installera inget systemomfattande
tillitsankare och använd inte ett generellt certifikatundantag.
Automatiserade browserprov använder samma certifikatspecifika tillit.

## Äldre protokolläge

Från repots rot:

```sh
cd prototype
./scripts/lab.sh build
./scripts/lab.sh init
./scripts/lab.sh start
```

Maven 3.9.11 hämtas och SHA-256-kontrolleras av wrappern. Första bygget
kräver internet. `init` skapar separata RSA-testnycklar för TLS, IdP och SP
i `.local/`, med 30 dagars certifikatgiltighet. Katalogen skrivs inte över.
Testlösenordet är offentligt; privata nycklar checkas inte in.

1. Öppna <https://127.0.0.1:8443/> och <https://127.0.0.1:8444/> i en separat
   testprofil. Kontrollera certifikatet mot `.local/tls.crt` och godta bara
   dessa adresser. Detta läge använder `127.0.0.1`, inte `localhost`.
2. Starta testinloggningen, välj `SYNTHETIC-alice`, bekräfta simuleringen
   och välj **Godkänn testinloggning**. `/me` ska visa identiteten.
3. Prova `SYNTHETIC-revoked`, `SYNTHETIC-expired` och **Avbryt**:
   ingen session ska skapas.
4. Spärra Alice på IdP:ns startsida och kontrollera att `/me` nekar sessionen.

Stoppa med **Ctrl+C**, även före ombyggnad av JAR-filen. Normal omstart
behåller register, spärrar, händelser och ursprunglig giltighet, men tappar
webbsessioner. För en ny testomgång: stoppa, flytta `.local/` åt sidan och kör
`init` igen. G1-kataloger utan `registry.sqlite` kan inte startas.

```sh
keytool -printcert -file .local/tls.crt
curl --cacert .local/tls.crt https://127.0.0.1:8444/
```

## Tester och beroenden

Stoppa den manuella labben före process- och webbläsartesterna.

```sh
./mvnw -B -ntp clean verify dependency:list -DoutputAbsoluteArtifactFilename=true -DoutputFile=target/dependencies.txt
python3 scripts/dependencies.py
python3 scripts/smoke.py
python3 scripts/recovery-smoke.py
npm ci --ignore-scripts
npx --no-install playwright install chromium --only-shell
npm run test:browser
```

Browserproven kräver Node 22–24 (CI: 24.19.0). Playwright 1.62.1 är låst i
`package-lock.json`. På Linux kan `install --with-deps chromium --only-shell`
behövas. `CHROMIUM_EXECUTABLE` kan ange motsvarande lokala browser.
`npm run test:web` kör bara WebAuthn-varianterna.

JUnit provar HTTPS, SAML-validering, WebAuthn, livscykel och lagring.
Negativa meddelanden omfattar giltiga signaturer med fel protokollinnehåll.
Chromium provar registrering, inloggning, Origin, automatisk POST,
utloggning, spärr, PWA och offlinebeteende med virtuella USB- och
plattformsautentiserare. Fysiska nycklar och OS-installation återstår.

`dependencies.lock.json` låser version och SHA-256 för varje upplöst JAR,
inklusive testberoenden. Byggpluginer styrs av POM/parent; deras transitiva
graf omfattas inte av JAR-låset. Efter en granskad beroendeändring:

```sh
./mvnw -B -ntp dependency:list -DoutputAbsoluteArtifactFilename=true -DoutputFile=target/dependencies.txt
python3 scripts/dependencies.py --write
./mvnw -B -ntp org.cyclonedx:cyclonedx-maven-plugin:2.9.1:makeBom
```

Granska diff, licenser och advisories och kör testerna.
Resultat: [SAML](evidence/verification.md), [lagring](evidence/g2-verification.md),
[WebAuthn](evidence/web-verification.md).

## Protokoll och tillstånd

| Del | Utförande |
|---|---|
| IdP | Sweden Connect Spring Authentication Server 1.0.3 med lokal autentiseringsprovider. |
| SP | Sweden Connect/OpenSAML och adapter från Test Client 1.0.19. |
| SAML | Signerad AuthnRequest via Redirect; signerad Response och signerad/krypterad Assertion via POST. RSA-SHA256/SHA256 för signaturvalidering. |
| Profil | `urn:openid:lab:simulated`, attribut `displayName=SYNTHETIC-…`. |
| Tillit | Fasta lokala metadata för en IdP och en SP, med separata signaturnycklar. |
| Bindning | Issuer, audience, destination, recipient, InResponseTo, RelayState, signatur, tid, replay, engångssession och cookiesbyte. |
| WebAuthn | Yubico Server 2.10.1, ES256/RS256, användarverifiering, attestering `none`. Challenge, ursprung, RP-ID och signatur kontrolleras. |
| Livscykel | PENDING → PROOFED → ACTIVE; utgång och permanent spärr. Ersättning spärrar den gamla nyckeln atomärt och testas utan supportgränssnitt. |
| Spärr | Samma lokala register läses av IdP och SP. Ny credential återupplivar inte gamla sessioner. |
| Tider | Begäran/godkännande 60 s, Assertion 30 s, mottaget svar inom ±5 s från IssueInstant, SP-session högst 5 min. SSO avstängt. |

## Lagring, spärr och återläsning

`registry.sqlite` innehåller testidentiteter, publika WebAuthn-nycklar,
räknare, backupflaggor, spärrversioner, revisionshändelser och terminala
SP-utfall. SQLite 3.53.4 använder WAL och `synchronous=FULL`.
Ett processlås nekar en andra JVM. Katalogen kräver POSIX-rättighet 0700;
delad nätverksdisk stöds inte. Händelsetriggers stoppar vanlig UPDATE/DELETE,
men databasägaren kan kringgå dem.

Stoppa labben före administrativa kommandon:

```sh
java -jar target/isolated-eid-lab.jar revoke .local TEST-CREDENTIAL-alice
java -jar target/isolated-eid-lab.jar audit .local
java -jar target/isolated-eid-lab.jar report .local 2026-10
mkdir -m 700 .local-backups
java -jar target/isolated-eid-lab.jar backup .local .local-backups/before-test.sqlite
java -jar target/isolated-eid-lab.jar restore .local-backups/before-test.sqlite .local-restored
java -jar target/isolated-eid-lab.jar start .local-restored
```

Backup använder `VACUUM INTO` och kräver ett nytt mål i en privat katalog.
Restore kräver ny katalog, skapar nya testnycklar och spärrar alla återställda
credentials. Återaktivering stöds inte.

`GET https://127.0.0.1:8444/health/ready` kontrollerar registret.
Lagringsfel stoppar autentisering. Efter skrivfel behålls markeringen för
osäker avstängning; ta inte bort den manuellt.

Rapporten räknar accepterade och nekade konsumerade SAML-svar, deduplicerar
terminala händelser och grupperar efter kalenderperiod i Europe/Stockholm.
Avbrutna flöden som når SP räknas som `failed`; övergivna begäranden utan svar
räknas inte. `compensableTransactions` är alltid 0 och `submission` är
`INTE SKICKAT`. Rapporten innehåller inga personidentifierare och skickas
inte till Digg.

## Begränsningar

IdP och SP kör i samma JVM på loopback. Operativsystemkonto och testprofil
måste vara betrodda; exponera inte labben via tunnel eller proxy.
Miljövariabler och CLI kan inte byta bindning, metadata eller nycklar.

Labben saknar verifierad personbindning, distribuerad spärr/lagring,
HSM, oberoende bevisarkiv, produktionsåterställning och driftberedskap.
Tillitsgodkännande och oberoende säkerhetsacceptans återstår.
Det korta SAML-svarsfönstret och upstreams audit-varning beskrivs i
[verifieringsrapporten](evidence/verification.md).

[Driftcontainern](../ops/README.md) innehåller inte labben eller dess nycklar.
Versioner, licenser och underhåll finns i [THIRD_PARTY.md](../THIRD_PARTY.md).

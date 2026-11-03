# Federationsnycklar och metadata: isolerat sandboxprov

Den lokala SAML-labben har redan självsignerade testcertifikat och PAdES-B-B med en separat, ej betrodd test-CA. Det här paketet lägger till **separata** SAML-signering- och krypteringscertifikat samt en läsande metadatakontroll. Varken nycklar, certifikat eller tillit i en driftsatt tjänst ändras.

## Skapa syntetiska certifikat lokalt

Kräver Bash och OpenSSL 3 på en betrodd utvecklingsmaskin. Kör från repots rot:

```sh
bash deployment/federation/generate-sandbox-certs.sh
```

Skriptet skapar två RSA-3072-nyckelpar och självsignerade X.509-certifikat i `deployment/federation/.local/` (katalog 0700, filer 0600). Alla hemligheter stannar lokalt och får **aldrig** kopieras till Git, CI-artefakter, Dockerbyggkontext eller en delad filyta. Skriptet vägrar skriva över befintliga nycklar. De skapade certifikaten är **inte inkopplade** i `phone-idp`/`phone-sp` och **inte färdiga för extern metadataregistrering**. Certifikaten är märkta SANDBOX.

Certifikatens publika data kan granskas med:

```sh
openssl x509 -in deployment/federation/.local/saml-signing.crt -noout -text
openssl x509 -in deployment/federation/.local/saml-encryption.crt -noout -text
```

Privata nycklar är exportbara i detta sandboxprov. Produktionsnycklar behöver separata säkerhetsgränser, HSM eller skyddad nyckeltjänst, granskad rotation och behörighetsseparation.

## Kontrollera SAML-metadata

Den lokala Java-labben exporterar i och med ändringen även `idp-metadata.xml`, med sina *befintliga pinnade testnycklar*, när labben startar. Det är inte ett externt godkänt metadatafeed. Exempel från repots rot efter att en lokal `phone-idp` har startats:

```sh
python3 deployment/federation/metadata_preflight.py \
  /privat/openid-federation/idp-metadata.xml \
  --role idp --expected-entity https://localhost:8443/idp
```

Kontrollen ger avsiktligt **FAIL** för den nuvarande labbmetadatan eftersom den saknar bland annat organisationsinformation och logotyp för en extern federation. Dessa uppgifter får inte fabriceras. Verktyget kontrollerar XML-struktur, SAML-roll, entityID, organisation/UIInfo, X.509-kodning och signerings-/krypteringsnycklar. `--json` ger maskinläsbart underlag.

**Begränsning:** Preflight validerar inte federationens *signerade metadata*, tillitsankare, att uppgifterna godkänts, att nycklarna används av körande IdP, protokollöverensstämmelse eller avtalsstatus. Ett självsignerat nyckelcertifikat ger aldrig federationstillit på egen hand.

## Nästa integrationsgrindar

1. Bekräfta juridisk identitet och federationsoperatörens accepterade profiler. Fastställ riktiga HTTPS-endpoints, logotyp och entityID.
2. Konfigurera körande IdP/SP med skyddade privata nycklar som matchar den publicerade metadatan. Den nuvarande labben använder `TestKeys` (offentligt testlösenord) och är inte produktionsmässig.
3. Implementera kontrollerad hämtning och **kryptografisk verifiering av signerad federationsmetadata**, med betrodda ankare och kontrollerad nyckelrotation. Kör positiva och negativa tester mot en godkänd testmotpart.
4. Dokumentunderskrift: den befintliga `PadesSigner` är PAdES-B-B med test-CA; extern certifikattillit, betrodd tid, spärrinformation och långtidsvalidering saknas. Värdera Sweden Connect SignService och EU DSS mot ett beslut om underskriftsprofil innan integrationskod tillförs.
5. iOS: befintlig TestFlight körs via Apples utvecklarsignering. Distribution direkt från webbplats i EU kräver separat Apples godkännande och notarisation. Ingen Android-klient finns i detta repo.

## Reproducerbara lokala tester

```sh
python3 -m unittest discover -s deployment/federation -p 'test_*.py' -v
bash -n deployment/federation/generate-sandbox-certs.sh
```

Primärkällor: [Sweden Connect Deployment Profile](https://docs.swedenconnect.se/technical-framework/latest/02_-_Deployment_Profile_for_the_Swedish_eID_Framework.html), [Sweden Connect SignService](https://github.com/swedenconnect/signservice), [EU DSS](https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/467109107/Digital+Signature+Service+-+DSS) och [Apple: webbdistribution](https://developer.apple.com/documentation/marketplacekit/distributing-your-app-from-your-website).

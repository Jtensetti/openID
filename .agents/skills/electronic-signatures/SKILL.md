---
name: electronic-signatures
description: >-
  Använd vid elektronisk underskrift, dokumentgodkännande, signaturformat,
  certifikat eller valideringsbevis. Skiljer autentisering från underskrift
  och kräver verifierbar bindning till innehåll och användaravsikt.
---

# Elektroniska underskrifter

Projektspecifik originalinstruktion. Läs `AGENTS.md`, SIG-raderna i kravmatrisen och underskriftsdelen av arkitekturen. Följ T01 till den aktuella underskriftsspecifikationen och kontrollera dess version. G04 är en kandidat, inte ett godkänt utförande.

## Avgränsning

Fastställ vem som undertecknar, vilket exakt innehåll som godkänns, varför underskrift behövs, vilken profil som gäller och vem som senare ska validera resultatet. Identifiering, avancerad underskrift och kvalificerad underskrift får inte användas som utbytbara etiketter.

När den juridiska betydelsen inte är fastställd ska leveransen vara en teknisk prototyp eller en frågelista till ansvarig jurist, inte en utfästelse om rättsverkan.

## Arbetsgång

1. Läs det aktuella flödet från mottaget dokument till validerat resultat. Identifiera transformationssteg: rendering, konvertering, normalisering, hashning och eventuell komplettering.
2. Specificera användaravsikten. Användaren ska förstå att åtgärden är en underskrift och vilket innehåll den avser. En vanlig inloggning får inte tyst uppgraderas till underskrift.
3. Bind godkännandet till exakt dokumentversion, transaktion och rätt undertecknare. Dokumentera vad som händer om innehållet inte kan visas korrekt.
4. Kartlägg nyckelkontroll och autentisering i den valda underskriftsmodellen. Följ `eid-lifecycle-security` för credential, spärr och nyckelförvaltning.
5. Välj granskad signerings- och valideringsimplementation med låsta versioner. Följ `supply-chain-and-release`; egen kryptografi är inte ett alternativ.
6. Specificera vilka certifikat-, tids- och valideringsbevis som behövs för vald profil och lagringshorisont. Anta inte att en lyckad kontroll i dag garanterar validering långt senare.
7. Kör positiva och negativa tester med syntetiska dokument. Använd en oberoende valideringsväg där det är genomförbart och redovisa begränsningar.
8. Klassificera utfallet separat för rapportering. Följ `eid-economics-and-reporting` innan en underskrift räknas som ersättningsgrundande.

## Negativa tester

Bytt dokument efter visning; annan undertecknare än den som godkänt; återspelat godkännande; fel certifikat eller kedja; utgången/spärrad credential; avbruten signering; felaktig validering; innehåll som ser olika ut i olika visare; dubblett i rapporteringen.

Ett framgångsrikt anrop till ett signeringsbibliotek räcker inte. Kontrollera att mottagaren kan verifiera just den relation mellan innehåll, avsikt och undertecknare som vårt flöde påstår.

## Leveransformat

```text
Ändamål och avgränsning:
Krav-ID och exakt profilversion:
Dokument-/transformationskedja:
Hur avsikt och undertecknare binds:
Nyckel- och certifikatmodell:
Valideringsresultat och bevisreferenser:
Negativa testresultat:
Vad som fortfarande kräver juridisk eller oberoende granskning:
Rapporteringsklassificering:
```

## Stoppsignaler

En JWT eller inloggningsassertion används som enda bevis för en dokumentunderskrift; dokumentet kan ändras efter godkännandet; testnycklar används i verkliga handlingar; eller produkten kallas kvalificerad utan stöd. Blockera påståendet och rätta scope innan fortsatt leverans.

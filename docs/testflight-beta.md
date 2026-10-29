# Automatisk aktivering i TestFlight-betan

Ett uttryckligen valt testläge för november 2026 aktiverar test-ID efter
godkänd App Attest, passets signatur- och chipkontroller, ansiktsjämförelse,
PAD och huvudrörelser. Trösklarna är fortsatt experimentella: ansikte minst
0,5 och PAD minst 0,8 i samtliga tre bilder. Läget som enbart loggar
huvudrörelser får inte autoaktivera. Biometrisk kalibrering och oberoende
injektionsprov återstår.

Ingen e-post krävs för denna aktivering. Appen visar bekräftelsen. En separat
spärrkod hämtas genom en enhetssignerad statusläsning och ska sparas utanför
telefonen. Koden kan bara spärra, aldrig aktivera eller återställa ett ID.
Ingen separat avisering till en oberoende kontaktväg skickas i testläget.
Standardlägets manuella aktivering och kontaktkontroll finns kvar.

Status är fortsatt `PRIVATE_PILOT`, `legalIdentityIssued=false` och
`issuanceEnabled=false`: inget Digg-godkännande, anslutningsavtal eller
godkänd tillitsnivå. Testläget ersätter inte information till deltagarna
eller behandlingsvillkor för deras riktiga pass- och ansiktsuppgifter.

## Tillstånd och befogenheter

| Övergång | Förvillkor och ansvar |
|---|---|
| Ny → aktivt test-ID | Verifieraren godkänner alla kontroller och binder passprofil till enhetsnyckel. Lokal registrering, krypterad spärrkod och aktivering är en transaktion. Den oberoende auktoriteten måste först bekräfta registreringen. |
| Aktivt → spärrat | Innehavaren med enhetssignatur eller separat spärrkod, eller behörig operatör. Spärr går före registrering och inloggning. Samma nyckel återaktiveras aldrig. |
| Aktivt → längre betagiltighet | Uttryckligt operatörskommando förlänger bara fortfarande aktiva, ospärrade ID:n med passprofil. Utgångna och väntande ID:n aktiveras inte. |
| Alla → spärrade vid betans slut | Wallet och auktoritet nekar användning från **1 december 2026 kl. 00.00 Europe/Stockholm**, motsvarande **30 november kl. 23.00 UTC**. |

Automatiska test-ID:n har ingen 24–72-timmarsgräns. Passets utgångsdatum är
fortfarande en övre gräns. Nyregistrering med samma pass ersätter den gamla
enhetsnyckeln enligt befintlig spärrpolicy. QR-koder och sessioner behåller
sina korta tidsgränser; deras giltighet är skild från ID:ts.

Slutspärren lagras som kampanjregel i SQLite och den befintliga DynamoDB-
auktoriteten. Den gäller även äldre manuella ID:n i det valda registret.
Auktoriteten skriver dessutom ID:ts permanenta spärrpost vid statusläsning
efter slutdatumet. Inget jobb behöver hinna före serverns avstängning.
Att stänga av autoaktivering tar inte bort kampanjens slutspärr. Återställning
av själva auktoriteten kräver avstämning av senare spärrar och kampanjregeln.

## Införande

Funktionen är avstängd som standard. En källkodsändring uppdaterar inte
installerade appar eller servern.

1. Testa och distribuera den nya appen. Äldre appar accepterar endast
   `PENDING_REVIEW` i registreringssvaret och behöver uppdateras först.
2. Uppdatera befintlig kontinuitetsstack med parametern
   `TestBetaMode=testflight-november-2026`. Samma funktioner, tabeller och
   IAM-rättigheter används. Inga nya AWS-resurser eller schemalagda jobb behövs.
3. Lägg `"testBeta": true` i privat `continuity.json`. Verifierare,
   federationsbrygga och operatörskommandon måste använda både den nya
   koden och samma konfiguration. Migrerad wallet nekar senare öppning
   med en konfiguration som saknar testläget.
4. Förläng vid behov befintliga aktiva ID:n med `wallet_cli.py --db
   /srv/openid/data/wallet.sqlite extend-active-test-ids` och samma
   `OPENID_CONTINUITY_CONFIG`. Svaret innehåller bara ett antal.
5. Prova fysisk registrering, status/spärrkod, SAML, OIDC, nekande och spärr.
   Publicera uppdaterad hjälp och TestFlight-text när beteendet är tillgängligt.

Det äldre privata VPN-registret har egen konfiguration. Installera samma
wallet-kod där och kör `wallet_cli.py --db /srv/openid/data/wallet.sqlite
set-test-beta-deadline`. Starta därefter om verifierare och brygga så att alla
processer läser den beständiga slutspärren. Detta aktiverar inte automatisk
utgivning och flyttar inte persondata. Bekräfta båda registrens konfiguration
före driftsättning. En avstängd server är inte ensam ett spärrbeslut.

## Prov

`test_test_beta` provar lång giltighet, passutgång, slutdatum, redan godkända
inloggningar och federationssessioner, återspelning, tjänstefel, avbruten
skrivning, konfigurationsbyte och återläsning. Pass- och biometrikontroller
simuleras; enhetssignaturer, kryptering och SQLite används på riktigt.
`test_authority` provar villkorad registrering, samtidig spärr, äldre ID:n
och slutspärr trots avstängd autoaktivering med simulerad AWS-tabell.
`WalletSecurityTests` provar appens bindning till nyckel och testkampanj.
Fysiska prov och driftverifiering redovisas separat.

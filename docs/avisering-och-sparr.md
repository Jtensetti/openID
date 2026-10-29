# Oberoende avisering och spärr

Status 2026-10-22: [den separata tjänsten](../deployment/continuity/README.md)
är kopplad till den publika SQLite-betan. Verifierare, federationsbrygga och
operatörskommandon använder samma spärrkontroll. Appbygge 106 innehåller
kodlagring och direkt spärr som kan avbryta en väntande statuskontroll.
Ett pågående godkännande eller avslag avbryts inte. Den privata testmiljön är inte migrerad.
K6.6 och K6.8 är delvis tekniskt täckta och har fortsatt formell status OPEN.

## Oberoende avisering

En adress som angriparen anger under samma passregistrering är inte i sig
oberoende. Operatören ska före aktivering fastställa och dokumentera kontaktens
ursprung, exempelvis separat kontrollerad befintlig kontakt eller registerstödd kanal.
E-postleveransens lämplighet och kontaktbindningen ska riskbedömas; ett
SMTP-svar eller en öppningspixel styrker inte att rätt person informerats.

Pilotkedja: granskad ansökan → separat kontaktbindning → manuellt
aktiveringsbeslut och aviseringspost i samma transaktion → beständig SQS-kö →
SES. Aktivering utan kontaktbindning nekas. Kontaktbindning aktiverar aldrig
ett ID. SES-mottagaren måste även vara verifierad medan kontot är i testläge.

Aviseringspost: stabilt händelse-ID, intern credentialreferens,
kontaktversion, mallversion, skapandetid, antal försök och transportstatus.
Kontaktadress lagras krypterat med begränsad åtkomst. Meddelandet innehåller
produkt och väg till spärrhjälp, inte personnummer, passnummer, bild,
nyckel eller länk som automatiskt godkänner något. Dubbel leverans kan ske
vid nätfel; dubbel utfärdning får aldrig ske. Bytt kontakt får inte omdirigera
redan beslutad avisering utan ny kontroll.

Syntetiska prov täcker saknad kontakt, ändrad kontaktversion, rollback, krasch mellan
beslut och leverans, dubbla jobb, leveransfel, förfalskad kvittens och spärr
under pågående leverans. Loggar får inte innehålla kontaktadresser eller tokens.

Utkorgens `QUEUED` och mottagarens `ACCEPTED` betyder transportkvittens, inte
bevis på att rätt person läst aviseringen. SES kan vidarebefordra studsar till
operatören. Separat person–kontaktkontroll, beslutad leveranspolicy, automatiska
driftlarm och bemanning återstår. Köexport sker på testservern; en oexporterad
post efter ett abrupt avbrott väntar till nästa serverstart. Redan köade jobb
behandlas av den separata tjänsten även när testservern är avstängd.

## Spärr när verifieraren är stängd

En statisk projektsida kan visas dygnet runt men kan inte ensam ändra
spärrstatus. En e-postlåda tar emot ärenden men bevisar varken identitet,
bemanning eller verkställighet. Vi får inte kalla något av detta en färdig
spärrtjänst. Testservern för registrering och legitimering är öppen dygnet runt
till och med 30 november 2026. Den stängs av 1 december 2026 kl. 00.00 svensk
tid enligt [betans driftplan](../deployment/README.md#betans-öppettider).

Den publika spärrfunktionen i Lambda tar emot ett separat återkallelsebevis och
skriver en permanent spärr i DynamoDB. Den får inte aktivera eller ändra kontakt.
Appen sparar beviset i Keychain och låter innehavaren spara det utanför telefonen.
Spärrformuläret fungerar utan appen och lägger aldrig koden i en URL.

Verifieraren och federationsbryggan kontrollerar aktuell spärrstatus utan positiv cache.
Om status inte kan kontrolleras ska åtkomst nekas. Efter ett serverstopp måste
spärrar vara synkroniserade innan någon legitimering tillåts. Lokalt cachad
ACTIVE-status får aldrig övertrumfa spärr. En kvittens om mottaget ärende
måste skiljas från bekräftad verkställighet.

Förlorad telefon: separat återkallelsebevis eller annan beslutad autentisering
behövs. Publicera ingen endpoint som spärrar på enbart personnummer eller
namn. Återkallelsebevis ska inte fungera som återställnings-/aktiveringsbevis.
Begränsa försök utan att möjliggöra masspärr eller permanent utelåsning.

Negativa tester täcker fel kod, replay, dubbel spärr, otillgänglig statuskälla,
gammal backup och kömanipulation. I AWS har ett syntetiskt ID spärrats med
betans tjänster stoppade. Efter återöppning av dess wallet nekades ny
legitimering, befintlig federationssession och konsumtion av en godkänd begäran.
Fysisk iPhone, sammanhängande återstartsprov i avsedd driftmiljö och oberoende missbruksprov återstår.

## Kvarvarande beslut

Fastställ kontaktkontroll, leveranspolicy, hantering när spärrkod saknas,
återställning av den auktoritativa tabellen och operativ beredskap.
Organisation, bemanning och oberoende granskning är separata förutsättningar.
En teknisk pilot med manuell aktivering är inte ett tillitsgodkännande.

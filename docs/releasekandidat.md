# Releasekandidat och återgång

En kandidat sammanför granskade ändringar till en bestämd källrevision.
Den är underlag för fortsatt prövning, inte ett produktionsgodkännande.
Produktionskraven i [utveckling](utveckling.md) och [inför utgivning](infor-utgivning.md)
gäller även när alla automatiska kontroller har passerat.

## Sammanför och verifiera

1. Utgå från aktuell `main`, använd separat branch och bevara de ingående
   ändringarnas historik. Kontrollera överlappande ändringar, inte bara
   konfliktmarkeringar. Låt en gemensam PR beskriva slutresultatet.
2. Granska beteende, säkerhetsgränser, låsfiler och CI-behörigheter. Ange
   kvarvarande fynd och om granskningen är egen eller oberoende.
3. Ge iPhone-bygget ett nytt byggnummer i `ios/scripts/project.py` och
   generera projektet. Kontrollera att låsta Swift-paket är oförändrade.
4. Kör hela `Assurance checks` på den gemensamma revisionen. Kräv att alla
   jobb, inklusive `assurance-gate` och nginx-provet, avslutas godkänt.
   Ett avbrutet eller överhoppat jobb är inget godkännande.
5. Bygg distributionsartefakter från samma källträd. För iPhone verifieras
   signatur, bundle/version, App Attest-miljö, debuggerbehörighet och profil.
   För servern bevaras exakt image-ID/digest och byggunderlag. En tagg ensam
   är inte en stabil referens. Återbyggnad kan ge andra artefaktbytes.
6. Efter merge: kontrollera att `main` har samma träd som det testade
   slutresultatet. Om trädet ändras krävs relevanta nya kontroller. Håll
   huvudrevision, CI:s tillfälliga merge-revision och lokalt byggd revision
   åtskilda även när träden är identiska.

## Bevispaket

Förvara kandidatens manifest och artefakter utanför kodrepot. Ange:

- full källrevision, Git-träd, ingående PR:er och huvudrevision efter merge;
- byggverktyg och plattform, appversion/byggnummer, IPA/JAR/image-checksummor;
- testkörningarnas länkar, exakta revisioner, resultat och begränsningar;
- de använda beroendelåsen, SBOM och daterade advisory-resultat;
- driftstatus per komponent: byggd, verifierad, installerad eller driftsatt;
- tidigare artefakter och konfigurationsreferenser för återgång;
- granskningsfynd, kvarvarande hinder, ansvarig och godkännandeomfattning.

Hämta CI-artefakterna innan deras retention löper ut. Kontrollsummor och
CI-proveniens stödjer spårbarhet men utgör inte oberoende godkännande.
Personuppgifter, enhetsidentifierare, profiler, nycklar och driftkonfiguration
med hemligheter får inte ingå i publika bilagor. Verkliga användarprov sparas
privat; syntetiska tester och användarens återkoppling märks separat.
Gamla fysiska prov får inte räknas som omprov på den nya kandidaten.

## Återgång av programvara i den privata betan

Innan ett byte: registrera alla körande komponenters image-ID, bevara
föregående konfigurationsfiler privat och kontrollera att de refererade
artefakterna faktiskt finns kvar. Bevara även det föregående signerade
iPhone-bygget och dess giltiga installationsprofil. Kontrollera schema- och
API-kompatibilitet; en återgång är inte generellt säker över migreringar.

Vid fel på en ändring utan datamigrering:

1. Stoppa nya prov och behåll den aktuella databasen, journalerna, nycklarna
   och spärrtjänsten. Dokumentera vilka pågående flöden som påverkas.
2. Återställ berörda tjänsters image-referenser och konfiguration från den
   verifierade föregående uppsättningen. Byt inte komponenter som saknar
   koppling till felet. Kör nginx-konfigurationskontroll före omladdning.
3. Kontrollera readiness, betakontoskydd, ett nytt syntetiskt flöde och att
   spärrade identiteter fortfarande nekas. Tidigare QR-koder, sessioner och
   underskriftsnedladdningar kan ha försvunnit vid processbytet.
4. För iPhone: installera endast en kompatibel, fortfarande giltigt signerad
   version över den befintliga appen. Avinstallera inte för att lösa ett
   versionsproblem; det kan påverka data och enhetsbindning. Bekräfta den
   installerade versionen. Om nedgradering inte stöds görs en rättning med
   högre byggnummer från den verifierade kodbasen.
5. Dokumentera faktisk återgång, kontroller och påverkan. En skriven plan
   eller befintlig artefakt får inte redovisas som en genomförd återgångsövning.

Återställ aldrig en äldre registerkopia för att backa en kodrelease: den kan
sakna senare spärrar och beslut. Vid verklig dataförlust används enbart den
stödda [återställningsproceduren](../deployment/README.md#säkerhetskopiering-och-återställning),
med dess spärr av återställda credentials och paus av nyregistrering.

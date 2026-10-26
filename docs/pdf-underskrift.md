# Synligt underskriftskvitto och certifikattillit

Kontotjänstens test-PDF visar namn, serverns tid, underskriftsreferens och
originaldokumentets SHA-256 i det faktiska signaturfältet. Fältets utseende
ingår i samma signerade PDF-revision som resten av filen. Originalrevisionen
bevaras byte för byte. Utrymmet reserveras redan i det original vars
kontrollsumma visas i appens underskriftstext.

En synlig ruta, logotyp, QR-kod eller skärmbild kan kopieras. Mottagaren
behöver validera den mottagna PDF-filens digitala signatur, undertecknare
och certifikatkedja. En läsare kan visa kvittot utan att utföra dessa
kontroller. Skriv inte ut till en ny PDF om underskriften ska bevaras.

## Testprofilens gränser

PDFBox 3.0.8 och Bouncy Castle skapar PAdES-B-B i kontotjänstens egna
enbladiga demodokument. Godtyckliga uppladdade dokument stöds inte.
Undertecknaren kommer från kontrollerad SAML-assertion, SignMessage och SAD.
Namnet förkortas aldrig för att få plats; testcertifikatets CN-fält tillåter
högst 64 tecken och längre namn avvisas före utfärdande.

CA:n skapas i processminnet vid start och är självsignerad, med 30 dagars
giltighet. Den är avsiktligt märkt TEST och är inte allmänt betrodd.
Tidpunkten kommer från serverklockan. Betrodd tidsstämpling, certifikatspärr
och långtidsbevis saknas. Kvittot förändrar inte dessa begränsningar.
Den privata valideringen använder en uttryckligen angiven test-CA.

Testkonsolen kan ladda ned original, underskriven PDF och JSON-underlag.
Underlaget innehåller den signaturens certifikat och test-CA och ska
bevaras tillsammans med PDF:en vid ett privat prov. Rapporterna finns bara
i den startade testprocessen och gallras efter 30 minuter.

## Vägen till mottagarnas tillit

Ett namnbyte eller lokal installation av testroten etablerar inte tillit
hos andra. Automatisk tillit i Acrobat/Reader kräver en certifikatkedja
till en utfärdare som mottagarens tillitskonfiguration accepterar, exempelvis
via [AATL](https://www.adobe.com/security/approved-trust-list.html) eller
en tillämplig tjänst i [EU:s tillitsförteckningar](https://digital-strategy.ec.europa.eu/en/policies/eu-trusted-lists).
Valet beror på användningsfallet; ett företags stämpel får inte presenteras
som en individs underskrift.

En produktionsintegration behöver en utsedd utfärdare och certifikatpolicy,
verifierad personbindning, lämpligt nyckelskydd och kontroll över varje
underskriftsbeslut. Tidsstämpling, spärrinformation, vald PAdES-profil,
bevarande och mottagarens validering behöver ingå i samma lösning.
Leverantörsavtal och organisatoriska beslut återstår. Denna teständring
ansluter ingen betrodd utfärdare och utfärdar inga kvalificerade certifikat.

[Diggs valideringsbeskrivning](https://www.digg.se/digitala-tjanster/e-underskrift/valideringstjanst)
skiljer dokumentintegritet, undertecknare och tillit och beskriver bevarande
av valideringsresultat. Sweden Connects certifikatprofil T06 och
underskriftsprotokoll T05 i [källregistret](SOURCES.md) är underlag för en
framtida integration, inte en certifiering av piloten.

## Verifiering

`PadesSignerTest` kontrollerar fältets signaturbindning, faktisk rendering
av båda mallarna och maximala namn/referenser utan trunkering. Ändrat kvitto,
ändrat dokument, tillagd revision, fel undertecknare, annan CA och rasterkopia
nekas. OpenSSL kontrollerar CMS-signaturen över samma bytes som en separat
implementation. Det är ett syntetiskt teknikprov, inte en oberoende revision
eller ett bevis på rättsverkan. SIG-01/02 förblir öppna.

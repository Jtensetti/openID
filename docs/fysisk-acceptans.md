# Protokoll för fysisk acceptans

Detta är en körinstruktion och en tom resultatmall, inte ett genomfört prov.
Tidigare delprov finns i [testöversikten](testning.md). Avsikten är att
verifiera hela registrerings-/inloggnings-/spärrkedjan på samma utgåva.
Provet ersätter inte oberoende biometri-, säkerhets- eller dataskyddsgranskning.

## Förberedelser

Välj uttryckligen en privat testmiljö och deltagare enligt beslutad
dataskyddshantering. Använd särskilda test-ID:n för förstörande fall. Planera
serverstopp med operatören; stoppa inte en delad beta där andra deltagare
kan påverkas utan ett separat driftbeslut. Använd separata registreringar
för prov som kräver permanent spärr eller utgång.

Registrera följande i det privata protokollet:

- Testdatum/tidszon, testansvarig och operatör.
- Appversion, byggnummer, Git-revision, signeringskanal och App Attest-miljö.
- Serverrevision, containerdigest, konfigurationsversion och registerbackend.
- iPhone-modell, iOS-version, nätverkstyp och stöd för aktuell passprofil.
- Modellhashar, tröskelpolicy, CSCA-paketets version och testmetod.
- Slumpad provreferens och privat bevisplats. Inga personnummer, passnummer,
  bilder, signaturpayloads, spärrkoder, tokens eller verkliga credential-ID:n
  i repot eller publika loggar. Modell-/konfigurationsversion får inte
  ersättas med hemligheternas innehåll.

## Körordning

Varje rad börjar med resultat **EJ KÖRT**. Använd **GODKÄNT**, **UNDERKÄNT**
eller **BLOCKERAT**, med faktiskt beteende och bevisreferens. Saknad funktion
ska markeras blockerad, inte testas genom att kringgå skyddet.

| ID / krav | Handling | Förväntat resultat |
|---|---|---|
| FP-01 / ID-07 | Installera valt bygge. Kontrollera nyckelskapande och lokal användarverifiering. | Nyckel kan användas endast genom avsett lokalt skydd. Simulatorresultat räknas inte. |
| FP-02 / ID-05 | Registrera med avsedd fysisk handling: första NFC-läsningen, App Attest och andra NFC-sessionens serverstyrda chipkontroll. | Kontrollerna slutförs på telefonen; rätt körmiljö används utan utvecklingsundantag i publik beta. |
| FP-03 / ID-05 | Genomför tre kamerafångster. Prova separat avbrott, nätbortfall och otillräcklig bildkvalitet. | Ingen aktiverad identitet efter avbrott/fel. Nytt försök använder ny session. En lyckad fångst är inte bevisad PAD-säkerhet. |
| FP-04 / ID-02, ID-09 | Kontrollera väntande registrering före operatörsbeslut. | `PENDING_REVIEW` kan inte legitimera. Visat DG1-nummer beskrivs inte som registerverifierat. |
| FP-05 / ID-09, K6.6 | Operatör utför separat kontaktkontroll och manuell aktivering enligt driftinstruktionen. Kontrollera aviseringen hos avsedd mottagare. | Appen visar aktiv status. Kö-/SES-kvittens redovisas separat från faktisk leverans; leveransfel fångas av operatören. |
| FP-06 / FED-02 | Genomför SAML-inloggning: skanna QR, kontrollera tjänst, syfte och kod, godkänn efter ny lokal verifiering. | Endast rätt webbläsarsession öppnas. Registrering till inloggning följs i samma provkedja. |
| FP-07 / FED-02 | Genomför motsvarande OIDC-inloggning i separat webbläsarsession. | Rätt session öppnas utan anspråk på en godkänd tillitsnivå. SAML-resultatet räknas inte som OIDC-prov. |
| FP-08 / ID-09 | Avböj, avbryt och låt en QR-begäran löpa ut; försök återanvända den. | Ingen åtkomst och tydligt slutläge i app/webbläsare. |
| FP-09 / ID-10 | Hämta/spara separat spärrkod säkert före avbrott. Spärra ett särskilt test-ID med servern igång. | Ny inloggning, väntande godkännande och nästa skyddade läsning i redan öppnad session nekas för både SAML och OIDC. |
| FP-10 / ID-10, K6.8 | Med ett annat test-ID: stoppa verifierare/brygga/exportör enligt överenskommet driftprov. Spärra från appen; prova förlust av telefon via det separata webbformuläret med ännu ett test-ID. | Spärrkanalen fungerar över mobilnät utan huvudservern. Koden finns tillgänglig utanför den förlorade telefonen. |
| FP-11 / ID-10, OPS-07 | Gör ett kort stopp/återstart inom begärans giltighet och prova en redan godkänd begäran. Prova separat en faktisk schemalagd återstart med tidigare aktivt ID och gammal session. | Inget spärrat ID eller gammalt godkännande får återfå åtkomst. Skilj spärravslag från vanlig utgång; dokumentera tid och avbrottslängd. |
| FP-12 / ID-08 | Registrera ny nyckel för samma pass och aktivera genom operatörsflödet. | Tidigare nyckel och sessioner nekas; nyckelbyte kräver ny kontroll. Registrering med förnyat pass prövas separat först när verklig registeradapter finns. |
| FP-13 / ID-09 | Låt ett särskilt test-ID löpa ut utan att ändra delad servers klocka. | App, SAML och OIDC nekar fortsatt legitimering; samma nyckel återaktiveras inte. |
| FP-14 / TEST-01 | Upprepa kärnflödet med avsedd äldre iPhone, annan stödd iOS-version, större text och VoiceOver. | Uppgifterna kan läsas och kontrolleras, avbrott/spärr kan genomföras och begränsningar dokumenteras per enhetskombination. |

Vid negativa fall dokumenteras även att ingen credential blev aktiv av
misstag. Ett saknat eller underkänt steg får inte döljas i en samlad
anteckning om att ”telefonprovet fungerade”. En rapport från en äldre
app-/serverkombination ska inte föras över till en ny revision utan bedömning.

## Resultatmall

Kopiera tabellen till den privata provrapporten och lägg till alla FP-ID:n.

| Fall | Förväntat | Faktiskt | Resultat | Tid | Bevisreferens | Avvikelse/omprov |
|---|---|---|---|---|---|---|
| FP-01 | Se körordning | Ej observerat | EJ KÖRT | — | — | — |

En publikt delbar sammanfattning kan ange byggrevision, enhetsmodell,
testfall, resultat och en opak rapportreferens. Fullt underlag och känsliga
avvikelser förvaras privat. Ansvarig granskare avgör om rapporten räcker för
angiven pilotomfattning; inga Digg-krav stängs automatiskt.

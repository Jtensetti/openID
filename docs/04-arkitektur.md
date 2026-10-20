# Föreslagen arkitektur och hotmodell

Designförslag, 2026-10-19. Krav finns i [kravmatrisen](02-kravmatris.md), källor i [SOURCES.md](SOURCES.md).

Implementerat hittills: [SAML/WebAuthn-labben](../prototype/README.md),
[iPhone-appen](../ios/README.md), [verifieraren och pilotregistret](../verification/README.md)
samt ett [stängt driftpaket](../ops/README.md). HSM, distribuerad spärr och
produktionsdrift i förslaget nedan återstår.

### Appbutiksoberoende

Målet är autentisering med öppna standarder utan obligatorisk appbutik eller
molnkonto. WebAuthn-labben använder externa FIDO2-nycklar eller
plattformsnycklar; PWA-installation är valfri. iPhone-spåret använder NFC,
Secure Enclave och App Attest och installeras från Xcode.

Alternativ utgivning via fysisk registrering eller dator med passläsare
återstår att utveckla. Projektets egen licens är ännu inte vald.

## 1. Beslut som återstår

Tillitsnivå 3 är produktmålet. Produktionsprofil, utgivningsmetod,
autentiseringsbärare och villkor för Sweden Connect-tillägg behöver fastställas.

Labben använder Java, Sweden Connect och SAML. Versionsval finns i
[THIRD_PARTY.md](../THIRD_PARTY.md). OIDC är ett möjligt senare spår.

## 2. Logiska komponenter

```text
Användare / autentiseringsbärare
  │ verifierad begäran och uttryckligt godkännande
  ▼
Autentiseringstjänst ─── Credential-/spärrregister
  │                            ▲
  │                        Utgivningsfunktion
  │                            ▲
  │                    Identitetskontroll / RA
  ▼
Federationslager, G01-kandidat ─── Godkänd metadata och tillitsankare
  │         │
  │         └── Underskriftsflöde, G04-kandidat
  ▼
Myndighetens SP / RP ─── Myndighetens egna behörighetsbeslut

Separata stödytor:
  Nyckelförvaltning / HSM       Säkerhetslogg och bevisarkiv
  Drift och incidentledning   Aggregerad ekonomirapportering
  Kontrollerad administration Oberoende testmotpart, G05-kandidat
```

Komponenterna kan samlas i en modulär tjänst. Administrativ åtkomst, nätverkszoner, nycklar och databehörigheter behöver separeras.

| Komponent | Föreslaget ansvar | Ska uttryckligen inte göra |
|---|---|---|
| Identitetskontroll / registreringsfunktion | Bedöma underlag enligt vald utgivningsmetod och dokumentera beslutets bevisreferens. | På egen hand skapa aktiva autentiseringsnycklar i någon annans namn. |
| Utgivningsfunktion | Binda verifierad person, godkänd utgivning och innehavarens nyckel. | Acceptera ett godtyckligt personnummer från klienten som verifierad identitet. |
| Credential-/spärrregister | Hantera nyckelreferenser, tillstånd, giltighet, ersättningshistorik och spärr. | Lagra privata innehavarnycklar utan ett uttryckligen granskat utförande. |
| Autentisering | Utvärdera faktorer, färskhet, nyckelbevis och bindning till rätt begäran. | Höja tillitsnivå för att motparten begärt en högre nivå. |
| Federationslager | Validera begäran och lämna minimalt, korrekt skyddat svar till betrodd mottagare. | Bestämma användarens rätt till myndighetens uppgifter. |
| Underskrift | Hantera innehåll, avsikt, autentisering, signatur och valideringsunderlag som en egen kedja. | Räkna en vanlig inloggning som en dokumentunderskrift. |
| HSM/nyckelförvaltning | Skydda servernycklar och stödja kontrollerade ceremonier, rotation och incidentåtgärder. | Förväxlas med innehavarens enhetsnyckel eller automatiskt ge enheten rätt tillitsnivå. |
| Logg/bevisarkiv | Bevara nödvändiga spår för avtal, säkerhet och rättsligt fastställda behov. | Skicka personakter till produktanalys eller logga hemligheter. |
| Ekonomirapportering | Härleda korrekta, aggregerade ersättningshändelser med avstämning. | Skapa identiteter, ändra säkerhetsbeslut eller räkna testtrafik. |

## 3. Utfärdning och återställning

Välj en huvudmetod för utgivning utifrån villkoren i D08 K5.10–K5.13 och D09.

### Utredningsalternativ

**A. Befintlig godkänd e-legitimation.** Verifiera tillitsnivå, avtalsrätt, identitetsattribut och hur samma person bevisar kontroll över den nya autentiseringsbäraren. Analysera beroendet av den befintliga utfärdaren och vad som händer om denna användning stoppas.

**B. Fysisk identitetskontroll.** Specificera utbildning, kontrollpunkter, behörigheter, verifiering av handling och säker överlämning. En anlitad registreringspartner kräver avtal och revisionsmöjlighet.

**C. Fjärrkontroll med identitetshandling.** Utred granskad komponent eller specialist för chip-/dokumentverifiering, personbindning och skydd mot injicerad eller återspelad data. En klient som säger ”passet är äkta” är inte ett tillräckligt förtroendeankare. Juridisk grund och hantering av biometriska uppgifter måste prövas för vår privata verksamhet; bestämmelser om statlig utgivning får inte återanvändas som antagen rättslig grund.

Projektet ska inte bygga egen ansikts-/livenessmotor under antagandet att AI kan avgöra identitetsäkthet tillräckligt bra. Eventuella sådana komponenter kräver separat juridisk, teknisk och oberoende granskning.

### Föreslagen livscykel

```text
PENDING → PROOFED → ISSUED → ACTIVE
                        └→ REVOKED / EXPIRED
ACTIVE → SUSPENDED → ACTIVE endast efter tillåten, granskad hävning
ACTIVE / SUSPENDED → REVOKED / EXPIRED
```

Spärrad (`REVOKED`) nyckel ska inte återaktiveras i detta designförslag. En ersättande nyckel får en ny identitet i registret och spårbar länk till ersättningsbeslutet. Säkerhetsbetydelsen av `SUSPENDED` och möjligheten att häva måste prövas; det är inte en beslutad avtalsfunktion.

Varje övergång behöver förvillkor, behörighet, atomisk databasändring, revisionshändelse och tester för samtidiga anrop. Misslyckad eller avbruten utgivning ska inte lämna en användbar credential efter sig.

Återställning designas före första skarpa utgivningen. Förlorad telefon, glömd PIN, ändrad kontaktuppgift och supportkontakter får inte kombineras till en enklare alternativ väg att ta över identiteten. Användaren ska kunna begära spärr utan den förlorade enheten; återutgivning kräver däremot en separat säker prövning.

## 4. Autentisering och federationssvar

Föreslagen ordning:

1. Validera begärans integritet, betrodd avsändare, mottagaradress och tillåten profil enligt låst version av T01–T03.
2. Skapa en kortlivad intern transaktion med entydig koppling till motpart, begäran, avsikt och session. Acceptera inte motpartsnamn enbart från fri klienttext.
3. Visa verifierad motpart och typ av åtgärd för användaren. Bind godkännandet till samma transaktion; en QR-kod får inte vara hela säkerhetsargumentet.
4. Verifiera godkänd credential, aktuell status, faktorer och färskt nyckelbevis. Gör det kritiska statusbeslutet tillräckligt nära svar/signering för att undvika att en samtidig spärr tappas bort.
5. Lämna ett korrekt signerat/skyddat svar endast till den mottagare som begäran och federationen tillåter. Lägg inte till mer identitetsinformation än den accepterade profilen och tjänsten behöver.
6. Registrera utfall och nödvändiga bevisreferenser. Separera det säkerhetsmässiga utfallet från den senare bedömningen om händelsen är ersättningsgrundande.

Protokollens exakta krav på exempelvis XML-signatur, assertion, audience, `InResponseTo`, redirect URI, `state`, `nonce`, kodflöde och PKCE ska mappas för det faktiskt valda flödet. De får inte ersättas av en hemmagjord gemensam ”tokenvaliderare”. Överlåt standardmekanismerna till granskade bibliotek, men testa vår konfiguration och integrationskod.

## 5. Underskrift är ett eget delsystem

Föreslagen kedja:

```text
Verkligt dokument → entydig presentation → uttrycklig underskriftsavsikt
→ bindning till exakt dokumentversion → godkänd autentisering
→ signering med rätt nyckel/kontroll → oberoende validering
→ bevisreferens och korrekt klassificerat utfall
```

G04 är en möjlig teknisk grund. Val av signaturformat, certifikatkedja, valideringsprofil, tidsbevis och långtidsbevarande återstår. Varje val ska kopplas till rätt teknisk specifikation och juridiskt bedömt ändamål.

Testa byte av dokument mellan visning och signering, fel undertecknare, återspelat godkännande och dokument som inte kan presenteras begripligt. En knapp märkt ”signera” eller ett kryptografiskt skyddat inloggningssvar bevisar inte att hela kedjan är korrekt.

## 6. Data och integritet

Föreslagna domänobjekt är `Identity`, `ProofingDecision`, `Credential`, `LifecycleEvent`, `AuthenticationTransaction`, `SignatureTransaction`, `EvidenceReference` och `ReportBatch`. Det här är koncept, inte en färdig databasmodell.

Använd ett internt opakt ID som teknisk referens där protokollet tillåter det. Personnummer, kontaktuppgifter och känsliga utgivningsunderlag ska ha separata åtkomstregler. Rådata från identitetskontroll bör inte spridas till autentiserings-, rapporterings- och analyslager.

En federerad utfärdare kan genom driften få insyn i var identifiering sker. Öppen källkod tar inte i sig bort den insynen. Vi får därför inte marknadsföra systemet som anonymt eller omöjligt att korrelera. Minimera åtkomst och lagring, använd ändamålsseparation och utred mer integritetsskyddande arkitektur där den kan förenas med aktuell profil och beviskrav.

Lagringstid bestäms per datakategori och rättsligt behov. D08 innehåller bevarandekrav; GDPR-bedömningen ska dokumenteras, inte lösas med ett generellt ”spara inget” eller ”spara allt”. Publika projektfiler ska bara innehålla syntetiska exempel.

## 7. Ekonomirapportering som separat kontrollsystem

D05 beskriver schemat och `ReportStatistics`-anropet. Dokumenterade fält omfattar `leverantorOrgnr`, `tjanst`, `swedenConnect`, `arKorrigering`, periodfält och aggregerad `anvandning`. Tjänsten använder AS01 och typerna AS011/AS012 för identifiering/underskrift. Implementera inte en gissad bas-URL eller autentiseringsheader.

Föreslagen intern pipeline:

```text
Oföränderlig sluthändelse
→ kontroll av avtal, miljö, motpart och transaktionstyp
→ dubblettkontroll
→ aggregation per period och offentlig aktör
→ avstämning mot kontrollerad händelsekälla
→ oberoende godkännande
→ kontrollerad insändning och kvittens
```

Prototypen ska sluta före insändning. Framtida produktionsnyckel och rättighet att rapportera hålls separerade från utvecklings- och identitetsadministration. Rapporteringen ska inte innehålla medborgarnas identitetsuppgifter.

Begär Diggs besked om idempotens, kvittenser, rättelseflöde, årsskifte och nollrapport. Automatisk omkörning efter timeout får inte råka dubblera underlag. Flaggan `swedenConnect` är en rapporteringsuppgift, inte ett sätt att själv besluta om ersättningsrätt.

## 8. Hotmodell, första arbetsversion

Testerna gäller endast våra egna isolerade miljöer eller uttryckligen godkända testmål.

| Hot / fel | Föreslagen motåtgärd | Bevis som ska tas fram |
|---|---|---|
| Fel person får ny credential | Separata roller, verifierad utgivning och nyckelbindning. | Testa ensam handläggare, admin och komprometterad klient. |
| Kapning genom återställning | Separat riskprövad återutgivning och oberoende avisering. | Scenarier med förlorad telefon och manipulerad kontaktuppgift. |
| Phishing eller förväxlad motpart | Betrodd metadata, tydlig presentation och transaktionsbindning. | Testa omdirigering, kopierad begäran och godkännande för fel tjänst. |
| Återspelning och sessionsförväxling | Färskhetskontroll, engångsanvändning och mottagarbindning. | Negativa protokolltester och samtidighetstester. |
| För gammal spärrstatus | Definierad statuskonsistens och kontrollerad cachepolicy. | Spärra mitt i ett pågående flöde och under nätverksfel. |
| Klonad/exporterad nyckel | Granskat autentiseringsmedel och explicit hantering av synkronisering. | Enhetsspecifik granskning; inga generella passkey-antaganden. |
| Manipulerat utgivningsunderlag | Verifierad beviskedja och oberoende identitetskontroll. | Specialistledd testning av dokument-/chip-/personbindning. |
| Missbruk av HSM via applikation | Snäva nyckelrättigheter, separation och kontrollerade signeringsanrop. | Testa fel tjänst, fel nyckel och obehörig massignering. |
| Metadata-/redirectmissbruk | Kontrollerad federation, endpointvalidering och begränsad nätverksåtkomst. | Testa förfalskat ankare och otillåtna interna adressmål. |
| CI- eller beroendekompromiss | Versionslåsning, granskningskrav, minsta behörighet och verifierbara byggen. | Revisionsspår från ändring till godkänd artefakt. |
| Insyn och korrelation | Minimering, åtkomstseparation och granskningsbara läsningar. | Datakarta, åtkomsttest och kontrollerad gallring. |
| Fel dokument underskrivs | Bindning till exakt visat innehåll och separat avsikt. | Byt dokumentversion före, under och efter godkännande. |
| Felaktig ersättning | Härledbar klassificering, avstämning och separerat godkännande. | Testtrafik, retry, dubblett, avbrott och fel motpart ska inte bli anspråk. |
| Driftstopp eller nyckelförlust | Kontinuitetsplan, kapacitetsmarginal och övad återställning. | Dokumenterat återställningstest utan att kringgå säkerhetskontroller. |

## 9. Säkerhetsgräns för första prototypen

Endast syntetiska personer, dokument och nycklar. Endast isolerad testfederation. Inga riktiga utgivningsbeslut, offentliga produktionsanslutningar eller insända ersättningsunderlag. Ingen LLM i säkerhetsbesluten. Ett godkänt labbtest betyder enbart att det angivna labbtestet klarades.

Produktionsöppning kräver de separata beslutspunkterna i [genomförandeplanen](05-genomforande.md).

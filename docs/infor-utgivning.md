# Förutsättningar inför bredare utgivning

Den tekniska basen är en sluten beta med manuell aktivering. Tabellen skiljer
kod från beslut, drift och verifiering. Avtal, finansieringsunderlag,
personförteckningar och känsliga granskningsrapporter hanteras utanför repot.
En saknad referens betyder att underlaget inte är styrkt här, inte att det
omöjligen finns någon annanstans. Formell kravstatus förblir `OPEN`.

| Fråga | Vad implementationen visar | Vad som behöver tillkomma | Typ av arbete |
|---|---|---|---|
| 1. Utfärdarorganisation och uthållighet | K2.1–K2.3 är öppna i [kravmatrisen](digg-kravmatris.md). | Beslut om juridisk utfärdare samt referenser till försäkring och ett års finansiering/riskbärande. Ansvarig: organisationen. | Beslut och externt styrkt underlag; ingen kodfunktion. |
| 2. Målgrupp | iPhone, pass med stödd chipprofil, experimentell biometri och operatörsaktivering. Person-/samordningsnummer kan förekomma i passfältet; detta ger inte täckning för alla innehavare av sådana nummer. | Fastställd pilot-/utgivningspolicy och stödda enheter/handlingar. Bredare målgrupp behöver dessutom prov och alternativa identifieringsvägar. | Beslut först, därefter avgränsad utveckling och provning. |
| 3. Polisens passkontroll | `PassportVerifier.java` validerar signaturkedja mot lokalt tillfört CSCA; `chip.py`/JMRTD verifierar chipkontroll. Ingen adapter till Polisens giltighetskontroll finns. | Auktoriserad väg att kontrollera aktuell giltighet/spärr hos utgivaren, dokumenterade användningsvillkor och negativa integrationsprov. Ansvarig: integrations-/avtalsansvarig. | Avtal/åtkomst och implementation. Ett CSCA-certifikat är inte en giltighetsfråga. |
| 4. Nationell personbindning | Signerat DG1-nummer finns i krypterad profil. [Adapterkontraktet](registerbindning.md) kan föra det vidare och stoppa avvikande svar. Det finns ingen verklig registeradapter och funktionen är inte inkopplad i betans aktivering. | Vald registerkälla, behörighet, klientautentisering, granskad matchningspolicy, avvikelsehantering och kundtest. Därefter integration i utgivningsflödet; PostgreSQL-stöd återstår. | Integration, verksamhetsbeslut och provning. |
| 5. Fysisk kedja | [Testöversikten](testning.md) anger privata prov av registrering/passläsning, visat nummer och SAML. Ett fullständigt prov inklusive separat spärr efter serverstopp är inte styrkt. | Genomför [acceptansprotokollet](fysisk-acceptans.md) på det exakta app-/serverbygget. Ansvarig: testledare och operatör. | Fysisk provning och evidens; inte en ny registreringsfunktion. |
| 6. Drift och befogenheter | Betan har [AWS-spärr/avisering](../deployment/continuity/README.md). SQLite och PostgreSQL/OpenBao är separata körlägen; två databaslogins i det senare är inte bevis på två personer. Render-paketet har ingen e-id. | Produktionsarkitektur med dataplacering, verkliga ansvariga/ersättare, behörighetsgranskning, larm och återställningsövning. Slutförvaltare och oberoende kontrollfunktion behöver utses. | Beslut, driftkonfiguration och operativ verifiering. |
| 7. Biometri och dataskydd | YuNet/SFace/MiniFASNet och ett verktyg för poängutvärdering finns. Trösklarna är experimentella; oberoende provning och juridiskt underlag är inte styrkta i repot. | Rättslig bedömning/DPIA, användarinformation, beslutad identifieringsmetod utan biometriskt samtycke där det krävs, modellrättigheter och oberoende prov av hela fångst-/PAD-kedjan. | Extern granskning och beslut; alternativa flöden kan även kräva kod. |

## Skilda kontroller

1. **Äkthet och chip:** är uppgifterna signerade av en betrodd utgivare och
   deltar chipet i den aktuella kontrollen? Implementerat för stödda profiler.
2. **Handlingens aktuella status:** är passet fortfarande giltigt hos
   utgivaren, inklusive spärr? Integration saknas. Detta är inte samma sak
   som OpenID-nyckelns egen spärrtjänst eller certifikatets spärrstatus.
3. **Personregister:** stämmer nationell identitet och relevanta statusfält
   med auktoritativa uppgifter? Adapter saknas. Ett nummer med korrekt
   kontrollsiffra eller ett `MATCH` från en testadapter bevisar inte detta.
4. **Person framför kameran:** hör bilderna till innehavaren och motstår
   fångstkedjan presentationer, injektion och relä? Kod finns; den avsedda
   säkerhetsnivån är inte oberoende verifierad.

Polisens [publika e-tjänst](SOURCES.md#komplettering-2026-10-23-utgivning)
beskriver ett formulär med handlingsnummer, personnummer och giltighetstid.
Den informationen styrker inte rätt att automatisera tjänsten eller ett
produktions-API. Bygg inte skrapning som en underförstådd registeranslutning.

## Tekniska prioriteringar

| Ordning | Nästa steg | När det kan bedömas klart |
|---|---|---|
| 1 | Granska adapterkontraktet och anslut vald registerkälla i kundtest. Håll passpärrkontroll som separat integration. | Entydiga och negativa källsvar provas; ingen aktivering vid avbrott eller otillräckliga uppgifter. |
| 2 | Genomför hela den fysiska kedjan på stödda iPhone-/iOS-kombinationer. | Protokoll med revisioner, förväntat/faktiskt resultat och privat bevisreferens per fall. |
| 3 | Verifiera den införda beständiga försöksbudgeten i avsedd drift. | SQLite och PostgreSQL debiterar före analys; parallellitet, omstart, modellfel och återläsningspaus provas i kod. Driftkonfiguration, utrednings-/återöppningspolicy och fysisk helkedja återstår. |
| 4 | Utvärdera biometri för hela registreringsbeslutet och beställ oberoende prov. | Låsta modeller/trösklar, angreppstyper, injektion, relä, försöksbudget, felgrader och osäkerhet kan granskas tillsammans. |
| 5 | Mät prestanda på vald driftmiljö innan fler processer eller större instanser införs. | Separata tider för modellstart, avkodning/detektion, SFace, PAD och hela registreringen; CPU/minne och svarstidsfördelning vid samtidig legitimering/spärr. Inga råbilder, mallar eller personnummer i mätloggar. |

Biometriarbetaren återanvänder nu bildanalys inom ett försök. En långlivad
modellprocess kan vara ett senare optimeringsspår, men kräver mätning samt
prov av tidsgränser, processavslut och isolering mellan försök. Ingen positiv
spärrstatus ska cachas för att förbättra svarstiden.

## Externt underlag

Källor kontrollerade 2026-10-23 finns i [källregistret](SOURCES.md).
Diggs vägledning till K5.13 beskriver oberoende provning av liveness-kedjan
med den konfiguration som används. Bilaga D, avsnitt 3 och 5, behandlar
alternativ grundidentifiering vid samtycke och konsekvensbedömning.
Detta är kravunderlag för fortsatt arbete, inte en egen juridisk attestering.

`evaluate_biometrics.py` beräknar statistik för inmatade poäng. Det provar
inte kamerans ursprung, hela beslutet över tre bilder, upprepade försök
eller en myndighetsanslutning. Funktionsprov och statistisk utvärdering ska
redovisas separat från den oberoende rapporten och dess giltiga konfiguration.

# Avtal, ersättning och affärshypotes

Kontrollerat 2026-10-19. Käll-ID hänvisar till [källregistret](SOURCES.md). Dokumentet är en förstudie, inte ett löfte om ersättning eller ett juridiskt utlåtande. Originalavtal och gällande författning har företräde.

## 1. Slutsats

Det finns en verklig kommersiell möjlighet att undersöka. Det finns däremot ingen verifierad väg där ett registrerat bolag med en demonstrationsapp automatiskt får pengar. Vi behöver bli en godkänd utfärdare, antas till auktorisationssystemet och faktiskt leverera enligt avtalet. Dessa är olika prövningar och tillstånd.

Vår affärshypotes är: **återanvänd öppen federations- och säkerhetskod för att sänka utvecklingskostnaden, men finansiera identitetskontroll, organisation, säkerhetsgranskning och löpande drift som verkliga verksamheter.**

## 2. Vad ersättningsmodellen säger

Sammanfattning av D04 §§2–5 och D12:

| Del | Publicerat villkor |
|---|---|
| Fast grundersättning | Högst 2 500 000 kronor per kalenderår. |
| Sweden Connect-tillägg | Högst 2 000 000 kronor per kalenderår för den föreskrivna anslutningsmöjligheten. |
| Periodisering | Tolftedelar för hela kvalificerande anslutnings-/leveransmånader. |
| Volymbrytpunkt | Grundersättningen täcker upp till 31 250 000 transaktioner per kalenderår. |
| Rörlig modell | 0,08 kronor per transaktion enligt bilagans övergångsregel, i stället för grundersättning. |
| Ersättningsgrundande händelser | Genomförd identifiering eller avancerad underskrift enligt systemets villkor; avbrutna försök räknas inte. |
| Redovisning | Identifiering och underskrift särredovisas. Beräkningsdata lämnas senast tredje helgfria vardagen följande månad. |
| Utbetalning | Digg fastställer beloppet; leverantören fakturerar elektroniskt. Betalningsvillkor är 30 dagar. Beloppen är exklusive moms. |

D12 anger att e-id-ersättningen saknar transaktionsgräns för ersättningsrätt. Digital posts separata volymkrav får inte överföras till e-id. Detta avgör inte ensamt när en ny tjänst utan användning anses avtalsenligt levererad.

### Vår räkneillustration – inte faktureringsspecifikation

För ett helt kalenderår där samtliga villkor är uppfyllda hela året kan följande illustrera modellens storleksordning:

```text
N = ersättningsgrundande transaktioner under kalenderåret
B = max(2 500 000, 0,08 × N)
S = 2 000 000 om villkoren för Sweden Connect-tillägg är uppfyllda hela året
Årsillustration = B + S
```

Detta är INTE en algoritm för månadsfakturering, delår, korrigeringar eller brytpunktsmånaden. Implementering ska följa originalbilagans avräkning och Diggs skriftliga besked. Man ska inte lägga 0,08 kronor på samtliga transaktioner ovanpå en redan erhållen hel grundersättning.

| Hypotetiskt helår | Grund-/volymdel | SC-del | Illustration, exkl. moms |
|---|---:|---:|---:|
| 1 miljon godkända transaktioner, utan SC-tillägg | 2 500 000 | 0 | 2 500 000 |
| 1 miljon godkända transaktioner, med SC-tillägg | 2 500 000 | 2 000 000 | 4 500 000 |
| 50 miljoner godkända transaktioner, med SC-tillägg | 4 000 000 | 2 000 000 | 6 000 000 |

Alla exempel förutsätter rätt till betalning. De är inte efterfrågeprognoser. Vi har inte fått någon intäktsgaranti, gjort en fakturering eller verifierat villkoren för nollvolymsmånader.

**4,5 miljoner är det möjliga fasta helårsbeloppet med tillägget, inte en garanterad intäkt och inte ett tak för all ersättning vid hög volym.**

## 3. Vägen in är längre än en godkänd app

D02 §§4–5 och D07 beskriver ansökan och prövningen. Centrala inträdeskrav är godkännande på relevant tillitsnivå, ekonomisk förmåga att bära åtaganden minst ett år, försäkring eller jämförbar garanti samt föreskrivna företags-, registrerings- och skatteförhållanden. Avtalet ska accepteras utan reservationer. Ansökan görs på svenska. Diggs tre månaders beslutsfrist räknas från att underlaget är komplett; det är inte en total tidsplan för att starta en utfärdare.

Granskningen för att bli godkänd utfärdare har enligt D07 ingen avgift. Detta innebär inte att utveckling, revision, penetrationstestning, försäkring eller drift är kostnadsfria.

**Vår konsekvens:** ansökan blir slutprodukten av en dokumenterad verksamhet, inte startskottet för att fundera på hur verksamheten ska fungera.

## 4. Vad offentlig acceptans faktiskt innebär

D10 skiljer på juridisk anslutning och teknisk integration. En offentlig aktör måste kunna ansluta och pröva den nya tjänsten; ett godkännande installerar inte vårt system hos myndigheten.

L02 och D13 beskriver statliga myndigheters införande under 2026, med april som tidigare huvudpunkt och möjlighet till uppskjutande till oktober. Den tidigare formuleringen att allt började den 1 oktober var för grov.

L01, 4 kap., börjar gälla **1 december 2026**, alltså efter detta dokuments kontrolltidpunkt. Erkännandeskyldigheten avser angivna offentliga aktörers berörda nättjänster till enskilda och e-legitimationer med tillräcklig tillitsnivå. Den ska inte likställas med en generell skyldighet att ansluta alla interna system till ett visst avtal. D11 behandlar avgränsningarna.

**Vår konsekvens:** distributionsfördelen är betydande, men den ger inte administrativa rättigheter, informationsåtkomst eller ett undantag från vanlig behörighetskontroll. Identifiering svarar på vem användaren är; myndighetens behörighetssystem avgör vad användaren får göra.

## 5. Avtalsrisker som kalkylen måste bära

D03 innehåller krav på tillgänglighet, support, testmiljö, incidenthantering, underleverantörer, revision och korrekt rapportering. Ändringar i ersättningsvillkor kan ske enligt avtalets ändringsmekanismer. Förlorat tillitsgodkännande påverkar avtalets fortsatta giltighet. Felaktiga ersättningsunderlag kan leda till återbetalning och andra påföljder. Ansvarsregler och undantag måste granskas som en helhet, inte reduceras till en enda påstådd ansvarsgräns. Se [kravmatrisen](02-kravmatris.md) och D03 §§13, 15, 18 och 20.

### Vår ekonomiska modell

Vi budgeterar inte från 4,5 miljoner och bakåt tills kalkylen ser bra ut. Vi tar fram en självständig kostnadsmodell och jämför sedan med flera intäktsscenarier.

| Kostnadspost som ska offereras eller beräknas | Vad som behöver ingå |
|---|---|
| Bemanning och ansvar | Säkerhetsledning, drift, utveckling, identitetskontroll, support, ersättare och separation av kritiska roller. |
| Identitetskontroll | Utgivningskanal, dokument-/registerkontroller, manuella undantag, skyddade identiteter och bedrägeriutredning. |
| Infrastruktur och nycklar | HSM-lösning, redundans, reservkapacitet, logg-/bevislagring, övervakning och återställningsövningar. |
| Oberoende granskning | Säkerhetsrevision, penetrationstest, protokoll- och kryptografigranskning, förnyad granskning efter ändringar. |
| Juridik och försäkring | Dataskydd, avtal, immaterialrätt, ansvar och försäkringsvillkor som motsvarar den faktiska tjänsten. |
| Integration och användarstöd | Testmiljö, partnerintroduktion, tillgänglighetsarbete, dokumentation och incidentkommunikation. |
| Företagsdrift | Redovisning, rapporteringskontroller, revision, administration och kontinuitet vid frånvaro. |

Inga av dessa kostnader har ännu offererats. Vi publicerar därför inte en påhittad marknadsbudget.

```text
Resultat före skatt = kvalificerande ersättning + andra intäkter
                     − personal − drift − kontroller − support − administration
Likviditetsbehov = etableringsutgifter + nettoutflöde fram till faktisk betalning
                  + beslutad reserv för försening, incident och avveckling
```

Minst följande scenarier ska prövas: ingen anslutning beviljad; senarelagd start; godkänd tjänst utan SC-tillägg; SC-tillägg men låg användning; högre kostnad för identitetskontroll; ändrad ersättningsnivå; tillfälligt leveransstopp. Omsättning får inte bokföras som säker finansiering före faktisk rätt till ersättning.

## 6. Tre möjliga roller – olika affärer

- **Egen utfärdare:** projektets huvudspår. Vi tar ansvar för identitetslivscykeln och prövas för godkännande och avtal.
- **Utfärdare med avtalade specialister:** delar kan köpas, exempelvis identitetskontroll eller säker drift. Ansvar och kontroll måste fortfarande säkras; en underleverantör är ingen genväg runt kraven.
- **Teknikleverantör/integratör:** vi säljer kod, integration eller förvaltning till en befintlig utfärdare. Det är ett annat intäktsflöde, inte automatiskt Diggs grundersättning till vårt bolag.

Att använda en befintlig godkänd e-legitimation vid nyutgivning kan under särskilda förutsättningar vara möjligt enligt D08 K5.12 och D09. Det gör inte en vanlig inloggningsförmedlare till en självständig godkänd utfärdare. Avtalsrätt till återanvändningen, nyckelbindning, livscykel och återställning måste prövas.

## 7. Beslut nu

**Ja till förstudie och isolerad prototyp. Nej till produktionspåståenden eller finansieringslöften.**

Innan en större investering behöver vi skriftliga svar om ersättningens start och nollvolym, accepterat anslutningsutförande, vald utgivningsmetod och rapporteringsdetaljer. Vi behöver också en finansierad organisation och verkliga offerter. Frågorna finns i [utkastet till Digg](06-fragor-till-digg.md).

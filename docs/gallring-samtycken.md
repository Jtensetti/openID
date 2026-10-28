# Gallring av registreringskvitton

`verification/consent_retention.py` hanterar utgångna registreringskvitton
separat från profilgallringen. Körningen kräver en uttryckligen vald policy.
Det finns ingen automatisk schemaläggning eller antagen lagringstid.
Ansvarig måste först besluta ändamål, rättslig grund, tider och ärenden som
ska bevaras. Ett tekniskt policyfält bevisar inte att beslutet är giltigt.

## Policy och urval

Policyfilen är en vanlig privat fil, läge 0600, ägd av körande användare
eller root. Symlänkar, hårdlänkar, extra fält och dubbla JSON-nycklar nekas.

| Fält | Innehåll |
|---|---|
| `version` | Heltalet `1`. |
| `reference` | Referens till det faktiska beslutet: 8–96 ASCII-bokstäver, siffror, bindestreck eller understreck. |
| `regime` | `private-beta` eller `digg`, valt efter verksamhetens tillämpliga krav. |
| `unboundDays` | 1–3650 hela dygn för kvitton som aldrig bands till ett ID. |
| `boundDays` | 1–3650 hela dygn för bundna kvitton. Läget `digg` nekar värden under 1827. |
| `protectedReceipts` | Explicit lista, även när tom, med högst 1000 unika kvitto-ID:n som ska undantas. |

1827 dygn är projektets konservativa tekniska golv för Diggs femårskrav
på relevant utgivningsdokumentation, inte en generell rättslig grund att
lagra alla uppgifter i en privat beta. Kortare tider i `private-beta`
kräver egen dokumenterad bedömning. Se [Digg K2.7–K2.8](https://www.digg.se/digitala-tjanster/e-legitimering/om-e-legitimering/tillitsnivaer-for-e-legitimering/tillitsramverk-for-svensk-e-legitimation).

Obundna kvitton kan väljas först efter senaste av accepttid plus fem
minuter och återkallelsetid, plus `unboundDays`. Bundna kvitton kan väljas
först efter senaste av accepttid, återkallelsetid, ID:ts giltighetsslut och
senaste credentialhändelse, plus `boundDays`. För ett aldrig aktiverat ID
utan giltighetstid används skapandetid plus ett dygn. Giltiga ID:n,
nyligen återkallade kvitton/ID:n och explicit skyddade kvitton behålls.
Exakt tidsgräns behålls; gallring kräver att gränsen passerats.

Textversioner tas bara bort när giltigheten löpt ut och inga kvarvarande
kvitton hänvisar till dem. Credentials, personprofiler, nycklar, händelser
och spärrhistorik ändras inte. Ett ärende måste omfattas av rätt kvitto-ID
i skyddslistan före körning; verktyget upptäcker inte rättsliga anspråk.

## Förhandsvisning och genomförande

Förhandsvisningen är en lästransaktion. Den returnerar antal, policyhash,
referens och om ytterligare kandidater finns, utan kvitto-ID eller bevis.
Kontrollera först att rätt databas, beslutad policy och skyddslista används:

```sh
python verification/consent_retention.py plan \
  --db /private/wallet.sqlite --policy /private/consent-retention.json --batch 100
```

För PostgreSQL ersätts `--db` med
`--database-file /private/maintenance-db`. Anslutningsfilen kräver fullständig
privat libpq-konfiguration och `sslmode=verify-full`. Kontot behöver
`openid_maintenance`; ingen OpenBao-token behövs. För ett behörigt
genomförande ersätts `plan` med `apply`. Förhandsvisningen reserverar inget;
genomförandet räknar om urvalet mot då aktuellt tillstånd.

Varje transaktion behandlar högst vald mängd kvitton och textversioner
(1–1000). SQLite serialiserar skrivare och nekar okända triggers och
kaskader. PostgreSQL låser kvitton, hoppar över redan låsta kvitton och
kontrollerar credentialhändelser igen efter låsning mot samtidig spärr.
`moreEligible=false` garanterar därför inte att en samtidig låst population
är färdigbehandlad. Kör om efter att samtidiga transaktioner avslutats.

Genomförandet journalför exakt kanonisk policy, dess SHA-256, tid och
antal i `consent_retention_runs`, i samma transaktion som borttagningen.
Fel i journalföringen rullar tillbaka hela batchen. Skyddslistans ID:n
ingår i policyn och journalen måste därför också skyddas och omfattas av
bevarandeplanen. Journalen är inte en oberoende signatur eller tidsstämpel.
PostgreSQLs underhållsroll får anropa den begränsade funktionen och läsa
journalen, men inte läsa samtyckesbevis eller radera tabeller direkt.

## Införande och återstående gränser

SQLite behöver aktuell applikationsschema med journalen. PostgreSQL kräver
schema 4; `migrate-3-to-4.sql` körs av kontrollerad ägare med stoppade
skrivare och verifierad backup från tidigare låst revision. Journalen ingår
i backup och [arkivformat 4](arkivexport.md). Äldre arkiv förblir läsbara.

Verktyget raderar inte redan tagna backuper, exporter, repliker eller
telefonens lokala kvitton. SQLite använder `secure_delete`, men detta är
inte ett löfte om fysisk radering i WAL, filsystemssnapshots eller SSD.
Återställning kräver avstämning mot senare återkallelser och gallring innan
trafik öppnas. Operativt införande, kopiors livscykel, faktisk gallring och
ansvarigs beslut behöver egna bevis.

`test_consent_retention` provar SQLite med syntetiska uppgifter;
`test_cluster` provar PostgreSQL-roller, direktanrop, återställning,
samtidighet och journalfel i den disponibla CI-miljön. Proven är inte
samtycken eller gallringsbeslut för verkliga personer.

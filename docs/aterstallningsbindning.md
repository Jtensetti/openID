# Bind SQLite-backup till rätt identitetsnyckel

`recovery.py restore` kräver en separat bindningsfil och dess externt förvarade
SHA-256. Filen binder de exakta backupbyten till SHA-256 för hela den 64 byte
långa identitetsnyckeln. Både AES-delen och HMAC-delen omfattas. Nyckeln ingår
inte i bindningsfilen eller databasbackupen.

Detta gäller också kopior utan nyckelberoende data: bindningen anger då
uttryckligen att ingen identitetsnyckel krävs. Att ta bort personkopplingar ur
en backup kan därför inte kringgå kontrollen. Gamla kopior utan bindning nekas
tills en förvarare kan skapa motsvarande underlag från betrodda uppgifter.

## Förutsättningar och ansvar

Nyckelförvaltaren behöver ett tidigare oberoende skyddat inventeringsvärde:
SHA-256 för **originalnyckelns samtliga 64 byte**, knutet till rätt tjänst och
nyckelgeneration. Detta värde ska fastställas vid kontrollerad nyckelutgivning
eller en granskad migrering. Verktyget skapar inte detta förtroende.

Beräkna inte ett nytt förväntat värde från en godtycklig återfunnen nyckelfil
och behandla det som bevis. Utan originalinventering, särskilt när profilerna
har gallrats, ska återställningen förbli stoppad. En fungerande AES-halva
bevisar inte att HMAC-halvan och personkopplingarna är de ursprungliga.

Förvararen kontrollerar kopians ursprung och bevarandeversion, rätt
nyckelinventering och kontinuitetskravet. Den returnerade bindningskontrollsumman
förvaras sedan separat, med rättighetsseparation, versionshistorik och
spårbart beslut. Operatören hämtar den därifrån vid återställning. En kontrollsumma
i samma ändringsbara katalog som kopian är inte ett oberoende ankare.

## Arbetsflöde

Ta först en fristående SQLite-kopia med det läsande backupkommandot. Det öppnar
inte Wallet, ändrar inte källschemat och läser inte identitetsnyckeln.

```sh
cd verification
.venv/bin/python recovery.py backup --db /privat/data/wallet.sqlite \
  --destination /privat/backups/kopia-001
```

Nyckelförvaltaren arbetar därefter i en privat miljö med kopian, originalnyckeln
och det sedan tidigare förankrade inventeringsvärdet. Variabeln nedan ska komma
från den skyddade inventeringen, inte från en omhashning av den tillförda filen.

```sh
.venv/bin/python recovery.py bind --backup /privat/backups/kopia-001/wallet.sqlite \
  --identity-key /separat/nyckelforvaring/wallet.identity-key \
  --expected-key-sha256 "$KEY_INVENTORY_SHA256" \
  --output /privat/aterstallningsunderlag/kopia-001.json
```

Utdata är endast bindningsfilens SHA-256. Förvararen skyddar den externt efter
sin kontroll. Befintliga bindningsfiler skrivs inte över. För en kopia helt
utan profiler, person-/dokumentkopplingar, PIN, spärrkoder eller försökshistorik
utelämnas båda nyckelargumenten; bindning och extern kontrollsumma krävs ändå.

Återställningsoperatören använder den förankrade kontrollsumman:

```sh
.venv/bin/python recovery.py restore --backup /privat/backups/kopia-001/wallet.sqlite \
  --destination /privat/aterstalld \
  --identity-key /separat/nyckelforvaring/wallet.identity-key \
  --binding /privat/aterstallningsunderlag/kopia-001.json \
  --binding-sha256 "$RECOVERY_BINDING_SHA256" --require-continuity \
  --erasure-ledger /separat/forvarare/raderingsbeslut.json \
  --erasure-ledger-sha256 "$CURRENT_ERASURE_LEDGER_SHA256"
```

Nyckelargumentet behövs bara när kopian har nyckelberoende data. Använd alltid
`--require-continuity` för en driftsatt tjänst. Ett kontinuitetskrav i den
förankrade bindningen består även om den separata markörfilen har försvunnit.
Aktuell oberoende spärrtjänst, avisering och driftkonfiguration måste ordnas
före start; bindningen återskapar inte dem.

## Kontroller och avgränsning

Kopian måste vara en stängd, privat SQLite-fil utan WAL, SHM eller journalfil.
Använd backupkommandot på en aktiv databas i stället för att kopiera dess
huvudfil. Källa och bindning kräver privata kataloger och vanliga privatägda
filer utan extra hårdlänkar. Symlänkar och named pipes avvisas.

Kopiering omfattar högst 2 GiB och kontrollerar en 30-sekundersgräns mellan
läsningarna. Filbyte, ändring under läsning och fel lämnar ingen färdig kopia.
Bindningsfilen är högst 4096 byte och valideras strikt mot externt ankare.
SQLite-views och triggers avvisas. Profilfält begränsas före JSON-avkodning
och kryptografi; profilverifieringen har en kontrollerad 120-sekundersgräns,
utöver pågående kryptografianrops egen timeout.

Bindningsskapandet använder en temporär privat databasfil under utdatakatalogen
och tar bort den efter kontrollen. Använd skyddad lagring; borttagning bevisar
inte fysisk utplåning ur mediet eller dess kopior.

Vid återställning kontrolleras kopians exakta bytehash före databasändringar,
nyckelns fullständiga fingeravtryck och varje kvarvarande profils AES-GCM-skydd.
Alla credentials spärras, väntande/godkända begäranden annulleras,
registerbindningar tas bort och nyregistrering/biometri stoppas i minst ett dygn.
Resultatet publiceras endast i en ny privat katalog; fel tar bort katalogen.

Detta är integritets- och nyckelbindning mot ett betrott externt ankare.
Det är ingen digital signatur, betrodd tidsstämpel eller garanti att en
förvarare har fattat rätt beslut. Manipulation av både kopia och dess
oberoende ankare, komprometterad nyckelförvaltare och manuell återläsning
utanför verktyget ligger utanför kontrollen. Operativ inventering,
förvararseparation, nyckelrotation och återställningsövning återstår.

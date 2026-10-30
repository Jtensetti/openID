# Bildarbetarnas Linux-begränsningar

`profile_worker.py` och `biometric_worker.py` aktiverar samma policy innan de
importerar bildbibliotek eller läser bilddata. Skyddet gäller kortlivade
barnprocesser. Det installeras inte i HTTP-processen eller testprocessens
förälder. Modellkontrollen vid tjänstens start använder också policyn och
arbetarens rensade miljö.

## Förutsättningar

- Linux x86-64, 64-bitars Python, aktiverad Landlock med ABI minst 3 och
  stöd för seccomp-filter. ABI-versionen kontrolleras i den faktiska kärnan.
- En tråd och endast stdin/stdout/stderr öppna när policyn installeras.
  `close_fds=True` används vid processstart; ett kvarvarande öppet descriptor
  eller en befintlig bakgrundstråd gör att arbetaren avbryter.
- Runtime, kod och modeller är betrodda, granskade och skrivskyddade under
  drift. Hemligheter, personakter och säkerhetskopior måste ligga utanför
  de läsbara runtime-/kodkatalogerna.
- Containerns vanliga skydd består: separat användare, borttagna capabilities,
  skrivskyddad root, resursgränser och begränsade monteringar.

Saknat eller nekat skydd stoppar Linux-arbetaren. Det finns ingen inställning
som faller tillbaka till oskyddad Linux-analys. På macOS används befintliga
process-/resursgränser för lokal utveckling; Landlock/seccomp installeras inte.
Det är ingen verifiering av motsvarande isolering på macOS.

## Filåtkomst

Landlock nekar som standard filinnehållsläsning, kataloglistning, skrivning,
trunkering, skapande, borttagning, länkning, namnbyte och exekvering enligt
ABI 3:s rättigheter. På ABI 5 eller senare hanteras också enhets-ioctl.
Endast läsning tillåts för:

- Systemets bibliotek och den aktuella Python-installationens bibliotek.
- Individuella reguljära Python-källfiler intill arbetaren samt dess
  `models` och `vendor`. Källfilssymlänkar tillför inte läsrättigheter;
  dessa två kataloger får inte peka utanför kodkatalogen.
- Den fasta granskningskandidatens `/opt/openid-opencv`, om den finns.
- Några fasta runtime-filer: dynamiska laddarens cache, lokal tidszon,
  `/dev/null`, `/dev/urandom`, CPU-/minnesinformation, arbetarens egen
  processstatus och `/sys/devices/system/cpu`.

Arbetskatalogen, `/srv`, `/tmp`, hemkataloger och andra processers `/proc`-
filer får ingen generell läsrättighet. `PYTHONPATH` skapar inga nya
Landlock-undantag. Vid processstart ärvs endast den exakta fasta
kandidatsökvägen; godtyckliga föräldrasökvägar får inte påverka importer
före skyddsaktiveringen. Ingen katalog får skrivrättighet.

## Systemanrop

Ett seccomp-filter tillåter en explicit mängd x86-64-systemanrop för minne,
trådsynkronisering, tid, filöppning och pipe-I/O. Filöppning måste dessutom
passera Landlock. Nya/okända systemanrop nekas med `EPERM`.
Andra systemanropsarkitekturer stoppar processen; x32-numren tillåts inte.

Nätverkssockets, socketpar, process-/trådskapande, programstart, ptrace,
åtkomst till andra processers minne/deskriptorer, io_uring, namnrymder,
mount, BPF-laddning och ändringar av filägare/rättigheter tillåts inte.
`tgkill` får bara avse arbetarens egen trådgrupp. `prctl` tillåts bara för
tre läsfrågor om skydd; dumpbarhet kan inte återaktiveras genom den vägen.
`prlimit64` får bara läsa egna gränser. `fcntl` begränsas till filbeskrivarens
vanliga duplicerings-/flagganrop; signalägarskap och leases nekas.

Policyn använder Linux UAPI via Pythons standardbibliotek. Inga nya paket,
privilegierade hjälpprogram eller kärnkonfigurationer installeras.

## Provning och kvarvarande gränser

`test_worker_confinement` provar faktiska nekade fil-, nätverks- och
processanrop i ett separat Linux-barn, inklusive försök via symlänk,
andra processers `/proc`, ärvda filbeskrivare och befintliga trådar.
Separata policyprov kontrollerar BPF-grenar, höga argumentbitar och andra
ABI:er; de ersätter inte Linux-körningen. Arbetarnas felvägar måste stoppa
före inläsning utan att återge känsliga felmeddelanden.

Ett separat Linux-barn laddar även de riktiga YuNet-, SFace- och PAD-modellerna
och utför beräkningar med genererade pixlar efter aktiverat skydd.
Det kontrollerar faktisk inferens och eventuella sent laddade bibliotek,
utöver startens modellkontroll. Det är inget prov på identifieringsnoggrannhet
eller godkännande av en verklig person. Proven körs på både ordinarie image
och den separata OpenCV-kandidaten, med kontroll av kandidatens faktiska importväg.

Befintliga codec-, profil-, modell- och tjänsteprov körs med skyddet i CI.
Testresultat knyts till testad revision; en kodändring är inte ett bevis på
att en driftsatt värd har rätt kärna eller att fysisk telefonacceptans är klar.

Landlock skyddar inte all filmetadata. Tillåtna runtime-filer är läsbara
och pipes är avsiktliga in-/utkanaler. Resursöverbelastning, kärnsårbarheter,
privilegierad värdadministratör, timingkanaler och ett manipulerat
runtime-/kodpaket kräver andra kontroller. Policyn rättar inga codecs eller
OS-paket och stänger inte deras sårbarhetsfynd. Oberoende granskning,
driftsättning och verifiering på avsedd värd återstår.

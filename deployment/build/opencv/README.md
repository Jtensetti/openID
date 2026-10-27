# Begränsat OpenCV-bygge för jämförande prov

Det uttryckliga Docker-målet `opencv-candidate` provar ett källbygge utan
att ändra standardmålet `release`. Kandidaten är inte en produktionsleverans.
Den innehåller fortfarande referenshjulet; ingen sårbarhet stängs genom att
bara välja en annan importväg. Efter godkänd jämförelse återstår integration,
full regression i slutimagen, bibliotekskontroll och oberoende granskning.

`native.lock.json` låser officiella källarkiv, byggverktyg, licenshashar och
CMake-val. OpenCV 4.14.0 kompileras med externa statiska libjpeg-turbo 3.2.0
och OpenJPEG 2.5.4 med upstreamrevision `8314119b067c0fc77834731168daaebd379fdb12`.
OpenJPEG-revisionen är en oreleasad snapshot med rättningar efter 2.5.4;
upstreams versionssträng är fortfarande 2.5.4. CMake 4.4.4 används enbart under bygge. CPython 3.12.16
och NumPy 2.2.6 återanvänds från befintliga hashlås. Inget pip-index anropas.
Kompilering och upstreams JPEG-prov körs med `RUN --network=none` i den
digestlåsta Linux-byggcontainern, utan produktionsdata eller behörigheter.

Modulerna core, imgproc, imgcodecs, dnn, objdetect och Pythonbindning väljs.
Objdetect kräver dessutom calib3d, features2d och flann. Video/GUI, FFmpeg,
IPP, OpenCL och oanvända externa bildformat stängs av. OpenCV:s inbyggda
BMP-kod och Protobuf 3.19.1 finns kvar; applikationens formatgrind består.
JPEG-SIMD är avstängd i första kandidaten. Det behöver vägas mot den uppmätta
avkodningstiden innan införande. Inga upstreamkällor ändras.

`build.py` verifierar arkiv och licenser, kör libjpeg-turbos tillgängliga
regressionsprov och OpenJPEG:s genererade sparse-array- och interleaved-tile-prov, och bevarar
CMake-cache, kompileringskommandon, byggloggar, ELF-information och en
avgränsad CycloneDX-inventering. OpenCV:s fulla upstreamkorpus ingår inte.
ELF-kontrollen nekar oväntade dynamiska bibliotek, textrelokering och
exekverbar stack. Relro och omedelbar symbolbindning krävs. Systembibliotek
och byggverktygets inbäddade komponenter kräver fortsatt separat bedömning.
Alla tre källbyggen får dessutom stackskydd, stack-clash-skydd,
`_FORTIFY_SOURCE=2` och formatkontroller för C/C++. De faktiska genererade
kompileringskommandona kontrolleras före bygge, även för statiska JPEG-objekt.
Saknade skydd, senare försvagande flaggor, avstängd optimering och oinspekterade
response-filer stoppar bygget. `compiler-hardening.json` bevarar täckningen.
Detta kompletterar ELF-provet; slutbibliotekets länkarflaggor bevisar inte
hur varje ingående objekt kompilerades. Skydden rättar inte kända kodfel.
Den tillåtna x86-64-systemladdaren `ld-linux-x86-64.so.2` tillhör Debians
`libc6`; den kan också förekomma som direkt ELF-beroende. Den separata
OS-bedömningen kvarstår. Negativa prov nekar extra codec-/kryptobibliotek,
godtyckliga bibliotekssökvägar och saknade minnesskydd.

Det befintliga pilotjobbet bygger referensimagen och den uttryckliga kandidaten.
Båda kör `probe.py` utan nät, skrivbar rot eller Linux-capabilities och med
samma genererade bilder och låsta modeller. Proven kontrollerar JPEG, JP2,
rå JPEG 2000, profilminiatyr, avvisade format/storlekar, YuNet, SFace och PAD.
`compare.py` nekar ändrade indata, modellresultat utanför angivna numeriska
toleranser och stor avkodningsförsämring. Toleranser: högst tre steg per
JPEG-färgkanal och ett steg i medel, exakt lossless JPEG 2000, SFace 1e-4,
PAD 1e-6, median avkodningstid högst tre gånger referensen plus 20 ms.
Detta är en begränsad kompatibilitetskontroll, inte ett statistiskt
noggrannhetsprov, biometrisk kalibrering eller PAD-godkännande.

Jämförelse, syntetiska fixturer, image-ID:n, testad revision, licenser och
hashbundna byggbevis sparas i pilotens befintliga inventeringsartefakt.
Inget nytt CI-jobb, molnresurs eller driftsättningssteg införs. Jobbets maximala
tid ökas för kompileringen; byggminuter omfattas av befintlig Actions-kvot.
Repoförvaltaren ansvarar för källor, licenser, advisorybevakning och omprov.

OpenJPEG:s README anger att projektet saknar regelbundet underhåll. Valet
är därför begränsat till jämförelse; förvaltning eller ersättare måste beslutas
före produktion. Revisionen innehåller upstreams rättningar för CVE-2026-6192
och OSV-2025-219 enligt verifierad commit-historik. Detta är källbevis, inte
egna exploitregressionsprov. OSV-2026-1068 för libjpeg-turbo och OSV-2023-444
för OpenCV kräver fortsatt bedömning av faktisk kodväg och reproduktion.
TurboJPEG-wrappern byggs inte, men den gemensamma JPEG-koden finns kvar.
Ingen av dessa kontroller innebär att alla native-sårbarheter är stängda.

OpenCV:s separata komponentnotiser bevaras, inklusive BSD-/FDLIBM-notiserna
i `softfloat.cpp`. Licensarkivet omfattar även ej byggda källkomponenter och
utgör därför inte en förteckning över enbart länkad runtime-kod.

This software is based in part on the work of the Independent JPEG Group.

Primärkällor kontrollerade 2026-10-27:

- [OpenCV 4.14.0](https://github.com/opencv/opencv/tree/0654a42e19215ef25b1d367d822f3c630447e7c7)
- [libjpeg-turbo 3.2.0](https://github.com/libjpeg-turbo/libjpeg-turbo/releases/tag/3.2.0)
- [OpenJPEG 2.5.4](https://github.com/uclouvain/openjpeg/releases/tag/v2.5.4)
- [Vald OpenJPEG-revision och underhållsstatus](https://github.com/uclouvain/openjpeg/tree/8314119b067c0fc77834731168daaebd379fdb12)
- [OpenJPEG: minnesgränskontroll](https://github.com/uclouvain/openjpeg/commit/91d08b11a72764f6d199f32fa0c1b1abd4edc2ad)
- [OpenJPEG: heltalsöverflöde](https://github.com/uclouvain/openjpeg/commit/839936aa33eb8899bbbd80fda02796bb65068951)
- [libjpeg-turbo OSV-2026-1068](https://osv.dev/vulnerability/OSV-2026-1068)
- [OpenCV OSV-2023-444](https://osv.dev/vulnerability/OSV-2023-444)
- [CMake 4.4.4](https://github.com/Kitware/CMake/releases/tag/v4.4.4)
- [Debian libc6: installerade filer på amd64](https://packages.debian.org/trixie/amd64/libc6/filelist)
- [GCC: stackskydd och stack-clash-skydd](https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html)
- [glibc: kontroll av buffertåtkomst](https://sourceware.org/glibc/manual/latest/html_node/Source-Fortification.html)
- [CMake: språkens kompileringsflaggor](https://cmake.org/cmake/help/latest/variable/CMAKE_LANG_FLAGS.html)

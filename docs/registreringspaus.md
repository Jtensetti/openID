# Pausa nya registreringar

Verifierarens WSGI-runtime har en separat inställning för ny registrering:

```json
"newRegistrationsEnabled": false
```

Utelämnat värde betyder `false`. Bara JSON-värdena `true` och `false` godtas.
Inställningen stöds i pilotens `serve.py` och registrets proofing-konfiguration.
Wallet-rollen tar inte emot proofing-inställningen.

Pausen nekar `/native/start`, attestering, chiputbyte och slutförande med
HTTP 503 och `REGISTRATION_PAUSED` innan applikationen läser anropskroppen
eller anropar registreringsfunktionerna. Även påbörjade registreringar
stoppas. Nätverksingressen kan redan ha tagit emot eller buffrat kroppen;
pausen är inte ett löfte om att inga byte når infrastrukturen.
`/native/cancel` kan fortfarande frigöra en session. Befintlig inloggning,
status och spärr använder wallet-/spärrfunktionerna och påverkas inte av flaggan.
Övriga säkerhets- och kapacitetskontroller gäller fortfarande.

`publicEnrollment` avgör om API:t medger opairade appanrop. Det aktiverar inte
nyregistrering. En kopplingskod ger inte heller undantag från pausen.

Konfigurationen läses vid processstart. En driftändring behöver kontrollerad
omstart och efterprov. En begäran som redan behandlas när omstarten beslutas
kan hinna slutföras. Dränera/stäng insamlingsingressen och kontrollera pågående
arbete om ett omedelbart insamlingsstopp krävs. Inställningen skickas inte
genom ett publikt administrations-API och upphäver inte registrets
tidsbegränsade återställningsspärr.

Vid uppgradering från en äldre version stängs nya registreringar om värdet
inte uttryckligen anges. `true` kräver ett separat beslut om att insamlingen
får börja. Flaggan bevisar varken laglig grund, information till deltagaren,
biometriskt samtycke eller accepterad villkorsversion. Versionsbundet
acceptbevis och en fullständig återkallelseprocess återstår att genomföra.
Syntetiska labbservrar i `server.py` omfattas inte av WSGI-konfigurationen
och får inte användas som publik ersättningsväg.

Införandeprov: rätt ursprung och befintligt behörighetsskydd, paus på samtliga
registreringsrutter, fungerande wallet och avbrott, samt inget nytt ID efter
paus. Använd syntetiska anrop. `test_runtime` och `test_cluster_revocation`
provar ruttgränsen, strikta flaggtyper och konfiguration. Mottagning,
iPhone-flöde och verklig driftsättning måste verifieras separat.

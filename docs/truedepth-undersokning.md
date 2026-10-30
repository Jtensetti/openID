# Undersökning av TrueDepth för ansiktsfångst

Status: separat hypotes, inte införd i registreringsflödet. Den automatiska
RGB-fångsten och serverns befintliga kontroll fungerar utan TrueDepth.

## Frågor och prov

- Kontrollera tillgång till TrueDepth och faktiska djupformat separat från
  ARKit-stöd för ansiktsspårning.
- Prototypa synkroniserade färg- och djupbilder under samma bekväma huvudrörelse.
  Mät saknade djupbilder, tidsförskjutning, latens och användbarhet på valda telefoner.
- Definiera ett servervaliderat sekvensformat och sessionsbindning innan signalerna
  kan ingå i ett beslut. Klientrapporterade flaggor räcker inte.
- Prova fotografier, skärmar, masker och bildinjektion samt felavvisning av
  riktiga användare. Dokumentera testuppställning och råa utfall separat från UX.
- Bestäm dataminimering, gallring och telefoner utan djupdata före pilotinförande.

Ingen maskskyddseffekt antas. Face ID:s privata biometriska underlag är
otillgängligt för appen. Lokal autentisering fastställer inte passinnehavarens identitet.

## API-underlag

- [Apple TrueDepth](https://developer.apple.com/documentation/avfoundation/streaming-depth-data-from-the-truedepth-camera)
- [Apple ARFaceTrackingConfiguration](https://developer.apple.com/documentation/arkit/arfacetrackingconfiguration/)
- [Apple Local Authentication](https://developer.apple.com/documentation/localauthentication)

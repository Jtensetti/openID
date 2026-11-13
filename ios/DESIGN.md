# Tjipps gränssnitt

`TjippDesign.swift` och `Palette.swift` samlar appens formspråk.
Färger och originalbilder följer webbplatsen [folkidentitet.se](https://folkidentitet.se).
Webbkällan är Lovable-projekt `64fa06b7-1f0d-43cc-9b88-e068e62fe7ad`,
revision `e73f0db79916c451caea7be65404d797f110d6b5`.

## Färg, bilder och typografi

| Del | Värde i ljust läge |
| --- | --- |
| Bakgrund | `#FAF8F2` |
| Panel | `#FFFDF8` |
| Text och huvudknapp | `#10343B` |
| Sekundär text | `#5E6C6B` |
| Linjer | `#D7DBD3` |
| Hav / Skog | `#070E3D` / `#2B6A50` |
| Aprikos / Lera | `#C96F49` / `#AA5547` |
| Sol / Lavendel | `#C08B22` / `#79719D` |
| Ros / Grafit | `#B37583` / `#5F6669` |

Personlig färg gäller hela appen: logotyp, huvudknappar, sekundärknappar,
flikmarkeringar, länkar, ikoner och svaga bakgrundstoner. `TjippTheme` ärvs
av alla vyer och modala flöden och uppdateras direkt när färgvalet ändras.
Huvudknappen använder färgens originalvärde; ljus eller mörk knapptext väljs
för kontrast. Textlänkar och små markeringar får en ljusare eller mörkare
nyans av samma färg vid behov. Säkerhetsstatus visas fortsatt med text och
symbol; fel och kamerans positioneringssignaler har egna semantiska färger.
Systemets mörka läge har neutrala mörka ytor. `PaletteTests` kontrollerar
kontrast för alla åtta teman i båda lägena samt paketerade bilder.

Symbolerna och ordmärket i `Assets.xcassets/Tjipp*.imageset` är projektets
tillhandahållna PNG-original från webbplatsen. De är kopierade utan omritning,
filter eller nya konturer. Ordmärkets originalform används som mask i gränssnittet,
med läsbar textfärg och punkt i vald färg, utan en ljus platta i mörkt läge.
`design-assets.json` binder filerna
till respektive originaladress och SHA-256. Inga nya externa typsnitt används.
Alla sidrubriker använder samma iOS serif med Dynamic Type. Underrubriker,
brödtext och knappar använder samma systemtextstilar genom hela appen.
`TjippPage`, `TjippSection`, `TjippFieldStyle` och knappstilarna samlar
marginaler, paneler, inmatning och åtgärder. Startsidan visar en enda rubrik:
Mitt ID när uppgifterna är dolda, annars den personliga hälsningen. Mönstren Papper, Ådring, Dyner
och Ringar ritas separat som diskreta SwiftUI-bakgrunder.

`tjipp.color` och `tjipp.pattern` sparas lokalt i UserDefaults. Inga ID- eller
personuppgifter sparas med utseendevalen. Hälsningen hämtas endast från den
upplåsta serverprofilen. Passfotot visas runt och rensas med befintlig låsning.
Det fullständiga namnet och de underliggande identitetsuppgifterna ändras inte.

## Tangentbord och beslut

`BottomActionBar` placeras i `safeAreaInset(edge: .bottom)` så att rullinnehållet
och tangentbordet lämnar plats åt knapparna. Det används vid underskrift,
säkerhetskod, passinmatning, anslutning och fokuserad länkinmatning.
Nummerfält har en **Klart**-knapp och formulär kan rullas med öppet tangentbord.

Underskrift med säkerhetskod visar mottagare, hela den bokstavliga
underskriftstexten, separat kontrollkod, kodfält och nästa steg med telefonens
autentisering. Både **Skriv under** och **Avböj underskrift** ligger ovanför
tangentbordet. Inmatad kod rensas vid beslut, låsning och när vyn lämnas.
Utgång, signeringsbindning och serverkontroll följer befintligt protokoll.

## Kamera och NFC

Passramens geometri och ansiktsovalens segment, placering och toleranser är
oförändrade. Mörka understreck ökar kontrasten mot ljusa kamerabilder.
Färg kompletteras fortsatt med instruktion, delsteg och bockar.

`PassportPlacementView` visar telefonens överkant mot ett plant pass och
förklarar att två läsningar behövs. Den är tillgänglig före läsning och under
chipsteget; Apples NFC-dialog ligger ovanpå appen när systemet läser.
Rörelse stängs av med systemets **Minska rörelse**. Animationen är vägledning,
inte ett mått på chipkontakt eller läsframsteg.

## Provning

Kör bygg- och testkommandona i [README](README.md#bygg-och-testa).
XCUITest kontrollerar bland annat att beslut och passläsning ligger ovanför
tangentbordet, att färg/mönster sparas och att hälsningen försvinner vid låsning.
`--design-preview` visar en syntetisk identitet endast i Debug/simulator;
övriga förhandsvisningsflaggor finns i `CapturePreviewFixture.swift`.
Fixturerna är inte kompilerade i enhetsbyggen och öppnar inte riktig kamera,
NFC eller en registrerad identitet. Fysiska prov behövs för dessa delar.

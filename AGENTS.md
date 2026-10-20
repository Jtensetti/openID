# Arbetsinstruktioner för kodagenter

Repot innehåller en iPhone-app, pass- och bildverifiering, ett personregister,
SAML-integration, en separat WebAuthn-labb och en driftcontainer utan e-id.
Aktuell implementation och verifierade begränsningar styr arbetet.

## Läs före ändring

1. `README.md` och den berörda komponentens README för start och tester.
2. `docs/arkitektur.md`, `docs/krav.md` och `docs/testning.md`.
3. `SECURITY.md`, `THIRD_PARTY.md` och relevant skill nedan.
4. `docs/SOURCES.md` och aktuella primärkällor när normativa villkor,
   API:er, licenser eller upstream-status berörs.

## Skills

| Uppgift | Fil under `.agents/skills/` |
|---|---|
| Digg, tillitsnivå, avtal eller godkännandepåståenden | `digg-compliance/SKILL.md` |
| SAML, OIDC, Sweden Connect, metadata eller sessionsbindning | `sweden-connect-integration/SKILL.md` |
| Identitetskontroll, enhetsnyckel, spärr eller återställning | `eid-lifecycle-security/SKILL.md` |
| Dokumentunderskrift och valideringsbevis | `electronic-signatures/SKILL.md` |
| Beroenden, licens, byggkedja, CI eller release | `supply-chain-and-release/SKILL.md` |
| Transaktionsklassificering, rapportering eller ersättning | `eid-economics-and-reporting/SKILL.md` |

Läs flera skills när ändringen korsar områden. Instruktionerna är
projektspecifika; de utgör inte myndighetskrav.

## Säkerhetsgränser

- CI, publika exempel och SAML/WebAuthn-labben använder genererade identiteter
  och testnycklar. Verkliga handlingar används bara i en uttryckligen vald
  privat testmiljö. Inga personakter eller hemligheter får publiceras.
- Använd etablerade bibliotek för kryptografi och protokollvalidering.
  Ingen generativ modell får avgöra identitet, tillitsnivå eller godkännande.
- Skilj teknisk funktion från tillitsgodkännande, anslutningsavtal och rätt
  till ersättning. Använd inte myndighetslogotyper eller kvalitetsmärken utan stöd.
- Säkerhetskritisk produktionsrelease kräver oberoende granskning och
  behörigt mänskligt beslut. En agent får inte attestera sin egen release.
- Spärr och återställning får inte kringgås av cache, gamla säkerhetskopior
  eller administrativa genvägar. Testa ändrade livscykelövergångar.
- Testtrafik, avbrott, dubbletter och icke kvalificerande motparter får inte
  bli ersättningsanspråk.
- Ändra inte skydd, behörigheter, hemligheter, produktionsmiljö eller externa
  avtal som bieffekt. Ingen force-push eller borttagning av befintligt arbete
  utan uttryckligt uppdrag.

## Genomförande och redovisning

Arbeta på separat branch och rikta PR:n mot `main`. Följ
`docs/utveckling.md`. Beroenden kräver låst version, ursprung, licens,
attribution, SBOM och dokumenterat uppdateringsansvar. Bevara NOTICE och
licenshuvuden. Kontrollera upstream-status på nytt före ett versionsbyte.

Kör relevanta tester och ange revision, resultat och delar som inte kunde
köras. Uppdatera berörda krav-ID när beteendet ändras; höj inte formell
status utan motsvarande bevis och rätt beslutsfattare.

Skriv kort och sakligt. Dokumentera hur programvaran fungerar, hur den
körs och vilka begränsningar som gäller. Affärsunderlag, kontaktutkast och
intern kommunikation hör inte hemma i den publika dokumentationen.
Tillfälliga arbetsloggar och granskningsresultat hör hemma i PR:n.

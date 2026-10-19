# Arbetsinstruktioner för kodagenter

## Projektets uppdrag

Undersök och utveckla stegvis en självständig svensk e-legitimation med öppen källkod som ambition. Första steget är förstudie och isolerad prototyp. Tillitsnivå 3 är ett föreslaget mål, inte en uppnådd egenskap.

Denna fil är ingång för alla agenter. Läs den och relevanta skills innan förändringar. Instruktionerna är projektspecifika, inte utfärdade av Digg. Automatiskt stöd för `.agents/skills/` varierar mellan verktyg; läs filerna uttryckligen när automatisk upptäckt saknas.

## Läsordning

1. `README.md` och `docs/05-genomforande.md` för aktuellt scope och grind.
2. `docs/02-kravmatris.md` för berörda krav och öppna evidensluckor.
3. `docs/SOURCES.md` och berörda originalkällor för normativa påståenden.
4. `docs/04-arkitektur.md` och den eller de skills som uppgiften berör.
5. `SECURITY.md` och `THIRD_PARTY.md` före kod, beroenden och publicering.

## Skill-routing

| När uppgiften berör | Läs |
|---|---|
| Digg, tillitsnivå, avtal, ansökan, juridiska villkor eller godkännandepåståenden | `.agents/skills/digg-compliance/SKILL.md` |
| SAML, OIDC, Sweden Connect, metadata, attribut, sessions-/motpartsbindning | `.agents/skills/sweden-connect-integration/SKILL.md` |
| Identitetskontroll, credential, enhetsnyckel, PIN, spärr, återställning eller HSM | `.agents/skills/eid-lifecycle-security/SKILL.md` |
| Signering, dokument, avancerad underskrift eller valideringsbevis | `.agents/skills/electronic-signatures/SKILL.md` |
| Nytt bibliotek, upstream-kod, licens, byggkedja, CI eller release | `.agents/skills/supply-chain-and-release/SKILL.md` |
| Ersättning, volymer, transaktionstyper, fakturering, rättelse eller likviditet | `.agents/skills/eid-economics-and-reporting/SKILL.md` |

Flera skills kan behövas samtidigt. En ändring i autentiseringsflödet som även ändrar vad som räknas som lyckad transaktion berör exempelvis protokoll, livscykel och ekonomi.

## Före varje ändring

- Läs det faktiska repot och den aktuella filversionen. Anta inte att denna första dokumentationsuppsättning fortfarande beskriver hela projektet.
- Ange berörda krav-ID, vad som är förslag och vad som faktiskt är verifierat.
- Kontrollera aktuella primärkällor när villkor, API:er eller upstream-status kan ha ändrats. Dokumentera åtkomstdatum och version. Använd inte gamla chattpåståenden som auktoritativ källa.
- Beskriv kort förändringens förtroendegränser, negativa testfall och eventuell risk för personuppgifter eller pengar.

## Gränser som inte får döljas av en fungerande demo

1. Syntetiska identiteter, testdokument och separata testnycklar fram till uttryckligen godkänd produktionsgrind. Inga personakter eller hemligheter i detta publika repo.
2. Ingen egen kryptografisk primitiv eller improviserad SAML/OIDC-validerare. Återanvänd granskade bibliotek och granska vår användning av dem.
3. Ingen LLM eller annan generativ modell avgör identitet, tillitsnivå, autentisering eller underskriftsgodkännande.
4. Protokollstöd, godkänt test, tillitsgodkännande, auktorisationsavtal och rätt till ersättning är separata saker. Skriv inte att den ena bevisar den andra.
5. En agent får inte själv besluta om produktionsöppning eller godkänna sin egen säkerhetskritiska release. Kritiska ändringar kräver oberoende granskning och behörigt mänskligt beslut.
6. Säker återställning och spärr är kärnfunktioner, inte uppskjutbara tillbehör. Läsning från gammal cache får inte bli en dold genväg runt spärr.
7. Testtrafik, avbrott, dubbletter och icke kvalificerande motparter får inte bli ersättningsanspråk.
8. Ändra inte skydd, behörigheter, hemligheter, produktionsmiljö eller externa avtal som bieffekt av en koduppgift. Ingen force-push eller borttagning av befintligt arbete utan uttryckligt uppdrag.

## Källor, kod och tester

`swedenconnect/saml-identity-provider` är i den kontrollerade README-versionen ersatt av `swedenconnect/spring-authentication-server`. Bekräfta upstream-status igen före versionsval. Referensautentisering och testklienter är inte verklig utgivning.

Tredjepartskod kräver dokumenterad revision, licens, attribution, beroenden och uppdateringsägare. Importera inte ett helt mallrepos CI-konfiguration utan granskning. Dokumenterade testkommandon ska vara kommandon som faktiskt finns i den aktuella implementationen; just nu finns inga implementations- eller produktionsbyggkommandon.

Kör relevanta tester när verktygen medger det. Redovisa exakt vad som kördes och vad som inte kunde köras. Öka inte status i kravmatrisen utan motsvarande bevis och korrekt beslutsfattare.

## Leveransrapport

Varje arbetsresultat ska ange:

```text
Uppgift och scope:
Lästa skills:
Berörda krav-ID och källversioner:
Ändrade filer/revision:
Genomförda tester och resultat:
Ej körda tester och varför:
Vad som fortfarande är simulerat:
Risker och öppna beslut:
Oberoende granskning som återstår:
```

Dokumentation ska vara saklig och begriplig på svenska; kodidentifierare kan följa bibliotekens språk. Använd aldrig kvalitetsmärken, myndighetslogotyper eller formuleringar som antyder godkännande utan faktiskt stöd. Projektets namn innebär inte anknytning till OpenID Foundation eller någon offentlig organisation.

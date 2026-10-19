---
name: sweden-connect-integration
description: >-
  Använd vid SAML-, OIDC- eller Sweden Connect-integration, metadata,
  attribut, sessioner och tillitsankare. Återanvänder aktuella bibliotek
  och kräver versionsbundna negativa tester i isolerad miljö.
---

# Sweden Connect: integration utan egen protokollstack

Projektspecifik originalinstruktion. Läs `AGENTS.md`, `docs/03-ateranvandning.md`, `docs/04-arkitektur.md` och T01–T03 i `docs/SOURCES.md`.

## Inmatning som behövs

Angivet protokoll och flöde, målmiljö, accepterad profilversion, berörda motparter, krav-ID och den nuvarande implementationen. Om profilen eller versionen inte är vald: leverera ett beslutsunderlag eller en tydligt avgränsad labb, inte ett påstående om produktionsinteroperabilitet.

## Arbetsgång

1. Bekräfta aktuell upstream-status. Vid den ursprungliga inventeringen var `swedenconnect/saml-identity-provider` ersatt av `swedenconnect/spring-authentication-server`. Börja inte ny kod på den äldre grunden av gammal vana.
2. Läs aktuell modulkonfiguration och välj en verifierad revision. Följ även `supply-chain-and-release` när ett beroende införs eller ändras.
3. Mappa just det valda flödets profilkrav till bibliotekets funktioner och vår konfiguration. Skilj normativ profil från utkast, demo och generisk standard.
4. Rita förtroendegränser: motpart → metadata/ankare → begäran → session → autentisering → svar → mottagare. Ange var varje bindning verifieras.
5. Implementera minsta förändring med bibliotekets avsedda integrationspunkter. Kopiera inte egna generiska token-/XML-signaturvaliderare eller kör vidare utan validering när testet blir svårt.
6. Använd separat testfederation och kontrollerade nycklar. Referensserverns simulerade användare ska förbli uppenbart simulerade.
7. Kör ett positivt flöde och relevanta negativa fall. Spara konfiguration, revision, test-ID och resultat utan hemligheter eller riktiga identiteter.
8. Uppdatera kravmatris och integrationsdokumentation med exakt verifierad omfattning.

## Negativa fall att välja för aktuellt flöde

Fel issuer eller tillitsankare; fel audience/mottagare; otillåten ACS/redirect URI; manipulerad signatur; utgången begäran; återspelning; fel sessionsbindning; otillåten algoritm; för lågt faktiskt tillitsresultat; för mycket attribut; metadata med oönskade nätverksmål; avbruten autentisering; spärrad credential.

Testa SAML-specifika respektive OIDC-specifika mekanismer enligt vald profil. `InResponseTo`, `nonce`, `state` och PKCE fyller inte automatiskt samma roll i alla flöden. Ett korrekt protokollnamn i dokumentationen är inte tillräckligt.

G05 är kandidat för vår egen testmotpart och får avsiktligt producera felaktiga meddelanden. Använd den endast mot egna eller uttryckligen godkända testmål.

## Leverans

```text
Protokoll, flöde och profilrevision:
Upstream-revision och ändrad konfiguration:
Krav-ID och bindningar som verifieras:
Positiva och negativa testresultat:
Attribut som lämnas och varför:
Simulerade delar:
Otestade motparter/egenskaper:
Kvarvarande risk och granskare:
```

## Stoppsignaler

Okänt tillitsankare, avstängd signaturvalidering, produktionscertifikat i labb, otestad redirect-/mottagarlogik eller tillitsnivå som bara kopieras från begäran. Markera blockerande fel. Skilj alltid autentisering från myndighetens efterföljande behörighetskontroll.

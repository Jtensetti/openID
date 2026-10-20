---
name: supply-chain-and-release
description: >-
  Använd vid införande eller uppdatering av bibliotek, kopierad kod,
  licenser, CI, byggverktyg och releaser. Kräver versionslåsning,
  proveniens, negativa tester och ärlig redovisning av releasebevis.
---

# Leveranskedja och säker release

Projektspecifik originalinstruktion. Läs `AGENTS.md`, `THIRD_PARTY.md`, `SECURITY.md` och den berörda komponentens licensregister. En myndighetsavsändare eller öppen källkod innebär inte att vår användning automatiskt är säker eller licensmässigt färdigbedömd.

## Arbetsgång för en kandidat

1. Bekräfta originalrepository, underhållsstatus, efterföljare och officiella distributionskanaler. Läs säkerhetsmeddelanden och aktuell dokumentation, inte bara sökresultat.
2. Välj en konkret release och identifiera hela revisionen. Skilj tagg, commit-SHA, README-blob och paketchecksumma. Ett värde på `latest` är inte en stabil versionslåsning.
3. Läs licensfiler, NOTICE, SPDX-/REUSE-uppgifter och villkor för berörda filer. Granska transitiva beroenden. Blanda inte en CC0-märkt README med kodens EUPL-licens.
4. Beskriv behovet. Föredra ett underhållet bibliotek framför en onödig fork, men dokumentera även integrationens risker. Kopiera inte källkod utan attribution och ett klarlagt licensbeslut.
5. Bygg och testa i isolerad utvecklingsmiljö. Kör inte okända installationsskript med produktionshemligheter, administratörsbehörighet eller fri åtkomst till interna nät.
6. Dokumentera kompatibilitet, beroendeförteckning, SBOM och publicerade sårbarheter. Frånvaro av kända fynd är inte bevis på frånvaro av sårbarheter.
7. Testa den egna integrationen, inklusive negativa säkerhetsfall. En upstream-testsvit testar inte automatiskt vår konfiguration.
8. Tilldela uppdateringsägare och planera hur säkerhetsfixar ska införas och verifieras.

## När CI eller release ändras

Granska lägsta nödvändiga tokenbehörigheter, tredjepartsactions, versionslåsning, opålitliga bidrag, hemligheters tillgänglighet och vilka miljöer en körning får påverka. Publicera inte workflows som ger externa pull requests åtkomst till produktionshemligheter.

Definiera en spårbar kedja från granskad ändring till byggd artefakt. Lägg till artefakt-/proveniensverifiering där verktygen stödjer det. Signera inte en artefakt med en nyckel som samma opålitliga byggsteg kan missbruka utan att den risken är hanterad.

En människa med rätt mandat och oberoende granskningsunderlag ska fatta säkerhetskritiska produktionsbeslut. Agenten får skapa förslag, inte attestera sin egen produktionsrelease.

## Leveransregister

```text
Komponent och ändamål:
Officiell källa och kontrolltidpunkt:
Release, full commit och artefaktchecksumma:
Licensfiler, attribution och transitiva licenser:
JDK/ramverk/plattform:
SBOM och sårbarhetsbedömning:
Körda bygg-/testkommandon och resultat:
Ändrade CI-behörigheter:
Kvarvarande risker och undantag:
Oberoende granskare:
Uppdateringsägare:
Beslut: utred / labb / godkänd för angiven användning:
```

Ange uttryckligen om bygget eller testerna inte kunde köras. Skapa inte en grön status, badge eller releasebeskrivning som antyder motsatsen.

## Stoppsignaler

Oklar licens, okänd originalkälla, ersatt komponent utan motivering, hemlighet i en diff, otestad säkerhetskonfiguration, obehörig publicering eller ett CI-steg med oproportionerliga rättigheter. Avbryt det riskfyllda steget och lämna ett konkret åtgärdsförslag.

## Exempel på uppdrag

”Utvärdera en låst version av G01 för vår labb. Läs licenserna, dokumentera beroenden och kör dess relevanta tester. För inte in produktionsteknik eller produktionsnycklar.”

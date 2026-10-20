---
name: eid-lifecycle-security
description: >-
  Använd vid utgivning, identitetskontroll, autentiseringsmedel, PIN,
  nycklar, HSM, spärr, återställning eller byte av enhet. Kräver explicit
  tillståndsmodell, befogenhetsseparation och negativa livscykeltester.
---

# Identitetens livscykel och nyckelsäkerhet

Projektspecifik originalinstruktion. Läs `AGENTS.md`, `docs/arkitektur.md`, ID-/SEC-/GOV-raderna i `docs/krav.md` samt D08/D09 via källregistret. Använd även `digg-compliance` när ett normativt krav behöver tolkas.

## Grundregel

En verifierad person, en nyckel, en enhet och en session är olika objekt. Arbetet ska visa hur de binds samman, vem som får ändra bindningen och hur den kan upphöra. Ett lyckat inloggningsexempel får inte dölja svag utgivning eller återställning.

## Arbetsgång

1. Fastställ utgivningsmetod och mål för tillitsnivå. Markera det som ännu är en hypotes. Följ datagränserna i `SECURITY.md` för publika tester och privat passverifiering.
2. Beskriv tillgångar och aktörer: innehavare, registreringsfunktion, utfärdarfunktion, support, drift, nyckelförvaltning och granskare. Identifiera vem som kan missbruka en administrativ genväg.
3. Rita tillståndsmodellen med övergångar, förvillkor, behörighet, bevisreferens och atomiska dataskrivningar. Håll isär spärr, tillfällig avstängning, utgång och ersättning.
4. Följ varje nyckel: skapande, skydd, eventuell export/synkronisering, registrering, användning, rotation, återställning och förstöring. Skilj serverns HSM-nycklar från innehavarens autentiseringsnycklar.
5. Granska separation av befogenheter även genom CI, databas, backup och support. Två knappar i samma administratörsgränssnitt är inte två oberoende kontrollfunktioner.
6. Designa förlorad enhet och spärr före nyutgivning. Utred hur spärr begärs utan den förlorade enheten och hur identiteten kontrolleras vid ersättning. Introducera inte e-post- eller supportgenvägar utan fullständig ny riskprövning.
7. Implementera kontroller med granskade bibliotek. Dokumentera vad enheten eller HSM-lösningen faktiskt bevisar; anta inte säkerhet från produktnamnet.
8. Kör negativa och samtidiga tester. Uppdatera hotmodell, krav-ID och kvarvarande avvikelser.

## Obligatoriska kontrollfrågor

- Kan en ensam person eller ett ensamt servicekonto skapa en credential åt någon annan?
- Kan en spärrad eller utgången credential användas via en gammal session eller cache?
- Kan en återställd backup återuppliva en spärrad nyckel?
- Är en ny enhet faktiskt bunden till rätt verifierad innehavare?
- Kan samma utgivningsbeslut konsumeras två gånger?
- Kan support ändra både kontaktväg och återställningsgodkännande utan oberoende kontroll?
- Finns hemligheter eller identitetsunderlag i loggar, testdata eller publika artefakter?

## Tester och bevis

Testa minst fel person, fel nyckel, återspelad utgivning, parallell spärr, utgången credential, avbruten utgivning, otillåten återaktivering och manipulerad återställning. HSM-gränssnittstest med SoftHSM ska märkas som just ett gränssnittstest, inte fysiskt nyckelskydd.

Leverera en tillståndstabell, behörighetskarta, nyckelflöde, utförda testresultat och lista över kontroller som kräver mänsklig eller oberoende verifiering. Ange alla simulerade kontroller.

## Stoppsignaler

Egen kryptografi, verkliga ID-handlingar i repot, passkey likställd med godkänd tillitsnivå utan underlag, otestad supportåterställning eller en modell som ensam avgör personens identitet. Blockera produktionssteget och dokumentera vad som behöver lösas.

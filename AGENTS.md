# Arbetsinstruktioner för kodagenter

Repot är en kodbas för iPhone-appen, verifieraren, registret och
SAML-/OIDC-tjänsterna. Läs [README.md](README.md), berörd komponents README,
[arkitekturen](docs/arkitektur.md), [testinstruktionen](docs/testning.md),
[SECURITY.md](SECURITY.md) och [THIRD_PARTY.md](THIRD_PARTY.md) före ändring.

## Arbetsgång

- Utgå från aktuell `main`; följ [utvecklingsinstruktionen](docs/utveckling.md).
- Ändra kod, relevanta tester och tillhörande körinstruktion tillsammans.
- Ange faktisk revision, körda kontroller och kvarstående begränsningar i PR:n.
- Behåll lås, SBOM, licenser och attribution. Verifiera upstream innan versionsbyte.
- Håll dokumentationen till implementation, byggning, testning och drift.
  Arbetsloggar, historiska rapporter, affärsplaner och organisationsunderlag
  hör inte hemma i källträdet. Använd Git-historiken för äldre material.
- Ha en huvudsaklig plats för varje uppgift och länka dit från övriga dokument.
  Skilj källkod, byggd artefakt, installerad app och driftsatt server.

## Säkerhetsgränser

Använd syntetiska identiteter i CI. Publicera aldrig personakter, pass,
biometrik, privata nycklar eller hemligheter. Verkliga handlingar får bara
användas i uttryckligen vald privat testmiljö.

Spärr och återställning får inte kringgås via gamla backuper eller
administrativa genvägar. Testa ändrade tillståndsövergångar. Använd etablerade
kryptografiska bibliotek; generativa modeller får inte avgöra identitet.

En merge eller grön CI är inget produktionsgodkännande. Säkerhetskritisk
produktionsrelease kräver oberoende granskning och behörigt mänskligt beslut.
En agent får inte attestera sin egen release. Ändra inte drift, åtkomst eller
externa avtal som en bieffekt av en kodändring. Ingen force-push utan uttryckligt uppdrag.

## Komponentspecifika instruktioner

Läs relevant fil under `.agents/skills/` när uppgiften berör området:

| Område | Skill |
|---|---|
| Identitet, nycklar, spärr och återställning | `eid-lifecycle-security/SKILL.md` |
| SAML, OIDC, metadata och sessionsbindning | `sweden-connect-integration/SKILL.md` |
| Dokumentunderskrift och validering | `electronic-signatures/SKILL.md` |
| Beroenden, byggkedja och leverans | `supply-chain-and-release/SKILL.md` |

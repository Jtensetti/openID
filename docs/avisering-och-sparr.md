# Oberoende avisering och spärr – teknisk design

Status 2026-10-22: design, inte implementerad eller driftsatt. K6.6 och
K6.8 kvarstår OPEN. Ingen ny molntjänst eller leveranskanal beställs.

## Oberoende avisering

En adress som angriparen anger under samma passregistrering är inte i sig
oberoende. Innan implementation behöver kontaktens ursprung beslutas:
exempelvis separat verifierad befintlig kontakt eller registerstödd kanal.
E-postleveransens lämplighet och kontaktbindningen ska riskbedömas; ett
SMTP-svar eller en öppningspixel styrker inte att rätt person informerats.

Föreslagen kedja: granskad ansökan → fastställd separat kontakt →
atomiskt utfärdandebeslut och aviseringspost → leverans → verifierad
hantering enligt beslutad policy. Fram till dess kvarstår manuell pilotaktivering.
En ny framtida produktionsaktivering ska stoppas om kontaktbevis eller
nödvändig avisering saknas; inför inte detta utan migration och negativa prov.

Aviseringspost: slumpmässigt händelse-ID, intern credentialreferens,
kontaktversion, mallversion, skapandetid, försökstid och leveransstatus.
Kontaktadress lagras krypterat med begränsad åtkomst. Meddelandet innehåller
produkt, tid och väg till spärrhjälp, inte personnummer, passnummer, bild,
nyckel eller länk som automatiskt godkänner något. Dubbel leverans kan ske
vid nätfel; dubbel utfärdning får aldrig ske. Bytt kontakt får inte omdirigera
redan beslutad avisering utan ny kontroll.

Acceptansprov: saknad kontakt, ändrad kontaktversion, rollback, krasch mellan
beslut och leverans, dubbla jobb, leveransfel, förfalskad kvittens och spärr
under pågående leverans. Loggar får inte innehålla kontaktadresser eller tokens.

## Spärr när verifieraren är stängd

En statisk projektsida kan visas dygnet runt men kan inte ensam ändra
spärrstatus. En e-postlåda tar emot ärenden men bevisar varken identitet,
bemanning eller verkställighet. Vi får inte kalla något av detta en färdig
spärrtjänst. Pilotens 09–17-begränsning ska fortsatt visas.

Alternativ att utreda utan beställning: separat liten beständig spärrtjänst
med autentiserad begäran och strikt separata rättigheter. Den får endast
spärra, aldrig aktivera eller ändra kontakt. Nyckeln till tjänsten och dess
auktoritativa status måste skyddas och återställas utan att spärrar går förlorade.
Gratisnivå hos leverantör är inget bevis på noll framtida kostnad eller SLA.

Alla verifierare och intygskonsumenter måste kontrollera aktuell spärrstatus.
Om status inte kan kontrolleras ska åtkomst nekas. Efter nattstopp måste
spärrar vara synkroniserade innan någon legitimering tillåts. Lokalt cachad
ACTIVE-status får aldrig övertrumfa spärr. En kvittens om mottaget ärende
måste skiljas från bekräftad verkställighet.

Förlorad telefon: separat återkallelsebevis eller annan beslutad autentisering
behövs. Publicera ingen endpoint som spärrar på enbart personnummer eller
namn. Återkallelsebevis ska inte fungera som återställnings-/aktiveringsbevis.
Begränsa försök utan att möjliggöra masspärr eller permanent utelåsning.

Acceptansprov: fel nyckel, replay, dubbel spärr, samtidig legitimering,
förlorad telefon, otillgänglig statuskälla, omstart efter nattspärr,
gammal backup, manipulerad kö, utebliven kvittens och isolerad nätverkspartition.

## Nästa beslut

Kontaktkälla, tillförlitlig leveranskontroll, autentisering utan telefon,
auktoritativ spärrlagring, tjänstens nyckelförvaltning och kostnadsunderlag
måste väljas innan detta blir drift. Befintliga projektverktyg ger åtkomst
men ersätter inte dessa beslut. Organisation och bemanning är separata
förutsättningar som kod inte kan uppfylla.

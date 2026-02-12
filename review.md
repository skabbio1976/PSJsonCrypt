# Code Review - PSJsonCrypt (Re-review)

Datum: 2026-02-12  
Repo: `/home/jok/gitrepos/PSJsonCrypt`  
Granskat: `PSJsonCrypt.psm1`, `README.md`, `tests/robustness.tests.ps1`

## Fynd (prioriterade)

### Inga kritiska/hoga fynd i denna rerun

Tidigare blockerande problem (MAC-bypass, tvetydig key source, osaker default for save/import) ar nu atgardade och verifierade med test.

### 1) [Medium] Import validerar att `items` finns, men inte att typen ar korrekt

**Fil:** `PSJsonCrypt.psm1`  
**Kod:** `Import-JsonCryptStore`

Observation:
- Importen kontrollerar endast att nyckeln `items` existerar.
- Om `items` har fel typ (t.ex. array/string) passerar import, men senare API-anrop kan ge mindre tydliga fel.

Forslag:
- Validera uttryckligen att `items` ar en hashtable/dictionary.
- Returnera tydligt fel direkt i importsteget.

### 2) [Low] Nyckelmaterial nollställs inte explicit efter användning

**Fil:** `PSJsonCrypt.psm1`  
**Kod:** `Invoke-Encrypt`, `Invoke-Decrypt`, `Resolve-KeySource`

Observation:
- Resurser (`Dispose`) hanteras bra, men byte-arrayer med hemligt material lever kvar tills GC.

Forslag:
- Overvaga explicit "best effort" nollstallning av temporara arrays med nyckelmaterial efter anvandning.

## Testresultat (ny robusthetssvit)

Ny testsvit skapad: `tests/robustness.tests.ps1`  
Korda testfall: **34**  
Resultat: **34 passerade, 0 failade**

Testerna täcker bl.a.:
- Roundtrip för `-Password`, `-Key`, `-KeyFile`, `-EnvironmentVariable`
- Felhantering: saknad/flera key sources, fel lösenord, tom/saknad/ogiltig MAC
- Envelope-validering: base64-fel, fel längd på `salt`/`iv`/`mac`, saknade fält, fel version
- Store-flöden: explicit mode-krav för save/import, plaintext/encrypted roundtrip, paths med mellanslag
- API-beteende: duplicate/add/get/remove, key-format från `New-JsonCryptKey`
- Stor payload (1 MiB) roundtrip

## Positivt i nuvarande implementation

- Tydlig hardening av envelope-validering före dekryptering.
- Constant-time-jämförelse över fast längd (efter längdvalidering).
- Secure-by-default förbättrat genom explicit mode-krav i save/import.
- Bättre plattformsdetektering i filrättighetsfunktionen.

## Rekommenderade nästa steg

- Lägg testsviten i CI (minst Linux + Windows, PowerShell 7).
- Komplettera med PS 5.1-körning i separat pipeline.
- Lägg till typvalidering av `items` i import för bättre felkvalitet.

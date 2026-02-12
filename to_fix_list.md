# To Fix List - PSJsonCrypt

Prioritetsskala: `P0` (kritisk), `P1` (hog), `P2` (medel), `P3` (lag)

- [x] **P0 - MAC bypass fix i `Invoke-Decrypt`**
  - Faltlangder valideras (`salt=16`, `iv=16`, `mac=32`, `ciphertext>0`)
  - Tom/saknad `mac` nekas
  - Constant-time-jamforelse kor over fast langd
  - Regressionstest finns i `tests/robustness.tests.ps1`

- [x] **P1 - Enforce exakt en nyckelkalla**
  - `Resolve-KeySource` kastar fel vid 0 eller fler an 1 key source
  - Beteende matchar README
  - Testfall finns for 0/1/flera nyckelkallor

- [x] **P1 - Saker default for save/import**
  - `Save-JsonCryptStore` och `Import-JsonCryptStore` kraver explicit mode
  - Ingen implicit plaintext-default langre

- [x] **P2 - Forbattra PowerShell 5.1-kompatibilitet**
  - OS-detektering ar uppdaterad och undviker `$IsLinux/$IsMacOS`-beroende

- [x] **P2 - Hardening av envelope parsing**
  - Parse/base64-fel hanteras med tydliga felmeddelanden
  - Schema-/faltvalidering lagd fore dekryptering

- [x] **P2 - Resurshantering och robusthet**
  - Crypto-objekt hanteras i `try/finally`

- [x] **P2 - Typvalidering av importerad store-struktur**
  - `Import-JsonCryptStore` validerar att `items` ar hashtable (string/array/number/null/boolean nekas)
  - `ConvertTo-Hashtable` hanterar null-properties utan Mandatory-bindningsfel
  - Tydligt felmeddelande: `"items" must be an object`
  - Regressionstest i `tests/edge-cases.tests.ps1` och `tests/security.tests.ps1`

- [x] **P2 - Strikt version-typkontroll i envelope**
  - `Invoke-Decrypt` kraver att `version` ar integer (`[int]`/`[long]`), inte string/float/bool/array
  - Forhindrar typforvirring via PowerShells losa jamforelse
  - Regressionstest i `tests/security.tests.ps1` (type confusion-sektionen)

- [ ] **P3 - Kvalitet och CI**
  - Koppla testsviter (`robustness`, `edge-cases`, `security`) till CI
  - Lagg till ScriptAnalyzer i CI
  - Testmatrix: PS 5.1 + PS 7 (Windows/Linux)

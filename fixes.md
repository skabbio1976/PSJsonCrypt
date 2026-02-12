# Fix List - PSJsonCrypt

Priority scale: `P0` (critical), `P1` (high), `P2` (medium), `P3` (low)

- [x] **P0 - MAC bypass fix in `Invoke-Decrypt`**
  - Field lengths validated (`salt=16`, `iv=16`, `mac=32`, `ciphertext>0`)
  - Empty/missing `mac` rejected
  - Constant-time comparison runs over fixed length
  - Regression tests in `tests/robustness.tests.ps1`

- [x] **P1 - Enforce exactly one key source**
  - `Resolve-KeySource` throws on 0 or more than 1 key source
  - Behavior matches README
  - Test cases for 0/1/multiple key sources

- [x] **P1 - Secure default for save/import**
  - `Save-JsonCryptStore` and `Import-JsonCryptStore` require explicit mode
  - No implicit plaintext default

- [x] **P2 - Improve PowerShell 5.1 compatibility**
  - OS detection updated to avoid `$IsLinux/$IsMacOS` dependency

- [x] **P2 - Hardening of envelope parsing**
  - Parse/base64 errors handled with clear error messages
  - Schema/field validation added before decryption

- [x] **P2 - Resource handling and robustness**
  - Crypto objects managed in `try/finally`

- [x] **P2 - Type validation of imported store structure**
  - `Import-JsonCryptStore` validates that `items` is a hashtable (string/array/number/null/boolean rejected)
  - `ConvertTo-Hashtable` handles null properties without Mandatory parameter binding errors
  - Clear error message: `"items" must be an object`
  - Regression tests in `tests/edge-cases.tests.ps1` and `tests/security.tests.ps1`

- [x] **P2 - Strict version type check in envelope**
  - `Invoke-Decrypt` requires `version` to be integer (`[int]`/`[long]`), not string/float/bool/array
  - Prevents type confusion via PowerShell's loose comparison
  - Regression tests in `tests/security.tests.ps1` (type confusion section)

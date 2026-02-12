# Security Audit - PSJsonCrypt

**Date:** 2026-02-12
**Auditor:** Security review (automated + manual analysis)
**Scope:** `PSJsonCrypt.psm1` - cryptographic operations, input validation, error handling
**Module version:** Envelope v1, AES-256-CBC + HMAC-SHA256 + PBKDF2-SHA256

---

## Executive Summary

The module demonstrates solid cryptographic design: Encrypt-then-MAC with constant-time
comparison, PBKDF2 with 600,000 iterations, proper field-length validation before
cryptographic operations, and generic error messages that do not leak padding oracle
information. The primary findings are input validation gaps (not cryptographic breaks)
and one defense-in-depth concern around key material lifecycle.

---

## Findings

### Finding 1: Loose version check accepts non-integer types

**Severity:** Low
**Location:** `PSJsonCrypt.psm1`, lines 134-137 (`Invoke-Decrypt`)
**Code:**
```powershell
$versionProp = $envelope.PSObject.Properties['version']
if ($null -eq $versionProp -or $versionProp.Value -ne 1) {
    throw "Unsupported or missing envelope version."
}
```

**Description:**
PowerShell's `-ne` operator performs type coercion. The version check `$versionProp.Value -ne 1`
accepts any value that PowerShell considers equal to integer 1, including:
- String `"1"` (type confusion from JSON manipulation)
- Float `1.0`
- Boolean `true` (since `[bool]$true -eq 1` in PowerShell)
- Array `[1]` (PowerShell tests if array *contains* matching element)

**Impact:** An attacker cannot exploit this for privilege escalation or decryption bypass since
the version field is not used in cryptographic operations. However, it weakens schema validation
and could mask malformed envelopes. The array case (`[1]`) is particularly concerning as it
represents a significant schema deviation that should be rejected.

**Proof:** Tested with `'{"version":"1",...}'`, `'{"version":true,...}'`, and
`'{"version":[1],...}'` -- all decrypt successfully.

**Suggested fix:**
```powershell
if ($null -eq $versionProp -or $versionProp.Value -isnot [int] -or $versionProp.Value -ne 1) {
    throw "Unsupported or missing envelope version."
}
```
Note: `ConvertFrom-Json` parses JSON integer `1` as `[int64]` or `[int]` depending on
PowerShell version. A more robust check would be:
```powershell
if ($null -eq $versionProp -or $versionProp.Value -isnot [System.ValueType] -or
    $versionProp.Value -isnot [long] -and $versionProp.Value -isnot [int] -or
    $versionProp.Value -ne 1) {
```

---

### Finding 2: Import validates `items` key existence but not its type

**Severity:** Medium
**Location:** `PSJsonCrypt.psm1`, lines 468-471 (`Import-JsonCryptStore`)
**Code:**
```powershell
if (-not $store.ContainsKey('items')) {
    throw 'Invalid store format: missing "items" key.'
}
```

**Description:**
After `ConvertTo-Hashtable` converts the parsed JSON, the import only checks that a key
named `items` exists. It does not verify that `items` is a hashtable/dictionary. If a
malformed or tampered store file has `items` set to a string, array, number, or null,
the import succeeds but subsequent API calls (`Add-JsonCryptItem`, `Get-JsonCryptItem`,
`Remove-JsonCryptItem`, `Get-JsonCryptItemNames`) fail with confusing .NET method-resolution
errors like *"Method invocation failed because [System.String] does not contain a method
named 'ContainsKey'"*.

**Impact:** This is a data integrity and usability issue. For encrypted stores, the attacker
would need to know the key to inject a malformed payload, limiting exploitability. For
plaintext stores, a corrupted file could cause confusing downstream errors.

**Proof:** Importing `{"items":"not-a-dict"}` as plaintext succeeds, but
`Get-JsonCryptItem -Store $store -Name "test"` throws a .NET method error.

**Suggested fix:**
```powershell
if (-not $store.ContainsKey('items') -or $store.items -isnot [hashtable]) {
    throw 'Invalid store format: "items" must be a JSON object (hashtable).'
}
```

---

### Finding 3: Key material byte arrays not zeroed after use

**Severity:** Low (defense-in-depth)
**Location:** `PSJsonCrypt.psm1`, lines 69-71 (`Invoke-Encrypt`), lines 178-180 (`Invoke-Decrypt`),
and line 31/32/37/41/48 (`Resolve-KeySource`)

**Description:**
The following byte arrays contain sensitive key material and are never explicitly zeroed:
- `$keyMaterial` (64 bytes: AES key + HMAC key)
- `$aesKey` (32 bytes)
- `$hmacKey` (32 bytes)
- `$SecretBytes` / return value from `Resolve-KeySource`
- `$plaintextBytes` (in `Invoke-Encrypt`, line 85)

These arrays remain in managed memory until garbage collected. In PowerShell, the slice
syntax `$keyMaterial[0..31]` creates new `[object[]]` arrays (not `[byte[]]`), which are
even harder to track and zero.

**Impact:** In a memory-dump or cold-boot attack scenario, key material could be recovered.
This is standard for managed-language cryptography but worth noting for high-security
deployments.

**Suggested fix:**
Add best-effort zeroing in `finally` blocks:
```powershell
finally {
    if ($keyMaterial) { [System.Array]::Clear($keyMaterial, 0, $keyMaterial.Length) }
    if ($aesKey)      { [System.Array]::Clear($aesKey, 0, $aesKey.Length) }
    if ($hmacKey)     { [System.Array]::Clear($hmacKey, 0, $hmacKey.Length) }
    # ... existing Dispose calls ...
}
```

---

### Finding 4: No ciphertext block-alignment validation before MAC

**Severity:** Informational
**Location:** `PSJsonCrypt.psm1`, lines 168-170 (`Invoke-Decrypt`)

**Description:**
The ciphertext length is validated to be non-zero (line 168-170) but is not checked
to be a multiple of 16 bytes (AES block size). A non-block-aligned ciphertext will
always fail MAC verification (since the MAC covers the ciphertext), so this is not
exploitable. However, adding an explicit check would provide a clearer error message
and reject malformed data earlier.

**Impact:** None -- the MAC check catches this. The error message is
"MAC verification failed" which is the correct generic message and does not leak
information about block alignment.

**Suggested fix (optional):**
```powershell
if ($ciphertext.Length -eq 0 -or $ciphertext.Length % 16 -ne 0) {
    throw "Invalid envelope: ciphertext length is invalid."
}
```

---

### Finding 5: Extra envelope fields are silently ignored

**Severity:** Informational
**Location:** `PSJsonCrypt.psm1`, lines 139-145 (`Invoke-Decrypt`)

**Description:**
The envelope parser validates the presence of `version`, `salt`, `iv`, `ciphertext`,
and `mac` but does not reject envelopes containing additional unexpected fields. An
envelope like `{"version":1,...,"extra":"data"}` is accepted.

**Impact:** This follows the robustness principle (be liberal in what you accept) and
does not create a security vulnerability since extra fields are not used in any
cryptographic operation. However, strict schema validation could detect envelope
tampering or corruption earlier.

---

### Finding 6: Duplicate JSON keys resolved by PowerShell parser (last-wins)

**Severity:** Informational
**Location:** Implicit -- relies on `ConvertFrom-Json` behavior (line 127)

**Description:**
When JSON input contains duplicate keys (e.g.,
`{"version":1,"salt":"...","version":999}`), PowerShell's `ConvertFrom-Json` uses
the last occurrence. This is standard JSON parser behavior (RFC 8259 says duplicate
keys produce "unpredictable" behavior) but could theoretically be used to craft
envelopes that bypass validation when processed by a different parser that takes
the first occurrence.

**Impact:** Not directly exploitable since the module consistently uses a single
parser. This is a general interoperability concern, not a vulnerability.

---

### Finding 7: Padding oracle protection is correctly implemented

**Severity:** Positive finding (no vulnerability)
**Location:** `PSJsonCrypt.psm1`, lines 190-197 (`Invoke-Decrypt`)

**Description:**
The Encrypt-then-MAC construction ensures that:
1. MAC verification happens *before* any decryption attempt (line 195 vs line 208).
2. MAC failure produces a generic message: "MAC verification failed. Wrong password/key
   or corrupted data." (line 196).
3. Decryption (including PKCS7 unpadding) only occurs after MAC passes (line 208).
4. The constant-time comparison iterates over all 32 bytes regardless of mismatch position.

This correctly prevents padding oracle attacks. An attacker who tampers with ciphertext
(to probe padding) will always hit the MAC check first and receive only the generic
MAC failure message.

**Verification:** Tested by flipping bits in ciphertext -- all produce "MAC verification
failed" errors, never padding-related errors.

---

### Finding 8: `ConvertTo-Hashtable` performance with deeply nested or large arrays

**Severity:** Low (DoS potential with crafted input)
**Location:** `PSJsonCrypt.psm1`, lines 221-247 (`ConvertTo-Hashtable`)

**Description:**
The recursive `ConvertTo-Hashtable` function uses `$list += (...)` in a loop (line 233),
which creates a new array on every iteration. For a JSON array with N elements, this
results in O(N^2) memory allocation. Additionally, there is no recursion depth limit,
so deeply nested JSON could cause a stack overflow.

For encrypted stores, the attacker would need to know the encryption key to inject
such a payload. For plaintext stores, a malicious file could trigger excessive resource
consumption.

**Impact:** Low -- requires either key knowledge (encrypted) or file write access
(plaintext). Not a realistic attack vector for most threat models.

---

### Finding 9: `chmod` return code not checked on Unix

**Severity:** Low
**Location:** `PSJsonCrypt.psm1`, line 262 (`Set-SecureFilePermission`)

**Code:**
```powershell
chmod 600 $Path
```

**Description:**
The external `chmod` command's exit code is not validated. If `chmod` fails (e.g.,
the file is on a filesystem that does not support Unix permissions, or the user does
not own the file), the error is silently ignored and the file remains with its
original permissions.

**Suggested fix:**
```powershell
$result = chmod 600 $Path 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Failed to set file permissions on '$Path': $result"
}
```

---

### Finding 10: Password/Key as `[string]` parameter -- empty string handling

**Severity:** Informational
**Location:** `PSJsonCrypt.psm1`, lines 8-49 (`Resolve-KeySource`)

**Description:**
The key source parameters are typed as `[string]`. In PowerShell, an empty string
`""` is falsy, so `if ($Password) { $count++ }` evaluates to `$false` for empty
strings. This means passing `-Password ""` is equivalent to not passing `-Password`
at all. This is arguably correct behavior (rejecting empty passwords) but is implicit
rather than explicit. A user passing `-Password ""` would get "No key source specified"
rather than "Password cannot be empty".

---

## Summary Table

| # | Severity      | Finding                                       | Exploitable? |
|---|---------------|-----------------------------------------------|--------------|
| 1 | Low           | Loose version type check                      | No           |
| 2 | Medium        | Import accepts non-dict `items`               | Limited      |
| 3 | Low           | Key material not zeroed                        | Memory dump  |
| 4 | Informational | No ciphertext block-alignment check           | No (MAC)     |
| 5 | Informational | Extra envelope fields ignored                 | No           |
| 6 | Informational | Duplicate JSON keys (last-wins)               | No           |
| 7 | Positive      | Padding oracle correctly mitigated            | N/A          |
| 8 | Low           | ConvertTo-Hashtable O(N^2) for arrays         | DoS only     |
| 9 | Low           | chmod return code not checked                 | Perm leak    |
|10 | Informational | Empty password implicitly rejected             | No           |

---

## Cryptographic Assessment

**PBKDF2 parameters:** 600,000 iterations of SHA-256 is above the 2023 OWASP minimum
(600,000) and adequate for 2026. The 16-byte salt provides sufficient uniqueness.

**AES-256-CBC + HMAC-SHA256:** The Encrypt-then-MAC construction is correctly
implemented. The MAC covers `salt || iv || ciphertext`, which binds all variable
envelope components to the MAC. The version field is NOT covered by the MAC, but
since it is validated before use and does not influence cryptographic operations,
this is acceptable.

**Constant-time comparison:** The XOR-accumulate loop over a fixed 32 bytes (after
length validation) is correct and does not leak timing information about which byte
differs.

**Random number generation:** Uses `RandomNumberGenerator.Create()` which provides
cryptographically secure randomness on all supported platforms.

---

## Test Coverage

A comprehensive security-focused test suite has been added at
`tests/security.tests.ps1` covering all findings above plus additional attack vectors.

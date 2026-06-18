# PSJsonCrypt

Encrypted JSON key-value storage for PowerShell. Store credentials and configuration securely in a single encrypted file.

Inspired by [jsoncrypt](https://github.com/skabbio1976/jsoncrypt) (Go), ported to a standalone PowerShell module.

## Features

- Single `.psm1` file, no external dependencies
- Works on PowerShell 5.1+ and PowerShell 7+
- Cross-platform: Windows, Linux, macOS
- AES-256-CBC with HMAC-SHA256 (Encrypt-then-MAC)
- PBKDF2-SHA256 key derivation (600,000 iterations)
- Automatic restrictive file permissions on saved stores
- Four key sources: password, key string, key file, environment variable
- Three storage formats: JSON (default), INI, and TOML — auto-detected by file extension

## Requirements

- PowerShell 5.1+ or PowerShell 7+
- .NET Framework 4.7.2+ (Windows) for `Rfc2898DeriveBytes` with SHA256 — included in Windows 10 1803+

## Installation

Copy `PSJsonCrypt.psm1` into your project or module path:

```powershell
Import-Module ./PSJsonCrypt.psm1
```

## Quick start

```powershell
Import-Module ./PSJsonCrypt.psm1

# Create a store and add items
$store = New-JsonCryptStore
Add-JsonCryptItem -Store $store -Name "prod" -Item @{
    host     = "db.prod.example.com"
    username = "admin"
    password = "s3cret"
}

# Save encrypted
Save-JsonCryptStore -Store $store -Path "./secrets.enc" -Password "master-password"

# Load it back
$loaded = Import-JsonCryptStore -Path "./secrets.enc" -Password "master-password"
$loaded.items.prod.password   # → s3cret
```

## Key sources

Every command that performs encryption/decryption requires exactly one key source. Providing zero or multiple key sources throws an error:

| Parameter | Description |
|-----------|-------------|
| `-Password <string>` | Inline password |
| `-Key <string>` | Direct secret string |
| `-KeyFile <string>` | Path to a file containing the secret (whitespace trimmed) |
| `-EnvironmentVariable <string>` | Name of an environment variable holding the secret |

```powershell
# Key file
$enc = Protect-JsonCryptString -Plaintext "secret" -KeyFile "./keyfile.txt"

# Environment variable
$env:APP_KEY = "my-key"
$enc = Protect-JsonCryptString -Plaintext "secret" -EnvironmentVariable "APP_KEY"
```

## Functions

### Store operations

```powershell
New-JsonCryptStore                                         # → @{ items = @{} }
Add-JsonCryptItem    -Store $s -Name "myitem" -Item $obj   # add (throws if exists)
Get-JsonCryptItem    -Store $s -Name "myitem"              # get (throws if missing)
Remove-JsonCryptItem -Store $s -Name "myitem"              # remove (throws if missing)
Get-JsonCryptItemNames -Store $s                           # → @("myitem", ...)
```

### String encryption

```powershell
$encrypted = Protect-JsonCryptString   -Plaintext "hello" -Password "pass"
$decrypted = Unprotect-JsonCryptString -EncryptedString $encrypted -Password "pass"
```

### Store persistence

You must explicitly choose either a key source or `-Plaintext`. Omitting both is an error (secure by default).

```powershell
# Encrypted
Save-JsonCryptStore   -Store $s -Path "./data.enc" -Password "pass"
$s = Import-JsonCryptStore -Path "./data.enc" -Password "pass"

# Plaintext (explicit opt-in, no encryption)
Save-JsonCryptStore   -Store $s -Path "./data.json" -Plaintext
$s = Import-JsonCryptStore -Path "./data.json" -Plaintext
```

### Storage formats (JSON / INI / TOML)

Stores can be serialized as JSON (default), INI, or TOML. The format is detected
automatically from the file extension (`.ini` → INI, `.toml` → TOML, anything else
→ JSON), or set explicitly with `-Format`. Format selection is independent of
encryption — any format can be saved encrypted or as `-Plaintext`.

```powershell
# Auto-detected from the extension
Save-JsonCryptStore   -Store $s -Path "./secrets.toml" -Password "pass"
$s = Import-JsonCryptStore -Path "./secrets.toml" -Password "pass"

Save-JsonCryptStore   -Store $s -Path "./secrets.ini" -Plaintext
$s = Import-JsonCryptStore -Path "./secrets.ini" -Plaintext

# Force a format regardless of extension
Save-JsonCryptStore   -Store $s -Path "./data.bin" -Password "pass" -Format Toml
$s = Import-JsonCryptStore -Path "./data.bin" -Password "pass" -Format Toml
```

A store is written as nested tables/sections keyed by item name. For example, a
store with an item `prod = @{ host = "db.example.com"; port = 5432 }` serializes to:

```toml
[items.prod]
host = "db.example.com"
port = 5432
```

```ini
[items.prod]
host = db.example.com
port = 5432
```

**Format notes:**

- **JSON** — full fidelity; the only format used for the encrypted envelope itself.
- **TOML** — preserves strings, integers, floats, booleans, and arrays of scalars.
  `null` is written as an empty string (TOML has no null).
- **INI** — an untyped format: every value is read back as a string (e.g. `5432`
  becomes `"5432"`, `true` becomes `"true"`). Arrays are joined with `, `. Use INI
  only when string values are sufficient. Lines beginning with `;` or `#` are
  treated as comments.

### Key generation

```powershell
$key = New-JsonCryptKey   # → 64-char hex string (32 random bytes)
```

## Cryptographic design

| Component | Algorithm |
|-----------|-----------|
| Key derivation | PBKDF2-HMAC-SHA256, 600,000 iterations |
| Encryption | AES-256-CBC with PKCS7 padding |
| Authentication | HMAC-SHA256 (Encrypt-then-MAC) |
| Salt | 16 random bytes |
| IV | 16 random bytes |
| Derived key | 64 bytes (32 AES + 32 HMAC) |

### Encrypted envelope format

```json
{
  "version": 1,
  "salt": "<base64>",
  "iv": "<base64>",
  "ciphertext": "<base64>",
  "mac": "<base64>"
}
```

The MAC covers `salt + iv + ciphertext` and is verified with constant-time comparison before decryption.

## File permissions

`Save-JsonCryptStore` automatically sets restrictive permissions on the output file:

- **Linux/macOS**: `chmod 600` (owner read/write only)
- **Windows**: ACL with `FullControl` for current user only, inheritance disabled

## License

MIT

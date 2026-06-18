#requires -Version 5.1
Set-StrictMode -Version Latest

# ────────────────────────────────────────────────────────────────
# [1] Private helper functions
# ────────────────────────────────────────────────────────────────

function Resolve-KeySource {
    [CmdletBinding()]
    param(
        [string]$Password,
        [string]$Key,
        [string]$KeyFile,
        [string]$EnvironmentVariable
    )

    # Enforce exactly one key source
    $count = 0
    if ($Password)            { $count++ }
    if ($Key)                 { $count++ }
    if ($KeyFile)             { $count++ }
    if ($EnvironmentVariable) { $count++ }

    if ($count -eq 0) {
        throw 'No key source specified. Use -Password, -Key, -KeyFile, or -EnvironmentVariable.'
    }
    if ($count -gt 1) {
        throw 'Multiple key sources specified. Provide exactly one of -Password, -Key, -KeyFile, or -EnvironmentVariable.'
    }

    if ($Password) { return [System.Text.Encoding]::UTF8.GetBytes($Password) }
    if ($Key)      { return [System.Text.Encoding]::UTF8.GetBytes($Key) }
    if ($KeyFile) {
        if (-not (Test-Path -LiteralPath $KeyFile)) {
            throw "KeyFile not found: $KeyFile"
        }
        $content = (Get-Content -LiteralPath $KeyFile -Raw).Trim()
        if ([string]::IsNullOrEmpty($content)) {
            throw "KeyFile is empty: $KeyFile"
        }
        return [System.Text.Encoding]::UTF8.GetBytes($content)
    }
    # EnvironmentVariable
    $val = [System.Environment]::GetEnvironmentVariable($EnvironmentVariable)
    if ([string]::IsNullOrEmpty($val)) {
        throw "Environment variable '$EnvironmentVariable' is not set or empty."
    }
    return [System.Text.Encoding]::UTF8.GetBytes($val)
}

function Invoke-Encrypt {
    [CmdletBinding()]
    param(
        [byte[]]$SecretBytes,
        [string]$Plaintext
    )

    $rng = $pbkdf2 = $aes = $encryptor = $hmac = $null
    try {
        # 1. Generate 16-byte salt
        $salt = New-Object byte[] 16
        $rng  = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $rng.GetBytes($salt)

        # 2. PBKDF2-SHA256 → 64 bytes (32 AES + 32 HMAC)
        $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
            $SecretBytes, $salt, 600000, [System.Security.Cryptography.HashAlgorithmName]::SHA256
        )
        $keyMaterial = $pbkdf2.GetBytes(64)
        $aesKey  = $keyMaterial[0..31]
        $hmacKey = $keyMaterial[32..63]

        # 3. Generate 16-byte IV
        $iv = New-Object byte[] 16
        $rng.GetBytes($iv)

        # 4. AES-256-CBC-PKCS7 encrypt
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.KeySize = 256
        $aes.Key     = [byte[]]$aesKey
        $aes.IV      = [byte[]]$iv

        $plaintextBytes = [System.Text.Encoding]::UTF8.GetBytes($Plaintext)
        $encryptor  = $aes.CreateEncryptor()
        $ciphertext = $encryptor.TransformFinalBlock($plaintextBytes, 0, $plaintextBytes.Length)

        # 5. HMAC-SHA256(hmacKey, salt + iv + ciphertext)
        $hmac = New-Object System.Security.Cryptography.HMACSHA256(,[byte[]]$hmacKey)
        $dataToMac = New-Object byte[] ($salt.Length + $iv.Length + $ciphertext.Length)
        [System.Buffer]::BlockCopy($salt,       0, $dataToMac, 0,                            $salt.Length)
        [System.Buffer]::BlockCopy($iv,         0, $dataToMac, $salt.Length,                  $iv.Length)
        [System.Buffer]::BlockCopy($ciphertext, 0, $dataToMac, $salt.Length + $iv.Length,     $ciphertext.Length)
        $mac = $hmac.ComputeHash($dataToMac)

        # 6. Build envelope
        $envelope = [ordered]@{
            version    = [int]1
            salt       = [System.Convert]::ToBase64String($salt)
            iv         = [System.Convert]::ToBase64String($iv)
            ciphertext = [System.Convert]::ToBase64String($ciphertext)
            mac        = [System.Convert]::ToBase64String($mac)
        }

        # 7. Return compressed JSON
        return ($envelope | ConvertTo-Json -Compress)
    }
    finally {
        if ($encryptor) { $encryptor.Dispose() }
        if ($aes)       { $aes.Dispose() }
        if ($hmac)      { $hmac.Dispose() }
        if ($pbkdf2)    { $pbkdf2.Dispose() }
        if ($rng)       { $rng.Dispose() }
    }
}

function Invoke-Decrypt {
    [CmdletBinding()]
    param(
        [byte[]]$SecretBytes,
        [string]$EncryptedString
    )

    # 1. Parse JSON envelope
    try {
        $envelope = $EncryptedString | ConvertFrom-Json
    }
    catch {
        throw 'Invalid encrypted data: not valid JSON.'
    }

    # 2. Validate version (strict: must be integer 1, not "1", 1.0, true, etc.)
    $versionProp = $envelope.PSObject.Properties['version']
    if ($null -eq $versionProp -or
        ($versionProp.Value -isnot [int] -and $versionProp.Value -isnot [long]) -or
        $versionProp.Value -ne 1) {
        throw "Unsupported or missing envelope version."
    }

    # 3. Validate required fields exist and are non-empty strings
    foreach ($field in @('salt', 'iv', 'ciphertext', 'mac')) {
        $prop = $envelope.PSObject.Properties[$field]
        if ($null -eq $prop -or $null -eq $prop.Value -or $prop.Value -isnot [string] -or $prop.Value.Length -eq 0) {
            throw "Invalid envelope: missing or empty '$field' field."
        }
    }

    # 4. Base64-decode all fields with error handling
    try {
        $salt       = [System.Convert]::FromBase64String($envelope.salt)
        $iv         = [System.Convert]::FromBase64String($envelope.iv)
        $ciphertext = [System.Convert]::FromBase64String($envelope.ciphertext)
        $mac        = [System.Convert]::FromBase64String($envelope.mac)
    }
    catch {
        throw 'Invalid envelope: one or more fields contain invalid base64.'
    }

    # 5. Validate field lengths
    if ($salt.Length -ne 16) {
        throw "Invalid envelope: salt must be 16 bytes, got $($salt.Length)."
    }
    if ($iv.Length -ne 16) {
        throw "Invalid envelope: iv must be 16 bytes, got $($iv.Length)."
    }
    if ($mac.Length -ne 32) {
        throw "Invalid envelope: mac must be 32 bytes, got $($mac.Length)."
    }
    if ($ciphertext.Length -eq 0) {
        throw "Invalid envelope: ciphertext is empty."
    }

    $pbkdf2 = $hmacObj = $aes = $decryptor = $null
    try {
        # 6. PBKDF2-SHA256 → aesKey + hmacKey
        $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
            $SecretBytes, $salt, 600000, [System.Security.Cryptography.HashAlgorithmName]::SHA256
        )
        $keyMaterial = $pbkdf2.GetBytes(64)
        $aesKey  = $keyMaterial[0..31]
        $hmacKey = $keyMaterial[32..63]

        # 7. Compute expected MAC
        $hmacObj = New-Object System.Security.Cryptography.HMACSHA256(,[byte[]]$hmacKey)
        $dataToMac = New-Object byte[] ($salt.Length + $iv.Length + $ciphertext.Length)
        [System.Buffer]::BlockCopy($salt,       0, $dataToMac, 0,                            $salt.Length)
        [System.Buffer]::BlockCopy($iv,         0, $dataToMac, $salt.Length,                  $iv.Length)
        [System.Buffer]::BlockCopy($ciphertext, 0, $dataToMac, $salt.Length + $iv.Length,     $ciphertext.Length)
        $expectedMac = $hmacObj.ComputeHash($dataToMac)

        # 8. Constant-time comparison over fixed 32-byte length
        $diff = 0
        for ($i = 0; $i -lt 32; $i++) {
            $diff = $diff -bor ($mac[$i] -bxor $expectedMac[$i])
        }
        if ($diff -ne 0) {
            throw 'MAC verification failed. Wrong password/key or corrupted data.'
        }

        # 9. AES-256-CBC-PKCS7 decrypt
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.KeySize = 256
        $aes.Key     = [byte[]]$aesKey
        $aes.IV      = [byte[]]$iv

        $decryptor      = $aes.CreateDecryptor()
        $plaintextBytes = $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)

        # 10. Return UTF-8 string
        return [System.Text.Encoding]::UTF8.GetString($plaintextBytes)
    }
    finally {
        if ($decryptor) { $decryptor.Dispose() }
        if ($aes)       { $aes.Dispose() }
        if ($hmacObj)   { $hmacObj.Dispose() }
        if ($pbkdf2)    { $pbkdf2.Dispose() }
    }
}

function ConvertTo-Hashtable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        $InputObject
    )

    if ($null -eq $InputObject) { return $null }

    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        $list = @()
        foreach ($item in $InputObject) {
            $list += (ConvertTo-Hashtable -InputObject $item)
        }
        return ,$list
    }

    if ($InputObject -is [PSCustomObject]) {
        $ht = @{}
        foreach ($prop in $InputObject.PSObject.Properties) {
            if ($null -eq $prop.Value) {
                $ht[$prop.Name] = $null
            }
            else {
                $ht[$prop.Name] = ConvertTo-Hashtable -InputObject $prop.Value
            }
        }
        return $ht
    }

    return $InputObject
}

function Set-SecureFilePermission {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $isUnix = ($PSVersionTable.PSEdition -eq 'Core') -and
              (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
                  [System.Runtime.InteropServices.OSPlatform]::Windows))

    if ($isUnix) {
        # PS 7+ on Linux/macOS
        chmod 600 $Path
    }
    else {
        # Windows (PS 5.1 Desktop + PS 7 Core on Windows)
        $acl  = New-Object System.Security.AccessControl.FileSecurity
        $acl.SetAccessRuleProtection($true, $false)   # disable inheritance, remove inherited rules
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $identity,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $Path -AclObject $acl
    }
}

# ────────────────────────────────────────────────────────────────
# [1b] Format serialization (JSON / INI / TOML)
# ────────────────────────────────────────────────────────────────

function Resolve-StoreFormat {
    [CmdletBinding()]
    param(
        [string]$Format,
        [string]$Path
    )

    if ($Format) { return $Format }

    $ext = [System.IO.Path]::GetExtension($Path)
    if ($ext) { $ext = $ext.ToLowerInvariant() }
    switch ($ext) {
        '.ini'  { return 'Ini' }
        '.toml' { return 'Toml' }
        default { return 'Json' }
    }
}

function Test-IsTableValue {
    param($Value)
    return ($Value -is [System.Collections.IDictionary]) -or ($Value -is [PSCustomObject])
}

function Get-TableEntry {
    # Normalizes IDictionary / PSCustomObject into an ordered list of @{ Key; Value }
    param($Table)

    $entries = @()
    if ($Table -is [System.Collections.IDictionary]) {
        foreach ($k in $Table.Keys) {
            $entries += [pscustomobject]@{ Key = [string]$k; Value = $Table[$k] }
        }
    }
    elseif ($Table -is [PSCustomObject]) {
        foreach ($p in $Table.PSObject.Properties) {
            $entries += [pscustomobject]@{ Key = $p.Name; Value = $p.Value }
        }
    }
    return ,$entries
}

# ---- TOML ----------------------------------------------------------

function Format-TomlString {
    param([string]$Value)
    $s = $Value.Replace('\', '\\').Replace('"', '\"').
        Replace("`b", '\b').Replace("`t", '\t').Replace("`n", '\n').
        Replace("`f", '\f').Replace("`r", '\r')
    return '"' + $s + '"'
}

function Format-TomlKey {
    param([string]$Key)
    if ($Key -match '^[A-Za-z0-9_-]+$' -and $Key.Length -gt 0) { return $Key }
    return (Format-TomlString -Value $Key)
}

function Format-TomlValue {
    param($Value)

    if ($null -eq $Value) { return '""' }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [int16] -or
        $Value -is [byte] -or $Value -is [sbyte] -or $Value -is [uint16] -or
        $Value -is [uint32]) {
        return [string]([long]$Value)
    }
    if ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal]) {
        return ([double]$Value).ToString([System.Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $parts = @()
        foreach ($v in $Value) { $parts += (Format-TomlValue -Value $v) }
        return '[' + ($parts -join ', ') + ']'
    }
    return (Format-TomlString -Value ([string]$Value))
}

function Write-TomlTable {
    param(
        [System.Text.StringBuilder]$Sb,
        $Table,
        [string[]]$Path
    )

    $entries    = Get-TableEntry -Table $Table
    $scalars    = @($entries | Where-Object { -not (Test-IsTableValue -Value $_.Value) })
    $subtables  = @($entries | Where-Object {      (Test-IsTableValue -Value $_.Value) })
    $isEmpty    = ($entries.Count -eq 0)

    if ($Path.Count -gt 0 -and ($scalars.Count -gt 0 -or $isEmpty)) {
        $header = ($Path | ForEach-Object { Format-TomlKey -Key $_ }) -join '.'
        [void]$Sb.AppendLine('[' + $header + ']')
    }
    foreach ($e in $scalars) {
        [void]$Sb.AppendLine((Format-TomlKey -Key $e.Key) + ' = ' + (Format-TomlValue -Value $e.Value))
    }
    if ($scalars.Count -gt 0) { [void]$Sb.AppendLine('') }
    foreach ($e in $subtables) {
        Write-TomlTable -Sb $Sb -Table $e.Value -Path ($Path + $e.Key)
    }
}

function ConvertTo-TomlString {
    param($InputObject)
    $sb = New-Object System.Text.StringBuilder
    Write-TomlTable -Sb $sb -Table $InputObject -Path @()
    return $sb.ToString().TrimEnd("`r", "`n")
}

function ConvertFrom-TomlBasicString {
    # $Token must start with a double-quote; reads up to the closing quote.
    param([string]$Token)
    $sb = New-Object System.Text.StringBuilder
    $i = 1
    while ($i -lt $Token.Length) {
        $c = $Token[$i]
        if ($c -eq '\' -and ($i + 1) -lt $Token.Length) {
            $n = $Token[$i + 1]
            switch ($n) {
                '"'     { [void]$sb.Append('"') }
                '\'     { [void]$sb.Append('\') }
                'n'     { [void]$sb.Append("`n") }
                't'     { [void]$sb.Append("`t") }
                'r'     { [void]$sb.Append("`r") }
                'b'     { [void]$sb.Append([char]8) }
                'f'     { [void]$sb.Append([char]12) }
                default { [void]$sb.Append($n) }
            }
            $i += 2
            continue
        }
        if ($c -eq '"') { break }
        [void]$sb.Append($c)
        $i++
    }
    return $sb.ToString()
}

function Split-TomlList {
    # Splits on top-level commas, respecting quotes and nested brackets.
    param([string]$Inner)
    $parts = @()
    $depth = 0
    $inStr = $false
    $cur = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $Inner.Length; $i++) {
        $c = $Inner[$i]
        if ($inStr) {
            [void]$cur.Append($c)
            if ($c -eq '\' -and ($i + 1) -lt $Inner.Length) { [void]$cur.Append($Inner[$i + 1]); $i++; continue }
            if ($c -eq '"') { $inStr = $false }
            continue
        }
        if ($c -eq '"') { $inStr = $true; [void]$cur.Append($c); continue }
        if ($c -eq '[') { $depth++; [void]$cur.Append($c); continue }
        if ($c -eq ']') { $depth--; [void]$cur.Append($c); continue }
        if ($c -eq ',' -and $depth -eq 0) { $parts += $cur.ToString(); $cur = New-Object System.Text.StringBuilder; continue }
        [void]$cur.Append($c)
    }
    if ($cur.ToString().Trim().Length -gt 0) { $parts += $cur.ToString() }
    return ,$parts
}

function ConvertFrom-TomlValue {
    param([string]$Token)

    $t = $Token.Trim()
    if ($t.Length -eq 0) { return '' }

    if ($t.StartsWith('"')) { return (ConvertFrom-TomlBasicString -Token $t) }

    if ($t.StartsWith('[')) {
        $rb = $t.LastIndexOf(']')
        if ($rb -lt 1) { return @() }
        $inner = $t.Substring(1, $rb - 1)
        $arr = @()
        foreach ($elem in (Split-TomlList -Inner $inner)) {
            $arr += (ConvertFrom-TomlValue -Token $elem)
        }
        return ,$arr
    }

    if ($t -eq 'true')  { return $true }
    if ($t -eq 'false') { return $false }
    if ($t -match '^[+-]?\d+$') { return [long]$t }
    if ($t -match '^[+-]?(\d+\.\d*|\.\d+|\d+)([eE][+-]?\d+)?$') {
        return [double]::Parse($t, [System.Globalization.CultureInfo]::InvariantCulture)
    }
    return $t.Trim('"')
}

function Split-TomlKeyPath {
    # Splits a dotted key path on top-level dots, respecting quoted segments.
    param([string]$Text)
    $parts = @()
    $inStr = $false
    $cur = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $Text.Length; $i++) {
        $c = $Text[$i]
        if ($inStr) {
            [void]$cur.Append($c)
            if ($c -eq '\' -and ($i + 1) -lt $Text.Length) { [void]$cur.Append($Text[$i + 1]); $i++; continue }
            if ($c -eq '"') { $inStr = $false }
            continue
        }
        if ($c -eq '"') { $inStr = $true; [void]$cur.Append($c); continue }
        if ($c -eq '.') { $parts += $cur.ToString(); $cur = New-Object System.Text.StringBuilder; continue }
        [void]$cur.Append($c)
    }
    $parts += $cur.ToString()

    return ,@($parts | ForEach-Object {
        $seg = $_.Trim()
        if ($seg.StartsWith('"')) { ConvertFrom-TomlBasicString -Token $seg } else { $seg }
    })
}

function ConvertFrom-TomlString {
    param([string]$Text)

    $root = @{}
    $current = $root
    foreach ($rawLine in ($Text -split "`r?`n")) {
        $line = $rawLine.Trim()
        if ($line.Length -eq 0) { continue }
        if ($line.StartsWith('#')) { continue }

        if ($line.StartsWith('[')) {
            $end = $line.IndexOf(']')
            if ($end -lt 0) { continue }
            $inner = $line.Substring(1, $end - 1).Trim()
            $segments = Split-TomlKeyPath -Text $inner
            $node = $root
            foreach ($seg in $segments) {
                if (-not $node.ContainsKey($seg) -or $node[$seg] -isnot [hashtable]) { $node[$seg] = @{} }
                $node = $node[$seg]
            }
            $current = $node
            continue
        }

        $eq = $line.IndexOf('=')
        if ($eq -lt 0) { continue }
        $keyToken = $line.Substring(0, $eq).Trim()
        $valToken = $line.Substring($eq + 1).Trim()
        if ($keyToken.StartsWith('"')) { $key = ConvertFrom-TomlBasicString -Token $keyToken } else { $key = $keyToken }
        $current[$key] = ConvertFrom-TomlValue -Token $valToken
    }
    return $root
}

# ---- INI -----------------------------------------------------------

function Format-IniValue {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $parts = @()
        foreach ($v in $Value) { $parts += [string]$v }
        return ($parts -join ', ')
    }
    return [string]$Value
}

function Write-IniTable {
    param(
        [System.Text.StringBuilder]$Sb,
        $Table,
        [string[]]$Path
    )

    $entries   = Get-TableEntry -Table $Table
    $scalars   = @($entries | Where-Object { -not (Test-IsTableValue -Value $_.Value) })
    $subtables = @($entries | Where-Object {      (Test-IsTableValue -Value $_.Value) })
    $isEmpty   = ($entries.Count -eq 0)

    if ($Path.Count -gt 0 -and ($scalars.Count -gt 0 -or $isEmpty)) {
        [void]$Sb.AppendLine('[' + ($Path -join '.') + ']')
    }
    foreach ($e in $scalars) {
        [void]$Sb.AppendLine($e.Key + ' = ' + (Format-IniValue -Value $e.Value))
    }
    if ($scalars.Count -gt 0) { [void]$Sb.AppendLine('') }
    foreach ($e in $subtables) {
        Write-IniTable -Sb $Sb -Table $e.Value -Path ($Path + $e.Key)
    }
}

function ConvertTo-IniString {
    param($InputObject)
    $sb = New-Object System.Text.StringBuilder
    Write-IniTable -Sb $sb -Table $InputObject -Path @()
    return $sb.ToString().TrimEnd("`r", "`n")
}

function ConvertFrom-IniString {
    param([string]$Text)

    $root = @{}
    $current = $root
    foreach ($rawLine in ($Text -split "`r?`n")) {
        $line = $rawLine.Trim()
        if ($line.Length -eq 0) { continue }
        if ($line.StartsWith(';') -or $line.StartsWith('#')) { continue }

        if ($line.StartsWith('[')) {
            $end = $line.IndexOf(']')
            if ($end -lt 0) { continue }
            $inner = $line.Substring(1, $end - 1).Trim()
            $node = $root
            foreach ($seg in ($inner -split '\.')) {
                $seg = $seg.Trim()
                if (-not $node.ContainsKey($seg) -or $node[$seg] -isnot [hashtable]) { $node[$seg] = @{} }
                $node = $node[$seg]
            }
            $current = $node
            continue
        }

        $eq = $line.IndexOf('=')
        if ($eq -lt 0) { continue }
        $key = $line.Substring(0, $eq).Trim()
        $val = $line.Substring($eq + 1).Trim()
        $current[$key] = $val
    }
    return $root
}

# ────────────────────────────────────────────────────────────────
# [2] Exported functions
# ────────────────────────────────────────────────────────────────

function New-JsonCryptStore {
    [CmdletBinding()]
    param()
    return @{ items = @{} }
}

function Add-JsonCryptItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Store,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        $Item
    )

    if ($Store.items.ContainsKey($Name)) {
        throw "Item '$Name' already exists. Remove it first to replace."
    }
    $Store.items[$Name] = $Item
}

function Get-JsonCryptItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Store,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not $Store.items.ContainsKey($Name)) {
        throw "Item '$Name' not found."
    }
    return $Store.items[$Name]
}

function Remove-JsonCryptItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Store,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not $Store.items.ContainsKey($Name)) {
        throw "Item '$Name' not found."
    }
    $Store.items.Remove($Name)
}

function Get-JsonCryptItemNames {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Store
    )

    return @($Store.items.Keys)
}

function Protect-JsonCryptString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Plaintext,

        [string]$Password,
        [string]$Key,
        [string]$KeyFile,
        [string]$EnvironmentVariable
    )

    $secretBytes = Resolve-KeySource -Password $Password -Key $Key -KeyFile $KeyFile -EnvironmentVariable $EnvironmentVariable
    return Invoke-Encrypt -SecretBytes $secretBytes -Plaintext $Plaintext
}

function Unprotect-JsonCryptString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$EncryptedString,

        [string]$Password,
        [string]$Key,
        [string]$KeyFile,
        [string]$EnvironmentVariable
    )

    $secretBytes = Resolve-KeySource -Password $Password -Key $Key -KeyFile $KeyFile -EnvironmentVariable $EnvironmentVariable
    return Invoke-Decrypt -SecretBytes $secretBytes -EncryptedString $EncryptedString
}

function Save-JsonCryptStore {
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Store,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory, ParameterSetName = 'Plaintext')]
        [switch]$Plaintext,

        [Parameter(Mandatory, ParameterSetName = 'Password')]
        [string]$Password,

        [Parameter(Mandatory, ParameterSetName = 'Key')]
        [string]$Key,

        [Parameter(Mandatory, ParameterSetName = 'KeyFile')]
        [string]$KeyFile,

        [Parameter(Mandatory, ParameterSetName = 'EnvironmentVariable')]
        [string]$EnvironmentVariable,

        [ValidateSet('Json', 'Ini', 'Toml')]
        [string]$Format
    )

    if ($PSCmdlet.ParameterSetName -eq 'None') {
        throw 'Specify -Plaintext for unencrypted storage, or provide a key source (-Password, -Key, -KeyFile, -EnvironmentVariable).'
    }

    $resolvedFormat = Resolve-StoreFormat -Format $Format -Path $Path
    switch ($resolvedFormat) {
        'Ini'   { $serialized = ConvertTo-IniString  -InputObject $Store }
        'Toml'  { $serialized = ConvertTo-TomlString -InputObject $Store }
        default { $serialized = $Store | ConvertTo-Json -Depth 20 -Compress }
    }

    if ($PSCmdlet.ParameterSetName -eq 'Plaintext') {
        $serialized | Set-Content -LiteralPath $Path -Encoding UTF8 -NoNewline
    }
    else {
        $secretBytes = Resolve-KeySource -Password $Password -Key $Key -KeyFile $KeyFile -EnvironmentVariable $EnvironmentVariable
        $encrypted = Invoke-Encrypt -SecretBytes $secretBytes -Plaintext $serialized
        $encrypted | Set-Content -LiteralPath $Path -Encoding UTF8 -NoNewline
    }

    Set-SecureFilePermission -Path $Path
}

function Import-JsonCryptStore {
    [CmdletBinding(DefaultParameterSetName = 'None')]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory, ParameterSetName = 'Plaintext')]
        [switch]$Plaintext,

        [Parameter(Mandatory, ParameterSetName = 'Password')]
        [string]$Password,

        [Parameter(Mandatory, ParameterSetName = 'Key')]
        [string]$Key,

        [Parameter(Mandatory, ParameterSetName = 'KeyFile')]
        [string]$KeyFile,

        [Parameter(Mandatory, ParameterSetName = 'EnvironmentVariable')]
        [string]$EnvironmentVariable,

        [ValidateSet('Json', 'Ini', 'Toml')]
        [string]$Format
    )

    if ($PSCmdlet.ParameterSetName -eq 'None') {
        throw 'Specify -Plaintext for unencrypted loading, or provide a key source (-Password, -Key, -KeyFile, -EnvironmentVariable).'
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Store file not found: $Path"
    }

    $raw = Get-Content -LiteralPath $Path -Raw

    if ($PSCmdlet.ParameterSetName -eq 'Plaintext') {
        $text = $raw
    }
    else {
        $secretBytes = Resolve-KeySource -Password $Password -Key $Key -KeyFile $KeyFile -EnvironmentVariable $EnvironmentVariable
        $text = Invoke-Decrypt -SecretBytes $secretBytes -EncryptedString $raw
    }

    $resolvedFormat = Resolve-StoreFormat -Format $Format -Path $Path
    switch ($resolvedFormat) {
        'Ini'   { $store = ConvertFrom-IniString  -Text $text }
        'Toml'  { $store = ConvertFrom-TomlString -Text $text }
        default { $store = ConvertTo-Hashtable -InputObject ($text | ConvertFrom-Json) }
    }

    # Ensure expected structure
    if (-not $store.ContainsKey('items')) {
        throw 'Invalid store format: missing "items" key.'
    }
    if ($null -eq $store.items -or $store.items -isnot [hashtable]) {
        throw 'Invalid store format: "items" must be an object.'
    }

    return $store
}

function New-JsonCryptKey {
    [CmdletBinding()]
    param()

    $bytes = New-Object byte[] 32
    $rng   = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()

    return ([System.BitConverter]::ToString($bytes) -replace '-','').ToLower()
}


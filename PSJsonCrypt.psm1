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
        [string]$EnvironmentVariable
    )

    if ($PSCmdlet.ParameterSetName -eq 'None') {
        throw 'Specify -Plaintext for unencrypted storage, or provide a key source (-Password, -Key, -KeyFile, -EnvironmentVariable).'
    }

    $json = $Store | ConvertTo-Json -Depth 20 -Compress

    if ($PSCmdlet.ParameterSetName -eq 'Plaintext') {
        $json | Set-Content -LiteralPath $Path -Encoding UTF8 -NoNewline
    }
    else {
        $secretBytes = Resolve-KeySource -Password $Password -Key $Key -KeyFile $KeyFile -EnvironmentVariable $EnvironmentVariable
        $encrypted = Invoke-Encrypt -SecretBytes $secretBytes -Plaintext $json
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
        [string]$EnvironmentVariable
    )

    if ($PSCmdlet.ParameterSetName -eq 'None') {
        throw 'Specify -Plaintext for unencrypted loading, or provide a key source (-Password, -Key, -KeyFile, -EnvironmentVariable).'
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Store file not found: $Path"
    }

    $raw = Get-Content -LiteralPath $Path -Raw

    if ($PSCmdlet.ParameterSetName -eq 'Plaintext') {
        $json = $raw
    }
    else {
        $secretBytes = Resolve-KeySource -Password $Password -Key $Key -KeyFile $KeyFile -EnvironmentVariable $EnvironmentVariable
        $json = Invoke-Decrypt -SecretBytes $secretBytes -EncryptedString $raw
    }

    $parsed = $json | ConvertFrom-Json
    $store  = ConvertTo-Hashtable -InputObject $parsed

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


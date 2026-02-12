$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot '..' 'PSJsonCrypt.psd1') -Force

$passed = 0
$failed = 0

function Assert-True {
    param(
        [Parameter(Mandatory)]
        [bool]$Condition,
        [Parameter(Mandatory)]
        [string]$Message
    )
    if ($Condition) {
        $script:passed++
        Write-Host "PASS: $Message" -ForegroundColor Green
    }
    else {
        $script:failed++
        Write-Host "FAIL: $Message" -ForegroundColor Red
    }
}

function Assert-Throws {
    param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,
        [Parameter(Mandatory)]
        [string]$Message,
        [string]$Contains
    )
    try {
        & $ScriptBlock
        $script:failed++
        Write-Host "FAIL: $Message (did not throw)" -ForegroundColor Red
    }
    catch {
        if ($Contains -and $_.Exception.Message -notlike "*$Contains*") {
            $script:failed++
            Write-Host "FAIL: $Message (unexpected message: $($_.Exception.Message))" -ForegroundColor Red
        }
        else {
            $script:passed++
            Write-Host "PASS: $Message" -ForegroundColor Green
        }
    }
}

function Assert-NotThrows {
    param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,
        [Parameter(Mandatory)]
        [string]$Message
    )
    try {
        & $ScriptBlock
        $script:passed++
        Write-Host "PASS: $Message" -ForegroundColor Green
    }
    catch {
        $script:failed++
        Write-Host "FAIL: $Message ($($_.Exception.Message))" -ForegroundColor Red
    }
}

function New-TempPath {
    param([string]$Suffix = '.tmp')
    return (Join-Path ([System.IO.Path]::GetTempPath()) ("psjsoncrypt-" + [guid]::NewGuid().ToString() + $Suffix))
}

Write-Host "Running PSJsonCrypt robustness tests..." -ForegroundColor Cyan

# 1) Basic roundtrip with password
$enc = Protect-JsonCryptString -Plaintext "hello" -Password "pw"
$dec = Unprotect-JsonCryptString -EncryptedString $enc -Password "pw"
Assert-True ($dec -eq "hello") "Encrypt/decrypt roundtrip with -Password"

# 2) Basic roundtrip with key
$enc = Protect-JsonCryptString -Plaintext "hello2" -Key "mykey"
$dec = Unprotect-JsonCryptString -EncryptedString $enc -Key "mykey"
Assert-True ($dec -eq "hello2") "Encrypt/decrypt roundtrip with -Key"

# 3) KeyFile trims whitespace
$keyFile = New-TempPath '.key'
Set-Content -LiteralPath $keyFile -Value " file-secret `n" -NoNewline
$enc = Protect-JsonCryptString -Plaintext "hello3" -KeyFile $keyFile
$dec = Unprotect-JsonCryptString -EncryptedString $enc -KeyFile $keyFile
Assert-True ($dec -eq "hello3") "Encrypt/decrypt roundtrip with -KeyFile"
Remove-Item -LiteralPath $keyFile -Force

# 4) EnvironmentVariable source
[System.Environment]::SetEnvironmentVariable('PSJSONCRYPT_TEST_KEY', 'env-secret')
$enc = Protect-JsonCryptString -Plaintext "hello4" -EnvironmentVariable 'PSJSONCRYPT_TEST_KEY'
$dec = Unprotect-JsonCryptString -EncryptedString $enc -EnvironmentVariable 'PSJSONCRYPT_TEST_KEY'
Assert-True ($dec -eq "hello4") "Encrypt/decrypt roundtrip with -EnvironmentVariable"
[System.Environment]::SetEnvironmentVariable('PSJSONCRYPT_TEST_KEY', $null)

# 5) Reject no key source
Assert-Throws { Protect-JsonCryptString -Plaintext "x" } "Reject missing key source on Protect" "No key source specified"

# 6) Reject multiple key sources
Assert-Throws { Protect-JsonCryptString -Plaintext "x" -Password "a" -Key "b" } "Reject multiple key sources on Protect" "Multiple key sources specified"

# 7) Wrong password rejected
$enc = Protect-JsonCryptString -Plaintext "hello" -Password "correct"
Assert-Throws { Unprotect-JsonCryptString -EncryptedString $enc -Password "wrong" } "Reject wrong password on decrypt" "MAC verification failed"

# 8) Empty MAC rejected
$obj = $enc | ConvertFrom-Json
$obj.mac = ""
$tampered = $obj | ConvertTo-Json -Compress
Assert-Throws { Unprotect-JsonCryptString -EncryptedString $tampered -Password "correct" } "Reject empty MAC" "missing or empty 'mac'"

# 9) Invalid base64 rejected
$obj = $enc | ConvertFrom-Json
$obj.iv = "###notbase64###"
$tampered = $obj | ConvertTo-Json -Compress
Assert-Throws { Unprotect-JsonCryptString -EncryptedString $tampered -Password "correct" } "Reject invalid base64 in envelope" "invalid base64"

# 10) Invalid salt length rejected
$obj = $enc | ConvertFrom-Json
$obj.salt = [Convert]::ToBase64String((1..8))
$tampered = $obj | ConvertTo-Json -Compress
Assert-Throws { Unprotect-JsonCryptString -EncryptedString $tampered -Password "correct" } "Reject invalid salt length" "salt must be 16 bytes"

# 11) Invalid iv length rejected
$obj = $enc | ConvertFrom-Json
$obj.iv = [Convert]::ToBase64String((1..8))
$tampered = $obj | ConvertTo-Json -Compress
Assert-Throws { Unprotect-JsonCryptString -EncryptedString $tampered -Password "correct" } "Reject invalid iv length" "iv must be 16 bytes"

# 12) Invalid mac length rejected
$obj = $enc | ConvertFrom-Json
$obj.mac = [Convert]::ToBase64String((1..16))
$tampered = $obj | ConvertTo-Json -Compress
Assert-Throws { Unprotect-JsonCryptString -EncryptedString $tampered -Password "correct" } "Reject invalid MAC length" "mac must be 32 bytes"

# 13) Missing required field rejected
$obj = $enc | ConvertFrom-Json
$obj.PSObject.Properties.Remove('ciphertext')
$tampered = $obj | ConvertTo-Json -Compress
Assert-Throws { Unprotect-JsonCryptString -EncryptedString $tampered -Password "correct" } "Reject missing ciphertext field" "missing or empty 'ciphertext'"

# 14) Unsupported version rejected
$obj = $enc | ConvertFrom-Json
$obj.version = 999
$tampered = $obj | ConvertTo-Json -Compress
Assert-Throws { Unprotect-JsonCryptString -EncryptedString $tampered -Password "correct" } "Reject unsupported version" "Unsupported or missing envelope version"

# 15) Save requires explicit mode
$store = New-JsonCryptStore
Add-JsonCryptItem -Store $store -Name "db" -Item @{ user = "a"; pass = "b" }
$tmp = New-TempPath '.json'
Assert-Throws { Save-JsonCryptStore -Store $store -Path $tmp } "Save requires -Plaintext or key source" "Specify -Plaintext"

# 16) Import requires explicit mode
Assert-Throws { Import-JsonCryptStore -Path $tmp } "Import requires -Plaintext or key source" "Specify -Plaintext"

# 17) Plaintext store roundtrip
$tmpPlain = New-TempPath '.json'
Assert-NotThrows { Save-JsonCryptStore -Store $store -Path $tmpPlain -Plaintext } "Save plaintext store"
$loaded = Import-JsonCryptStore -Path $tmpPlain -Plaintext
Assert-True ($loaded.items.db.user -eq "a") "Import plaintext store data matches"
Remove-Item -LiteralPath $tmpPlain -Force

# 18) Encrypted store roundtrip
$tmpEnc = New-TempPath '.enc'
Assert-NotThrows { Save-JsonCryptStore -Store $store -Path $tmpEnc -Password "pw" } "Save encrypted store"
$loaded = Import-JsonCryptStore -Path $tmpEnc -Password "pw"
Assert-True ($loaded.items.db.pass -eq "b") "Import encrypted store data matches"
Remove-Item -LiteralPath $tmpEnc -Force

# 19) Path with spaces works
$tmpSpacedDir = Join-Path ([System.IO.Path]::GetTempPath()) ("psjsoncrypt test " + [guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $tmpSpacedDir | Out-Null
$tmpSpaced = Join-Path $tmpSpacedDir "data file.enc"
Assert-NotThrows { Save-JsonCryptStore -Store $store -Path $tmpSpaced -Password "pw2" } "Save works on path with spaces"
$loaded = Import-JsonCryptStore -Path $tmpSpaced -Password "pw2"
Assert-True ($loaded.items.db.user -eq "a") "Import works on path with spaces"
Remove-Item -LiteralPath $tmpSpacedDir -Recurse -Force

# 20) Invalid store format rejected on import
$tmpInvalid = New-TempPath '.json'
Set-Content -LiteralPath $tmpInvalid -Value '{"notItems":{}}' -NoNewline
Assert-Throws { Import-JsonCryptStore -Path $tmpInvalid -Plaintext } "Reject store without items key" 'missing "items" key'
Remove-Item -LiteralPath $tmpInvalid -Force

# 21) New-JsonCryptKey format
$k1 = New-JsonCryptKey
$k2 = New-JsonCryptKey
Assert-True ($k1 -match '^[0-9a-f]{64}$') "Generated key has expected 64-char lowercase hex format"
Assert-True ($k1 -ne $k2) "Generated keys are non-deterministic"

# 22) Store API behavior
$s = New-JsonCryptStore
Add-JsonCryptItem -Store $s -Name "a" -Item @{ x = 1 }
Assert-Throws { Add-JsonCryptItem -Store $s -Name "a" -Item @{ x = 2 } } "Reject duplicate item name" "already exists"
Assert-True ((Get-JsonCryptItem -Store $s -Name "a").x -eq 1) "Get-JsonCryptItem returns stored value"
Assert-Throws { Get-JsonCryptItem -Store $s -Name "missing" } "Reject get missing item" "not found"
Assert-Throws { Remove-JsonCryptItem -Store $s -Name "missing" } "Reject remove missing item" "not found"

# 23) Decrypt rejects non-JSON payload
Assert-Throws { Unprotect-JsonCryptString -EncryptedString "not-json" -Password "pw" } "Reject non-JSON encrypted payload" "not valid JSON"

# 24) KeyFile error cases
$missingKeyFile = New-TempPath '.missing'
Assert-Throws { Protect-JsonCryptString -Plaintext "x" -KeyFile $missingKeyFile } "Reject missing key file" "KeyFile not found"
$emptyKeyFile = New-TempPath '.key'
Set-Content -LiteralPath $emptyKeyFile -Value "   " -NoNewline
Assert-Throws { Protect-JsonCryptString -Plaintext "x" -KeyFile $emptyKeyFile } "Reject empty key file content" "KeyFile is empty"
Remove-Item -LiteralPath $emptyKeyFile -Force

# 25) Environment variable error case
[System.Environment]::SetEnvironmentVariable('PSJSONCRYPT_TEST_EMPTY', $null)
Assert-Throws { Protect-JsonCryptString -Plaintext "x" -EnvironmentVariable 'PSJSONCRYPT_TEST_EMPTY' } "Reject missing/empty environment variable key source" "not set or empty"

# 26) Large payload roundtrip (1 MiB)
$largeText = "A" * 1048576
$enc = Protect-JsonCryptString -Plaintext $largeText -Password "pw-large"
$dec = Unprotect-JsonCryptString -EncryptedString $enc -Password "pw-large"
Assert-True ($dec.Length -eq $largeText.Length -and $dec -eq $largeText) "Roundtrip with 1 MiB payload"

Write-Host ""
Write-Host "Total passed: $passed" -ForegroundColor Green
Write-Host "Total failed: $failed" -ForegroundColor Red

if ($failed -gt 0) {
    exit 1
}

Write-Host "All robustness tests passed." -ForegroundColor Green

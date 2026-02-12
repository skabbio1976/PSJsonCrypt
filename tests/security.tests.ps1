$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot '..' 'PSJsonCrypt.psm1') -Force

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
    return (Join-Path ([System.IO.Path]::GetTempPath()) ("psjsoncrypt-sec-" + [guid]::NewGuid().ToString() + $Suffix))
}

# Helper: get a valid encrypted envelope object for manipulation
function Get-ValidEnvelope {
    param(
        [string]$Plaintext = "test-plaintext",
        [string]$Password = "test-password"
    )
    $enc = Protect-JsonCryptString -Plaintext $Plaintext -Password $Password
    return ($enc | ConvertFrom-Json)
}

# Helper: reconstruct JSON from envelope object
function ConvertTo-EnvelopeJson {
    param($Envelope)
    return ($Envelope | ConvertTo-Json -Compress)
}

Write-Host "Running PSJsonCrypt security tests..." -ForegroundColor Cyan
Write-Host ""

# ────────────────────────────────────────────────────────────────
# SECTION 1: Padding Oracle Protection
# ────────────────────────────────────────────────────────────────
Write-Host "--- Padding Oracle Protection ---" -ForegroundColor Yellow

# 1) Tampered ciphertext should fail MAC, not produce padding error
$env1 = Get-ValidEnvelope
$ctBytes = [System.Convert]::FromBase64String($env1.ciphertext)
$ctBytes[0] = $ctBytes[0] -bxor 0xFF
$env1.ciphertext = [System.Convert]::ToBase64String($ctBytes)
$tampered1 = ConvertTo-EnvelopeJson $env1
Assert-Throws { Unprotect-JsonCryptString -EncryptedString $tampered1 -Password "test-password" } `
    "Tampered ciphertext fails with MAC error (not padding)" `
    "MAC verification failed"

# 2) Tampered last byte of ciphertext (PKCS7 padding byte location) also fails MAC
$env2 = Get-ValidEnvelope
$ctBytes2 = [System.Convert]::FromBase64String($env2.ciphertext)
$ctBytes2[$ctBytes2.Length - 1] = $ctBytes2[$ctBytes2.Length - 1] -bxor 0x01
$env2.ciphertext = [System.Convert]::ToBase64String($ctBytes2)
$tampered2 = ConvertTo-EnvelopeJson $env2
Assert-Throws { Unprotect-JsonCryptString -EncryptedString $tampered2 -Password "test-password" } `
    "Tampered padding byte fails with MAC error (not padding)" `
    "MAC verification failed"

# 3) Multiple ciphertext blocks: tamper middle block
$longText = "A" * 100  # Produces multiple AES blocks
$env3 = Get-ValidEnvelope -Plaintext $longText
$ctBytes3 = [System.Convert]::FromBase64String($env3.ciphertext)
# Flip bit in middle of ciphertext
$midpoint = [int]($ctBytes3.Length / 2)
$ctBytes3[$midpoint] = $ctBytes3[$midpoint] -bxor 0x42
$env3.ciphertext = [System.Convert]::ToBase64String($ctBytes3)
$tampered3 = ConvertTo-EnvelopeJson $env3
Assert-Throws { Unprotect-JsonCryptString -EncryptedString $tampered3 -Password "test-password" } `
    "Tampered middle block fails with MAC error" `
    "MAC verification failed"

Write-Host ""

# ────────────────────────────────────────────────────────────────
# SECTION 2: Bit-Flip Attacks on All Envelope Fields
# ────────────────────────────────────────────────────────────────
Write-Host "--- Bit-Flip Attacks ---" -ForegroundColor Yellow

# 4) Bit-flip in IV
$env4 = Get-ValidEnvelope
$ivBytes = [System.Convert]::FromBase64String($env4.iv)
$ivBytes[0] = $ivBytes[0] -bxor 0x01
$env4.iv = [System.Convert]::ToBase64String($ivBytes)
Assert-Throws { Unprotect-JsonCryptString -EncryptedString (ConvertTo-EnvelopeJson $env4) -Password "test-password" } `
    "Bit-flip in IV fails MAC" `
    "MAC verification failed"

# 5) Bit-flip in salt
$env5 = Get-ValidEnvelope
$saltBytes = [System.Convert]::FromBase64String($env5.salt)
$saltBytes[0] = $saltBytes[0] -bxor 0x01
$env5.salt = [System.Convert]::ToBase64String($saltBytes)
Assert-Throws { Unprotect-JsonCryptString -EncryptedString (ConvertTo-EnvelopeJson $env5) -Password "test-password" } `
    "Bit-flip in salt fails MAC" `
    "MAC verification failed"

# 6) Bit-flip in MAC itself
$env6 = Get-ValidEnvelope
$macBytes = [System.Convert]::FromBase64String($env6.mac)
$macBytes[0] = $macBytes[0] -bxor 0x01
$env6.mac = [System.Convert]::ToBase64String($macBytes)
Assert-Throws { Unprotect-JsonCryptString -EncryptedString (ConvertTo-EnvelopeJson $env6) -Password "test-password" } `
    "Bit-flip in MAC fails verification" `
    "MAC verification failed"

# 7) All-zeros MAC
$env7 = Get-ValidEnvelope
$env7.mac = [System.Convert]::ToBase64String((New-Object byte[] 32))
Assert-Throws { Unprotect-JsonCryptString -EncryptedString (ConvertTo-EnvelopeJson $env7) -Password "test-password" } `
    "All-zeros MAC fails verification" `
    "MAC verification failed"

# 8) Swap IV and salt (same length, both 16 bytes)
$env8 = Get-ValidEnvelope
$origSalt = $env8.salt
$origIv = $env8.iv
$env8.salt = $origIv
$env8.iv = $origSalt
Assert-Throws { Unprotect-JsonCryptString -EncryptedString (ConvertTo-EnvelopeJson $env8) -Password "test-password" } `
    "Swapped salt/IV fails MAC" `
    "MAC verification failed"

Write-Host ""

# ────────────────────────────────────────────────────────────────
# SECTION 3: Type Confusion in Envelope Fields
# ────────────────────────────────────────────────────────────────
Write-Host "--- Type Confusion ---" -ForegroundColor Yellow

# 9) Version as string "1" -- FIXED: now rejected by strict integer type check
$env9 = Get-ValidEnvelope
$jsonStr = '{"version":"1","salt":"' + $env9.salt + '","iv":"' + $env9.iv + '","ciphertext":"' + $env9.ciphertext + '","mac":"' + $env9.mac + '"}'
Assert-Throws { Unprotect-JsonCryptString -EncryptedString $jsonStr -Password "test-password" } "Version as string '1' is rejected (strict type check)" "Unsupported or missing envelope version"

# 10) Version as float 1.0 -- FIXED: now rejected
$env10 = Get-ValidEnvelope
$jsonFloat = '{"version":1.0,"salt":"' + $env10.salt + '","iv":"' + $env10.iv + '","ciphertext":"' + $env10.ciphertext + '","mac":"' + $env10.mac + '"}'
Assert-Throws { Unprotect-JsonCryptString -EncryptedString $jsonFloat -Password "test-password" } "Version as float 1.0 is rejected (strict type check)" "Unsupported or missing envelope version"

# 11) Version as boolean true -- FIXED: now rejected
$env11 = Get-ValidEnvelope
$jsonBool = '{"version":true,"salt":"' + $env11.salt + '","iv":"' + $env11.iv + '","ciphertext":"' + $env11.ciphertext + '","mac":"' + $env11.mac + '"}'
Assert-Throws { Unprotect-JsonCryptString -EncryptedString $jsonBool -Password "test-password" } "Version as boolean true is rejected (strict type check)" "Unsupported or missing envelope version"

# 12) Version as array [1] -- FIXED: now rejected
$env12 = Get-ValidEnvelope
$jsonArr = '{"version":[1],"salt":"' + $env12.salt + '","iv":"' + $env12.iv + '","ciphertext":"' + $env12.ciphertext + '","mac":"' + $env12.mac + '"}'
Assert-Throws { Unprotect-JsonCryptString -EncryptedString $jsonArr -Password "test-password" } "Version as array [1] is rejected (strict type check)" "Unsupported or missing envelope version"

# 13) Version as 2 should be rejected
$env13 = Get-ValidEnvelope
$env13.version = 2
Assert-Throws { Unprotect-JsonCryptString -EncryptedString (ConvertTo-EnvelopeJson $env13) -Password "test-password" } `
    "Version 2 is rejected" `
    "Unsupported or missing envelope version"

# 14) Version as 0 should be rejected
$env14 = Get-ValidEnvelope
$env14.version = 0
Assert-Throws { Unprotect-JsonCryptString -EncryptedString (ConvertTo-EnvelopeJson $env14) -Password "test-password" } `
    "Version 0 is rejected" `
    "Unsupported or missing envelope version"

# 15) Version as negative
$env15 = Get-ValidEnvelope
$env15.version = -1
Assert-Throws { Unprotect-JsonCryptString -EncryptedString (ConvertTo-EnvelopeJson $env15) -Password "test-password" } `
    "Version -1 is rejected" `
    "Unsupported or missing envelope version"

# 16) Version as null
$env16 = Get-ValidEnvelope
$jsonNull = '{"version":null,"salt":"' + $env16.salt + '","iv":"' + $env16.iv + '","ciphertext":"' + $env16.ciphertext + '","mac":"' + $env16.mac + '"}'
Assert-Throws { Unprotect-JsonCryptString -EncryptedString $jsonNull -Password "test-password" } `
    "Version null is rejected" `
    "Unsupported or missing envelope version"

# 17) Salt as numeric type (not a string)
$env17 = Get-ValidEnvelope
$jsonNumSalt = '{"version":1,"salt":12345,"iv":"' + $env17.iv + '","ciphertext":"' + $env17.ciphertext + '","mac":"' + $env17.mac + '"}'
Assert-Throws { Unprotect-JsonCryptString -EncryptedString $jsonNumSalt -Password "test-password" } `
    "Numeric salt is rejected (not a string)" `
    "missing or empty"

# 18) IV as array
$env18 = Get-ValidEnvelope
$jsonArrIv = '{"version":1,"salt":"' + $env18.salt + '","iv":[1,2,3],"ciphertext":"' + $env18.ciphertext + '","mac":"' + $env18.mac + '"}'
Assert-Throws { Unprotect-JsonCryptString -EncryptedString $jsonArrIv -Password "test-password" } `
    "Array IV is rejected" `
    "missing or empty"

# 19) Ciphertext as null
$env19 = Get-ValidEnvelope
$jsonNullCt = '{"version":1,"salt":"' + $env19.salt + '","iv":"' + $env19.iv + '","ciphertext":null,"mac":"' + $env19.mac + '"}'
Assert-Throws { Unprotect-JsonCryptString -EncryptedString $jsonNullCt -Password "test-password" } `
    "Null ciphertext is rejected" `
    "missing or empty"

# 20) MAC as boolean
$env20 = Get-ValidEnvelope
$jsonBoolMac = '{"version":1,"salt":"' + $env20.salt + '","iv":"' + $env20.iv + '","ciphertext":"' + $env20.ciphertext + '","mac":false}'
Assert-Throws { Unprotect-JsonCryptString -EncryptedString $jsonBoolMac -Password "test-password" } `
    "Boolean MAC is rejected" `
    "missing or empty"

Write-Host ""

# ────────────────────────────────────────────────────────────────
# SECTION 4: Unicode and Null-Byte Edge Cases
# ────────────────────────────────────────────────────────────────
Write-Host "--- Unicode / Null-Byte Edge Cases ---" -ForegroundColor Yellow

# 21) Null byte in plaintext roundtrips correctly
$nullText = "before" + [char]0x0000 + "after"
$enc21 = Protect-JsonCryptString -Plaintext $nullText -Password "pw"
$dec21 = Unprotect-JsonCryptString -EncryptedString $enc21 -Password "pw"
Assert-True ($dec21 -eq $nullText) "Null byte in plaintext roundtrips correctly"
Assert-True ($dec21.Length -eq $nullText.Length) "Null byte plaintext preserves length"

# 22) Null byte in password
$nullPw = "pass" + [char]0x0000 + "word"
$enc22 = Protect-JsonCryptString -Plaintext "hello" -Password $nullPw
$dec22 = Unprotect-JsonCryptString -EncryptedString $enc22 -Password $nullPw
Assert-True ($dec22 -eq "hello") "Null byte in password roundtrips correctly"

# 23) Null byte password is not truncated at null
$truncPw = "pass"
Assert-Throws { Unprotect-JsonCryptString -EncryptedString $enc22 -Password $truncPw } `
    "Password with null byte is not truncated" `
    "MAC verification failed"

# 24) Multi-byte Unicode (BMP characters)
$unicodeText = [char]0x00E9 + [char]0x00F1 + [char]0x00FC + [char]0x4E16 + [char]0x754C
$enc24 = Protect-JsonCryptString -Plaintext $unicodeText -Password "pw"
$dec24 = Unprotect-JsonCryptString -EncryptedString $enc24 -Password "pw"
Assert-True ($dec24 -eq $unicodeText) "Multi-byte BMP Unicode roundtrips correctly"

# 25) Supplementary plane characters (emoji, surrogate pairs)
$emojiText = "Hello " + [char]::ConvertFromUtf32(0x1F600) + " World " + [char]::ConvertFromUtf32(0x1F4A9)
$enc25 = Protect-JsonCryptString -Plaintext $emojiText -Password "pw"
$dec25 = Unprotect-JsonCryptString -EncryptedString $enc25 -Password "pw"
Assert-True ($dec25 -eq $emojiText) "Emoji/supplementary plane characters roundtrip correctly"

# 26) Unicode password
$unicodePw = [char]0x00FC + "ber-" + [char]0x00E9 + "lite-" + [char]0x4E16
$enc26 = Protect-JsonCryptString -Plaintext "secret" -Password $unicodePw
$dec26 = Unprotect-JsonCryptString -EncryptedString $enc26 -Password $unicodePw
Assert-True ($dec26 -eq "secret") "Unicode password roundtrips correctly"

# 27) Very long Unicode string
$longUnicode = ([char]0x4E16).ToString() * 10000
$enc27 = Protect-JsonCryptString -Plaintext $longUnicode -Password "pw"
$dec27 = Unprotect-JsonCryptString -EncryptedString $enc27 -Password "pw"
Assert-True ($dec27 -eq $longUnicode) "Long Unicode string (10k chars) roundtrips correctly"

Write-Host ""

# ────────────────────────────────────────────────────────────────
# SECTION 5: Store with items as Wrong Type (Finding 2)
# ────────────────────────────────────────────────────────────────
Write-Host "--- Store Items Type Validation (Finding 2) ---" -ForegroundColor Yellow

# 28) items as string -- FIXED: now rejected with clear error
$tmpStr = New-TempPath '.json'
Set-Content -LiteralPath $tmpStr -Value '{"items":"not-a-dict"}' -NoNewline
Assert-Throws { Import-JsonCryptStore -Path $tmpStr -Plaintext } "Import rejects items as string" '"items" must be an object'
Remove-Item -LiteralPath $tmpStr -Force

# 29) items as array -- FIXED: now rejected
$tmpArr = New-TempPath '.json'
Set-Content -LiteralPath $tmpArr -Value '{"items":[1,2,3]}' -NoNewline
Assert-Throws { Import-JsonCryptStore -Path $tmpArr -Plaintext } "Import rejects items as array" '"items" must be an object'
Remove-Item -LiteralPath $tmpArr -Force

# 30) items as number -- FIXED: now rejected
$tmpNum = New-TempPath '.json'
Set-Content -LiteralPath $tmpNum -Value '{"items":42}' -NoNewline
Assert-Throws { Import-JsonCryptStore -Path $tmpNum -Plaintext } "Import rejects items as number" '"items" must be an object'
Remove-Item -LiteralPath $tmpNum -Force

# 31) items as null -- now rejected with clear error
$tmpNull = New-TempPath '.json'
Set-Content -LiteralPath $tmpNull -Value '{"items":null}' -NoNewline
Assert-Throws { Import-JsonCryptStore -Path $tmpNull -Plaintext } "Import rejects items as null" '"items" must be an object'
Remove-Item -LiteralPath $tmpNull -Force

# 32) items as boolean -- FIXED: now rejected
$tmpBool = New-TempPath '.json'
Set-Content -LiteralPath $tmpBool -Value '{"items":true}' -NoNewline
Assert-Throws { Import-JsonCryptStore -Path $tmpBool -Plaintext } "Import rejects items as boolean" '"items" must be an object'
Remove-Item -LiteralPath $tmpBool -Force

Write-Host ""

# ────────────────────────────────────────────────────────────────
# SECTION 6: Extremely Long Field Values
# ────────────────────────────────────────────────────────────────
Write-Host "--- Long Field Values ---" -ForegroundColor Yellow

# 33) Very long but valid-length salt (decoded to not-16 bytes)
$env33 = Get-ValidEnvelope
$env33.salt = [System.Convert]::ToBase64String((New-Object byte[] 1048576))
Assert-Throws { Unprotect-JsonCryptString -EncryptedString (ConvertTo-EnvelopeJson $env33) -Password "test-password" } `
    "1MB salt is rejected (wrong length)" `
    "salt must be 16 bytes"

# 34) Very long ciphertext (valid base64, will fail MAC)
$env34 = Get-ValidEnvelope
$env34.ciphertext = [System.Convert]::ToBase64String((New-Object byte[] 65536))
Assert-Throws { Unprotect-JsonCryptString -EncryptedString (ConvertTo-EnvelopeJson $env34) -Password "test-password" } `
    "64KB ciphertext fails MAC" `
    "MAC verification failed"

# 35) Extremely long non-base64 string in salt field
$env35 = Get-ValidEnvelope
$env35.salt = "A" * 100000
Assert-Throws { Unprotect-JsonCryptString -EncryptedString (ConvertTo-EnvelopeJson $env35) -Password "test-password" } `
    "Very long non-base64 salt is rejected"

Write-Host ""

# ────────────────────────────────────────────────────────────────
# SECTION 7: Duplicate JSON Keys
# ────────────────────────────────────────────────────────────────
Write-Host "--- Duplicate JSON Keys ---" -ForegroundColor Yellow

# 36) Duplicate version key (last wins in PowerShell)
$env36 = Get-ValidEnvelope
$dupeVersionJson = '{"version":1,"salt":"' + $env36.salt + '","iv":"' + $env36.iv + '","ciphertext":"' + $env36.ciphertext + '","mac":"' + $env36.mac + '","version":999}'
Assert-Throws { Unprotect-JsonCryptString -EncryptedString $dupeVersionJson -Password "test-password" } `
    "Duplicate version key (last=999) is rejected" `
    "Unsupported or missing envelope version"

# 37) Duplicate mac key -- second mac replaces first (could bypass if attacker controls JSON construction)
$env37 = Get-ValidEnvelope
$zeroesMac = [System.Convert]::ToBase64String((New-Object byte[] 32))
$dupeMacJson = '{"version":1,"salt":"' + $env37.salt + '","iv":"' + $env37.iv + '","ciphertext":"' + $env37.ciphertext + '","mac":"' + $env37.mac + '","mac":"' + $zeroesMac + '"}'
Assert-Throws { Unprotect-JsonCryptString -EncryptedString $dupeMacJson -Password "test-password" } `
    "Duplicate mac key (last=zeros) fails MAC" `
    "MAC verification failed"

Write-Host ""

# ────────────────────────────────────────────────────────────────
# SECTION 8: Ciphertext Block Alignment
# ────────────────────────────────────────────────────────────────
Write-Host "--- Ciphertext Block Alignment ---" -ForegroundColor Yellow

# 38) Ciphertext with 15 bytes (not aligned to 16-byte AES block) fails MAC
$env38 = Get-ValidEnvelope
$env38.ciphertext = [System.Convert]::ToBase64String((New-Object byte[] 15))
Assert-Throws { Unprotect-JsonCryptString -EncryptedString (ConvertTo-EnvelopeJson $env38) -Password "test-password" } `
    "15-byte ciphertext (not block-aligned) fails MAC" `
    "MAC verification failed"

# 39) Ciphertext with 17 bytes (not aligned) fails MAC
$env39 = Get-ValidEnvelope
$env39.ciphertext = [System.Convert]::ToBase64String((New-Object byte[] 17))
Assert-Throws { Unprotect-JsonCryptString -EncryptedString (ConvertTo-EnvelopeJson $env39) -Password "test-password" } `
    "17-byte ciphertext (not block-aligned) fails MAC" `
    "MAC verification failed"

# 40) Ciphertext with 1 byte fails MAC
$env40 = Get-ValidEnvelope
$env40.ciphertext = [System.Convert]::ToBase64String((New-Object byte[] 1))
Assert-Throws { Unprotect-JsonCryptString -EncryptedString (ConvertTo-EnvelopeJson $env40) -Password "test-password" } `
    "1-byte ciphertext fails MAC" `
    "MAC verification failed"

Write-Host ""

# ────────────────────────────────────────────────────────────────
# SECTION 9: Cross-Key-Source Isolation / Compatibility
# ────────────────────────────────────────────────────────────────
Write-Host "--- Cross-Key-Source Compatibility ---" -ForegroundColor Yellow

# 41) Password and Key use same UTF8 encoding -- should be interchangeable
$secret = "shared-secret-value"
$enc41 = Protect-JsonCryptString -Plaintext "cross-key-test" -Password $secret
$dec41 = Unprotect-JsonCryptString -EncryptedString $enc41 -Key $secret
Assert-True ($dec41 -eq "cross-key-test") "Password encrypt -> Key decrypt works (same UTF8 path)"

# 42) Key encrypt -> Password decrypt
$enc42 = Protect-JsonCryptString -Plaintext "cross-key-test2" -Key $secret
$dec42 = Unprotect-JsonCryptString -EncryptedString $enc42 -Password $secret
Assert-True ($dec42 -eq "cross-key-test2") "Key encrypt -> Password decrypt works (same UTF8 path)"

# 43) KeyFile with same content as Password
$keyFile43 = New-TempPath '.key'
Set-Content -LiteralPath $keyFile43 -Value $secret -NoNewline
$enc43 = Protect-JsonCryptString -Plaintext "cross-key-test3" -KeyFile $keyFile43
$dec43 = Unprotect-JsonCryptString -EncryptedString $enc43 -Password $secret
Assert-True ($dec43 -eq "cross-key-test3") "KeyFile encrypt -> Password decrypt works (same content)"
Remove-Item -LiteralPath $keyFile43 -Force

# 44) EnvironmentVariable with same content as Password
[System.Environment]::SetEnvironmentVariable('PSJSONCRYPT_SEC_TEST', $secret)
$enc44 = Protect-JsonCryptString -Plaintext "cross-key-test4" -EnvironmentVariable 'PSJSONCRYPT_SEC_TEST'
$dec44 = Unprotect-JsonCryptString -EncryptedString $enc44 -Password $secret
Assert-True ($dec44 -eq "cross-key-test4") "EnvVar encrypt -> Password decrypt works (same content)"
[System.Environment]::SetEnvironmentVariable('PSJSONCRYPT_SEC_TEST', $null)

# 45) KeyFile trims whitespace but Password does not -- they differ for padded content
$keyFile45 = New-TempPath '.key'
Set-Content -LiteralPath $keyFile45 -Value "  secret-with-spaces  " -NoNewline
$enc45 = Protect-JsonCryptString -Plaintext "trim-test" -KeyFile $keyFile45
# KeyFile trims to "secret-with-spaces", Password uses raw "  secret-with-spaces  "
Assert-Throws { Unprotect-JsonCryptString -EncryptedString $enc45 -Password "  secret-with-spaces  " } `
    "KeyFile trims whitespace but Password does not -- mismatch fails MAC" `
    "MAC verification failed"
# But using the trimmed version should work
$dec45 = Unprotect-JsonCryptString -EncryptedString $enc45 -Password "secret-with-spaces"
Assert-True ($dec45 -eq "trim-test") "KeyFile trimmed content matches Password without spaces"
Remove-Item -LiteralPath $keyFile45 -Force

Write-Host ""

# ────────────────────────────────────────────────────────────────
# SECTION 10: Error Message Information Leakage
# ────────────────────────────────────────────────────────────────
Write-Host "--- Error Message Analysis ---" -ForegroundColor Yellow

# 47) Wrong password error does not reveal key material or plaintext
$enc47 = Protect-JsonCryptString -Plaintext "sensitive-data-here" -Password "correct"
$errorMsg47 = ""
try {
    Unprotect-JsonCryptString -EncryptedString $enc47 -Password "wrong"
} catch {
    $errorMsg47 = $_.Exception.Message
}
Assert-True ($errorMsg47 -notlike "*sensitive*") "Error message does not leak plaintext"
Assert-True ($errorMsg47 -notlike "*correct*") "Error message does not leak correct password"
Assert-True ($errorMsg47 -like "*MAC verification failed*") "Error message is the expected generic MAC failure"

# 48) Invalid JSON error is generic
$errorMsg48 = ""
try {
    Unprotect-JsonCryptString -EncryptedString "not{json" -Password "pw"
} catch {
    $errorMsg48 = $_.Exception.Message
}
Assert-True ($errorMsg48 -eq "Invalid encrypted data: not valid JSON.") "Invalid JSON error is generic"

# 49) Base64 error is generic
$env49 = Get-ValidEnvelope
$env49.salt = "not!valid!base64!"
$errorMsg49 = ""
try {
    Unprotect-JsonCryptString -EncryptedString (ConvertTo-EnvelopeJson $env49) -Password "pw"
} catch {
    $errorMsg49 = $_.Exception.Message
}
Assert-True ($errorMsg49 -like "*invalid base64*") "Base64 error message is generic"
Assert-True ($errorMsg49 -notlike "*FormatException*") "Base64 error does not leak .NET exception type"

Write-Host ""

# ────────────────────────────────────────────────────────────────
# SECTION 11: Envelope Structural Edge Cases
# ────────────────────────────────────────────────────────────────
Write-Host "--- Envelope Structural Edge Cases ---" -ForegroundColor Yellow

# 50) Extra fields in envelope are accepted (informational - Finding 5)
$env50 = Get-ValidEnvelope
$extraJson = '{"version":1,"salt":"' + $env50.salt + '","iv":"' + $env50.iv + '","ciphertext":"' + $env50.ciphertext + '","mac":"' + $env50.mac + '","extra":"injected","another":123}'
$dec50 = Unprotect-JsonCryptString -EncryptedString $extraJson -Password "test-password"
Assert-True ($dec50 -eq "test-plaintext") "Extra envelope fields are silently ignored (Finding 5)"

# 51) Reordered fields still work (JSON is unordered)
$env51 = Get-ValidEnvelope
$reorderedJson = '{"mac":"' + $env51.mac + '","ciphertext":"' + $env51.ciphertext + '","iv":"' + $env51.iv + '","salt":"' + $env51.salt + '","version":1}'
$dec51 = Unprotect-JsonCryptString -EncryptedString $reorderedJson -Password "test-password"
Assert-True ($dec51 -eq "test-plaintext") "Reordered envelope fields work correctly"

# 52) Completely empty JSON object
Assert-Throws { Unprotect-JsonCryptString -EncryptedString '{}' -Password "pw" } `
    "Empty JSON object is rejected" `
    "Unsupported or missing envelope version"

# 53) JSON array instead of object
Assert-Throws { Unprotect-JsonCryptString -EncryptedString '[1,2,3]' -Password "pw" } `
    "JSON array instead of object is rejected" `
    "Unsupported or missing envelope version"

# 54) JSON with only version
Assert-Throws { Unprotect-JsonCryptString -EncryptedString '{"version":1}' -Password "pw" } `
    "JSON with only version is rejected" `
    "missing or empty"

# 55) Nested JSON object in ciphertext field
$env55 = Get-ValidEnvelope
$nestedJson = '{"version":1,"salt":"' + $env55.salt + '","iv":"' + $env55.iv + '","ciphertext":{"nested":"value"},"mac":"' + $env55.mac + '"}'
Assert-Throws { Unprotect-JsonCryptString -EncryptedString $nestedJson -Password "test-password" } `
    "Nested object in ciphertext is rejected" `
    "missing or empty"

Write-Host ""

# ────────────────────────────────────────────────────────────────
# SECTION 12: Replay and Substitution Attacks
# ────────────────────────────────────────────────────────────────
Write-Host "--- Replay and Substitution ---" -ForegroundColor Yellow

# 56) Two encryptions of same plaintext with same password produce different envelopes
$enc56a = Protect-JsonCryptString -Plaintext "same" -Password "same-pw"
$enc56b = Protect-JsonCryptString -Plaintext "same" -Password "same-pw"
Assert-True ($enc56a -ne $enc56b) "Same plaintext+password produces different ciphertexts (random salt/IV)"

# 57) Cannot substitute ciphertext from one envelope into another (different salt -> different key)
$env57a = Get-ValidEnvelope -Plaintext "message-A" -Password "pw"
$env57b = Get-ValidEnvelope -Plaintext "message-B" -Password "pw"
# Substitute B's ciphertext into A's envelope
$env57a.ciphertext = $env57b.ciphertext
Assert-Throws { Unprotect-JsonCryptString -EncryptedString (ConvertTo-EnvelopeJson $env57a) -Password "pw" } `
    "Ciphertext substitution between envelopes fails MAC" `
    "MAC verification failed"

# 58) Cannot substitute MAC from one envelope to another
$env58a = Get-ValidEnvelope -Plaintext "msg-A" -Password "pw"
$env58b = Get-ValidEnvelope -Plaintext "msg-B" -Password "pw"
$env58a.mac = $env58b.mac
Assert-Throws { Unprotect-JsonCryptString -EncryptedString (ConvertTo-EnvelopeJson $env58a) -Password "pw" } `
    "MAC substitution between envelopes fails" `
    "MAC verification failed"

Write-Host ""

# ────────────────────────────────────────────────────────────────
# SECTION 13: Encrypted Store Security
# ────────────────────────────────────────────────────────────────
Write-Host "--- Encrypted Store Security ---" -ForegroundColor Yellow

# 59) Encrypted store cannot be decrypted with wrong password
$store59 = New-JsonCryptStore
Add-JsonCryptItem -Store $store59 -Name "secret" -Item @{ key = "value" }
$tmpEnc59 = New-TempPath '.enc'
Save-JsonCryptStore -Store $store59 -Path $tmpEnc59 -Password "correct-pw"
Assert-Throws { Import-JsonCryptStore -Path $tmpEnc59 -Password "wrong-pw" } `
    "Encrypted store rejects wrong password" `
    "MAC verification failed"
Remove-Item -LiteralPath $tmpEnc59 -Force

# 60) Encrypted store file content looks like a JSON envelope (not plaintext)
$store60 = New-JsonCryptStore
Add-JsonCryptItem -Store $store60 -Name "sensitive" -Item @{ password = "hunter2" }
$tmpEnc60 = New-TempPath '.enc'
Save-JsonCryptStore -Store $store60 -Path $tmpEnc60 -Password "pw"
$rawContent60 = Get-Content -LiteralPath $tmpEnc60 -Raw
Assert-True ($rawContent60 -notlike "*hunter2*") "Encrypted store does not contain plaintext values"
Assert-True ($rawContent60 -notlike "*sensitive*") "Encrypted store does not contain plaintext keys"
$parsedRaw60 = $rawContent60 | ConvertFrom-Json
Assert-True ($null -ne $parsedRaw60.version -and $null -ne $parsedRaw60.salt -and $null -ne $parsedRaw60.mac) "Encrypted store file is a valid envelope"
Remove-Item -LiteralPath $tmpEnc60 -Force

Write-Host ""

# ────────────────────────────────────────────────────────────────
# SECTION 14: Special Characters in Plaintext
# ────────────────────────────────────────────────────────────────
Write-Host "--- Special Characters ---" -ForegroundColor Yellow

# 61) JSON special characters in plaintext
$jsonSpecial = '{"key":"value","array":[1,2,3],"nested":{"a":"b"}}'
$enc61 = Protect-JsonCryptString -Plaintext $jsonSpecial -Password "pw"
$dec61 = Unprotect-JsonCryptString -EncryptedString $enc61 -Password "pw"
Assert-True ($dec61 -eq $jsonSpecial) "JSON string as plaintext roundtrips correctly"

# 62) Backslashes and escape sequences
$escapeText = 'C:\Users\admin\path\to\file "quoted" and' + "`t" + "tab" + "`n" + "newline"
$enc62 = Protect-JsonCryptString -Plaintext $escapeText -Password "pw"
$dec62 = Unprotect-JsonCryptString -EncryptedString $enc62 -Password "pw"
Assert-True ($dec62 -eq $escapeText) "Backslashes and escape chars roundtrip correctly"

# 63) Single character plaintext
$enc63 = Protect-JsonCryptString -Plaintext "x" -Password "pw"
$dec63 = Unprotect-JsonCryptString -EncryptedString $enc63 -Password "pw"
Assert-True ($dec63 -eq "x") "Single character plaintext roundtrips correctly"

# 64) Very long password (> 64 bytes, longer than HMAC block size)
$longPw = "A" * 1000
$enc64 = Protect-JsonCryptString -Plaintext "long-pw-test" -Password $longPw
$dec64 = Unprotect-JsonCryptString -EncryptedString $enc64 -Password $longPw
Assert-True ($dec64 -eq "long-pw-test") "Very long password (1000 chars) works correctly"

# 65) Password with only whitespace
$wsPw = "   "
$enc65 = Protect-JsonCryptString -Plaintext "ws-pw-test" -Password $wsPw
$dec65 = Unprotect-JsonCryptString -EncryptedString $enc65 -Password $wsPw
Assert-True ($dec65 -eq "ws-pw-test") "Whitespace-only password works correctly"

Write-Host ""

# ────────────────────────────────────────────────────────────────
# SECTION 15: Constant-Time MAC Comparison
# ────────────────────────────────────────────────────────────────
Write-Host "--- Constant-Time Comparison Verification ---" -ForegroundColor Yellow

# 66) MAC differing in first byte is rejected
$env66 = Get-ValidEnvelope
$macBytes66 = [System.Convert]::FromBase64String($env66.mac)
$macBytes66[0] = $macBytes66[0] -bxor 0xFF
$env66.mac = [System.Convert]::ToBase64String($macBytes66)
Assert-Throws { Unprotect-JsonCryptString -EncryptedString (ConvertTo-EnvelopeJson $env66) -Password "test-password" } `
    "MAC differing in first byte is rejected" `
    "MAC verification failed"

# 67) MAC differing in last byte is rejected
$env67 = Get-ValidEnvelope
$macBytes67 = [System.Convert]::FromBase64String($env67.mac)
$macBytes67[31] = $macBytes67[31] -bxor 0xFF
$env67.mac = [System.Convert]::ToBase64String($macBytes67)
Assert-Throws { Unprotect-JsonCryptString -EncryptedString (ConvertTo-EnvelopeJson $env67) -Password "test-password" } `
    "MAC differing in last byte is rejected" `
    "MAC verification failed"

# 68) MAC differing in middle byte is rejected
$env68 = Get-ValidEnvelope
$macBytes68 = [System.Convert]::FromBase64String($env68.mac)
$macBytes68[15] = $macBytes68[15] -bxor 0xFF
$env68.mac = [System.Convert]::ToBase64String($macBytes68)
Assert-Throws { Unprotect-JsonCryptString -EncryptedString (ConvertTo-EnvelopeJson $env68) -Password "test-password" } `
    "MAC differing in middle byte is rejected" `
    "MAC verification failed"

# 69) Completely random MAC is rejected
$env69 = Get-ValidEnvelope
$randomMac = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($randomMac)
$rng.Dispose()
$env69.mac = [System.Convert]::ToBase64String($randomMac)
Assert-Throws { Unprotect-JsonCryptString -EncryptedString (ConvertTo-EnvelopeJson $env69) -Password "test-password" } `
    "Completely random MAC is rejected" `
    "MAC verification failed"

Write-Host ""

# ────────────────────────────────────────────────────────────────
# SECTION 16: File Permission Security
# ────────────────────────────────────────────────────────────────
Write-Host "--- File Permissions ---" -ForegroundColor Yellow

# 70) Saved store file has restricted permissions (Unix: 600)
$isUnix = ($PSVersionTable.PSEdition -eq 'Core') -and
          (-not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
              [System.Runtime.InteropServices.OSPlatform]::Windows))

$store70 = New-JsonCryptStore
Add-JsonCryptItem -Store $store70 -Name "test" -Item "value"
$tmpPerm = New-TempPath '.enc'
Save-JsonCryptStore -Store $store70 -Path $tmpPerm -Password "pw"

if ($isUnix) {
    $perms = (stat -c '%a' $tmpPerm)
    Assert-True ($perms -eq "600") "Saved store file has Unix permissions 600 (got: $perms)"
} else {
    Write-Host "SKIP: Unix permission test (running on Windows)" -ForegroundColor DarkGray
}
Remove-Item -LiteralPath $tmpPerm -Force

Write-Host ""

# ────────────────────────────────────────────────────────────────
# Summary
# ────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Security Test Results" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total passed: $passed" -ForegroundColor Green
Write-Host "Total failed: $failed" -ForegroundColor Red
Write-Host ""

if ($failed -gt 0) {
    Write-Host "NOTE: Some 'PASS' results above document confirmed bugs (prefixed with BUG-)." -ForegroundColor Yellow
    Write-Host "These tests pass because they verify the current (buggy) behavior exists." -ForegroundColor Yellow
    exit 1
}

Write-Host "All security tests passed." -ForegroundColor Green
Write-Host "NOTE: Tests prefixed with 'BUG-' document known issues that should be fixed." -ForegroundColor Yellow

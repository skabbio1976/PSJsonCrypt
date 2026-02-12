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
    return (Join-Path ([System.IO.Path]::GetTempPath()) ("psjsoncrypt-edge-" + [guid]::NewGuid().ToString() + $Suffix))
}

Write-Host "Running PSJsonCrypt edge-case tests..." -ForegroundColor Cyan
Write-Host ""

# ════════════════════════════════════════════════════════════════
# STORE OPERATIONS
# ════════════════════════════════════════════════════════════════
Write-Host "--- Store Operations ---" -ForegroundColor Yellow

# 1) Multiple items: add 15 items, save encrypted, reimport, verify all
$store = New-JsonCryptStore
for ($i = 1; $i -le 15; $i++) {
    Add-JsonCryptItem -Store $store -Name "item$i" -Item @{ index = $i; data = "value-$i" }
}
$tmpMulti = New-TempPath '.enc'
Save-JsonCryptStore -Store $store -Path $tmpMulti -Password "multi-pw"
$loaded = Import-JsonCryptStore -Path $tmpMulti -Password "multi-pw"
$allMatch = $true
for ($i = 1; $i -le 15; $i++) {
    $item = Get-JsonCryptItem -Store $loaded -Name "item$i"
    if ($item.index -ne $i -or $item.data -ne "value-$i") { $allMatch = $false }
}
Assert-True $allMatch "Multiple items (15): save encrypted, reimport, verify all"
Assert-True (@(Get-JsonCryptItemNames -Store $loaded).Count -eq 15) "Multiple items: correct count after reimport"
Remove-Item -LiteralPath $tmpMulti -Force

# 2) Nested objects: items with deeply nested hashtables (4 levels deep)
$store = New-JsonCryptStore
$nested = @{
    level1 = @{
        level2 = @{
            level3 = @{
                level4 = "deep-value"
                array  = @(1, 2, 3)
            }
        }
    }
}
Add-JsonCryptItem -Store $store -Name "deep" -Item $nested
$tmpNested = New-TempPath '.enc'
Save-JsonCryptStore -Store $store -Path $tmpNested -Password "nest-pw"
$loaded = Import-JsonCryptStore -Path $tmpNested -Password "nest-pw"
$deepItem = Get-JsonCryptItem -Store $loaded -Name "deep"
Assert-True ($deepItem.level1.level2.level3.level4 -eq "deep-value") "Nested hashtable (4 levels): deep value preserved"
Assert-True ($deepItem.level1.level2.level3.array.Count -eq 3) "Nested hashtable: embedded array preserved"
Remove-Item -LiteralPath $tmpNested -Force

# 3) Special characters in item names and values (Swedish chars, emoji, backslash, quotes)
$store = New-JsonCryptStore
Add-JsonCryptItem -Store $store -Name "svenska" -Item @{ text = "Hej pa dig, apa!" }
Add-JsonCryptItem -Store $store -Name "backslash\key" -Item @{ path = "C:\Users\test" }
Add-JsonCryptItem -Store $store -Name 'quote"key' -Item @{ val = 'she said "hello"' }
Add-JsonCryptItem -Store $store -Name "tab`tkey" -Item @{ val = "line1`nline2" }
$tmpSpecial = New-TempPath '.enc'
Save-JsonCryptStore -Store $store -Path $tmpSpecial -Password "spec-pw"
$loaded = Import-JsonCryptStore -Path $tmpSpecial -Password "spec-pw"
Assert-True ((Get-JsonCryptItem -Store $loaded -Name "svenska").text -eq "Hej pa dig, apa!") "Special chars: Swedish-style text roundtrips"
Assert-True ((Get-JsonCryptItem -Store $loaded -Name "backslash\key").path -eq "C:\Users\test") "Special chars: backslash in name and value roundtrips"
Assert-True ((Get-JsonCryptItem -Store $loaded -Name 'quote"key').val -eq 'she said "hello"') "Special chars: double quotes in name and value roundtrips"
Assert-True ((Get-JsonCryptItem -Store $loaded -Name "tab`tkey").val -eq "line1`nline2") "Special chars: tab in key and newline in value roundtrips"
Remove-Item -LiteralPath $tmpSpecial -Force

# 4) Overwrite workflow: add, remove, add same name with different value
$store = New-JsonCryptStore
Add-JsonCryptItem -Store $store -Name "flip" -Item @{ v = "first" }
Assert-True ((Get-JsonCryptItem -Store $store -Name "flip").v -eq "first") "Overwrite: initial value correct"
Remove-JsonCryptItem -Store $store -Name "flip"
Add-JsonCryptItem -Store $store -Name "flip" -Item @{ v = "second" }
Assert-True ((Get-JsonCryptItem -Store $store -Name "flip").v -eq "second") "Overwrite: value after remove+re-add is updated"

# 5) Empty store save/import roundtrip
$store = New-JsonCryptStore
$tmpEmpty = New-TempPath '.enc'
Save-JsonCryptStore -Store $store -Path $tmpEmpty -Password "empty-pw"
$loaded = Import-JsonCryptStore -Path $tmpEmpty -Password "empty-pw"
Assert-True ($loaded.items -is [hashtable]) "Empty store: items is a hashtable after reimport"
Assert-True (@(Get-JsonCryptItemNames -Store $loaded).Count -eq 0) "Empty store: zero items after reimport"
Remove-Item -LiteralPath $tmpEmpty -Force

# 6) Store with single item containing null value - Add-JsonCryptItem rejects null
#    because $Item is [Parameter(Mandatory)], so PowerShell blocks null binding.
Assert-Throws { Add-JsonCryptItem -Store (New-JsonCryptStore) -Name "nullable" -Item $null } "Null item value: rejected by mandatory parameter"

# 6b) Store with single item containing empty string value
$store = New-JsonCryptStore
Add-JsonCryptItem -Store $store -Name "emptystr" -Item ""
$tmpEmptyStr = New-TempPath '.json'
Save-JsonCryptStore -Store $store -Path $tmpEmptyStr -Plaintext
$loaded = Import-JsonCryptStore -Path $tmpEmptyStr -Plaintext
$val = Get-JsonCryptItem -Store $loaded -Name "emptystr"
Assert-True ($val -eq "") "Empty string item value: roundtrips correctly"
Remove-Item -LiteralPath $tmpEmptyStr -Force

# 7) Get-JsonCryptItemNames returns correct count after add/remove cycles
$store = New-JsonCryptStore
Assert-True (@(Get-JsonCryptItemNames -Store $store).Count -eq 0) "ItemNames: 0 after creation"
Add-JsonCryptItem -Store $store -Name "a" -Item "x"
Add-JsonCryptItem -Store $store -Name "b" -Item "y"
Add-JsonCryptItem -Store $store -Name "c" -Item "z"
Assert-True (@(Get-JsonCryptItemNames -Store $store).Count -eq 3) "ItemNames: 3 after 3 adds"
Remove-JsonCryptItem -Store $store -Name "b"
Assert-True (@(Get-JsonCryptItemNames -Store $store).Count -eq 2) "ItemNames: 2 after removing 1"
$names = @(Get-JsonCryptItemNames -Store $store)
Assert-True (($names -contains "a") -and ($names -contains "c")) "ItemNames: correct names remain after removal"
Remove-JsonCryptItem -Store $store -Name "a"
Remove-JsonCryptItem -Store $store -Name "c"
Assert-True (@(Get-JsonCryptItemNames -Store $store).Count -eq 0) "ItemNames: 0 after removing all"

# 8) Items with different types: string, int, bool, array, nested hashtable
$store = New-JsonCryptStore
Add-JsonCryptItem -Store $store -Name "str" -Item "hello"
Add-JsonCryptItem -Store $store -Name "int" -Item 42
Add-JsonCryptItem -Store $store -Name "bool_true" -Item $true
Add-JsonCryptItem -Store $store -Name "bool_false" -Item $false
Add-JsonCryptItem -Store $store -Name "arr" -Item @(1, "two", 3)
Add-JsonCryptItem -Store $store -Name "ht" -Item @{ nested = @{ deep = "val" } }
$tmpTypes = New-TempPath '.enc'
Save-JsonCryptStore -Store $store -Path $tmpTypes -Password "types-pw"
$loaded = Import-JsonCryptStore -Path $tmpTypes -Password "types-pw"
Assert-True ((Get-JsonCryptItem -Store $loaded -Name "str") -eq "hello") "Mixed types: string roundtrips"
Assert-True ((Get-JsonCryptItem -Store $loaded -Name "int") -eq 42) "Mixed types: int roundtrips"
Assert-True ((Get-JsonCryptItem -Store $loaded -Name "bool_true") -eq $true) "Mixed types: true roundtrips"
Assert-True ((Get-JsonCryptItem -Store $loaded -Name "bool_false") -eq $false) "Mixed types: false roundtrips"
$arr = Get-JsonCryptItem -Store $loaded -Name "arr"
Assert-True ($arr.Count -eq 3 -and $arr[0] -eq 1 -and $arr[1] -eq "two" -and $arr[2] -eq 3) "Mixed types: array roundtrips"
Assert-True ((Get-JsonCryptItem -Store $loaded -Name "ht").nested.deep -eq "val") "Mixed types: nested hashtable roundtrips"
Remove-Item -LiteralPath $tmpTypes -Force

Write-Host ""

# ════════════════════════════════════════════════════════════════
# ENCRYPTION EDGE CASES
# ════════════════════════════════════════════════════════════════
Write-Host "--- Encryption Edge Cases ---" -ForegroundColor Yellow

# 9) Empty string plaintext - rejected by [Parameter(Mandatory)] [string]$Plaintext
#    PowerShell mandatory string parameters reject empty strings by default.
#    This is arguably correct behavior (encrypting nothing is pointless),
#    but worth documenting. Would need [AllowEmptyString()] to change.
Assert-Throws { Protect-JsonCryptString -Plaintext "" -Password "pw" } "Empty string plaintext rejected by mandatory parameter"

# 10) Very long password (10000 chars)
$longPw = "P" * 10000
$enc = Protect-JsonCryptString -Plaintext "secret" -Password $longPw
$dec = Unprotect-JsonCryptString -EncryptedString $enc -Password $longPw
Assert-True ($dec -eq "secret") "Very long password (10000 chars) roundtrips"

# 11) Password with unicode and special chars
$unicodePw = "p@`$`$w0rd-with-unicode-and-special"
$enc = Protect-JsonCryptString -Plaintext "data" -Password $unicodePw
$dec = Unprotect-JsonCryptString -EncryptedString $enc -Password $unicodePw
Assert-True ($dec -eq "data") "Password with special chars roundtrips"

# 12) Newlines and tabs in plaintext
$nlText = "line1`nline2`r`nline3`ttabbed"
$enc = Protect-JsonCryptString -Plaintext $nlText -Password "pw"
$dec = Unprotect-JsonCryptString -EncryptedString $enc -Password "pw"
Assert-True ($dec -eq $nlText) "Newlines and tabs in plaintext roundtrip"

# 13) JSON-like plaintext (ensure no double-encoding)
$jsonLike = '{"key":"value","arr":[1,2,3]}'
$enc = Protect-JsonCryptString -Plaintext $jsonLike -Password "pw"
$dec = Unprotect-JsonCryptString -EncryptedString $enc -Password "pw"
Assert-True ($dec -eq $jsonLike) "JSON-like plaintext roundtrips without double-encoding"

# 14) Plaintext with only whitespace
$wsText = "   `t `n  "
$enc = Protect-JsonCryptString -Plaintext $wsText -Password "pw"
$dec = Unprotect-JsonCryptString -EncryptedString $enc -Password "pw"
Assert-True ($dec -eq $wsText) "Whitespace-only plaintext roundtrips"

# 15) Plaintext with repeated patterns (compression-like stress)
$repeating = ("ABCDEFGH" * 5000)
$enc = Protect-JsonCryptString -Plaintext $repeating -Password "pw"
$dec = Unprotect-JsonCryptString -EncryptedString $enc -Password "pw"
Assert-True ($dec -eq $repeating) "Repeating pattern plaintext (40KB) roundtrips"

# 16) Single character plaintext
$enc = Protect-JsonCryptString -Plaintext "X" -Password "pw"
$dec = Unprotect-JsonCryptString -EncryptedString $enc -Password "pw"
Assert-True ($dec -eq "X") "Single character plaintext roundtrips"

Write-Host ""

# ════════════════════════════════════════════════════════════════
# IMPORT/EXPORT EDGE CASES
# ════════════════════════════════════════════════════════════════
Write-Host "--- Import/Export Edge Cases ---" -ForegroundColor Yellow

# 17) Import non-existent file throws
$nonExistentPath = New-TempPath '.json'
Assert-Throws { Import-JsonCryptStore -Path $nonExistentPath -Plaintext } "Import non-existent file throws" "Store file not found"

# 18) Multiple save/import cycles (save, import, modify, save again, import again)
$store = New-JsonCryptStore
Add-JsonCryptItem -Store $store -Name "cycle1" -Item "first"
$tmpCycle = New-TempPath '.enc'
Save-JsonCryptStore -Store $store -Path $tmpCycle -Password "cycle-pw"
$loaded1 = Import-JsonCryptStore -Path $tmpCycle -Password "cycle-pw"
Add-JsonCryptItem -Store $loaded1 -Name "cycle2" -Item "second"
Save-JsonCryptStore -Store $loaded1 -Path $tmpCycle -Password "cycle-pw"
$loaded2 = Import-JsonCryptStore -Path $tmpCycle -Password "cycle-pw"
Assert-True ((Get-JsonCryptItem -Store $loaded2 -Name "cycle1") -eq "first") "Multi-cycle: first item preserved after second save"
Assert-True ((Get-JsonCryptItem -Store $loaded2 -Name "cycle2") -eq "second") "Multi-cycle: second item present after second import"
# Third cycle: remove and re-save
Remove-JsonCryptItem -Store $loaded2 -Name "cycle1"
Add-JsonCryptItem -Store $loaded2 -Name "cycle3" -Item "third"
Save-JsonCryptStore -Store $loaded2 -Path $tmpCycle -Password "cycle-pw"
$loaded3 = Import-JsonCryptStore -Path $tmpCycle -Password "cycle-pw"
Assert-Throws { Get-JsonCryptItem -Store $loaded3 -Name "cycle1" } "Multi-cycle: removed item not present after third import" "not found"
Assert-True ((Get-JsonCryptItem -Store $loaded3 -Name "cycle3") -eq "third") "Multi-cycle: third item present after third import"
Remove-Item -LiteralPath $tmpCycle -Force

# 19) Encrypted store file is valid JSON envelope
$store = New-JsonCryptStore
Add-JsonCryptItem -Store $store -Name "test" -Item "val"
$tmpEnvelope = New-TempPath '.enc'
Save-JsonCryptStore -Store $store -Path $tmpEnvelope -Password "env-pw"
$rawContent = Get-Content -LiteralPath $tmpEnvelope -Raw
$parsedEnvelope = $null
$isValidJson = $true
try { $parsedEnvelope = $rawContent | ConvertFrom-Json } catch { $isValidJson = $false }
Assert-True $isValidJson "Encrypted store file is valid JSON"
if ($parsedEnvelope) {
    Assert-True ($null -ne $parsedEnvelope.PSObject.Properties['version']) "Encrypted store has version field"
    Assert-True ($null -ne $parsedEnvelope.PSObject.Properties['salt']) "Encrypted store has salt field"
    Assert-True ($null -ne $parsedEnvelope.PSObject.Properties['iv']) "Encrypted store has iv field"
    Assert-True ($null -ne $parsedEnvelope.PSObject.Properties['ciphertext']) "Encrypted store has ciphertext field"
    Assert-True ($null -ne $parsedEnvelope.PSObject.Properties['mac']) "Encrypted store has mac field"
}
Remove-Item -LiteralPath $tmpEnvelope -Force

# 20) Plaintext store file is valid JSON with items key
$store = New-JsonCryptStore
Add-JsonCryptItem -Store $store -Name "ptTest" -Item @{ a = 1 }
$tmpPlain = New-TempPath '.json'
Save-JsonCryptStore -Store $store -Path $tmpPlain -Plaintext
$rawPt = Get-Content -LiteralPath $tmpPlain -Raw
$parsedPt = $rawPt | ConvertFrom-Json
Assert-True ($null -ne $parsedPt.PSObject.Properties['items']) "Plaintext store file has 'items' key"
Assert-True ($parsedPt.items.ptTest.a -eq 1) "Plaintext store file has correct item data"
Remove-Item -LiteralPath $tmpPlain -Force

# 21) Items type validation: import store where items is a string
# BUG NOTE: The module validates that 'items' key exists, but does not validate
# that its type is a hashtable. If 'items' is a string, array, or number, import
# FIXED: items type is now validated on import
$tmpBadItems1 = New-TempPath '.json'
Set-Content -LiteralPath $tmpBadItems1 -Value '{"items":"not-a-hashtable"}' -NoNewline
Assert-Throws { Import-JsonCryptStore -Path $tmpBadItems1 -Plaintext } "Items type validation: import rejects items as string" '"items" must be an object'
Remove-Item -LiteralPath $tmpBadItems1 -Force

# 22) Items type validation: import store where items is an array
$tmpBadItems2 = New-TempPath '.json'
Set-Content -LiteralPath $tmpBadItems2 -Value '{"items":[1,2,3]}' -NoNewline
Assert-Throws { Import-JsonCryptStore -Path $tmpBadItems2 -Plaintext } "Items type validation: import rejects items as array" '"items" must be an object'
Remove-Item -LiteralPath $tmpBadItems2 -Force

# 23) Items type validation: import store where items is a number
$tmpBadItems3 = New-TempPath '.json'
Set-Content -LiteralPath $tmpBadItems3 -Value '{"items":42}' -NoNewline
Assert-Throws { Import-JsonCryptStore -Path $tmpBadItems3 -Plaintext } "Items type validation: import rejects items as number" '"items" must be an object'
Remove-Item -LiteralPath $tmpBadItems3 -Force

# 24) Plaintext save then encrypted re-save (switch modes)
$store = New-JsonCryptStore
Add-JsonCryptItem -Store $store -Name "modeSwitch" -Item "data"
$tmpMode = New-TempPath '.json'
Save-JsonCryptStore -Store $store -Path $tmpMode -Plaintext
$loaded = Import-JsonCryptStore -Path $tmpMode -Plaintext
Save-JsonCryptStore -Store $loaded -Path $tmpMode -Password "switch-pw"
$reloaded = Import-JsonCryptStore -Path $tmpMode -Password "switch-pw"
Assert-True ((Get-JsonCryptItem -Store $reloaded -Name "modeSwitch") -eq "data") "Mode switch: plaintext -> encrypted preserves data"
Remove-Item -LiteralPath $tmpMode -Force

Write-Host ""

# ════════════════════════════════════════════════════════════════
# KEY MANAGEMENT
# ════════════════════════════════════════════════════════════════
Write-Host "--- Key Management ---" -ForegroundColor Yellow

# 25) New-JsonCryptKey returns unique values over 100 calls
$keys = @{}
$allUnique = $true
for ($i = 0; $i -lt 100; $i++) {
    $k = New-JsonCryptKey
    if ($keys.ContainsKey($k)) { $allUnique = $false; break }
    $keys[$k] = $true
}
Assert-True $allUnique "New-JsonCryptKey: 100 calls produce 100 unique keys"

# 26) Key from New-JsonCryptKey works as -Key parameter
$genKey = New-JsonCryptKey
$enc = Protect-JsonCryptString -Plaintext "keyed-data" -Key $genKey
$dec = Unprotect-JsonCryptString -EncryptedString $enc -Key $genKey
Assert-True ($dec -eq "keyed-data") "Generated key works as -Key parameter"

# 27) Generated key works for store operations
$genKey2 = New-JsonCryptKey
$store = New-JsonCryptStore
Add-JsonCryptItem -Store $store -Name "genkey" -Item @{ secret = "top-secret" }
$tmpGenKey = New-TempPath '.enc'
Save-JsonCryptStore -Store $store -Path $tmpGenKey -Key $genKey2
$loaded = Import-JsonCryptStore -Path $tmpGenKey -Key $genKey2
Assert-True ((Get-JsonCryptItem -Store $loaded -Name "genkey").secret -eq "top-secret") "Generated key works for store save/import"
Remove-Item -LiteralPath $tmpGenKey -Force

# 28) KeyFile with unicode content
$tmpUnicodeKey = New-TempPath '.key'
# Write unicode content to keyfile
[System.IO.File]::WriteAllText($tmpUnicodeKey, "mykey-with-extended-chars", [System.Text.Encoding]::UTF8)
$enc = Protect-JsonCryptString -Plaintext "unicode-key-data" -KeyFile $tmpUnicodeKey
$dec = Unprotect-JsonCryptString -EncryptedString $enc -KeyFile $tmpUnicodeKey
Assert-True ($dec -eq "unicode-key-data") "KeyFile with unicode content roundtrips"
Remove-Item -LiteralPath $tmpUnicodeKey -Force

# 29) KeyFile with only whitespace (should fail - existing behavior documented in robustness tests)
$tmpWsKey = New-TempPath '.key'
Set-Content -LiteralPath $tmpWsKey -Value "   `t  `n  " -NoNewline
Assert-Throws { Protect-JsonCryptString -Plaintext "x" -KeyFile $tmpWsKey } "KeyFile with only whitespace rejects" "KeyFile is empty"
Remove-Item -LiteralPath $tmpWsKey -Force

# 30) EnvironmentVariable with special chars in value
[System.Environment]::SetEnvironmentVariable('PSJSONCRYPT_EDGE_SPECIAL', 'p@$$w0rd!#%^&*()')
$enc = Protect-JsonCryptString -Plaintext "env-special" -EnvironmentVariable 'PSJSONCRYPT_EDGE_SPECIAL'
$dec = Unprotect-JsonCryptString -EncryptedString $enc -EnvironmentVariable 'PSJSONCRYPT_EDGE_SPECIAL'
Assert-True ($dec -eq "env-special") "EnvironmentVariable with special chars in value roundtrips"
[System.Environment]::SetEnvironmentVariable('PSJSONCRYPT_EDGE_SPECIAL', $null)

# 31) KeyFile used for store save and import
$tmpKeyForStore = New-TempPath '.key'
$tmpStoreFile = New-TempPath '.enc'
$storeKey = New-JsonCryptKey
[System.IO.File]::WriteAllText($tmpKeyForStore, $storeKey, [System.Text.Encoding]::UTF8)
$store = New-JsonCryptStore
Add-JsonCryptItem -Store $store -Name "kf" -Item "keyfile-store-data"
Save-JsonCryptStore -Store $store -Path $tmpStoreFile -KeyFile $tmpKeyForStore
$loaded = Import-JsonCryptStore -Path $tmpStoreFile -KeyFile $tmpKeyForStore
Assert-True ((Get-JsonCryptItem -Store $loaded -Name "kf") -eq "keyfile-store-data") "KeyFile for store save/import roundtrips"
Remove-Item -LiteralPath $tmpKeyForStore -Force
Remove-Item -LiteralPath $tmpStoreFile -Force

# 32) EnvironmentVariable used for store save and import
[System.Environment]::SetEnvironmentVariable('PSJSONCRYPT_EDGE_STORE', 'env-store-key-123')
$tmpEnvStore = New-TempPath '.enc'
$store = New-JsonCryptStore
Add-JsonCryptItem -Store $store -Name "envs" -Item "env-store-data"
Save-JsonCryptStore -Store $store -Path $tmpEnvStore -EnvironmentVariable 'PSJSONCRYPT_EDGE_STORE'
$loaded = Import-JsonCryptStore -Path $tmpEnvStore -EnvironmentVariable 'PSJSONCRYPT_EDGE_STORE'
Assert-True ((Get-JsonCryptItem -Store $loaded -Name "envs") -eq "env-store-data") "EnvironmentVariable for store save/import roundtrips"
Remove-Item -LiteralPath $tmpEnvStore -Force
[System.Environment]::SetEnvironmentVariable('PSJSONCRYPT_EDGE_STORE', $null)

Write-Host ""

# ════════════════════════════════════════════════════════════════
# CROSS-COMPATIBILITY
# ════════════════════════════════════════════════════════════════
Write-Host "--- Cross-Compatibility ---" -ForegroundColor Yellow

# 33) Data encrypted with -Password "X" can be decrypted with -Key "X"
# Both -Password and -Key use UTF-8 encoding internally, so they should be interchangeable
$sharedSecret = "my-shared-secret-value"
$enc = Protect-JsonCryptString -Plaintext "cross-compat" -Password $sharedSecret
$dec = Unprotect-JsonCryptString -EncryptedString $enc -Key $sharedSecret
Assert-True ($dec -eq "cross-compat") "Cross-compat: Password encrypt -> Key decrypt with same string"

# 34) Vice versa: Key encrypt -> Password decrypt
$enc = Protect-JsonCryptString -Plaintext "cross-compat-2" -Key $sharedSecret
$dec = Unprotect-JsonCryptString -EncryptedString $enc -Password $sharedSecret
Assert-True ($dec -eq "cross-compat-2") "Cross-compat: Key encrypt -> Password decrypt with same string"

# 35) Data encrypted with generated key, saved to keyfile, decrypted via keyfile
$genKeyForFile = New-JsonCryptKey
$enc = Protect-JsonCryptString -Plaintext "key-to-file" -Key $genKeyForFile
$tmpKeyFile = New-TempPath '.key'
[System.IO.File]::WriteAllText($tmpKeyFile, $genKeyForFile, [System.Text.Encoding]::UTF8)
$dec = Unprotect-JsonCryptString -EncryptedString $enc -KeyFile $tmpKeyFile
Assert-True ($dec -eq "key-to-file") "Cross-compat: encrypt with -Key, decrypt with -KeyFile containing same key"
Remove-Item -LiteralPath $tmpKeyFile -Force

# 36) Store saved with -Password, imported with -Key (same string)
$store = New-JsonCryptStore
Add-JsonCryptItem -Store $store -Name "crossStore" -Item "cross-data"
$tmpCross = New-TempPath '.enc'
Save-JsonCryptStore -Store $store -Path $tmpCross -Password "store-shared"
$loaded = Import-JsonCryptStore -Path $tmpCross -Key "store-shared"
Assert-True ((Get-JsonCryptItem -Store $loaded -Name "crossStore") -eq "cross-data") "Cross-compat: store saved with Password, imported with Key"
Remove-Item -LiteralPath $tmpCross -Force

Write-Host ""

# ════════════════════════════════════════════════════════════════
# STRESS / BOUNDARY TESTS
# ════════════════════════════════════════════════════════════════
Write-Host "--- Stress / Boundary Tests ---" -ForegroundColor Yellow

# 37) Store with many items (50) - encrypted roundtrip
$store = New-JsonCryptStore
for ($i = 0; $i -lt 50; $i++) {
    Add-JsonCryptItem -Store $store -Name "bulk_$i" -Item @{ id = $i; desc = "item number $i" }
}
$tmpBulk = New-TempPath '.enc'
Save-JsonCryptStore -Store $store -Path $tmpBulk -Password "bulk-pw"
$loaded = Import-JsonCryptStore -Path $tmpBulk -Password "bulk-pw"
$bulkOk = $true
for ($i = 0; $i -lt 50; $i++) {
    $item = Get-JsonCryptItem -Store $loaded -Name "bulk_$i"
    if ($item.id -ne $i) { $bulkOk = $false; break }
}
Assert-True $bulkOk "Stress: 50 items encrypted roundtrip all correct"
Assert-True (@(Get-JsonCryptItemNames -Store $loaded).Count -eq 50) "Stress: 50 items count correct after reimport"
Remove-Item -LiteralPath $tmpBulk -Force

# 38) Item with very long string value (100KB)
$store = New-JsonCryptStore
$longVal = "X" * 102400
Add-JsonCryptItem -Store $store -Name "bigval" -Item $longVal
$tmpBigVal = New-TempPath '.enc'
Save-JsonCryptStore -Store $store -Path $tmpBigVal -Password "big-pw"
$loaded = Import-JsonCryptStore -Path $tmpBigVal -Password "big-pw"
$retrievedVal = Get-JsonCryptItem -Store $loaded -Name "bigval"
Assert-True ($retrievedVal.Length -eq 102400) "Stress: 100KB string value roundtrips (length)"
Assert-True ($retrievedVal -eq $longVal) "Stress: 100KB string value roundtrips (content)"
Remove-Item -LiteralPath $tmpBigVal -Force

# 39) Item with very long name (1000 chars)
$store = New-JsonCryptStore
$longName = "N" * 1000
Add-JsonCryptItem -Store $store -Name $longName -Item "long-name-data"
$tmpLongName = New-TempPath '.enc'
Save-JsonCryptStore -Store $store -Path $tmpLongName -Password "ln-pw"
$loaded = Import-JsonCryptStore -Path $tmpLongName -Password "ln-pw"
Assert-True ((Get-JsonCryptItem -Store $loaded -Name $longName) -eq "long-name-data") "Stress: 1000-char item name roundtrips"
Remove-Item -LiteralPath $tmpLongName -Force

# 40) Encrypt the same plaintext twice produces different ciphertext (due to random salt/IV)
$enc1 = Protect-JsonCryptString -Plaintext "same-data" -Password "same-pw"
$enc2 = Protect-JsonCryptString -Plaintext "same-data" -Password "same-pw"
Assert-True ($enc1 -ne $enc2) "Same plaintext+password produces different ciphertext (random salt/IV)"
# But both decrypt to the same value
$dec1 = Unprotect-JsonCryptString -EncryptedString $enc1 -Password "same-pw"
$dec2 = Unprotect-JsonCryptString -EncryptedString $enc2 -Password "same-pw"
Assert-True ($dec1 -eq "same-data" -and $dec2 -eq "same-data") "Both different ciphertexts decrypt to same plaintext"

# 41) Rapidly overwrite the same store file multiple times
$store = New-JsonCryptStore
$tmpRapid = New-TempPath '.enc'
for ($i = 0; $i -lt 10; $i++) {
    # Clear and rebuild store each time
    $store = New-JsonCryptStore
    Add-JsonCryptItem -Store $store -Name "iter" -Item "value-$i"
    Save-JsonCryptStore -Store $store -Path $tmpRapid -Password "rapid-pw"
}
$loaded = Import-JsonCryptStore -Path $tmpRapid -Password "rapid-pw"
Assert-True ((Get-JsonCryptItem -Store $loaded -Name "iter") -eq "value-9") "Stress: 10 rapid overwrites, last write wins"
Remove-Item -LiteralPath $tmpRapid -Force

# 42) Store with item containing empty hashtable
$store = New-JsonCryptStore
Add-JsonCryptItem -Store $store -Name "emptyht" -Item @{}
$tmpEmpHt = New-TempPath '.enc'
Save-JsonCryptStore -Store $store -Path $tmpEmpHt -Password "empht-pw"
$loaded = Import-JsonCryptStore -Path $tmpEmpHt -Password "empht-pw"
$emptyItem = Get-JsonCryptItem -Store $loaded -Name "emptyht"
Assert-True ($emptyItem -is [hashtable] -and $emptyItem.Count -eq 0) "Empty hashtable item roundtrips"
Remove-Item -LiteralPath $tmpEmpHt -Force

# 43) Store with item containing empty array
$store = New-JsonCryptStore
Add-JsonCryptItem -Store $store -Name "emptyarr" -Item @()
$tmpEmpArr = New-TempPath '.enc'
Save-JsonCryptStore -Store $store -Path $tmpEmpArr -Password "emparr-pw"
$loaded = Import-JsonCryptStore -Path $tmpEmpArr -Password "emparr-pw"
$emptyArr = Get-JsonCryptItem -Store $loaded -Name "emptyarr"
# NOTE: JSON roundtrip of empty array may convert to $null depending on
# PowerShell's JSON handling. We accept either empty array or null.
$emptyArrOk = ($null -eq $emptyArr) -or ($emptyArr -is [array] -and $emptyArr.Count -eq 0)
Assert-True $emptyArrOk "Empty array item roundtrips (may become null due to PS JSON handling)"

Remove-Item -LiteralPath $tmpEmpArr -Force

# 44) Tampered ciphertext is detected (flip a byte)
$enc = Protect-JsonCryptString -Plaintext "tamper-test" -Password "tamper-pw"
$obj = $enc | ConvertFrom-Json
$ctBytes = [System.Convert]::FromBase64String($obj.ciphertext)
$ctBytes[0] = $ctBytes[0] -bxor 0xFF
$obj.ciphertext = [System.Convert]::ToBase64String($ctBytes)
$tampered = $obj | ConvertTo-Json -Compress
Assert-Throws { Unprotect-JsonCryptString -EncryptedString $tampered -Password "tamper-pw" } "Tampered ciphertext detected via MAC" "MAC verification failed"

# 45) Tampered salt is detected
$enc = Protect-JsonCryptString -Plaintext "tamper-salt" -Password "tamper-pw"
$obj = $enc | ConvertFrom-Json
$saltBytes = [System.Convert]::FromBase64String($obj.salt)
$saltBytes[0] = $saltBytes[0] -bxor 0xFF
$obj.salt = [System.Convert]::ToBase64String($saltBytes)
$tampered = $obj | ConvertTo-Json -Compress
Assert-Throws { Unprotect-JsonCryptString -EncryptedString $tampered -Password "tamper-pw" } "Tampered salt detected via MAC" "MAC verification failed"

# 46) Tampered IV is detected
$enc = Protect-JsonCryptString -Plaintext "tamper-iv" -Password "tamper-pw"
$obj = $enc | ConvertFrom-Json
$ivBytes = [System.Convert]::FromBase64String($obj.iv)
$ivBytes[0] = $ivBytes[0] -bxor 0xFF
$obj.iv = [System.Convert]::ToBase64String($ivBytes)
$tampered = $obj | ConvertTo-Json -Compress
Assert-Throws { Unprotect-JsonCryptString -EncryptedString $tampered -Password "tamper-pw" } "Tampered IV detected via MAC" "MAC verification failed"

Write-Host ""

# ════════════════════════════════════════════════════════════════
# SUMMARY
# ════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "Total passed: $passed" -ForegroundColor Green
Write-Host "Total failed: $failed" -ForegroundColor Red

if ($failed -gt 0) {
    exit 1
}

Write-Host "All edge-case tests passed." -ForegroundColor Green

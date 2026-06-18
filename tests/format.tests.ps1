$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot '..' 'PSJsonCrypt.psd1') -Force

$passed = 0
$failed = 0

function Assert-True {
    param([Parameter(Mandatory)][bool]$Condition, [Parameter(Mandatory)][string]$Message)
    if ($Condition) {
        $script:passed++
        Write-Host "PASS: $Message" -ForegroundColor Green
    }
    else {
        $script:failed++
        Write-Host "FAIL: $Message" -ForegroundColor Red
    }
}

function Assert-Equal {
    param($Expected, $Actual, [Parameter(Mandatory)][string]$Message)
    Assert-True -Condition ($Expected -eq $Actual) -Message "$Message (expected '$Expected', got '$Actual')"
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("psjc-fmt-" + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null

try {
    # Build a representative store
    function New-SampleStore {
        $s = New-JsonCryptStore
        Add-JsonCryptItem -Store $s -Name 'prod' -Item @{
            host     = 'db.prod.example.com'
            username = 'admin'
            password = 's3cret'
            port     = 5432
            enabled  = $true
        }
        Add-JsonCryptItem -Store $s -Name 'tags' -Item @{
            roles = @('web', 'db', 'cache')
        }
        return $s
    }

    # ── TOML round-trip (encrypted, extension-detected) ──
    $store = New-SampleStore
    $tomlPath = Join-Path $tmp 'secrets.toml'
    Save-JsonCryptStore -Store $store -Path $tomlPath -Password 'pw'
    Assert-True -Condition (Test-Path $tomlPath) -Message 'TOML file created'

    $loaded = Import-JsonCryptStore -Path $tomlPath -Password 'pw'
    Assert-Equal 'db.prod.example.com' $loaded.items.prod.host     'TOML: prod.host round-trips'
    Assert-Equal 'admin'               $loaded.items.prod.username 'TOML: prod.username round-trips'
    Assert-Equal 's3cret'              $loaded.items.prod.password 'TOML: prod.password round-trips'
    Assert-Equal 5432                  $loaded.items.prod.port     'TOML: integer type preserved'
    Assert-True  -Condition ($loaded.items.prod.enabled -eq $true) -Message 'TOML: bool type preserved'
    Assert-True  -Condition ($loaded.items.prod.enabled -is [bool]) -Message 'TOML: bool is [bool]'
    Assert-Equal 3      $loaded.items.tags.roles.Count 'TOML: array length preserved'
    Assert-Equal 'web'  $loaded.items.tags.roles[0]    'TOML: array element 0'
    Assert-Equal 'cache' $loaded.items.tags.roles[2]   'TOML: array element 2'

    # ── INI round-trip (plaintext, extension-detected) ──
    $store = New-SampleStore
    $iniPath = Join-Path $tmp 'secrets.ini'
    Save-JsonCryptStore -Store $store -Path $iniPath -Plaintext
    Assert-True -Condition (Test-Path $iniPath) -Message 'INI file created'

    $loaded = Import-JsonCryptStore -Path $iniPath -Plaintext
    Assert-Equal 'db.prod.example.com' $loaded.items.prod.host     'INI: prod.host round-trips'
    Assert-Equal 'admin'               $loaded.items.prod.username 'INI: prod.username round-trips'
    Assert-Equal 's3cret'              $loaded.items.prod.password 'INI: prod.password round-trips'
    # INI is an untyped format → values come back as strings
    Assert-Equal '5432' $loaded.items.prod.port 'INI: numbers come back as strings'

    # ── Explicit -Format overrides extension ──
    $store = New-SampleStore
    $jsonExt = Join-Path $tmp 'data.json'
    Save-JsonCryptStore -Store $store -Path $jsonExt -Plaintext -Format Toml
    $content = Get-Content -LiteralPath $jsonExt -Raw
    Assert-True -Condition ($content -match '\[items\.prod\]') -Message '-Format Toml overrides .json extension'
    $loaded = Import-JsonCryptStore -Path $jsonExt -Plaintext -Format Toml
    Assert-Equal 'admin' $loaded.items.prod.username '-Format Toml import override works'

    # ── JSON still the default for unknown/other extensions ──
    $store = New-SampleStore
    $encPath = Join-Path $tmp 'data.enc'
    Save-JsonCryptStore -Store $store -Path $encPath -Password 'pw'
    $loaded = Import-JsonCryptStore -Path $encPath -Password 'pw'
    Assert-Equal 'admin' $loaded.items.prod.username 'JSON default for .enc extension'

    # ── Imported store has correct structure (items is a hashtable) ──
    Assert-True -Condition ($loaded.items -is [hashtable]) 'JSON: items is a hashtable'
    $tomlLoaded = Import-JsonCryptStore -Path $tomlPath -Password 'pw'
    Assert-True -Condition ($tomlLoaded.items -is [hashtable]) 'TOML: items is a hashtable'
    $iniLoaded = Import-JsonCryptStore -Path $iniPath -Plaintext
    Assert-True -Condition ($iniLoaded.items -is [hashtable]) 'INI: items is a hashtable'

    # ── Parse a hand-written TOML file ──
    $handToml = @'
[items.app]
name = "myapp"
retries = 3
debug = false
hosts = ["a.local", "b.local"]
'@
    $handTomlPath = Join-Path $tmp 'hand.toml'
    Set-Content -LiteralPath $handTomlPath -Value $handToml -Encoding UTF8
    $h = Import-JsonCryptStore -Path $handTomlPath -Plaintext
    Assert-Equal 'myapp' $h.items.app.name    'hand TOML: string'
    Assert-Equal 3       $h.items.app.retries 'hand TOML: int'
    Assert-True -Condition ($h.items.app.debug -eq $false) -Message 'hand TOML: bool false'
    Assert-Equal 2 $h.items.app.hosts.Count 'hand TOML: array'

    # ── Parse a hand-written INI file (with comments) ──
    $handIni = @'
; a comment
[items.app]
name = myapp
# another comment
token = abc123
'@
    $handIniPath = Join-Path $tmp 'hand.ini'
    Set-Content -LiteralPath $handIniPath -Value $handIni -Encoding UTF8
    $hi = Import-JsonCryptStore -Path $handIniPath -Plaintext
    Assert-Equal 'myapp'  $hi.items.app.name  'hand INI: name (comments skipped)'
    Assert-Equal 'abc123' $hi.items.app.token 'hand INI: token'

    # ── Special characters round-trip in TOML ──
    $store = New-JsonCryptStore
    Add-JsonCryptItem -Store $store -Name 'weird' -Item @{
        quote   = 'he said "hi"'
        tabbed  = "a`tb"
        newline = "line1`nline2"
        path    = 'C:\temp\x'
    }
    $sp = Join-Path $tmp 'special.toml'
    Save-JsonCryptStore -Store $store -Path $sp -Plaintext
    $loaded = Import-JsonCryptStore -Path $sp -Plaintext
    Assert-Equal 'he said "hi"'   $loaded.items.weird.quote   'TOML: embedded quotes'
    Assert-Equal "a`tb"           $loaded.items.weird.tabbed  'TOML: embedded tab'
    Assert-Equal "line1`nline2"   $loaded.items.weird.newline 'TOML: embedded newline'
    Assert-Equal 'C:\temp\x'      $loaded.items.weird.path    'TOML: backslashes'
}
finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "Results: $passed passed, $failed failed" -ForegroundColor Cyan
if ($failed -gt 0) { exit 1 }

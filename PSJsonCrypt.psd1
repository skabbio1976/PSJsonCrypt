@{
    RootModule        = 'PSJsonCrypt.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'bc2ed140-634b-4958-9859-efa50b7192bb'
    Author            = 'jok'
    Description       = 'Encrypted JSON key-value storage for PowerShell. AES-256-CBC with HMAC-SHA256 (Encrypt-then-MAC) and PBKDF2-SHA256 key derivation.'
    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        'New-JsonCryptStore'
        'Add-JsonCryptItem'
        'Get-JsonCryptItem'
        'Remove-JsonCryptItem'
        'Get-JsonCryptItemNames'
        'Protect-JsonCryptString'
        'Unprotect-JsonCryptString'
        'Save-JsonCryptStore'
        'Import-JsonCryptStore'
        'New-JsonCryptKey'
    )

    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()
}

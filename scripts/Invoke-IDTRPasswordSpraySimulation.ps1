[CmdletBinding()]
param(
    [string]$ExpectedDomainDistinguishedName = "DC=corporate,DC=test",
    [string]$DomainNetBIOSName = "CORPORATE",
    [string[]]$SamAccountNames = @(
        "idtr-user01",
        "idtr-user02",
        "idtr-user03",
        "idtr-user04",
        "idtr-user05"
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory

$Domain = Get-ADDomain
if ($Domain.DistinguishedName -ine $ExpectedDomainDistinguishedName) {
    throw "Expected domain '$ExpectedDomainDistinguishedName' but found '$($Domain.DistinguishedName)'."
}

$LockoutPolicy = Get-ADDefaultDomainPasswordPolicy
if ($LockoutPolicy.LockoutThreshold -lt 2) {
    throw "The domain lockout threshold is lower than two attempts. Stop and review the safety control."
}

$Users = foreach ($SamAccountName in $SamAccountNames) {
    $User = Get-ADUser `
        -Identity $SamAccountName `
        -Properties Enabled, LockedOut, DistinguishedName

    if ($User.DistinguishedName -notlike "*,$ExpectedDomainDistinguishedName") {
        throw "User '$SamAccountName' is outside the expected domain."
    }

    if ($User.LockedOut) {
        throw "User '$SamAccountName' is already locked out. Restore the safe state before testing."
    }

    $User
}

$OriginalEnabledState = @{}
foreach ($User in $Users) {
    $OriginalEnabledState[$User.SamAccountName] = [bool]$User.Enabled
}

Write-Host "Controlled password-spray simulation" -ForegroundColor Cyan
Write-Host "Accounts: $($SamAccountNames -join ', ')"
Write-Host "Attempts: one deliberately invalid password per identity"
Write-Host "Lockout threshold: $($LockoutPolicy.LockoutThreshold)`n"

$WrongPassword = Read-Host "Enter one deliberately incorrect lab password" -AsSecureString
$TestStarted = Get-Date
$UnexpectedSuccess = $false

try {
    foreach ($User in $Users) {
        if (-not $User.Enabled) {
            Enable-ADAccount -Identity $User
        }
    }

    foreach ($SamAccountName in $SamAccountNames) {
        $Credential = [PSCredential]::new(
            "$DomainNetBIOSName\$SamAccountName",
            $WrongPassword
        )

        try {
            $Process = Start-Process `
                -FilePath "$env:SystemRoot\System32\cmd.exe" `
                -ArgumentList "/c exit 0" `
                -Credential $Credential `
                -WorkingDirectory $env:SystemRoot `
                -WindowStyle Hidden `
                -PassThru `
                -Wait

            Write-Host "UNEXPECTED SUCCESS: $SamAccountName" -ForegroundColor Red
            $UnexpectedSuccess = $true
            break
        }
        catch {
            Write-Host "EXPECTED FAILURE: $SamAccountName" -ForegroundColor Green
        }
        finally {
            $Credential = $null
        }
    }
}
finally {
    foreach ($User in $Users) {
        if (-not $OriginalEnabledState[$User.SamAccountName]) {
            Disable-ADAccount -Identity $User -ErrorAction Continue
        }
    }

    $WrongPassword = $null
}

$TestEnded = Get-Date
$LockedOutUsers = @(
    foreach ($SamAccountName in $SamAccountNames) {
        Get-ADUser -Identity $SamAccountName -Properties LockedOut |
            Where-Object { $_.LockedOut }
    }
)

Write-Host "`nTest started: $($TestStarted.ToString('o'))"
Write-Host "Test ended:   $($TestEnded.ToString('o'))"
Write-Host "Validate Event ID 4625 locally before checking Microsoft Sentinel ingestion."

if ($UnexpectedSuccess) {
    throw "The deliberately incorrect password authenticated successfully. Stop testing and reset the lab credentials."
}

if ($LockedOutUsers.Count -gt 0) {
    throw "One or more controlled accounts became locked out. Run Restore-IDTRLabState.ps1 before continuing."
}

Write-Host "PASS: All controlled attempts failed and original account enabled states were restored." -ForegroundColor Green

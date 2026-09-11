#requires -RunAsAdministrator
#requires -Modules ActiveDirectory

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory

$TargetOU = "OU=IDTR-Lab,DC=corporate,DC=test"
$DomainNetBIOS = "CORPORATE"
$TargetAccount = "idtr-user01"
$HighValueGroup = "IDTR-HighValue-Lab"
$ControlledAccounts = @(
    "idtr-user01",
    "idtr-user02",
    "idtr-user03",
    "idtr-user04",
    "idtr-user05"
)

if (-not ("IDTR.IntegratedLogon" -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace IDTR
{
    public static class IntegratedLogon
    {
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LogonUser(
            string userName,
            string domain,
            string password,
            int logonType,
            int logonProvider,
            out IntPtr token);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr handle);
    }
}
'@
}

function Invoke-ControlledNetworkLogon {
    param(
        [Parameter(Mandatory)]
        [string]$UserName,

        [Parameter(Mandatory)]
        [string]$Domain,

        [Parameter(Mandatory)]
        [string]$Password
    )

    $Token = [IntPtr]::Zero
    $Succeeded = [IDTR.IntegratedLogon]::LogonUser(
        $UserName,
        $Domain,
        $Password,
        3,
        0,
        [ref]$Token
    )

    $ErrorCode = 0
    if (-not $Succeeded) {
        $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    }

    if ($Token -ne [IntPtr]::Zero) {
        [void][IDTR.IntegratedLogon]::CloseHandle($Token)
    }

    [pscustomobject]@{
        Succeeded = $Succeeded
        ErrorCode = $ErrorCode
    }
}

function Convert-SecurityEvent {
    param(
        [Parameter(Mandatory)]
        [System.Diagnostics.Eventing.Reader.EventRecord]$EventRecord
    )

    $EventXml = [xml]$EventRecord.ToXml()
    $Fields = @{}

    foreach ($DataField in $EventXml.Event.EventData.Data) {
        if ($DataField.Name) {
            $Fields[[string]$DataField.Name] = [string]$DataField.'#text'
        }
    }

    [pscustomobject]@{
        TimeUTC        = $EventRecord.TimeCreated.ToUniversalTime()
        EventId        = $EventRecord.Id
        TargetUserName = $Fields["TargetUserName"]
        MemberName     = $Fields["MemberName"]
        LogonType      = $Fields["LogonType"]
        Status         = $Fields["Status"]
        SubStatus      = $Fields["SubStatus"]
    }
}

$Users = @(
    foreach ($Account in $ControlledAccounts) {
        $User = Get-ADUser `
            -Identity $Account `
            -Properties Enabled, LockedOut, badPwdCount, LastBadPasswordAttempt

        if ($User.DistinguishedName -notlike "*,$TargetOU") {
            throw "$Account is outside the controlled IDTR-Lab OU."
        }

        if ($User.Enabled -or $User.LockedOut) {
            throw "$Account must start disabled and unlocked."
        }

        $User
    }
)

$InitialGroupMembers = @(Get-ADGroupMember -Identity $HighValueGroup)
if ($InitialGroupMembers.Count -ne 0) {
    throw "The controlled high-value group must start empty."
}

$DomainPolicy = Get-ADDefaultDomainPasswordPolicy
$LockoutThreshold = [int]$DomainPolicy.LockoutThreshold
$ObservationWindow = $DomainPolicy.LockoutObservationWindow.Duration()

foreach ($User in $Users) {
    $PlannedFailures = 1
    if ($User.SamAccountName -eq $TargetAccount) {
        $PlannedFailures = 5
    }

    $EffectiveBadPwdCount = [int]$User.badPwdCount
    if (
        $User.LastBadPasswordAttempt -and
        (Get-Date) - $User.LastBadPasswordAttempt -gt $ObservationWindow
    ) {
        $EffectiveBadPwdCount = 0
    }

    if (
        $LockoutThreshold -gt 0 -and
        ($EffectiveBadPwdCount + $PlannedFailures) -ge $LockoutThreshold
    ) {
        throw "$($User.SamAccountName) could reach the lockout threshold."
    }
}

$RandomBytes = New-Object byte[] 24
$RandomGenerator = [Security.Cryptography.RandomNumberGenerator]::Create()
try {
    $RandomGenerator.GetBytes($RandomBytes)
}
finally {
    $RandomGenerator.Dispose()
}

$TemporaryPassword = "M6!" + [Convert]::ToBase64String($RandomBytes)
$IncorrectPassword = $TemporaryPassword + "!incorrect"
$SecureTemporaryPassword = ConvertTo-SecureString `
    -String $TemporaryPassword `
    -AsPlainText `
    -Force

$TargetUser = $Users | Where-Object SamAccountName -EQ $TargetAccount
$TargetWasAdded = $false
$SimulationStartUTC = $null
$SimulationEndUTC = $null
$SprayFailuresCompleted = 0
$AdditionalFailuresCompleted = 0
$SuccessfulAuthentication = $false

try {
    Set-ADAccountPassword `
        -Identity $TargetUser `
        -Reset `
        -NewPassword $SecureTemporaryPassword

    foreach ($User in $Users) {
        Enable-ADAccount -Identity $User
    }

    $SimulationStartUTC = [datetime]::UtcNow

    Write-Host "`n=== Phase 1: Password spray ===" -ForegroundColor Cyan
    foreach ($Account in $ControlledAccounts) {
        $Failure = Invoke-ControlledNetworkLogon `
            -UserName $Account `
            -Domain $DomainNetBIOS `
            -Password $IncorrectPassword

        if ($Failure.Succeeded -or $Failure.ErrorCode -ne 1326) {
            throw "The controlled spray failure for $Account was not validated."
        }

        $SprayFailuresCompleted++
        Write-Host "Controlled spray failure $SprayFailuresCompleted of 5: $Account"
        Start-Sleep -Milliseconds 750
    }

    Write-Host "`n=== Phase 2: Repeated failures and success ===" -ForegroundColor Cyan
    for ($Attempt = 1; $Attempt -le 4; $Attempt++) {
        $Failure = Invoke-ControlledNetworkLogon `
            -UserName $TargetAccount `
            -Domain $DomainNetBIOS `
            -Password $IncorrectPassword

        if ($Failure.Succeeded -or $Failure.ErrorCode -ne 1326) {
            throw "Additional controlled failure $Attempt was not validated."
        }

        $AdditionalFailuresCompleted++
        Write-Host "Additional target failure $Attempt of 4 completed."
        Start-Sleep -Milliseconds 750
    }

    $Success = Invoke-ControlledNetworkLogon `
        -UserName $TargetAccount `
        -Domain $DomainNetBIOS `
        -Password $TemporaryPassword

    if (-not $Success.Succeeded) {
        throw "The controlled successful authentication failed."
    }

    $SuccessfulAuthentication = $true
    Write-Host "Controlled network authentication succeeded."
    Start-Sleep -Seconds 2

    Write-Host "`n=== Phase 3: High-value group change ===" -ForegroundColor Cyan
    Add-ADGroupMember -Identity $HighValueGroup -Members $TargetUser
    $TargetWasAdded = $true
    Write-Host "$TargetAccount was added to $HighValueGroup."
    Start-Sleep -Seconds 2

    Remove-ADGroupMember `
        -Identity $HighValueGroup `
        -Members $TargetUser `
        -Confirm:$false

    $TargetWasAdded = $false
    Write-Host "$TargetAccount was removed from $HighValueGroup."
    $SimulationEndUTC = [datetime]::UtcNow
}
finally {
    if ($TargetWasAdded) {
        Remove-ADGroupMember `
            -Identity $HighValueGroup `
            -Members $TargetUser `
            -Confirm:$false `
            -ErrorAction SilentlyContinue
    }

    foreach ($User in $Users) {
        Disable-ADAccount -Identity $User -ErrorAction SilentlyContinue
    }

    $TemporaryPassword = $null
    $IncorrectPassword = $null
    $SecureTemporaryPassword = $null
    [Array]::Clear($RandomBytes, 0, $RandomBytes.Length)
}

if (-not $SimulationEndUTC) {
    $SimulationEndUTC = [datetime]::UtcNow
}

Start-Sleep -Seconds 5

$LocalEvents = @(
    Get-WinEvent -FilterHashtable @{
        LogName = "Security"
        Id      = 4624, 4625, 4728, 4729
    } -MaxEvents 5000 |
    Where-Object {
        $EventTimeUTC = $_.TimeCreated.ToUniversalTime()
        $EventTimeUTC -ge $SimulationStartUTC.AddSeconds(-2) -and
        $EventTimeUTC -le $SimulationEndUTC.AddSeconds(5)
    } |
    ForEach-Object { Convert-SecurityEvent -EventRecord $_ } |
    Sort-Object TimeUTC
)

$FailureEvents = @(
    $LocalEvents |
    Where-Object {
        $_.EventId -eq 4625 -and
        $_.TargetUserName -in $ControlledAccounts
    }
)
$TargetFailureEvents = @(
    $FailureEvents | Where-Object TargetUserName -EQ $TargetAccount
)
$SuccessEvents = @(
    $LocalEvents |
    Where-Object {
        $_.EventId -eq 4624 -and
        $_.TargetUserName -eq $TargetAccount -and
        $_.LogonType -eq "3"
    }
)
$AdditionEvents = @(
    $LocalEvents |
    Where-Object {
        $_.EventId -eq 4728 -and
        $_.TargetUserName -eq $HighValueGroup
    }
)
$RemovalEvents = @(
    $LocalEvents |
    Where-Object {
        $_.EventId -eq 4729 -and
        $_.TargetUserName -eq $HighValueGroup
    }
)

$FinalUsers = @(
    foreach ($Account in $ControlledAccounts) {
        Get-ADUser -Identity $Account -Properties Enabled, LockedOut
    }
)
$FinalGroupMembers = @(Get-ADGroupMember -Identity $HighValueGroup)

$SequenceOrderCorrect = $false
if (
    $FailureEvents.Count -eq 9 -and
    $TargetFailureEvents.Count -eq 5 -and
    $SuccessEvents.Count -eq 1 -and
    $AdditionEvents.Count -eq 1 -and
    $RemovalEvents.Count -eq 1
) {
    $SequenceOrderCorrect = (
        $FailureEvents[-1].TimeUTC -lt $SuccessEvents[0].TimeUTC -and
        $SuccessEvents[0].TimeUTC -lt $AdditionEvents[0].TimeUTC -and
        $AdditionEvents[0].TimeUTC -lt $RemovalEvents[0].TimeUTC
    )
}

$ValidatedSuccessLogonType = ""
if ($SuccessEvents.Count -eq 1) {
    $ValidatedSuccessLogonType = $SuccessEvents[0].LogonType
}

$Result = [pscustomobject]@{
    SimulationStartUTC        = $SimulationStartUTC
    SimulationEndUTC          = $SimulationEndUTC
    SprayIdentityCount        = @(
        $FailureEvents.TargetUserName | Sort-Object -Unique
    ).Count
    TotalFailureEvents        = $FailureEvents.Count
    TargetFailureEvents       = $TargetFailureEvents.Count
    SuccessEventCount         = $SuccessEvents.Count
    SuccessLogonType          = $ValidatedSuccessLogonType
    AdditionEventCount        = $AdditionEvents.Count
    RemovalEventCount         = $RemovalEvents.Count
    SequenceOrderCorrect      = $SequenceOrderCorrect
    FinalEnabledUsers         = @($FinalUsers | Where-Object Enabled).Count
    FinalLockedOutUsers       = @($FinalUsers | Where-Object LockedOut).Count
    FinalHighValueMembers     = $FinalGroupMembers.Count
    SuccessfulAuthentication = $SuccessfulAuthentication
}

$Result | Format-List

if (
    $Result.SprayIdentityCount -ne 5 -or
    $Result.TotalFailureEvents -ne 9 -or
    $Result.TargetFailureEvents -ne 5 -or
    $Result.SuccessEventCount -ne 1 -or
    $Result.SuccessLogonType -ne "3" -or
    $Result.AdditionEventCount -ne 1 -or
    $Result.RemovalEventCount -ne 1 -or
    -not $Result.SequenceOrderCorrect -or
    $Result.FinalEnabledUsers -ne 0 -or
    $Result.FinalLockedOutUsers -ne 0 -or
    $Result.FinalHighValueMembers -ne 0 -or
    -not $Result.SuccessfulAuthentication
) {
    throw "The controlled integrated attack-chain sequence failed validation."
}

Write-Host `
    "PASS: The integrated identity attack chain was generated and restored safely." `
    -ForegroundColor Green

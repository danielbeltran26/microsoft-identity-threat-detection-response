#requires -RunAsAdministrator
#requires -Modules ActiveDirectory

[CmdletBinding()]
param(
    [string]$SamAccountName = "idtr-user01",
    [string]$NetBIOSDomain = "CORPORATE",
    [string]$Computer = "DC01.corporate.test",
    [string]$TargetOU = "OU=IDTR-Lab,DC=corporate,DC=test",
    [ValidateRange(1, 8)]
    [int]$FailureCount = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory

if (-not ("IDTR.NativeLogon" -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace IDTR
{
    public static class NativeLogon
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

function Invoke-NetworkLogon {
    param(
        [Parameter(Mandatory)]
        [string]$UserName,

        [Parameter(Mandatory)]
        [string]$Domain,

        [Parameter(Mandatory)]
        [string]$Password
    )

    $Token = [IntPtr]::Zero
    $Succeeded = [IDTR.NativeLogon]::LogonUser(
        $UserName,
        $Domain,
        $Password,
        3,
        0,
        [ref]$Token
    )

    $ErrorCode = if ($Succeeded) {
        0
    }
    else {
        [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    }

    if ($Token -ne [IntPtr]::Zero) {
        [void][IDTR.NativeLogon]::CloseHandle($Token)
    }

    [pscustomobject]@{
        Succeeded = $Succeeded
        ErrorCode = $ErrorCode
    }
}

function Convert-EventRecord {
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
        TimeCreated      = $EventRecord.TimeCreated.ToUniversalTime()
        EventId         = $EventRecord.Id
        TargetUserName  = $Fields["TargetUserName"]
        TargetDomain    = $Fields["TargetDomainName"]
        LogonType       = $Fields["LogonType"]
        Status          = $Fields["Status"]
        SubStatus       = $Fields["SubStatus"]
        WorkstationName = $Fields["WorkstationName"]
        IpAddress       = $Fields["IpAddress"]
    }
}

$TargetUser = Get-ADUser `
    -Identity $SamAccountName `
    -Properties Enabled, LockedOut, badPwdCount, LastBadPasswordAttempt

if ($TargetUser.DistinguishedName -notlike "*,$TargetOU") {
    throw "The target account is outside the isolated IDTR-Lab OU."
}

if ($TargetUser.Enabled -or $TargetUser.LockedOut) {
    throw "The target must start disabled and unlocked."
}

$DomainPolicy = Get-ADDefaultDomainPasswordPolicy
$LockoutThreshold = [int]$DomainPolicy.LockoutThreshold
$ObservationWindow = $DomainPolicy.LockoutObservationWindow.Duration()
$EffectiveBadPasswordCount = [int]$TargetUser.badPwdCount

if (
    $TargetUser.LastBadPasswordAttempt -and
    (Get-Date) - $TargetUser.LastBadPasswordAttempt -gt $ObservationWindow
) {
    $EffectiveBadPasswordCount = 0
}

if (
    $LockoutThreshold -gt 0 -and
    ($EffectiveBadPasswordCount + $FailureCount) -ge $LockoutThreshold
) {
    throw "The requested sequence could reach the domain lockout threshold."
}

$RandomBytes = New-Object byte[] 18
$RandomGenerator = [Security.Cryptography.RandomNumberGenerator]::Create()

try {
    $RandomGenerator.GetBytes($RandomBytes)
}
finally {
    $RandomGenerator.Dispose()
}

$TemporaryPassword = "M4!" + [Convert]::ToBase64String($RandomBytes)
$IncorrectPassword = $TemporaryPassword + "!incorrect"
$SecureTemporaryPassword = ConvertTo-SecureString `
    -String $TemporaryPassword `
    -AsPlainText `
    -Force

$SimulationStartUTC = $null
$SimulationEndUTC = $null
$CompletedFailures = 0
$SuccessfulAuthentication = $false

try {
    Set-ADAccountPassword `
        -Identity $TargetUser `
        -Reset `
        -NewPassword $SecureTemporaryPassword

    Enable-ADAccount -Identity $TargetUser

    $SimulationStartUTC = [datetime]::UtcNow

    for ($Attempt = 1; $Attempt -le $FailureCount; $Attempt++) {
        $FailedResult = Invoke-NetworkLogon `
            -UserName $SamAccountName `
            -Domain $NetBIOSDomain `
            -Password $IncorrectPassword

        if ($FailedResult.Succeeded -or $FailedResult.ErrorCode -ne 1326) {
            throw "Controlled failure $Attempt did not return invalid-credentials error 1326."
        }

        $CompletedFailures++
        Write-Host "Controlled 4625 attempt $Attempt of $FailureCount completed."
        Start-Sleep -Milliseconds 750
    }

    $SuccessResult = Invoke-NetworkLogon `
        -UserName $SamAccountName `
        -Domain $NetBIOSDomain `
        -Password $TemporaryPassword

    if (-not $SuccessResult.Succeeded) {
        throw "The controlled successful network authentication failed."
    }

    $SuccessfulAuthentication = $true
    $SimulationEndUTC = [datetime]::UtcNow
    Write-Host "Controlled 4624 network authentication completed."
}
finally {
    Disable-ADAccount -Identity $TargetUser -ErrorAction SilentlyContinue
    $TemporaryPassword = $null
    $IncorrectPassword = $null
    $SecureTemporaryPassword = $null
    [Array]::Clear($RandomBytes, 0, $RandomBytes.Length)
}

if (-not $SimulationEndUTC) {
    $SimulationEndUTC = [datetime]::UtcNow
}

Start-Sleep -Seconds 3

$LocalEvents = @(
    Get-WinEvent -FilterHashtable @{
        LogName   = "Security"
        Id        = 4624, 4625
        StartTime = $SimulationStartUTC.AddSeconds(-2)
        EndTime   = $SimulationEndUTC.AddSeconds(5)
    } |
    ForEach-Object {
        Convert-EventRecord -EventRecord $_
    } |
    Where-Object {
        $_.TargetUserName -ieq $SamAccountName
    } |
    Sort-Object TimeCreated
)

$FailureEvents = @(
    $LocalEvents |
    Where-Object EventId -EQ 4625
)

$SuccessEvents = @(
    $LocalEvents |
    Where-Object EventId -EQ 4624
)

$FailureFieldsCorrect = @(
    $FailureEvents |
    Where-Object {
        $_.Status -ine "0xc000006d" -or
        $_.SubStatus -ine "0xc000006a"
    }
).Count -eq 0

$ValidatedSuccessLogonType = if ($SuccessEvents.Count -eq 1) {
    $SuccessEvents[0].LogonType
}
else {
    ""
}

$SequenceOrderCorrect = (
    $FailureEvents.Count -eq $FailureCount -and
    $SuccessEvents.Count -eq 1 -and
    $FailureEvents[-1].TimeCreated -lt $SuccessEvents[0].TimeCreated
)

$FinalUser = Get-ADUser `
    -Identity $SamAccountName `
    -Properties Enabled, LockedOut, badPwdCount

$Summary = [pscustomobject]@{
    TargetAccount            = $SamAccountName
    SimulationStartUTC       = $SimulationStartUTC
    SimulationEndUTC         = $SimulationEndUTC
    ControlledFailedAttempts = $CompletedFailures
    SuccessfulAuthentication = $SuccessfulAuthentication
    FailureEventCount        = $FailureEvents.Count
    SuccessEventCount        = $SuccessEvents.Count
    FailureFieldsCorrect     = $FailureFieldsCorrect
    SuccessLogonType         = $ValidatedSuccessLogonType
    SequenceOrderCorrect     = $SequenceOrderCorrect
    FinalEnabled             = $FinalUser.Enabled
    FinalLockedOut           = $FinalUser.LockedOut
    FinalBadPwdCount         = [int]$FinalUser.badPwdCount
    RecordingHost            = $Computer
}

$Summary | Format-List

if (
    $CompletedFailures -ne $FailureCount -or
    -not $SuccessfulAuthentication -or
    $FailureEvents.Count -ne $FailureCount -or
    $SuccessEvents.Count -ne 1 -or
    -not $FailureFieldsCorrect -or
    $ValidatedSuccessLogonType -ne "3" -or
    -not $SequenceOrderCorrect -or
    $FinalUser.Enabled -or
    $FinalUser.LockedOut -or
    [int]$FinalUser.badPwdCount -ne 0
) {
    throw "The IDTR002 authentication sequence or final state failed validation."
}

Write-Host `
    "PASS: Five 4625 failures followed by one 4624 network success were generated safely." `
    -ForegroundColor Green

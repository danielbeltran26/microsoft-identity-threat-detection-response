[CmdletBinding()]
param(
    [string]$TargetAccount = "idtr-user01",
    [string]$HighValueGroup = "IDTR-HighValue-Lab",
    [string]$TargetOU = "OU=IDTR-Lab,DC=corporate,DC=test"
)

$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory

$RequiredServices = @(
    "NTDS",
    "DNS",
    "ADWS",
    "Netlogon",
    "himds",
    "GCArcService",
    "ExtensionService"
)

$RecoveryValidationUTC = [datetime]::UtcNow
$ProcessTestStartUTC = [datetime]::UtcNow

& "$env:SystemRoot\System32\whoami.exe" | Out-Null
Start-Sleep -Seconds 3

$DisposableUsers = @(
    Get-ADUser `
        -SearchBase $TargetOU `
        -Filter 'SamAccountName -like "idtr-user*"' `
        -Properties Enabled, LockedOut, badPwdCount
)

$TargetUser = Get-ADUser `
    -Identity $TargetAccount `
    -Properties Enabled, LockedOut

$HighValueMembers = @(
    Get-ADGroupMember `
        -Identity $HighValueGroup `
        -ErrorAction Stop
)

$ServiceState = @(
    foreach ($ServiceName in $RequiredServices) {
        Get-Service -Name $ServiceName -ErrorAction Stop
    }
)

$StoppedRequiredServices = @(
    $ServiceState |
        Where-Object Status -NE "Running"
)

$AmaProcesses = @(
    Get-Process `
        -Name "MonAgentCore" `
        -ErrorAction SilentlyContinue
)

$SecurityLog = Get-WinEvent `
    -ListLog "Security" `
    -ErrorAction Stop

$FreshProcessEvents = @(
    Get-WinEvent `
        -FilterHashtable @{
            LogName   = "Security"
            Id        = 4688
            StartTime = $ProcessTestStartUTC.AddSeconds(-2)
        } `
        -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Message -match [regex]::Escape("whoami.exe")
        }
)

$EnabledUsers = @(
    $DisposableUsers |
        Where-Object Enabled
).Count

$LockedUsers = @(
    $DisposableUsers |
        Where-Object LockedOut
).Count

$HistoricalBadPwdCounters = @(
    $DisposableUsers |
        Where-Object badPwdCount -GT 0
).Count

$LatestProcessEvent = @(
    $FreshProcessEvents |
        Sort-Object TimeCreated -Descending
)[0]

[pscustomobject]@{
    RecoveryValidationUTC    = $RecoveryValidationUTC.ToString("o")
    DisposableUserCount      = $DisposableUsers.Count
    EnabledUserCount         = $EnabledUsers
    LockedOutUserCount       = $LockedUsers
    HistoricalBadPwdCounters = $HistoricalBadPwdCounters
    TargetEnabled            = $TargetUser.Enabled
    TargetLockedOut          = $TargetUser.LockedOut
    HighValueGroupMembers    = $HighValueMembers.Count
    RequiredServiceCount     = $ServiceState.Count
    StoppedRequiredServices  = $StoppedRequiredServices.Count
    AmaProcessCount          = $AmaProcesses.Count
    AmaProcessIds            = @($AmaProcesses.Id) -join ", "
    SecurityLogEnabled       = $SecurityLog.IsEnabled
    FreshProcessEventCount   = $FreshProcessEvents.Count
    FreshProcessEventUTC     = if ($LatestProcessEvent) {
        $LatestProcessEvent.TimeCreated.ToUniversalTime().ToString("o")
    }
    else {
        $null
    }
    FreshProcessEventId      = if ($LatestProcessEvent) {
        $LatestProcessEvent.Id
    }
    else {
        $null
    }
    FreshProcessPath         = "C:\Windows\System32\whoami.exe"
} | Format-List

if (
    $DisposableUsers.Count -ne 5 -or
    $EnabledUsers -ne 0 -or
    $LockedUsers -ne 0 -or
    $TargetUser.Enabled -or
    $TargetUser.LockedOut -or
    $HighValueMembers.Count -ne 0 -or
    $ServiceState.Count -ne 7 -or
    $StoppedRequiredServices.Count -ne 0 -or
    $AmaProcesses.Count -lt 1 -or
    -not $SecurityLog.IsEnabled -or
    $FreshProcessEvents.Count -lt 1
) {
    throw "Recovery state or telemetry validation failed."
}

Write-Host `
    "PASS: Identity recovery is verified and local telemetry remains healthy." `
    -ForegroundColor Green

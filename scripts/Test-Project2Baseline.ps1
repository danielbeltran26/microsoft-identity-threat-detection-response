[CmdletBinding()]
param(
    [string]$ExpectedComputerName = "DC01",
    [string]$ExpectedDomainName = "corporate.test"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-CheckResult {
    param(
        [Parameter(Mandatory)]
        [string]$Check,

        [Parameter(Mandatory)]
        [bool]$Passed,

        [Parameter(Mandatory)]
        [string]$Details
    )

    [PSCustomObject]@{
        Check   = $Check
        Status  = if ($Passed) { "PASS" } else { "FAIL" }
        Details = $Details
    }
}

Write-Host "Project 2 baseline validation" -ForegroundColor Cyan
Write-Host "This script is read-only and must be run on DC01.`n"

$Results = [System.Collections.Generic.List[object]]::new()

$ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
$ActualComputerName = $env:COMPUTERNAME
$ActualDomainName = $ComputerSystem.Domain

$Results.Add((New-CheckResult `
    -Check "Computer name" `
    -Passed ($ActualComputerName -ieq $ExpectedComputerName) `
    -Details $ActualComputerName))

$Results.Add((New-CheckResult `
    -Check "Domain membership" `
    -Passed ($ActualDomainName -ieq $ExpectedDomainName) `
    -Details $ActualDomainName))

try {
    $Domain = Get-ADDomain
    $DomainDetails = "DNSRoot={0}; PDCEmulator={1}; DomainMode={2}" -f `
        $Domain.DNSRoot,
        $Domain.PDCEmulator,
        $Domain.DomainMode

    $Results.Add((New-CheckResult `
        -Check "Active Directory domain" `
        -Passed ($Domain.DNSRoot -ieq $ExpectedDomainName) `
        -Details $DomainDetails))
}
catch {
    $Results.Add((New-CheckResult `
        -Check "Active Directory domain" `
        -Passed $false `
        -Details $_.Exception.Message))
}

$RequiredServices = @(
    @{ Name = "NTDS"; Label = "Active Directory Domain Services" },
    @{ Name = "DNS"; Label = "Domain Name System Server" },
    @{ Name = "ADWS"; Label = "Active Directory Web Services" },
    @{ Name = "Netlogon"; Label = "Netlogon" },
    @{ Name = "himds"; Label = "Azure Hybrid Instance Metadata Service" },
    @{ Name = "GCArcService"; Label = "Guest Configuration Arc Service" },
    @{ Name = "ExtensionService"; Label = "Guest Configuration Extension Service" }
)

foreach ($RequiredService in $RequiredServices) {
    $Service = Get-Service -Name $RequiredService.Name -ErrorAction SilentlyContinue

    if ($null -eq $Service) {
        $Results.Add((New-CheckResult `
            -Check $RequiredService.Label `
            -Passed $false `
            -Details "Service not found"))
        continue
    }

    $ServicePassed = (
        $Service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running -and
        $Service.StartType -eq [System.ServiceProcess.ServiceStartMode]::Automatic
    )

    $ServiceDetails = "Name={0}; Status={1}; StartType={2}" -f `
        $Service.Name,
        $Service.Status,
        $Service.StartType

    $Results.Add((New-CheckResult `
        -Check $RequiredService.Label `
        -Passed $ServicePassed `
        -Details $ServiceDetails))
}

$MonitorProcess = Get-Process -Name "MonAgentCore" -ErrorAction SilentlyContinue

if ($null -eq $MonitorProcess) {
    $Results.Add((New-CheckResult `
        -Check "Azure Monitor Agent process" `
        -Passed $false `
        -Details "MonAgentCore.exe is not running"))
}
else {
    $ProcessDetails = "PID={0}; Path={1}" -f `
        $MonitorProcess.Id,
        $MonitorProcess.Path

    $Results.Add((New-CheckResult `
        -Check "Azure Monitor Agent process" `
        -Passed $true `
        -Details $ProcessDetails))
}

$ExtensionFolder = Get-ChildItem `
    -LiteralPath "C:\Packages\Plugins" `
    -Directory `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -eq "Microsoft.Azure.Monitor.AzureMonitorWindowsAgent" } |
    Select-Object -First 1

$Results.Add((New-CheckResult `
    -Check "Azure Monitor Agent extension files" `
    -Passed ($null -ne $ExtensionFolder) `
    -Details $(if ($ExtensionFolder) { $ExtensionFolder.FullName } else { "Extension folder not found" })))

$DataCollectionRuleConfiguration = Get-ChildItem `
    -LiteralPath "C:\Resources\Directory" `
    -Filter "mcsconfig.latest.xml" `
    -File `
    -Recurse `
    -ErrorAction SilentlyContinue |
    Select-Object -First 1

if ($null -eq $DataCollectionRuleConfiguration) {
    $Results.Add((New-CheckResult `
        -Check "Downloaded Data Collection Rule configuration" `
        -Passed $false `
        -Details "mcsconfig.latest.xml was not found"))
}
else {
    $ConfigurationDetails = "Path={0}; LastWriteTime={1:o}" -f `
        $DataCollectionRuleConfiguration.FullName,
        $DataCollectionRuleConfiguration.LastWriteTime

    $Results.Add((New-CheckResult `
        -Check "Downloaded Data Collection Rule configuration" `
        -Passed $true `
        -Details $ConfigurationDetails))
}

$Results | Format-Table -AutoSize -Wrap

$FailedChecks = @($Results | Where-Object { $_.Status -eq "FAIL" })

if ($FailedChecks.Count -eq 0) {
    Write-Host "`nOverall result: PASS" -ForegroundColor Green
    exit 0
}

Write-Host "`nOverall result: FAIL ($($FailedChecks.Count) failed check(s))" -ForegroundColor Red
exit 1

[CmdletBinding()]
param(
    [string]$ResourceGroupName = "rg-sentinel-siem-lab-uks",
    [string]$WorkspaceName = "law-sentinel-siem-lab-uks",
    [string]$ApiVersion = "2025-09-01"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "Project 1 Microsoft Sentinel rule baseline" -ForegroundColor Cyan
Write-Host "This script performs one read-only List analytics rules request.`n"

$SubscriptionId = (az account show --query id --output tsv --only-show-errors).Trim()

if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($SubscriptionId)) {
    throw "Unable to determine the active Azure subscription. Confirm that Azure Cloud Shell is authenticated."
}

$Uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/alertRules?api-version=$ApiVersion"

$RawResponse = az rest `
    --method get `
    --url $Uri `
    --only-show-errors

if ($LASTEXITCODE -ne 0) {
    throw "The Microsoft Sentinel List analytics rules request failed."
}

$Response = $RawResponse | ConvertFrom-Json

$Rules = @(
    $Response.value |
        Where-Object { $_.properties.displayName -like "SOC*" } |
        ForEach-Object {
            [PSCustomObject]@{
                DisplayName    = $_.properties.displayName
                Enabled        = [bool]$_.properties.enabled
                Severity       = $_.properties.severity
                Kind           = $_.kind
                QueryFrequency = $_.properties.queryFrequency
                QueryPeriod    = $_.properties.queryPeriod
            }
        } |
        Sort-Object DisplayName
)

Write-Host "SOC rule count: $($Rules.Count)" -ForegroundColor Cyan
$Rules | Format-Table -AutoSize

$ExpectedPrefixes = @("SOC001", "SOC002", "SOC003")
$MissingRules = @(
    foreach ($Prefix in $ExpectedPrefixes) {
        if (-not ($Rules.DisplayName -like "$Prefix*")) {
            $Prefix
        }
    }
)

$DisabledRules = @($Rules | Where-Object { -not $_.Enabled })

if ($MissingRules.Count -gt 0) {
    throw "Missing expected rule(s): $($MissingRules -join ', ')"
}

if ($DisabledRules.Count -gt 0) {
    throw "Disabled expected rule(s): $($DisabledRules.DisplayName -join ', ')"
}

Write-Host "`nOverall result: PASS - SOC001, SOC002 and SOC003 are present and enabled." -ForegroundColor Green

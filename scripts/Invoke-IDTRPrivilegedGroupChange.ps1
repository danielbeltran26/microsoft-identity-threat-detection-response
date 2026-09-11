[CmdletBinding()]
param(
    [string]$SamAccountName = "idtr-user01",
    [string]$HighValueGroupName = "IDTR-HighValue-Lab",
    [string]$ExpectedDomainDistinguishedName = "DC=corporate,DC=test"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory

$Domain = Get-ADDomain
if ($Domain.DistinguishedName -ine $ExpectedDomainDistinguishedName) {
    throw "Expected domain '$ExpectedDomainDistinguishedName' but found '$($Domain.DistinguishedName)'."
}

$User = Get-ADUser -Identity $SamAccountName
$Group = Get-ADGroup -Identity $HighValueGroupName
$OriginalMembers = @(Get-ADGroupMember -Identity $Group)

if ($OriginalMembers.Count -ne 0) {
    throw "The controlled high-value lab group must be empty before this simulation."
}

$MemberAddedByThisScript = $false
$TestStartedUTC = [DateTime]::UtcNow

Write-Host "Controlled high-value group-membership simulation" -ForegroundColor Cyan
Write-Host "Group: $HighValueGroupName"
Write-Host "Member: $SamAccountName"
Write-Host "This group is a synthetic monitoring marker and grants no production privilege.`n"

try {
    Add-ADGroupMember -Identity $Group -Members $User
    $MemberAddedByThisScript = $true
    Write-Host "ADDED: $SamAccountName -> $HighValueGroupName" -ForegroundColor Yellow

    Start-Sleep -Seconds 1
}
finally {
    if ($MemberAddedByThisScript) {
        Remove-ADGroupMember `
            -Identity $Group `
            -Members $User `
            -Confirm:$false `
            -ErrorAction Continue

        Write-Host "REMOVED: $SamAccountName <- $HighValueGroupName" -ForegroundColor Green
    }
}

$FinalMembers = @(Get-ADGroupMember -Identity $Group)
$UserStillMember = $null -ne ($FinalMembers | Where-Object DistinguishedName -eq $User.DistinguishedName)

[PSCustomObject]@{
    TestStartedUTC  = $TestStartedUTC
    FinalMemberCount = $FinalMembers.Count
    UserStillMember = $UserStillMember
} | Format-Table -AutoSize

if ($FinalMembers.Count -ne 0 -or $UserStillMember) {
    throw "The high-value lab group did not return to an empty state."
}

Write-Host "Validate Event IDs 4728 and 4729 locally before checking Microsoft Sentinel ingestion."
Write-Host "PASS: Temporary membership was removed and the group is empty." -ForegroundColor Green

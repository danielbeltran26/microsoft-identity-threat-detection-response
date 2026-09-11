[CmdletBinding()]
param(
    [string]$OrganizationalUnitPath = "OU=IDTR-Lab,DC=corporate,DC=test",
    [string]$HighValueGroupName = "IDTR-HighValue-Lab",
    [int]$ExpectedUserCount = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory

$OrganizationalUnit = Get-ADOrganizationalUnit -Identity $OrganizationalUnitPath
$Group = Get-ADGroup -Identity $HighValueGroupName
$Users = @(
    Get-ADUser `
        -SearchBase $OrganizationalUnitPath `
        -Filter "SamAccountName -like 'idtr-user*'" `
        -Properties Enabled, LockedOut
)
$Members = @(Get-ADGroupMember -Identity $Group)

$Result = [PSCustomObject]@{
    OrganizationalUnit      = $OrganizationalUnit.Name
    DisposableUserCount     = $Users.Count
    EnabledUserCount        = @($Users | Where-Object Enabled).Count
    LockedOutUserCount      = @($Users | Where-Object LockedOut).Count
    HighValueGroupMembers   = $Members.Count
}

$Result | Format-Table -AutoSize

$Passed = (
    $Result.DisposableUserCount -eq $ExpectedUserCount -and
    $Result.EnabledUserCount -eq 0 -and
    $Result.LockedOutUserCount -eq 0 -and
    $Result.HighValueGroupMembers -eq 0
)

if ($Passed) {
    Write-Host "PASS: Project 2 final Active Directory state is safe." -ForegroundColor Green
    exit 0
}

Write-Host "FAIL: Project 2 final Active Directory state requires investigation." -ForegroundColor Red
exit 1

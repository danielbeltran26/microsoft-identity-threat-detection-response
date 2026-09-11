[CmdletBinding()]
param(
    [string]$OrganizationalUnitPath = "OU=IDTR-Lab,DC=corporate,DC=test",
    [string]$HighValueGroupName = "IDTR-HighValue-Lab"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory

$Users = @(
    Get-ADUser `
        -SearchBase $OrganizationalUnitPath `
        -Filter "SamAccountName -like 'idtr-user*'" `
        -Properties Enabled, LockedOut
)

if ($Users.Count -ne 5) {
    throw "Expected five controlled users in '$OrganizationalUnitPath' but found $($Users.Count)."
}

$Group = Get-ADGroup -Identity $HighValueGroupName

foreach ($User in $Users) {
    if ($User.Enabled) {
        Disable-ADAccount -Identity $User
        Write-Host "DISABLED: $($User.SamAccountName)" -ForegroundColor Green
    }

    if ($User.LockedOut) {
        Unlock-ADAccount -Identity $User
        Write-Host "UNLOCKED: $($User.SamAccountName)" -ForegroundColor Green
    }

    $Membership = Get-ADGroupMember -Identity $Group |
        Where-Object DistinguishedName -eq $User.DistinguishedName

    if ($null -ne $Membership) {
        Remove-ADGroupMember `
            -Identity $Group `
            -Members $User `
            -Confirm:$false

        Write-Host "REMOVED FROM GROUP: $($User.SamAccountName)" -ForegroundColor Green
    }
}

$UnexpectedMembers = @(
    Get-ADGroupMember -Identity $Group |
    Where-Object { $_.DistinguishedName -notin $Users.DistinguishedName }
)

if ($UnexpectedMembers.Count -gt 0) {
    Write-Warning "Unexpected members were not removed automatically:"
    $UnexpectedMembers | Select-Object Name, SamAccountName, DistinguishedName | Format-Table -AutoSize
    throw "The controlled group contains an unexpected member. Investigate before making another change."
}

$FinalUsers = Get-ADUser `
    -SearchBase $OrganizationalUnitPath `
    -Filter "SamAccountName -like 'idtr-user*'" `
    -Properties Enabled, LockedOut

$Result = [PSCustomObject]@{
    DisposableUserCount = @($FinalUsers).Count
    EnabledUserCount    = @($FinalUsers | Where-Object Enabled).Count
    LockedOutUserCount  = @($FinalUsers | Where-Object LockedOut).Count
    HighValueGroupMembers = @(Get-ADGroupMember -Identity $Group).Count
}

$Result | Format-Table -AutoSize

if (
    $Result.DisposableUserCount -ne 5 -or
    $Result.EnabledUserCount -ne 0 -or
    $Result.LockedOutUserCount -ne 0 -or
    $Result.HighValueGroupMembers -ne 0
) {
    throw "The Project 2 lab did not return to the required safe state."
}

Write-Host "PASS: Controlled users are disabled and unlocked, and the high-value lab group is empty." -ForegroundColor Green

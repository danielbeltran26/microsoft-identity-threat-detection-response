[CmdletBinding()]
param(
    [string]$TargetAccount = "idtr-user01",
    [string]$HighValueGroup = "IDTR-HighValue-Lab",
    [string]$TargetOU = "OU=IDTR-Lab,DC=corporate,DC=test"
)

$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory

$ContainmentUTC = [datetime]::UtcNow
$TargetUser = Get-ADUser `
    -Identity $TargetAccount `
    -Properties Enabled, LockedOut, DistinguishedName

$MembersBefore = @(
    Get-ADGroupMember `
        -Identity $HighValueGroup `
        -ErrorAction Stop
)

$WasGroupMember = @(
    $MembersBefore |
        Where-Object DistinguishedName -EQ $TargetUser.DistinguishedName
).Count -eq 1

$DisableAction = "Already disabled"
$UnlockAction = "Not locked"
$GroupRemovalAction = "Already absent"
$ChangesApplied = 0

if ($TargetUser.Enabled) {
    Disable-ADAccount -Identity $TargetUser
    $DisableAction = "Disabled"
    $ChangesApplied++
}

if ($TargetUser.LockedOut) {
    Unlock-ADAccount -Identity $TargetUser
    $UnlockAction = "Unlocked"
    $ChangesApplied++
}

if ($WasGroupMember) {
    Remove-ADGroupMember `
        -Identity $HighValueGroup `
        -Members $TargetUser `
        -Confirm:$false

    $GroupRemovalAction = "Removed"
    $ChangesApplied++
}

$TargetAfter = Get-ADUser `
    -Identity $TargetAccount `
    -Properties Enabled, LockedOut, DistinguishedName

$MembersAfter = @(
    Get-ADGroupMember `
        -Identity $HighValueGroup `
        -ErrorAction Stop
)

$IsGroupMemberAfter = @(
    $MembersAfter |
        Where-Object DistinguishedName -EQ $TargetAfter.DistinguishedName
).Count -eq 1

$DisposableUsers = @(
    Get-ADUser `
        -SearchBase $TargetOU `
        -Filter 'SamAccountName -like "idtr-user*"' `
        -Properties Enabled, LockedOut
)

$EnabledDisposableUsers = @(
    $DisposableUsers |
        Where-Object Enabled
).Count

$LockedDisposableUsers = @(
    $DisposableUsers |
        Where-Object LockedOut
).Count

[pscustomobject]@{
    ContainmentUTC         = $ContainmentUTC.ToString("o")
    TargetAccount          = $TargetAccount
    BeforeEnabled          = $TargetUser.Enabled
    BeforeLockedOut        = $TargetUser.LockedOut
    BeforeGroupMember      = $WasGroupMember
    DisableAction          = $DisableAction
    UnlockAction           = $UnlockAction
    GroupRemovalAction     = $GroupRemovalAction
    ChangesApplied         = $ChangesApplied
    AfterEnabled           = $TargetAfter.Enabled
    AfterLockedOut         = $TargetAfter.LockedOut
    AfterGroupMember       = $IsGroupMemberAfter
    DisposableUserCount    = $DisposableUsers.Count
    EnabledDisposableUsers = $EnabledDisposableUsers
    LockedDisposableUsers  = $LockedDisposableUsers
    HighValueGroupMembers  = $MembersAfter.Count
} | Format-List

if (
    $TargetAfter.Enabled -or
    $TargetAfter.LockedOut -or
    $IsGroupMemberAfter -or
    $DisposableUsers.Count -ne 5 -or
    $EnabledDisposableUsers -ne 0 -or
    $LockedDisposableUsers -ne 0 -or
    $MembersAfter.Count -ne 0
) {
    throw "Identity containment validation failed."
}

Write-Host `
    "PASS: Controlled identity containment is enforced and validated." `
    -ForegroundColor Green

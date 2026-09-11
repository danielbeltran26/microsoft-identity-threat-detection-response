[CmdletBinding()]
param(
    [string]$ExpectedDomainDistinguishedName = "DC=corporate,DC=test",
    [string]$OrganizationalUnitName = "IDTR-Lab",
    [string]$HighValueGroupName = "IDTR-HighValue-Lab",
    [ValidateRange(1, 20)]
    [int]$UserCount = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory

$Domain = Get-ADDomain
if ($Domain.DistinguishedName -ine $ExpectedDomainDistinguishedName) {
    throw "Expected domain '$ExpectedDomainDistinguishedName' but found '$($Domain.DistinguishedName)'."
}

$OrganizationalUnitPath = "OU=$OrganizationalUnitName,$ExpectedDomainDistinguishedName"
$Description = "Disposable Project 2 identity-testing account"

Write-Host "Project 2 controlled Active Directory object creation" -ForegroundColor Cyan
Write-Host "Domain: $($Domain.DNSRoot)"
Write-Host "Target OU: $OrganizationalUnitPath`n"

$OrganizationalUnit = Get-ADOrganizationalUnit `
    -Identity $OrganizationalUnitPath `
    -ErrorAction SilentlyContinue

if ($null -eq $OrganizationalUnit) {
    New-ADOrganizationalUnit `
        -Name $OrganizationalUnitName `
        -Path $ExpectedDomainDistinguishedName `
        -ProtectedFromAccidentalDeletion $true

    Write-Host "CREATED: $OrganizationalUnitPath" -ForegroundColor Green
}
else {
    Set-ADOrganizationalUnit `
        -Identity $OrganizationalUnitPath `
        -ProtectedFromAccidentalDeletion $true

    Write-Host "EXISTS:  $OrganizationalUnitPath" -ForegroundColor Yellow
}

$ExistingGroup = Get-ADGroup `
    -Filter "SamAccountName -eq '$HighValueGroupName'" `
    -Properties GroupCategory, GroupScope `
    -ErrorAction SilentlyContinue

if ($null -ne $ExistingGroup -and $ExistingGroup.DistinguishedName -ine "CN=$HighValueGroupName,$OrganizationalUnitPath") {
    throw "A conflicting group named '$HighValueGroupName' exists at '$($ExistingGroup.DistinguishedName)'."
}

if ($null -eq $ExistingGroup) {
    New-ADGroup `
        -Name $HighValueGroupName `
        -SamAccountName $HighValueGroupName `
        -GroupCategory Security `
        -GroupScope Global `
        -Path $OrganizationalUnitPath `
        -Description "Synthetic Project 2 high-value group; no production privilege assigned"

    Write-Host "CREATED: $HighValueGroupName" -ForegroundColor Green
}
else {
    if ($ExistingGroup.GroupCategory -ne "Security" -or $ExistingGroup.GroupScope -ne "Global") {
        throw "Existing group '$HighValueGroupName' is not a global security group."
    }

    Write-Host "EXISTS:  $HighValueGroupName" -ForegroundColor Yellow
}

$UserSpecifications = foreach ($Index in 1..$UserCount) {
    $Number = $Index.ToString("00")

    [PSCustomObject]@{
        Name              = "IDTR User$Number"
        SamAccountName    = "idtr-user$Number"
        UserPrincipalName = "idtr-user$Number@$($Domain.DNSRoot)"
    }
}

$MissingUsers = @(
    foreach ($Specification in $UserSpecifications) {
        $ExistingUser = Get-ADUser `
            -Filter "SamAccountName -eq '$($Specification.SamAccountName)'" `
            -ErrorAction SilentlyContinue

        if ($null -ne $ExistingUser -and $ExistingUser.DistinguishedName -ine "CN=$($Specification.Name),$OrganizationalUnitPath") {
            throw "A conflicting user '$($Specification.SamAccountName)' exists at '$($ExistingUser.DistinguishedName)'."
        }

        if ($null -eq $ExistingUser) {
            $Specification
        }
    }
)

$LabPassword = $null
if ($MissingUsers.Count -gt 0) {
    Write-Host "`nA password is required only for the $($MissingUsers.Count) missing disposable account(s)." -ForegroundColor Yellow
    Write-Host "It is entered as a SecureString and is never printed or written to disk."
    $LabPassword = Read-Host "Temporary shared lab password" -AsSecureString
}

foreach ($Specification in $UserSpecifications) {
    $ExistingUser = Get-ADUser `
        -Filter "SamAccountName -eq '$($Specification.SamAccountName)'" `
        -Properties Description, Enabled, LockedOut, PasswordNeverExpires `
        -ErrorAction SilentlyContinue

    if ($null -eq $ExistingUser) {
        New-ADUser `
            -Name $Specification.Name `
            -DisplayName $Specification.Name `
            -SamAccountName $Specification.SamAccountName `
            -UserPrincipalName $Specification.UserPrincipalName `
            -Path $OrganizationalUnitPath `
            -Description $Description `
            -AccountPassword $LabPassword `
            -Enabled $false `
            -ChangePasswordAtLogon $false `
            -PasswordNeverExpires $false

        Write-Host "CREATED: $($Specification.SamAccountName) (disabled)" -ForegroundColor Green
        continue
    }

    Set-ADUser `
        -Identity $ExistingUser `
        -DisplayName $Specification.Name `
        -Description $Description `
        -PasswordNeverExpires $false

    if ($ExistingUser.Enabled) {
        Disable-ADAccount -Identity $ExistingUser
    }

    Write-Host "EXISTS:  $($Specification.SamAccountName) (left disabled)" -ForegroundColor Yellow
}

$LabPassword = $null

$ValidatedUsers = Get-ADUser `
    -SearchBase $OrganizationalUnitPath `
    -Filter "SamAccountName -like 'idtr-user*'" `
    -Properties Enabled, LockedOut, PasswordNeverExpires |
    Sort-Object SamAccountName

$GroupMemberCount = @(Get-ADGroupMember -Identity $HighValueGroupName).Count

Write-Host "`nValidated disposable identities" -ForegroundColor Cyan
$ValidatedUsers |
    Select-Object Name, SamAccountName, Enabled, LockedOut, PasswordNeverExpires |
    Format-Table -AutoSize

Write-Host "High-value lab group member count: $GroupMemberCount"

if ($ValidatedUsers.Count -ne $UserCount) {
    throw "Expected $UserCount disposable users but found $($ValidatedUsers.Count)."
}

if (@($ValidatedUsers | Where-Object { $_.Enabled }).Count -ne 0) {
    throw "One or more disposable accounts remained enabled."
}

if ($GroupMemberCount -ne 0) {
    throw "The high-value lab group is not empty."
}

Write-Host "`nPASS: Project 2 lab objects exist in a safe disabled and empty-group state." -ForegroundColor Green

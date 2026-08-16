#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Users, Microsoft.Graph.Groups

<#
.SYNOPSIS
    Summarizes Microsoft Entra Conditional Access policy scope and authentication requirements.

.DESCRIPTION
    Reviews Conditional Access policies and reports each policy's state, target scope,
    authentication requirement, Authentication Strength display name when present,
    and whether exclusions are configured. Results are written to the console and
    exported to a local CSV file.

.NOTES
    This script is read-only and does not modify Conditional Access policies.
#>

# Connect if needed
if (-not (Get-MgContext)) {
    Connect-MgGraph `
        -Scopes "Policy.Read.All","Group.Read.All","User.Read.All","Directory.Read.All" `
        -NoWelcome
}

# Cache role templates
$roleTemplates = Get-MgDirectoryRoleTemplate -All

function Resolve-UserTarget {
    param([string]$UserId)

    switch ($UserId) {
        "All" { return "ALL USERS" }
        "GuestsOrExternalUsers" { return "Guests/External Users" }
        "None" { return "None" }
        default {
            try {
                $user = Get-MgUser -UserId $UserId -Property DisplayName,UserPrincipalName
                return "$($user.DisplayName) <$($user.UserPrincipalName)>"
            }
            catch {
                return $UserId
            }
        }
    }
}

function Resolve-GroupTarget {
    param([string]$GroupId)

    try {
        $group = Get-MgGroup -GroupId $GroupId -Property DisplayName
        return "$($group.DisplayName)"
    }
    catch {
        return $GroupId
    }
}

function Resolve-RoleTarget {
    param([string]$RoleId)

    $role = $roleTemplates | Where-Object { $_.Id -eq $RoleId }

    if ($role) {
        return "$($role.DisplayName)"
    }
    else {
        return $RoleId
    }
}

function Get-TargetSummary {
    param($Users)

    if ($Users.IncludeUsers -contains "All") {
        return "ALL USERS"
    }

    if ($Users.IncludeUsers -and $Users.IncludeUsers.Count -gt 0) {
        $resolved = $Users.IncludeUsers | ForEach-Object { Resolve-UserTarget $_ }
        return "Users: $($resolved -join '; ')"
    }

    if ($Users.IncludeGroups -and $Users.IncludeGroups.Count -gt 0) {
        $resolved = $Users.IncludeGroups | ForEach-Object { Resolve-GroupTarget $_ }
        return "Groups: $($resolved -join '; ')"
    }

    if ($Users.IncludeRoles -and $Users.IncludeRoles.Count -gt 0) {
        $resolved = $Users.IncludeRoles | ForEach-Object { Resolve-RoleTarget $_ }
        return "Roles: $($resolved -join '; ')"
    }

    return "No target found"
}

function Get-AuthRequirement {
    param($Policy)

    $grant = $Policy.GrantControls

    if (-not $grant) {
        return "None"
    }

    if ($grant.BuiltInControls -contains "block") {
        return "Block Access"
    }

    if ($grant.AuthenticationStrength) {
        if ($grant.AuthenticationStrength.DisplayName) {
            return "Authentication Strength: $($grant.AuthenticationStrength.DisplayName)"
        }
        else {
            return "Authentication Strength"
        }
    }

    if ($grant.BuiltInControls -contains "mfa") {
        return "Require MFA"
    }

    return "None"
}

function Test-ExclusionsPresent {
    param($Users)

    if (
        ($Users.ExcludeUsers -and $Users.ExcludeUsers.Count -gt 0) -or
        ($Users.ExcludeGroups -and $Users.ExcludeGroups.Count -gt 0) -or
        ($Users.ExcludeRoles -and $Users.ExcludeRoles.Count -gt 0)
    ) {
        return "Yes"
    }

    return "No"
}

$policies = Get-MgIdentityConditionalAccessPolicy -All | Sort-Object DisplayName
$results = @()

foreach ($policy in $policies) {
    $users = $policy.Conditions.Users

    $targetSummary = Get-TargetSummary -Users $users
    $authRequirement = Get-AuthRequirement -Policy $policy
    $exclusions = Test-ExclusionsPresent -Users $users

    $includedUsers = ($users.IncludeUsers | ForEach-Object { Resolve-UserTarget $_ }) -join "; "
    $includedGroups = ($users.IncludeGroups | ForEach-Object { Resolve-GroupTarget $_ }) -join "; "
    $includedRoles = ($users.IncludeRoles | ForEach-Object { Resolve-RoleTarget $_ }) -join "; "

    $excludedUsers = ($users.ExcludeUsers | ForEach-Object { Resolve-UserTarget $_ }) -join "; "
    $excludedGroups = ($users.ExcludeGroups | ForEach-Object { Resolve-GroupTarget $_ }) -join "; "
    $excludedRoles = ($users.ExcludeRoles | ForEach-Object { Resolve-RoleTarget $_ }) -join "; "

    $results += [PSCustomObject]@{
        PolicyName        = $policy.DisplayName
        State             = $policy.State
        TargetSummary     = $targetSummary
        AuthRequirement   = $authRequirement
        ExclusionsPresent = $exclusions
        IncludedUsers     = $includedUsers
        IncludedGroups    = $includedGroups
        IncludedRoles     = $includedRoles
        ExcludedUsers     = $excludedUsers
        ExcludedGroups    = $excludedGroups
        ExcludedRoles     = $excludedRoles
    }

    Write-Host ""
    Write-Host "Policy : $($policy.DisplayName)" -ForegroundColor Cyan
    Write-Host "State  : $($policy.State)"
    Write-Host "Target : $targetSummary" -ForegroundColor Yellow
    Write-Host "Auth   : $authRequirement" -ForegroundColor Green
    Write-Host "Excl.  : $exclusions"
}

$path = Join-Path $PSScriptRoot "ConditionalAccessPolicyScope_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$results | Export-Csv -Path $path -NoTypeInformation
Write-Host "`nExported to: $path" -ForegroundColor Green

function Get-SAWPasskeyProfileAssignments {
    <#
    .SYNOPSIS
        Resolves the passkey profiles assigned to the users in an assessment roster.
    .DESCRIPTION
        Uses the FIDO2 policy's includeTargets.allowedPasskeyProfiles relationship. Group
        membership is read through Microsoft Graph; unresolved groups are reported as unknown
        rather than treating every user as in or out of scope.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Fido2Configuration,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Roster,

        [switch]$UseSampleData
    )

    $profiles = @(@($Fido2Configuration.passkeyProfiles) | Where-Object { $_ })
    $userIds = @($Roster | ForEach-Object { [string]$_.UserId } | Where-Object { $_ })
    $byUserId = @{}
    foreach ($userId in $userIds) { $byUserId[$userId] = @() }

    if ($profiles.Count -eq 0) {
        return @{ HasProfiles = $false; IsKnown = $true; ByUserId = $byUserId; UnresolvedTargetIds = @() }
    }

    if (@($Roster | Where-Object { -not $_.UserId }).Count -gt 0) {
        return @{ HasProfiles = $true; IsKnown = $false; ByUserId = $byUserId; UnresolvedTargetIds = @('user IDs unavailable') }
    }

    $targetsPresent = if ($Fido2Configuration -is [System.Collections.IDictionary]) {
        $Fido2Configuration.Contains('includeTargets')
    }
    else {
        [bool]$Fido2Configuration.PSObject.Properties['includeTargets']
    }
    if (-not $targetsPresent) {
        return @{ HasProfiles = $true; IsKnown = $false; ByUserId = $byUserId; UnresolvedTargetIds = @('includeTargets unavailable') }
    }

    $knownUsers = @{}
    foreach ($userId in $userIds) { $knownUsers[$userId] = $true }
    $groupMembers = @{}
    $unresolvedTargets = @{}

    $resolveTargetUsers = {
        param([object]$Target)

        $targetId = [string]$Target.id
        if (-not $targetId) { return @{ IsKnown = $false; UserIds = @() } }
        if ($targetId -eq 'all_users') { return @{ IsKnown = $true; UserIds = $userIds } }
        if ($Target.targetType -eq 'user') {
            $matchingUser = if ($knownUsers.ContainsKey($targetId)) { @($targetId) } else { @() }
            return @{ IsKnown = $true; UserIds = $matchingUser }
        }
        if ($Target.targetType -ne 'group') { return @{ IsKnown = $false; UserIds = @() } }
        if ($UseSampleData) { return @{ IsKnown = $false; UserIds = @() } }

        if (-not $groupMembers.ContainsKey($targetId)) {
            $members = @{}
            $escapedId = [uri]::EscapeDataString($targetId)
            $nextLink = "https://graph.microsoft.com/v1.0/groups/$escapedId/transitiveMembers/microsoft.graph.user?`$select=id&`$top=999"
            try {
                while ($nextLink) {
                    $response = Invoke-SAWGraphRequest -Method GET -Uri $nextLink
                    foreach ($member in @($response.value)) {
                        $memberId = [string]$member.id
                        if ($knownUsers.ContainsKey($memberId)) { $members[$memberId] = $true }
                    }
                    $nextLink = [string]$response.'@odata.nextLink'
                }
                $groupMembers[$targetId] = @{ IsKnown = $true; UserIds = @($members.Keys) }
            }
            catch {
                Write-Verbose "Get-SAWPasskeyProfileAssignments: could not resolve group '$targetId': $($_.Exception.Message)"
                $groupMembers[$targetId] = @{ IsKnown = $false; UserIds = @() }
            }
        }
        return $groupMembers[$targetId]
    }

    foreach ($target in @($Fido2Configuration.includeTargets)) {
        if (-not $target) { continue }
        $profileIds = @($target.allowedPasskeyProfiles) | ForEach-Object { [string]$_ } | Where-Object { $_ }
        if ($profileIds.Count -eq 0) {
            $unresolvedTargets[[string]$target.id] = $true
            continue
        }

        $resolution = & $resolveTargetUsers $target
        if (-not $resolution.IsKnown) {
            $unresolvedTargets[[string]$target.id] = $true
            continue
        }
        foreach ($userId in $resolution.UserIds) {
            $byUserId[$userId] = @(@($byUserId[$userId]) + $profileIds | Select-Object -Unique)
        }
    }

    return @{
        HasProfiles         = $true
        IsKnown             = ($unresolvedTargets.Count -eq 0)
        ByUserId            = $byUserId
        UnresolvedTargetIds = @($unresolvedTargets.Keys)
    }
}
function ConvertTo-SAWNormalizedConditionalAccess {
    <#
    .SYNOPSIS
        Normalizes raw Conditional Access policies into Secure At Work capability checks.
    .DESCRIPTION
        Unlike authentication methods (a 1:1 setting-to-state mapping), Conditional Access
        gap analysis is inherently cross-policy: "is legacy auth blocked" depends on whether
        ANY enabled policy satisfies that intent, not on a single field. This normalizer scans
        every policy and derives a small set of { Category, Setting, State } capability facts
        that the (unchanged, logic-free) rules engine can then compare against Expected values,
        keeping the "no PowerShell logic in rules" rule (spec section 8) intact - the derivation
        happens here, not in the rule JSON.

        A policy only counts toward a capability if its state is exactly 'enabled' -
        'enabledForReportingButNotEnforced' (report-only) does not count, since it enforces
        nothing.
    .PARAMETER RawResponse
        The object returned by Get-SAWConditionalAccess (has a .value array of policies).
    .OUTPUTS
        Hashtable[]
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$RawResponse
    )

    begin {
        function ConvertTo-SAWStateLabel {
            param([bool]$Value)
            if ($Value) { return 'Enabled' }
            return 'Disabled'
        }
    }

    process {
        $policies = $RawResponse.value
        if (-not $policies) { $policies = @() }

        $legacyAuthBlocked = $false
        $mfaForAllUsers = $false
        $compliantDeviceForAdmins = $false

        foreach ($policy in $policies) {
            if ($policy.state -ne 'enabled') {
                Write-Verbose "ConvertTo-SAWNormalizedConditionalAccess: skipping '$($policy.displayName)' (state: $($policy.state))"
                continue
            }

            $targetsAllUsers = $policy.conditions.users.includeUsers -contains 'All'
            $targetsAllApps = $policy.conditions.applications.includeApplications -contains 'All'
            $targetsAdminRoles = ($policy.conditions.users.includeRoles | Measure-Object).Count -gt 0
            $controls = $policy.grantControls.builtInControls
            $clientAppTypes = $policy.conditions.clientAppTypes

            if (-not $legacyAuthBlocked -and $targetsAllUsers -and $targetsAllApps -and
                ($controls -contains 'block') -and
                (($clientAppTypes -contains 'exchangeActiveSync') -or ($clientAppTypes -contains 'other'))) {
                $legacyAuthBlocked = $true
            }

            if (-not $mfaForAllUsers -and $targetsAllUsers -and $targetsAllApps -and ($controls -contains 'mfa')) {
                $mfaForAllUsers = $true
            }

            if (-not $compliantDeviceForAdmins -and $targetsAdminRoles -and ($controls -contains 'compliantDevice')) {
                $compliantDeviceForAdmins = $true
            }
        }

        @{
            Category = 'Conditional Access'
            Setting  = 'Block Legacy Authentication'
            State    = ConvertTo-SAWStateLabel $legacyAuthBlocked
        }
        @{
            Category = 'Conditional Access'
            Setting  = 'Require MFA For All Users'
            State    = ConvertTo-SAWStateLabel $mfaForAllUsers
        }
        @{
            Category = 'Conditional Access'
            Setting  = 'Require Compliant Device For Admins'
            State    = ConvertTo-SAWStateLabel $compliantDeviceForAdmins
        }
    }
}

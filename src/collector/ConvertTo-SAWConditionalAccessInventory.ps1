function ConvertTo-SAWConditionalAccessInventory {
    <#
    .SYNOPSIS
        Produces a plain-language inventory of every Conditional Access policy.
    .DESCRIPTION
        A separate data product from ConvertTo-SAWNormalizedConditionalAccess's derived
        Category/Setting/State pass/fail facts - this is a per-policy listing (name, state,
        who/what it targets, what it enforces), for the report/dashboard layer to show
        directly rather than something the Green/Yellow/Red/Grey rules engine evaluates.
        Answers "which CA policies exist and what do they actually do", independent of the
        handful of synthetic capability checks derived elsewhere.
    .PARAMETER RawResponse
        The object returned by Get-SAWConditionalAccess (has a .value array of policies).
    .OUTPUTS
        Hashtable[] - one per policy, with DisplayName, State, UserTargetSummary,
        AppTargetSummary, GrantControlsSummary, TargetsSecurityInfoRegistration.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$RawResponse
    )

    begin {
        $stateLabels = @{
            enabled                            = 'Enabled'
            disabled                           = 'Disabled'
            enabledForReportingButNotEnforced  = 'Enabled (report-only)'
        }

        function ConvertTo-SAWStateDisplayLabel {
            param([string]$Text, [hashtable]$Labels)
            if ($Labels.ContainsKey($Text)) { return $Labels[$Text] }
            if ([string]::IsNullOrEmpty($Text)) { return $Text }
            return $Text.Substring(0, 1).ToUpper() + $Text.Substring(1)
        }

        function Get-SAWUserTargetSummary {
            param($Policy)

            $includeUsers = @($Policy.conditions.users.includeUsers)
            $includeRoles = @($Policy.conditions.users.includeRoles) | Where-Object { $_ }
            $includeGroups = @($Policy.conditions.users.includeGroups) | Where-Object { $_ }
            $excludeUsers = @($Policy.conditions.users.excludeUsers) | Where-Object { $_ }

            if ($includeUsers -contains 'All') {
                $summary = 'All users'
                if ($excludeUsers.Count -gt 0) {
                    $summary += " ($($excludeUsers.Count) excluded)"
                }
                return $summary
            }
            if ($includeRoles.Count -gt 0) {
                return "$($includeRoles.Count) admin role(s)"
            }
            if ($includeGroups.Count -gt 0) {
                return "$($includeGroups.Count) group(s)"
            }
            $specificUsers = @($includeUsers) | Where-Object { $_ }
            if ($specificUsers.Count -gt 0) {
                return "$($specificUsers.Count) specific user(s)"
            }
            return 'None'
        }

        function Get-SAWAppTargetSummary {
            param($Policy)

            $userActions = @($Policy.conditions.applications.includeUserActions) | Where-Object { $_ }
            if ($userActions -contains 'urn:user:registersecurityinfo') {
                return 'Register security information'
            }

            $includeApplications = @($Policy.conditions.applications.includeApplications) | Where-Object { $_ }
            if ($includeApplications -contains 'All') {
                return 'All apps'
            }
            if ($includeApplications.Count -gt 0) {
                return "$($includeApplications.Count) app(s)"
            }
            return 'None'
        }

        function Get-SAWGrantControlsSummary {
            param($Policy)

            $labelByControl = @{
                block               = 'Block access'
                mfa                 = 'Require MFA'
                compliantDevice     = 'Require compliant device'
                domainJoinedDevice  = 'Require hybrid Azure AD joined device'
                approvedApplication = 'Require approved client app'
                passwordChange      = 'Require password change'
            }

            $parts = @()
            $builtInControls = @($Policy.grantControls.builtInControls) | Where-Object { $_ }
            foreach ($control in $builtInControls) {
                if ($labelByControl.ContainsKey($control)) {
                    $parts += $labelByControl[$control]
                }
                else {
                    $parts += $control
                }
            }

            $authStrength = $Policy.grantControls.authenticationStrength
            if ($authStrength) {
                $parts += "Require auth strength: $($authStrength.displayName)"
            }

            if ($parts.Count -eq 0) { return 'None' }
            return ($parts -join ', ')
        }
    }

    process {
        $policies = $RawResponse.value
        if (-not $policies) { $policies = @() }

        foreach ($policy in $policies) {
            $userActions = @($policy.conditions.applications.includeUserActions) | Where-Object { $_ }

            @{
                DisplayName                     = $policy.displayName
                State                           = ConvertTo-SAWStateDisplayLabel $policy.state $stateLabels
                UserTargetSummary                = Get-SAWUserTargetSummary $policy
                AppTargetSummary                 = Get-SAWAppTargetSummary $policy
                GrantControlsSummary             = Get-SAWGrantControlsSummary $policy
                TargetsSecurityInfoRegistration  = ($userActions -contains 'urn:user:registersecurityinfo')
            }
        }
    }
}

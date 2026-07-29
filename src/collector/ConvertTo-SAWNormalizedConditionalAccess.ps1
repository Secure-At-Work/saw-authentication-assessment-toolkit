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

        Admin protection is intentionally modeled as a composite, not a single hard-coded
        control: requiring a compliant device is only one way to harden privileged accounts -
        a phishing-resistant authentication strength required for admin roles achieves the
        same intent, and so (outside what Graph can observe) does a PAW-based access model.
        This normalizer reports both underlying facts plus the composite so the rules engine
        only needs to evaluate "is at least one admin-protection control in place", not force
        a single specific implementation.
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
        $phishingResistantMethods = @('fido2', 'windowsHelloForBusiness', 'x509CertificateMultiFactor')

        function ConvertTo-SAWStateLabel {
            param([bool]$Value)
            if ($Value) { return 'Enabled' }
            return 'Disabled'
        }

        function Test-SAWPhishingResistantStrength {
            param([object]$AuthenticationStrength)

            if (-not $AuthenticationStrength) { return $false }

            $combinations = $AuthenticationStrength.allowedCombinations
            if ($combinations -and (@($combinations)).Count -gt 0) {
                foreach ($combination in $combinations) {
                    if ($phishingResistantMethods -notcontains $combination) { return $false }
                }
                return $true
            }

            # Fall back to name matching if allowedCombinations wasn't expanded inline -
            # covers Graph responses that only include an authenticationStrength reference.
            if ($AuthenticationStrength.displayName -match 'phishing.?resistant') { return $true }

            return $false
        }
    }

    process {
        $policies = $RawResponse.value
        if (-not $policies) { $policies = @() }

        $legacyAuthBlocked = $false
        $mfaForAllUsers = $false
        $compliantDeviceForAdmins = $false
        $phishingResistantStrengthForAdmins = $false

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

            if (-not $phishingResistantStrengthForAdmins -and $targetsAdminRoles -and
                (Test-SAWPhishingResistantStrength $policy.grantControls.authenticationStrength)) {
                $phishingResistantStrengthForAdmins = $true
            }
        }

        $adminProtectionInPlace = $compliantDeviceForAdmins -or $phishingResistantStrengthForAdmins

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
        @{
            Category = 'Conditional Access'
            Setting  = 'Require Phishing-Resistant Auth Strength For Admins'
            State    = ConvertTo-SAWStateLabel $phishingResistantStrengthForAdmins
        }
        @{
            Category = 'Conditional Access'
            Setting  = 'Privileged Access Protection In Place (Compliant Device Or Phishing-Resistant Auth Strength For Admins)'
            State    = ConvertTo-SAWStateLabel $adminProtectionInPlace
        }
    }
}

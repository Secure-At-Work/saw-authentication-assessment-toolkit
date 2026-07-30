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

        Also checks for a specific lockout trap: an enabled policy targeting the "Register
        security information" user action (urn:user:registersecurityinfo) whose grantControls
        require a custom authentication strength that a Temporary Access Pass does not satisfy
        (allowedCombinations omits temporaryAccessPassOneTime/temporaryAccessPassMultiUse). A
        user with no phishing-resistant method yet - exactly the population Microsoft's
        automatic passkey nudges from 2026-09-01 target, see AUTH006 - relies on TAP as their
        only way to bootstrap into registering one (see BOOT001). If the policy gating that
        registration page itself demands a phishing-resistant strength with no TAP escape,
        that user can never reach the page that would let them register a phishing-resistant
        method in the first place. A plain "mfa" builtin control (no custom strength) does not
        trigger this - TAP satisfies a generic MFA requirement.
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

        $tapSatisfyingCombinations = @('temporaryAccessPassOneTime', 'temporaryAccessPassMultiUse')

        function Test-SAWStrengthBlocksTapOnlyUser {
            param([object]$AuthenticationStrength)

            # No custom strength configured - the policy just uses a plain "mfa" builtin
            # control, which a Temporary Access Pass generically satisfies. Nothing to block.
            if (-not $AuthenticationStrength) { return $false }

            $combinations = @($AuthenticationStrength.allowedCombinations) | Where-Object { $_ }
            if ($combinations.Count -eq 0) {
                # Can't determine what this strength actually allows - don't flag a false
                # positive off incomplete data.
                return $false
            }

            foreach ($combination in $combinations) {
                if ($tapSatisfyingCombinations -contains $combination) { return $false }
            }
            return $true
        }
    }

    process {
        $policies = $RawResponse.value
        if (-not $policies) { $policies = @() }

        $legacyAuthBlocked = $false
        $mfaForAllUsers = $false
        $compliantDeviceForAdmins = $false
        $phishingResistantStrengthForAdmins = $false
        $securityInfoRegistrationBlockedForTapOnlyUsers = $false

        foreach ($policy in $policies) {
            if ($policy.state -ne 'enabled') {
                Write-Verbose "ConvertTo-SAWNormalizedConditionalAccess: skipping '$($policy.displayName)' (state: $($policy.state))"
                continue
            }

            $targetsAllUsers = $policy.conditions.users.includeUsers -contains 'All'
            $targetsAllApps = $policy.conditions.applications.includeApplications -contains 'All'
            $targetsAdminRoles = ($policy.conditions.users.includeRoles | Measure-Object).Count -gt 0
            $targetsSecurityInfoRegistration = @($policy.conditions.applications.includeUserActions) -contains 'urn:user:registersecurityinfo'
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

            if ($targetsSecurityInfoRegistration -and
                (Test-SAWStrengthBlocksTapOnlyUser $policy.grantControls.authenticationStrength)) {
                Write-Verbose "ConvertTo-SAWNormalizedConditionalAccess: '$($policy.displayName)' gates Register Security Information with a strength that does not accept a Temporary Access Pass"
                $securityInfoRegistrationBlockedForTapOnlyUsers = $true
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
        @{
            Category = 'Conditional Access'
            Setting  = 'Security Info Registration Reachable With Only A Temporary Access Pass'
            State    = ConvertTo-SAWStateLabel (-not $securityInfoRegistrationBlockedForTapOnlyUsers)
        }
    }
}

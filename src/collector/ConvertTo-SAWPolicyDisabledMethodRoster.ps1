function ConvertTo-SAWPolicyDisabledMethodRoster {
    <#
    .SYNOPSIS
        Cross-references registered authentication methods against the tenant-wide
        authenticationMethodsPolicy, and flags any registered method whose policy toggle is
        now Disabled - a dead credential that structurally cannot be used to sign in anymore.
    .DESCRIPTION
        This is a stronger, more deterministic sibling to ConvertTo-SAWMethodUsageRoster.ps1's
        "not observed as used recently" check: that one is a proxy based on sign-in activity
        (a method could be unused for other reasons and still work). This one is a direct fact:
        if the tenant policy for a method type is Disabled, a user's registration for that
        method type cannot be used to authenticate, full stop - it's dead weight worth removing
        (smaller attack surface, less user confusion about which method actually works).

        Takes an already-built roster (ConvertTo-SAWUserRegistrationRoster.ps1's output, whether
        or not it's already been through ConvertTo-SAWMethodUsageRoster.ps1) and the raw
        authenticationMethodsPolicy response (Get-SAWAuthenticationMethods.ps1's output), and
        adds two fields per user: PolicyDisabledMethods (comma-joined list of registered methods
        whose policy toggle is Disabled) and HasPolicyDisabledMethod.

        Method-name mapping caveat, same spirit as ConvertTo-SAWMethodUsageRoster.ps1: only a
        well-established subset of userRegistrationDetails.methodsRegistered values map onto an
        authenticationMethodsPolicy.authenticationMethodConfigurations entry. Two real gaps:
          - Windows Hello for Business has NO tenant-level toggle in authenticationMethodsPolicy
            at all (it's governed by device/WHfB policy, a completely different API) - a WHfB
            registration can never be flagged by this function, not because it's assumed fine,
            but because there's nothing here to check it against.
          - Passkey (device-bound) variants aren't yet in this function's mapping table either
            (this toolkit's authenticationMethodsPolicy normalizer doesn't currently parse a
            dedicated Passkey config entry - see Get-SAWPasskeys.ps1 for the separate policy
            that actually governs those).
        A registered method type with no mapping entry is left unevaluated rather than risking
        a false claim from a guessed mapping - same principle as the sign-in-usage check.

        mobilePhone/alternateMobilePhone map to BOTH Sms and Voice (a single registered phone
        number can be used for either delivery channel, and registration data doesn't say which
        one a given user actually relies on) - flagged if EITHER is Disabled, not only when both
        are, since a channel that no longer works is worth knowing about even if the other one
        still does. officePhone maps to Voice only (no SMS delivery to a desk phone).
    .PARAMETER Roster
        Output of ConvertTo-SAWUserRegistrationRoster.ps1 (optionally already enriched by
        ConvertTo-SAWMethodUsageRoster.ps1).
    .PARAMETER AuthenticationMethodsPolicy
        The object returned by Get-SAWAuthenticationMethods (has
        .authenticationMethodConfigurations, an array of { id, state }).
    .OUTPUTS
        Hashtable[] - the same shape as -Roster, each entry with two added fields:
        PolicyDisabledMethods (comma-joined string, possibly empty) and
        HasPolicyDisabledMethod (bool).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Roster,

        [Parameter(Mandatory)]
        [object]$AuthenticationMethodsPolicy
    )

    # registered-method-name -> the authenticationMethodConfigurations id(s) that govern it.
    # High-confidence, well-established mappings only - see the caveat in .DESCRIPTION.
    $policyMethodMap = @{
        fido2                      = @('Fido2')
        microsoftAuthenticatorPush = @('MicrosoftAuthenticator')
        softwareOneTimePasscode   = @('SoftwareOath')
        mobilePhone                = @('Sms', 'Voice')
        alternateMobilePhone       = @('Sms', 'Voice')
        officePhone                = @('Voice')
        temporaryAccessPass        = @('TemporaryAccessPass')
        email                      = @('Email')
    }

    $methodConfigs = @($AuthenticationMethodsPolicy.authenticationMethodConfigurations)
    if (-not $methodConfigs) { $methodConfigs = @() }

    # authenticationMethodConfigurations id -> is it Disabled (case-insensitive, Graph returns
    # lowercase 'enabled'/'disabled' state strings).
    $disabledPolicyIds = @{}
    foreach ($config in $methodConfigs) {
        if ($config.id -and ([string]$config.state).ToLowerInvariant() -eq 'disabled') {
            $disabledPolicyIds[$config.id] = $true
        }
    }

    $result = foreach ($user in $Roster) {
        $registeredMethods = @()
        if ($user.MethodsRegistered) {
            $registeredMethods = @($user.MethodsRegistered -split ',\s*' | Where-Object { $_ })
        }

        $policyDisabledMethods = @()
        foreach ($method in $registeredMethods) {
            if (-not $policyMethodMap.ContainsKey($method)) {
                # No confident mapping for this method type (e.g. windowsHelloForBusiness has
                # no tenant policy toggle at all, passkey variants aren't mapped yet) - skip
                # rather than guess.
                continue
            }
            $policyIds = $policyMethodMap[$method]
            $isDisabled = $false
            foreach ($policyId in $policyIds) {
                if ($disabledPolicyIds.ContainsKey($policyId)) { $isDisabled = $true; break }
            }
            if ($isDisabled) { $policyDisabledMethods += $method }
        }

        $userCopy = $user.Clone()
        $userCopy['PolicyDisabledMethods'] = ($policyDisabledMethods -join ', ')
        $userCopy['HasPolicyDisabledMethod'] = ($policyDisabledMethods.Count -gt 0)
        $userCopy
    }

    , @($result)
}

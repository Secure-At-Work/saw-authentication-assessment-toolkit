function ConvertTo-SAWNormalizedRegistration {
    <#
    .SYNOPSIS
        Normalizes raw per-user registration details into Secure At Work capability checks.
    .DESCRIPTION
        Scans every user's registration record and derives three aggregate facts: whether
        every admin account is MFA CAPABLE, whether overall MFA capability coverage
        across all users meets a 90% target, and - among users the tenant actually allows to
        use self-service password reset (isSsprEnabled) - whether SSPR registration coverage
        meets a 90% target. All thresholds are evaluated here (not in a rule JSON) per spec
        section 8 - rules stay pure Category/Setting/Expected comparisons.

        Whether SSPR should be enabled at all is a customer-baseline question (a fully
        cloud-native, passwordless-only tenant may not need SSPR - there's no password to
        reset), not something this normalizer decides; it only reports observed coverage
        among users the tenant has SSPR turned on for. There is no supported Microsoft Graph
        endpoint for tenant-wide SSPR scope/policy (which users/groups) - only the per-user
        effective state collected here.
    .PARAMETER RawResponse
        The object returned by Get-SAWRegistration (has a .value array of user records).
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

        # Kept deliberately in sync with ConvertTo-SAWUserRegistrationRoster.ps1's own list. Used
        # only to cross-check Microsoft's isPasswordlessCapable against method-based phishing
        # resistance, never as the source of the coverage number itself.
        #
        # Known gap, not yet closed: Microsoft also counts certificate-based authentication and
        # Platform Credential for macOS as phishing-resistant, and neither appears here. Adding
        # them needs the exact methodsRegistered strings Graph emits for them, which this project
        # hasn't yet observed on a live tenant - and guessing a string would silently under-count
        # rather than fail loudly. Until then this cross-check under-reports phishing resistance
        # for tenants using CBA or macOS Platform SSO, which is the safe direction for a
        # discrepancy counter but is worth knowing when reading it.
        $phishingResistantMethodNames = @(
            'fido2',
            'passKeyDeviceBound',
            'passKeyDeviceBoundAuthenticator',
            'passKeyDeviceBoundWindowsHello',
            'windowsHelloForBusiness'
        )
    }

    process {
        $users = $RawResponse.value
        if (-not $users) { $users = @() }

        # isMfaCapable, NOT isMfaRegistered. Microsoft's own wording is the whole reason:
        #   isMfaRegistered - "has registered a strong authentication method ... The method MAY NOT
        #                      NECESSARILY BE ALLOWED by the authentication methods policy."
        #   isMfaCapable    - "... The method MUST BE ALLOWED by the authentication methods policy."
        # Coverage built on isMfaRegistered therefore counts people who cannot actually complete
        # MFA, because the only method they registered has since been disabled tenant-wide. That
        # overstates readiness, and it gets worse precisely as a customer follows this toolkit's
        # own Phase 4 advice to turn off SMS and Voice: those users keep isMfaRegistered = true on
        # the strength of a now-dead registration while isMfaCapable correctly flips to false.
        # The metric would have looked healthiest at the exact moment it became least true.
        $totalUsers = 0
        $mfaCapableUsers = 0
        $mfaRegisteredNotCapable = 0
        $passwordlessCapableUsers = 0
        $phishingResistantRegistered = 0
        $passwordlessNotPhishingResistant = 0
        $phishingResistantNotPasswordlessCapable = 0
        $adminUsers = 0
        $adminUsersMissingMfa = 0
        $ssprEnabledUsers = 0
        $ssprRegisteredUsers = 0

        foreach ($user in $users) {
            $totalUsers++
            if ($user.isMfaCapable) { $mfaCapableUsers++ }

            # isPasswordlessCapable is policy-aware in the same way isMfaCapable is: the method
            # must be ALLOWED by the authentication methods policy, not merely registered.
            #
            # It is NOT a synonym for "phishing-resistant", and treating it as one would repeat the
            # mistake that made isMfaRegistered wrong. Microsoft's definition covers "FIDO2, Windows
            # Hello for Business, and Microsoft Authenticator (Passwordless)". Compare that against
            # Microsoft's own list of phishing-resistant methods (WHfB, Platform Credential for
            # macOS, synced passkeys, FIDO2 security keys, passkeys in Microsoft Authenticator, and
            # certificate-based authentication) and the two sets diverge in BOTH directions:
            #   - Microsoft Authenticator passwordless PHONE SIGN-IN is passwordless but push-based,
            #     so it is not phishing-resistant. It counts here and should not count as the goal.
            #   - Certificate-based authentication is phishing-resistant but is not named in the
            #     passwordless-capable definition at all.
            # So this is reported as its own measure, alongside the roster's method-based
            # phishing-resistant bucketing, rather than replacing it.
            if ($user.isPasswordlessCapable) { $passwordlessCapableUsers++ }

            $hasPhishingResistantMethod = $false
            foreach ($method in @($user.methodsRegistered)) {
                if ($phishingResistantMethodNames -contains $method) {
                    $hasPhishingResistantMethod = $true
                    break
                }
            }
            if ($hasPhishingResistantMethod) { $phishingResistantRegistered++ }

            # The two directions of disagreement mean different things, so they are counted apart.
            if ($user.isPasswordlessCapable -and -not $hasPhishingResistantMethod) {
                $passwordlessNotPhishingResistant++
            }
            if ($hasPhishingResistantMethod -and -not $user.isPasswordlessCapable) {
                $phishingResistantNotPasswordlessCapable++
            }

            # The gap between the two is itself a finding, not noise: this user registered a strong
            # method and the policy no longer permits it. They are one policy change away from
            # being locked out of their own MFA, and they will not appear in any "not registered"
            # list. Counted here so the verbose stream and the roster can name them.
            if ($user.isMfaRegistered -and -not $user.isMfaCapable) {
                $mfaRegisteredNotCapable++
                Write-Verbose "ConvertTo-SAWNormalizedRegistration: '$($user.userPrincipalName)' is MFA REGISTERED but not MFA CAPABLE - their registered method isn't allowed by the authentication methods policy"
            }

            if ($user.isAdmin) {
                $adminUsers++
                if (-not $user.isMfaCapable) {
                    $adminUsersMissingMfa++
                    Write-Verbose "ConvertTo-SAWNormalizedRegistration: admin '$($user.userPrincipalName)' is not MFA capable"
                }
            }

            # SSPR needs no equivalent change: isSsprEnabled AND isSsprRegistered together are
            # exactly Microsoft's definition of isSsprCapable ("registered the required number of
            # methods AND allowed to perform SSPR by policy"), so this was already policy-aware.
            if ($user.isSsprEnabled) {
                $ssprEnabledUsers++
                if ($user.isSsprRegistered) { $ssprRegisteredUsers++ }
            }
        }

        $allAdminsMfaRegistered = ($adminUsers -gt 0) -and ($adminUsersMissingMfa -eq 0)

        $coveragePercent = 0
        $coverageMeetsTarget = $false
        if ($totalUsers -gt 0) {
            $coveragePercent = $mfaCapableUsers / $totalUsers * 100
            $coverageMeetsTarget = $coveragePercent -ge 90
        }

        Write-Verbose ("ConvertTo-SAWNormalizedRegistration: {0}/{1} users MFA capable ({2:N1}%); {3}/{4} admins not MFA capable; {5} registered-but-not-capable" -f `
            $mfaCapableUsers, $totalUsers, $coveragePercent, $adminUsersMissingMfa, $adminUsers, $mfaRegisteredNotCapable)

        if ($mfaRegisteredNotCapable -gt 0) {
            Write-Warning "$mfaRegisteredNotCapable user(s) have a registered MFA method that the authentication methods policy no longer allows. They count as registered but cannot actually complete MFA. Run with -Verbose to list them."
        }

        $passwordlessCoveragePercent = 0
        $passwordlessMeetsTarget = $false
        if ($totalUsers -gt 0) {
            $passwordlessCoveragePercent = $passwordlessCapableUsers / $totalUsers * 100
            $passwordlessMeetsTarget = $passwordlessCoveragePercent -ge 90
        }

        Write-Verbose ("ConvertTo-SAWNormalizedRegistration: {0}/{1} users passwordless capable ({2:N1}%); {3} have a phishing-resistant method registered" -f `
            $passwordlessCapableUsers, $totalUsers, $passwordlessCoveragePercent, $phishingResistantRegistered)

        if ($passwordlessNotPhishingResistant -gt 0) {
            Write-Verbose "ConvertTo-SAWNormalizedRegistration: $passwordlessNotPhishingResistant user(s) are passwordless-capable WITHOUT a phishing-resistant method registered - most likely Microsoft Authenticator passwordless phone sign-in, which is passwordless but push-based and therefore still phishable"
        }
        if ($phishingResistantNotPasswordlessCapable -gt 0) {
            Write-Verbose "ConvertTo-SAWNormalizedRegistration: $phishingResistantNotPasswordlessCapable user(s) have a phishing-resistant method registered but are NOT passwordless-capable - the authentication methods policy isn't allowing the method they registered"
        }

        @{
            Category = 'Registration'
            Setting  = 'All Privileged Admins MFA Capable'
            State    = ConvertTo-SAWStateLabel $allAdminsMfaRegistered
        }
        @{
            Category = 'Registration'
            Setting  = 'Passwordless Capability Coverage At Least 90 Percent'
            State    = ConvertTo-SAWStateLabel $passwordlessMeetsTarget
        }
        @{
            Category = 'Registration'
            Setting  = 'Overall MFA Capability Coverage At Least 90 Percent'
            State    = ConvertTo-SAWStateLabel $coverageMeetsTarget
        }

        if ($ssprEnabledUsers -gt 0) {
            $ssprCoveragePercent = $ssprRegisteredUsers / $ssprEnabledUsers * 100
            $ssprCoverageMeetsTarget = $ssprCoveragePercent -ge 90

            Write-Verbose ("ConvertTo-SAWNormalizedRegistration: {0}/{1} SSPR-enabled users are SSPR registered ({2:N1}%)" -f `
                $ssprRegisteredUsers, $ssprEnabledUsers, $ssprCoveragePercent)

            @{
                Category = 'Registration'
                Setting  = 'SSPR Registration Coverage At Least 90 Percent (Among SSPR-Enabled Users)'
                State    = ConvertTo-SAWStateLabel $ssprCoverageMeetsTarget
            }
        }
        else {
            Write-Verbose 'ConvertTo-SAWNormalizedRegistration: no users are SSPR-enabled - SSPR coverage check not applicable'
        }
    }
}

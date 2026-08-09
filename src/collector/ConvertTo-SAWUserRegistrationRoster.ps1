function ConvertTo-SAWUserRegistrationRoster {
    <#
    .SYNOPSIS
        Buckets every user into OK / Hunt / Remove / Guest (FIDO2 Not Supported) based on
        their registered authentication methods, for the security-info registration campaign
        and downgrade-attack cleanup.
    .DESCRIPTION
        This is a separate data product from ConvertTo-SAWNormalizedRegistration's aggregate
        Category/Setting/State facts - it's a per-user roster, not something the Green/Yellow/
        Red/Grey rules engine model fits, so it's consumed directly by the report/dashboard
        layer instead of Invoke-SAWRulesEngine.

        Bucketing logic per user, based on methodsRegistered:
          - OK     - has a phishing-resistant method (FIDO2/passkey/Windows Hello for
                      Business) and no phone-based fallback method still registered.
          - Hunt   - member (not guest) user with no phishing-resistant method yet. These are
                      the users to chase down for passkey/Authenticator registration (see the
                      registration campaign, spec section 9's "Register security information").
          - Remove - has a phishing-resistant method AND a phone-based fallback method
                      (mobilePhone/alternateMobilePhone/officePhone) still registered. The
                      fallback should be removed: its continued presence is exactly what
                      enables an MFA/FIDO downgrade attack (forcing a fallback to the weaker
                      method), even though the user already has something better.
          - Guest (FIDO2 Not Supported) - guest/B2B user with no phishing-resistant method.
                      Not the same as Hunt: Microsoft doesn't support FIDO2/passkey
                      registration for guest or B2B collaboration users yet (confirmed via
                      Microsoft's own documentation; planned for end of 2026), so nudging
                      these users to "go register a passkey" is advice they currently cannot
                      act on. Called out separately rather than silently lumped into Hunt so
                      an assessor doesn't chase an impossible ask. A guest who already has a
                      phishing-resistant method (e.g. registered before guest support was
                      pulled, or via some other path) still lands in OK/Remove normally -
                      this carve-out only applies to the "needs to register one" case.

        Push notifications (microsoftAuthenticatorPush) and OTP methods are treated as
        "not phishing-resistant" for this check (per Microsoft's own phishing-resistant
        authentication strength definition - see STR001/ConvertTo-SAWNormalizedAuthentication-
        Strengths.ps1 - limited to FIDO2/WHfB/certificate-based) but are NOT treated as a
        downgrade-risk fallback either; only phone-based methods are, since those are the
        documented vector in the real-world FIDO downgrade attack against Entra ID.

        Buckets sort Remove > Hunt > Guest (FIDO2 Not Supported) > OK, admins first within
        each bucket, since admin accounts are the highest-priority targets for both
        registration campaigns and downgrade-risk cleanup.

        Possible external member detection: a UPN containing "#EXT#" (e.g.
        guest.partner_fabrikam.com#EXT#@contoso.onmicrosoft.com) is Microsoft's own
        auto-generated shape for a B2B guest invitation - no other flow produces it. If such a
        UPN shows up with userType = member rather than guest, that's a strong signal the
        account was originally a guest and either got converted to Member by an admin (a real,
        if unusual, supported action), or was provisioned as Member by cross-tenant
        synchronization (B2B Direct Connect) rather than as a guest. Either way it's still an
        externally-sourced identity - IsPossibleExternalMember flags this so it's visible rather
        than silently indistinguishable from a genuine internal member. This is a UPN-shape
        heuristic, not authoritative: Get-SAWRegistration's userRegistrationDetails source has no
        other field (no creationType, identities, or cross-tenant signal) to confirm it outright.
        Deliberately does NOT move these users into the Guest bucket or its FIDO2-not-supported
        carve-out - whether Microsoft's guest FIDO2 restriction still applies after a userType
        conversion isn't something this toolkit can determine from Graph data alone, so the
        normal bucket (based on their actual registered methods) still applies; this is an
        additional flag layered on top, not a bucket override.

        WHfB-only detection: Windows Hello for Business is bound to the specific device it was
        set up on - unlike FIDO2 security keys or passkeys, it cannot be carried to a different
        machine. A user whose only phishing-resistant method is WHfB effectively has no working
        phishing-resistant credential the moment they're not on that one device - a real risk
        for admin accounts specifically, since many admins don't do routine interactive sign-in
        on a managed Windows device with their admin account at all (PIM activation from a
        different context, a jump box, browser-only workflows). IsWhfbOnly flags any user (not
        just admins - the mechanism isn't admin-specific, though the operational impact usually
        is) who has a phishing-resistant method but WHfB is the only kind of phishing-resistant
        method present - i.e. no FIDO2/passkey alongside it. Same as IsPossibleExternalMember,
        this is a flag layered on top of the existing bucket, not a bucket override: WHfB is
        still a legitimate phishing-resistant method for the OK/Hunt/Remove bucketing itself,
        this just surfaces the portability gap separately.

        SMS/Voice-only detection: distinct from - and narrower than - HasDowngradeRiskMethod
        above. HasDowngradeRiskMethod fires whenever a phone-based method is registered AT ALL,
        even alongside a stronger method (that's the Remove bucket's whole point). IsSmsVoiceOnlyMfa
        fires only when a phone-based method (mobilePhone/alternateMobilePhone/officePhone) is
        the user's ONLY registered method - nothing else, not even a weaker non-phishing-resistant
        one like Authenticator OTP. This matches Microsoft's own criterion for the 2027-02-01
        SMS/Voice retirement's mandatory, no-opt-out blocking passkey prompt: "users whose only
        available MFA method is SMS or voice will be required to register a passkey during
        sign-in to continue accessing their account" - confirmed against
        https://learn.microsoft.com/entra/identity/authentication/concept-sms-voice-retirement.
        A user with SMS AND Authenticator registered is unaffected by that specific Feb 2027
        requirement even though HasDowngradeRiskMethod is also true for them - this flag is what
        distinguishes the two. A user with zero registered methods at all is not flagged here
        either (methods.Count must be greater than zero) - that's a distinct, worse problem
        (no MFA registered at all, see REG001/REG002), not "still relying on SMS/Voice".
        SystemPreferredMethod passes through userRegistrationDetails.systemPreferredAuthenticationMethod
        as-is (nullable - Graph returns null when the system hasn't yet determined a preference
        for that user, e.g. no MFA-capable method registered). This is what Microsoft's
        System-Preferred Authentication feature (systemCredentialPreferences on
        authenticationMethodsPolicy - a distinct tenant-wide setting from everything else
        collected here, see ConvertTo-SAWAuthenticationMethodsInventory.ps1) would currently
        present first at sign-in for this specific user, if that tenant-wide feature is active
        for them. Included here purely as visible context for a person reading the triage table -
        it doesn't affect bucketing, since which method a tenant prefers to present first doesn't
        change whether the user's underlying registration is itself in a good state.
    .PARAMETER RawResponse
        The object returned by Get-SAWRegistration (has a .value array of user records).
    .OUTPUTS
        Hashtable[] - one per user, with UserPrincipalName, DisplayName, IsAdmin, IsGuest,
        IsPossibleExternalMember, IsWhfbOnly, Bucket, HasPhishingResistantMethod,
        HasDowngradeRiskMethod, IsSmsVoiceOnlyMfa, SystemPreferredMethod, MethodsRegistered.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$RawResponse
    )

    begin {
        $portablePhishingResistantMethods = @(
            'fido2',
            'passKeyDeviceBound',
            'passKeyDeviceBoundAuthenticator',
            'passKeyDeviceBoundWindowsHello'
        )
        $phishingResistantMethods = $portablePhishingResistantMethods + @('windowsHelloForBusiness')
        $downgradeRiskMethods = @('mobilePhone', 'alternateMobilePhone', 'officePhone')

        $roster = @()
    }

    process {
        $users = $RawResponse.value
        if (-not $users) { $users = @() }

        foreach ($user in $users) {
            $methods = $user.methodsRegistered
            if (-not $methods) { $methods = @() }
            $isGuest = ($user.userType -eq 'guest')
            $isPossibleExternalMember = (-not $isGuest) -and ($user.userPrincipalName -match '(?i)#EXT#@')

            $hasPhishingResistant = $false
            foreach ($method in $methods) {
                if ($phishingResistantMethods -contains $method) {
                    $hasPhishingResistant = $true
                    break
                }
            }

            $hasPortablePhishingResistant = $false
            foreach ($method in $methods) {
                if ($portablePhishingResistantMethods -contains $method) {
                    $hasPortablePhishingResistant = $true
                    break
                }
            }
            $isWhfbOnly = $hasPhishingResistant -and (-not $hasPortablePhishingResistant)

            $hasDowngradeRisk = $false
            foreach ($method in $methods) {
                if ($downgradeRiskMethods -contains $method) {
                    $hasDowngradeRisk = $true
                    break
                }
            }

            $isSmsVoiceOnlyMfa = $false
            if ($methods.Count -gt 0) {
                $isSmsVoiceOnlyMfa = $true
                foreach ($method in $methods) {
                    if ($downgradeRiskMethods -notcontains $method) {
                        $isSmsVoiceOnlyMfa = $false
                        break
                    }
                }
            }

            if ($hasPhishingResistant -and $hasDowngradeRisk) {
                $bucket = 'Remove'
            }
            elseif ($hasPhishingResistant) {
                $bucket = 'OK'
            }
            elseif ($isGuest) {
                $bucket = 'Guest (FIDO2 Not Supported)'
            }
            else {
                $bucket = 'Hunt'
            }

            $roster += @{
                UserPrincipalName          = $user.userPrincipalName
                DisplayName                = $user.userDisplayName
                IsAdmin                    = [bool]$user.isAdmin
                # Microsoft's own policy-aware verdict, carried alongside this roster's
                # method-based bucketing rather than replacing it. Where the two disagree that is
                # a real signal: passwordless-capable without a phishing-resistant method usually
                # means Authenticator passwordless phone sign-in (passwordless, still phishable),
                # while the reverse means the policy isn't allowing the method they registered.
                IsPasswordlessCapable      = [bool]$user.isPasswordlessCapable
                IsGuest                    = $isGuest
                IsPossibleExternalMember   = $isPossibleExternalMember
                IsWhfbOnly                 = $isWhfbOnly
                Bucket                     = $bucket
                HasPhishingResistantMethod = $hasPhishingResistant
                HasDowngradeRiskMethod     = $hasDowngradeRisk
                IsSmsVoiceOnlyMfa          = $isSmsVoiceOnlyMfa
                SystemPreferredMethod      = $user.systemPreferredAuthenticationMethod
                MethodsRegistered          = ($methods -join ', ')
            }
        }
    }

    end {
        $bucketRank = @{ Remove = 0; Hunt = 1; 'Guest (FIDO2 Not Supported)' = 2; OK = 3 }
        $roster |
            Sort-Object -Property `
                { if ($bucketRank.ContainsKey($_.Bucket)) { $bucketRank[$_.Bucket] } else { 99 } }, `
                { if ($_.IsAdmin) { 0 } else { 1 } }, `
                { $_.UserPrincipalName }
    }
}

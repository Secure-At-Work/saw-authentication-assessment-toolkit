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
    .PARAMETER RawResponse
        The object returned by Get-SAWRegistration (has a .value array of user records).
    .OUTPUTS
        Hashtable[] - one per user, with UserPrincipalName, DisplayName, IsAdmin, IsGuest,
        IsPossibleExternalMember, Bucket, HasPhishingResistantMethod, HasDowngradeRiskMethod,
        MethodsRegistered.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$RawResponse
    )

    begin {
        $phishingResistantMethods = @(
            'fido2',
            'passKeyDeviceBound',
            'passKeyDeviceBoundAuthenticator',
            'passKeyDeviceBoundWindowsHello',
            'windowsHelloForBusiness'
        )
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

            $hasDowngradeRisk = $false
            foreach ($method in $methods) {
                if ($downgradeRiskMethods -contains $method) {
                    $hasDowngradeRisk = $true
                    break
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
                IsGuest                    = $isGuest
                IsPossibleExternalMember   = $isPossibleExternalMember
                Bucket                     = $bucket
                HasPhishingResistantMethod = $hasPhishingResistant
                HasDowngradeRiskMethod     = $hasDowngradeRisk
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

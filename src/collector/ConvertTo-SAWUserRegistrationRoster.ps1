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
    .PARAMETER RawResponse
        The object returned by Get-SAWRegistration (has a .value array of user records).
    .OUTPUTS
        Hashtable[] - one per user, with UserPrincipalName, DisplayName, IsAdmin, IsGuest,
        Bucket, HasPhishingResistantMethod, HasDowngradeRiskMethod, MethodsRegistered.
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

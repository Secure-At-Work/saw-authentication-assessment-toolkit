function ConvertTo-SAWUserRegistrationRoster {
    <#
    .SYNOPSIS
        Buckets every user into OK / Hunt / Remove based on their registered authentication
        methods, for the security-info registration campaign and downgrade-attack cleanup.
    .DESCRIPTION
        This is a separate data product from ConvertTo-SAWNormalizedRegistration's aggregate
        Category/Setting/State facts - it's a per-user roster, not something the Green/Yellow/
        Red/Grey rules engine model fits, so it's consumed directly by the report/dashboard
        layer instead of Invoke-SAWRulesEngine.

        Bucketing logic per user, based on methodsRegistered:
          - OK     - has a phishing-resistant method (FIDO2/passkey/Windows Hello for
                      Business) and no phone-based fallback method still registered.
          - Hunt   - has no phishing-resistant method yet. These are the users to chase down
                      for passkey/Authenticator registration (see the registration campaign,
                      spec section 9's "Register security information").
          - Remove - has a phishing-resistant method AND a phone-based fallback method
                      (mobilePhone/alternateMobilePhone/officePhone) still registered. The
                      fallback should be removed: its continued presence is exactly what
                      enables an MFA/FIDO downgrade attack (forcing a fallback to the weaker
                      method), even though the user already has something better.

        Push notifications (microsoftAuthenticatorPush) and OTP methods are treated as
        "not phishing-resistant" for this check (per Microsoft's own phishing-resistant
        authentication strength definition - see STR001/ConvertTo-SAWNormalizedAuthentication-
        Strengths.ps1 - limited to FIDO2/WHfB/certificate-based) but are NOT treated as a
        downgrade-risk fallback either; only phone-based methods are, since those are the
        documented vector in the real-world FIDO downgrade attack against Entra ID.

        Every bucket is sorted admins-first, since admin accounts are the highest-priority
        targets for both registration campaigns and downgrade-risk cleanup.
    .PARAMETER RawResponse
        The object returned by Get-SAWRegistration (has a .value array of user records).
    .OUTPUTS
        Hashtable[] - one per user, with UserPrincipalName, DisplayName, IsAdmin, Bucket,
        HasPhishingResistantMethod, HasDowngradeRiskMethod, MethodsRegistered.
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
            else {
                $bucket = 'Hunt'
            }

            $roster += @{
                UserPrincipalName          = $user.userPrincipalName
                DisplayName                = $user.userDisplayName
                IsAdmin                    = [bool]$user.isAdmin
                Bucket                     = $bucket
                HasPhishingResistantMethod = $hasPhishingResistant
                HasDowngradeRiskMethod     = $hasDowngradeRisk
                MethodsRegistered          = ($methods -join ', ')
            }
        }
    }

    end {
        $bucketRank = @{ Remove = 0; Hunt = 1; OK = 2 }
        $roster |
            Sort-Object -Property `
                { if ($bucketRank.ContainsKey($_.Bucket)) { $bucketRank[$_.Bucket] } else { 99 } }, `
                { if ($_.IsAdmin) { 0 } else { 1 } }, `
                { $_.UserPrincipalName }
    }
}

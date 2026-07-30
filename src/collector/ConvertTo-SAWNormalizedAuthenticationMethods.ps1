function ConvertTo-SAWNormalizedAuthenticationMethods {
    <#
    .SYNOPSIS
        Normalizes a raw authenticationMethodsPolicy Graph response into the
        Secure At Work normalized schema consumed by the rules engine.
    .DESCRIPTION
        Maps each entry in authenticationMethodConfigurations to a
        { Category, Setting, State } object, using the same Category/Setting
        naming the rule JSON files key off of.

        Also derives three "Registration" facts from data already present in this same raw
        response, no extra Graph calls needed:
          - whether the registration campaign (registrationEnforcement.
            authenticationMethodsRegistrationCampaign) is actively enabled and targeting
            someone. Only "enabled" with at least one includeTarget counts - "default" is
            ambiguous (Microsoft's own resource docs say it currently means "disabled", but
            the "Microsoft managed" UI option is rolling out different default behavior over
            time) and isn't something an assessor should treat as an attestable control.
          - if the campaign is active, whether it targets passkeys (fido2) specifically
            rather than only Microsoft Authenticator - passkeys are the stronger target.
            Omitted (not just "Disabled") when no campaign is active at all, since the
            question doesn't apply yet.
          - whether there's any way for a user to bootstrap a phishing-resistant method:
            either FIDO2 self-service registration is allowed, or Temporary Access Pass is
            enabled (a TAP lets a user with nothing register FIDO2/a passkey without needing
            an existing strong method or their password). Without either, phishing-resistant
            rollout has no on-ramp for users who don't already have one.

        Also derives a fact from RawPolicy.optOutSettings.passkeyDynamicMigration (only
        present via the beta Graph endpoint - see Get-SAWAuthenticationMethods.ps1), a real,
        easy-to-get-backwards property: setting it to true OPTS OUT of - i.e. EXCLUDES the
        tenant from - Microsoft's automatic passkey enablement and registration-campaign
        rollout for SMS/Voice users, which otherwise starts 2026-09-01 (confirmed verbatim
        against https://learn.microsoft.com/entra/identity/authentication/concept-sms-voice-retirement,
        after an initial paraphrase got this backwards and was caught before it shipped).
        Left absent/false (the default), the automatic rollout applies to the tenant. Opting
        out only buys time to prepare - it does not exempt the tenant from the 2027-02-01
        Microsoft-provided SMS/Voice retirement, which has no opt-out at all.
    .PARAMETER RawPolicy
        The object returned by Get-SAWAuthenticationMethods.
    .OUTPUTS
        Hashtable[]
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$RawPolicy
    )

    begin {
        $displayNameByMethodId = @{
            Fido2                  = 'FIDO2'
            MicrosoftAuthenticator = 'Microsoft Authenticator'
            Sms                    = 'SMS'
            Voice                  = 'Voice'
            Email                  = 'Email OTP'
            TemporaryAccessPass    = 'Temporary Access Pass'
            SoftwareOath           = 'Software OATH'
            X509Certificate        = 'Certificate Authentication'
        }

        function ConvertTo-SAWStateLabel {
            param([bool]$Value)
            if ($Value) { return 'Enabled' }
            return 'Disabled'
        }
    }

    process {
        $methodConfigs = $RawPolicy.authenticationMethodConfigurations
        if (-not $methodConfigs) { $methodConfigs = @() }

        foreach ($config in $methodConfigs) {
            $setting = $displayNameByMethodId[$config.id]
            if (-not $setting) {
                Write-Verbose "ConvertTo-SAWNormalizedAuthenticationMethods: no display name mapping for method id '$($config.id)', using raw id"
                $setting = $config.id
            }

            $state = [string]$config.state
            if ($state.Length -gt 0) {
                $state = $state.Substring(0, 1).ToUpper() + $state.Substring(1).ToLower()
            }

            @{
                Category = 'Authentication Methods'
                Setting  = $setting
                State    = $state
                RawId    = $config.id
            }
        }

        # --- Registration campaign ---
        $campaign = $RawPolicy.registrationEnforcement.authenticationMethodsRegistrationCampaign
        $includeTargetCount = (@($campaign.includeTargets) | Where-Object { $_ }).Count
        $campaignActive = ($campaign.state -eq 'enabled') -and ($includeTargetCount -gt 0)

        Write-Verbose "ConvertTo-SAWNormalizedAuthenticationMethods: registration campaign state='$($campaign.state)', includeTargets=$includeTargetCount"

        @{
            Category = 'Registration'
            Setting  = 'Registration Campaign Actively Enabled'
            State    = ConvertTo-SAWStateLabel $campaignActive
        }

        if ($campaignActive) {
            $targetsPasskey = $false
            foreach ($target in $campaign.includeTargets) {
                if ($target.targetedAuthenticationMethod -eq 'fido2') {
                    $targetsPasskey = $true
                    break
                }
            }

            @{
                Category = 'Registration'
                Setting  = 'Registration Campaign Targets Passkey (FIDO2)'
                State    = ConvertTo-SAWStateLabel $targetsPasskey
            }
        }
        else {
            Write-Verbose 'ConvertTo-SAWNormalizedAuthenticationMethods: no active registration campaign - passkey-targeting check not applicable'
        }

        # --- Phishing-resistant registration bootstrap ---
        $fido2Config = $methodConfigs | Where-Object { $_.id -eq 'Fido2' } | Select-Object -First 1
        $tapConfig = $methodConfigs | Where-Object { $_.id -eq 'TemporaryAccessPass' } | Select-Object -First 1

        $fido2SelfServiceAvailable = ($fido2Config.state -eq 'enabled') -and [bool]$fido2Config.isSelfServiceRegistrationAllowed
        $tapAvailable = ($tapConfig.state -eq 'enabled')
        $bootstrapAvailable = $fido2SelfServiceAvailable -or $tapAvailable

        Write-Verbose "ConvertTo-SAWNormalizedAuthenticationMethods: phishing-resistant bootstrap - FIDO2 self-service=$fido2SelfServiceAvailable, TAP=$tapAvailable"

        @{
            Category = 'Registration'
            Setting  = 'Phishing-Resistant Registration Bootstrap Available (Self-Service FIDO2 or TAP)'
            State    = ConvertTo-SAWStateLabel $bootstrapAvailable
        }

        # --- Passkey dynamic migration opt-out (beta-only field, see collector) ---
        # true = opted OUT = tenant EXCLUDED from Microsoft's automatic passkey rollout.
        # absent/false = the default = the automatic rollout applies to this tenant.
        $passkeyDynamicMigrationOptedOut = [bool]$RawPolicy.optOutSettings.passkeyDynamicMigration

        Write-Verbose "ConvertTo-SAWNormalizedAuthenticationMethods: passkeyDynamicMigration opted out=$passkeyDynamicMigrationOptedOut"

        @{
            Category = 'Authentication Methods'
            Setting  = 'Passkey Dynamic Migration Not Opted Out'
            State    = ConvertTo-SAWStateLabel (-not $passkeyDynamicMigrationOptedOut)
        }
    }
}

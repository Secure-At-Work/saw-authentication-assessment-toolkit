function ConvertTo-SAWAuthenticationMethodsInventory {
    <#
    .SYNOPSIS
        Produces a plain-language inventory of every authentication method's tenant-wide
        policy configuration: enabled/disabled, who's included/excluded, and key settings.
    .DESCRIPTION
        A separate data product from ConvertTo-SAWNormalizedAuthenticationMethods's derived
        Category/Setting/State pass/fail facts - this is a per-method listing (state, target
        scope, settings in plain language), for the report/dashboard layer to show directly,
        mirroring ConvertTo-SAWConditionalAccessInventory.ps1's role for CA policies. Answers
        "what does this tenant's authentication methods policy actually say", independent of
        the pass/fail checks derived elsewhere.

        Target scoping, confirmed against Microsoft's own Graph API reference rather than
        guessed (authenticationMethodConfiguration/excludeTarget/authenticationMethodTarget
        resource pages): every method configuration has an excludeTargets array (id +
        targetType) on the base type, common to all 8 method types, and each derived type has
        its own typed includeTargets array (id, targetType, isRegistrationRequired) sharing the
        same shape. "all_users" is the well-known id value Microsoft uses to represent the
        built-in default target (everyone), as opposed to a specific group/user id. No group or
        user display-name resolution is done here - only counts and the all_users/specific-target
        distinction - to avoid extra Graph calls (Directory.Read.All would be needed to resolve
        an arbitrary group id to a name, and this toolkit does not request that scope for this
        purpose), same "keep the footprint small" choice as the CA inventory.
    .PARAMETER RawPolicy
        The object returned by Get-SAWAuthenticationMethods (has
        .authenticationMethodConfigurations, an array of per-method config objects).
    .OUTPUTS
        Hashtable[] - one per method, with Setting, State, TargetSummary, SettingsSummary.
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

        function ConvertTo-SAWStateDisplayLabel {
            param([string]$Text)
            if ([string]::IsNullOrEmpty($Text)) { return $Text }
            return $Text.Substring(0, 1).ToUpper() + $Text.Substring(1)
        }

        function Get-SAWMethodTargetSummary {
            param($Config)

            $includeTargets = @($Config.includeTargets) | Where-Object { $_ }
            $excludeTargets = @($Config.excludeTargets) | Where-Object { $_ }
            $excludeSuffix = ''
            if ($excludeTargets.Count -gt 0) {
                $excludeSuffix = " ($($excludeTargets.Count) group(s)/user(s) excluded)"
            }

            $includesAllUsers = ($includeTargets | Where-Object { $_.id -eq 'all_users' }).Count -gt 0
            if ($includesAllUsers) {
                return "All users$excludeSuffix"
            }

            $groupTargets = @($includeTargets | Where-Object { $_.targetType -eq 'group' })
            $userTargets = @($includeTargets | Where-Object { $_.targetType -eq 'user' })
            $parts = @()
            if ($groupTargets.Count -gt 0) { $parts += "$($groupTargets.Count) group(s)" }
            if ($userTargets.Count -gt 0) { $parts += "$($userTargets.Count) user(s)" }
            if ($parts.Count -eq 0) { return "None$excludeSuffix" }
            return (($parts -join ', ') + $excludeSuffix)
        }

        function Get-SAWMethodSettingsSummary {
            param($Config)

            $parts = @()
            switch ($Config.id) {
                'Fido2' {
                    $parts += "Self-service registration: $(if ($Config.isSelfServiceRegistrationAllowed) { 'Allowed' } else { 'Not allowed' })"
                    $parts += "Attestation enforced: $(if ($Config.isAttestationEnforced) { 'Yes' } else { 'No' })"
                }
                'MicrosoftAuthenticator' {
                    $numberMatching = $Config.featureSettings.numberMatchingRequiredState.state
                    if ($numberMatching) { $parts += "Number matching: $(ConvertTo-SAWStateDisplayLabel $numberMatching)" }
                    $locationInfo = $Config.featureSettings.displayLocationInformationRequiredState.state
                    if ($locationInfo) { $parts += "Location display: $(ConvertTo-SAWStateDisplayLabel $locationInfo)" }
                }
                'TemporaryAccessPass' {
                    if ($null -ne $Config.defaultLifetimeInMinutes) { $parts += "Default lifetime: $($Config.defaultLifetimeInMinutes) min" }
                    $parts += "One-time use: $(if ($Config.isUsableOnce) { 'Yes' } else { 'No (reusable)' })"
                }
                'Email' {
                    if ($Config.allowExternalIdToUseEmailOtp) { $parts += "External ID email OTP: $($Config.allowExternalIdToUseEmailOtp)" }
                }
                'X509Certificate' {
                    $bindingCount = @($Config.certificateUserBindings | Where-Object { $_ }).Count
                    $parts += "Certificate user bindings: $bindingCount configured"
                }
            }

            if ($parts.Count -eq 0) { return '-' }
            return ($parts -join '; ')
        }
    }

    process {
        $methodConfigs = $RawPolicy.authenticationMethodConfigurations
        if (-not $methodConfigs) { $methodConfigs = @() }

        foreach ($config in $methodConfigs) {
            $setting = $displayNameByMethodId[$config.id]
            if (-not $setting) { $setting = $config.id }

            @{
                Setting         = $setting
                State           = ConvertTo-SAWStateDisplayLabel ([string]$config.state)
                TargetSummary   = Get-SAWMethodTargetSummary $config
                SettingsSummary = Get-SAWMethodSettingsSummary $config
            }
        }
    }
}

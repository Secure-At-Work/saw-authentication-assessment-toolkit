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

        Also appends one extra row, not sourced from authenticationMethodConfigurations, for
        systemCredentialPreferences - the policy that controls which already-registered method
        is presented FIRST at sign-in (distinct from the registration campaign above, which
        controls what gets nudged for registration, not what's presented for an existing
        credential). This genuinely has three different behaviors, not a simple on/off, per
        https://learn.microsoft.com/entra/identity/authentication/concept-system-preferred-authentication:
        Graph state 'disabled' -> no change to sign-in order; state 'enabled' -> the
        strongest-registered-method ranking applies to the second factor only, first-factor
        sign-in is unchanged; state 'default' (or the field absent entirely) -> "Microsoft
        managed", which applies the ranking to BOTH first and second factor - the more
        far-reaching behavior, counterintuitively sitting behind the "default"/unset state
        rather than an explicit opt-in. Microsoft's own docs are inconsistent about this exact
        point: an older resource reference page states the default value is "disabled", while
        the current concept article states "By default, system-preferred authentication is
        Microsoft managed for all users" and separately notes the Microsoft-managed behavior is
        "being gradually deployed to tenants through August 2026" - so a tenant reading 'default'
        today may or may not actually be experiencing it yet. This inventory row surfaces the
        literal configured state rather than resolving that ambiguity; it deliberately isn't a
        pass/fail rules-engine finding for the same reason the registration campaign's 'default'
        state isn't treated as an attestable control elsewhere in this codebase.
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

        # --- System-Preferred Authentication (not a method configuration - see .DESCRIPTION) ---
        $sysPref = $RawPolicy.systemCredentialPreferences
        $sysPrefState = [string]$sysPref.state
        if ([string]::IsNullOrEmpty($sysPrefState)) { $sysPrefState = 'default' }

        $sysPrefStateLabel = switch ($sysPrefState) {
            'disabled' { 'Disabled' }
            'enabled'  { 'Enabled (second factor only)' }
            default    { 'Microsoft managed (first + second factor - rolling out through 2026-08)' }
        }
        $sysPrefSettings = switch ($sysPrefState) {
            'disabled' { 'No change to sign-in order' }
            'enabled'  { 'Strongest registered method presented first for MFA only; first-factor sign-in unchanged' }
            default    { 'Strongest registered method presented first for BOTH first and second factor' }
        }

        @{
            Setting         = 'System-Preferred Authentication'
            State           = $sysPrefStateLabel
            TargetSummary   = Get-SAWMethodTargetSummary $sysPref
            SettingsSummary = $sysPrefSettings
        }
    }
}

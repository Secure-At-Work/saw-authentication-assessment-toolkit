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

        Also appends two extra rows, not sourced from authenticationMethodConfigurations:

        - **Registration Campaign** (registrationEnforcement.authenticationMethodsRegistrationCampaign)
          - what gets nudged for registration after a successful MFA attempt. Three real states,
          not a simple on/off, per
          https://learn.microsoft.com/entra/identity/authentication/how-to-mfa-registration-campaign:
          Graph state 'disabled' -> no nudge at all; state 'enabled' -> the admin's own configured
          target method/snooze settings apply, shown verbatim; state 'default' (or the field
          absent) -> "Microsoft managed", where Microsoft incrementally rolls out its own
          recommended defaults (currently documented as: target method passkeys rather than
          Authenticator, 1-day snooze, unlimited snoozes, targeting all MFA-capable users) - but
          see the MICROSOFT-MANAGED ROLLOUT TIMING note below, since this codebase's own resource
          reference page for this same field contradicts the how-to article and states the
          default value is "disabled", not "Microsoft managed".
        - **System-Preferred Authentication** (systemCredentialPreferences) - the policy that
          controls which already-registered method is presented FIRST at sign-in (distinct from
          the registration campaign above, which controls what gets nudged for registration, not
          what's presented for an existing credential). Also three real states, per
          https://learn.microsoft.com/entra/identity/authentication/concept-system-preferred-authentication:
          Graph state 'disabled' -> no change to sign-in order; state 'enabled' -> the
          strongest-registered-method ranking applies to the second factor only, first-factor
          sign-in is unchanged; state 'default' (or the field absent entirely) -> "Microsoft
          managed", which applies the ranking to BOTH first and second factor - the more
          far-reaching behavior, counterintuitively sitting behind the "default"/unset state
          rather than an explicit opt-in.

        MICROSOFT-MANAGED ROLLOUT TIMING: for both rows above, Microsoft's own documentation is
        internally inconsistent about what the "default" state actually means today - an older
        resource reference page for each field literally states the default value is "disabled",
        while the newer how-to/concept article for each feature describes "Microsoft managed" as
        an actively-rolling-out set of new defaults, on Microsoft's own batch schedule, not the
        tenant's. Microsoft communicating a start date for a "Microsoft managed" behavior change
        (e.g. "gradually deployed... through August 2026") is not the same as every tenant
        already having it: tenants are migrated in batches on a schedule this toolkit has no way
        to observe, so a tenant reading "Microsoft managed" today may be on the old behavior, the
        new behavior, or partway through the transition, regardless of what today's date is
        relative to Microsoft's announced start. Both rows surface the literal configured state
        plus the documented target-state description, explicitly labeled as Microsoft's stated
        *intent* for that setting rather than a confirmed *current* per-tenant fact - and
        deliberately aren't pass/fail rules-engine findings, for the same reason.
    .PARAMETER RawPolicy
        The object returned by Get-SAWAuthenticationMethods (has
        .authenticationMethodConfigurations, an array of per-method config objects).
    .OUTPUTS
        Hashtable[] - one per method, with Setting, State, TargetSummary, SettingsSummary.
        The Registration Campaign and System-Preferred Authentication rows also carry
        RolloutNote (nullable) - set only when State is "Microsoft managed", flagging that the
        SettingsSummary description is Microsoft's stated intent, not a confirmed current fact
        for this specific tenant (see the MICROSOFT-MANAGED ROLLOUT TIMING note above).
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
                    # Three-state on purpose. "No" and "couldn't read it" are different answers,
                    # and the inventory is where a reader checks what the tenant actually says.
                    $fido2Effective = ConvertTo-SAWPasskeyPolicyEffective -RawConfig $Config
                    $attestationLabel = if ($null -eq $fido2Effective.AttestationEnforced) {
                        'Could not be determined'
                    }
                    elseif ($fido2Effective.AttestationEnforced) { 'Yes' } else { 'No' }
                    $parts += "Attestation enforced: $attestationLabel"
                    if ($fido2Effective.Source -eq 'PasskeyProfiles') {
                        $parts += "Passkey profiles in use: $($fido2Effective.ProfileCount)$(if ($fido2Effective.MixedEnforcement) { ' (settings differ between profiles)' })"
                    }
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

        # --- Registration Campaign (not a method configuration - see .DESCRIPTION) ---
        $campaign = $RawPolicy.registrationEnforcement.authenticationMethodsRegistrationCampaign
        $campaignState = [string]$campaign.state
        if ([string]::IsNullOrEmpty($campaignState)) { $campaignState = 'default' }

        $campaignRolloutNote = $null
        switch ($campaignState) {
            'disabled' {
                $campaignStateLabel = 'Disabled'
                $campaignSettings = 'No registration nudge occurs'
            }
            'enabled' {
                $campaignStateLabel = 'Enabled'
                $targetMethod = (@($campaign.includeTargets) | Where-Object { $_ } | Select-Object -First 1).targetedAuthenticationMethod
                $targetLabel = switch ($targetMethod) {
                    'fido2' { 'passkey (FIDO2)' }
                    'microsoftAuthenticator' { 'Microsoft Authenticator' }
                    default { 'not yet targeted' }
                }
                $snoozeDays = if ($null -ne $campaign.snoozeDurationInDays) { $campaign.snoozeDurationInDays } else { 'default' }
                $snoozeLimit = if ($campaign.enforceRegistrationAfterAllowedSnoozes -eq $true) { 'limited (required after 3 skips)' } elseif ($campaign.enforceRegistrationAfterAllowedSnoozes -eq $false) { 'unlimited' } else { 'not set' }
                $campaignSettings = "Target: $targetLabel; Snooze: $snoozeDays day(s); Snooze limit: $snoozeLimit"
            }
            default {
                $campaignStateLabel = 'Microsoft managed'
                $campaignSettings = "Microsoft's stated intent for this state: target passkeys (FIDO2) rather than Authenticator, 1-day snooze, unlimited snoozes, targeting all MFA-capable users - see the rollout-timing note"
                $campaignRolloutNote = 'Microsoft-managed rollout: this tenant may still be on the prior default, mid-transition, or already on Microsoft''s current recommended settings - timing is Microsoft''s batch schedule, not something this toolkit can observe. Re-check this row rather than assuming the description above already applies.'
            }
        }

        @{
            Setting         = 'Registration Campaign'
            State           = $campaignStateLabel
            TargetSummary   = Get-SAWMethodTargetSummary $campaign
            SettingsSummary = $campaignSettings
            RolloutNote     = $campaignRolloutNote
        }

        # --- System-Preferred Authentication (not a method configuration - see .DESCRIPTION) ---
        $sysPref = $RawPolicy.systemCredentialPreferences
        $sysPrefState = [string]$sysPref.state
        if ([string]::IsNullOrEmpty($sysPrefState)) { $sysPrefState = 'default' }

        $sysPrefRolloutNote = $null
        switch ($sysPrefState) {
            'disabled' {
                $sysPrefStateLabel = 'Disabled'
                $sysPrefSettings = 'No change to sign-in order'
            }
            'enabled' {
                $sysPrefStateLabel = 'Enabled (second factor only)'
                $sysPrefSettings = 'Strongest registered method presented first for MFA only; first-factor sign-in unchanged'
            }
            default {
                $sysPrefStateLabel = 'Microsoft managed'
                $sysPrefSettings = "Microsoft's stated intent for this state: strongest registered method presented first for BOTH first and second factor - see the rollout-timing note"
                $sysPrefRolloutNote = 'Microsoft-managed rollout: Microsoft''s own docs describe this being "gradually deployed to tenants through August 2026" - this tenant may not yet be experiencing it even if that date has passed. Re-check this row rather than assuming the description above already applies.'
            }
        }

        @{
            Setting         = 'System-Preferred Authentication'
            State           = $sysPrefStateLabel
            TargetSummary   = Get-SAWMethodTargetSummary $sysPref
            SettingsSummary = $sysPrefSettings
            RolloutNote     = $sysPrefRolloutNote
        }
    }
}

function ConvertTo-SAWNudgeForecast {
    <#
    .SYNOPSIS
        Predicts which users are eligible to be interrupted with a registration prompt, so the
        change can be communicated before it happens rather than explained afterwards.
    .DESCRIPTION
        Enriches the user roster with a per-user forecast of which registration nudges that user
        is *eligible* for. The operational risk this addresses is not technical: an unannounced
        interrupt at sign-in generates help-desk volume and erodes trust in the rollout, and the
        people who need to write that communication need a named list, not a percentage.

        Four distinct interrupts are modeled, because they have genuinely different triggers,
        different populations, and different skip behavior:

        1. Registration campaign - passkey (RCAMP002). Fires after a successful MFA, for users in
           campaign scope who don't already have the targeted method. Snoozeable (limited to
           three skips, or unlimited, depending on configuration).
        2. Registration campaign - Microsoft Authenticator (RCAMP001 targeting authenticator).
           Same mechanic, different target method.
        3. SSPR registration interrupt. Fires for users who are SSPR-enabled but not
           SSPR-registered. Per Microsoft: "If only an SSPR policy is enabled, then users are
           able to skip (indefinitely) the registration interruption" - so this one is a nag, not
           a gate, unless MFA registration is also enforced.
        4. The 2026-09-01 automatic passkey enablement. Fires for users enabled for SMS or Voice,
           who are auto-enabled for passkeys and put into a Microsoft-managed campaign targeting
           passkeys. This one arrives on Microsoft's schedule whether or not the tenant has its
           own campaign configured, which makes it the highest communication risk of the four.

        A fifth, degenerate case is also flagged: an administrator who is in scope for the
        user-facing SSPR policy while admin SSPR is disabled tenant-wide is interrupted to
        register and then shown a message saying they can't register anything (see SSPR002).
        That's a broken experience rather than a nudge, and it's worth catching before a customer
        reports it as a bug.

        WHAT THIS CANNOT SEE, and therefore does not claim:

        - The passkey nudge is evaluated per device-and-browser combination, not per account.
          Microsoft's own wording: "The nudge evaluation is based on each device-and-browser
          combination that you use, rather than for your user account." A user who already has a
          passkey can still be nudged on a different machine. This forecast therefore predicts
          *eligibility*, and deliberately does not claim a user with a passkey will never see a
          prompt.
        - Campaign include/exclude targets are group object IDs. Resolving them would need a
          group-membership call per group, which this toolkit avoids. When the campaign is scoped
          to specific groups rather than all users, per-user predictions are marked
          scope-uncertain rather than silently assumed to apply to everyone.
        - Several documented suppressors are invisible to Graph (terms-of-use screens, Conditional
          Access custom controls, SSO sessions, Linux clients, Authenticator campaigns on mobile).
          These make the forecast an over-estimate, which is the safer direction for planning a
          communication.

        Tenant-wide suppressors that switch the campaign off for *everyone* are returned on the
        summary rather than per user, because they change the answer from "these people" to
        "nobody, and that's probably not what you intended".

        Sources: how-to-mfa-registration-campaign, concept-registration-mfa-sspr-combined,
        concept-sms-voice-retirement, concept-sspr-policy. See docs/references.md.
    .PARAMETER Roster
        Output of ConvertTo-SAWUserRegistrationRoster (optionally already enriched by the other
        roster enrichers).
    .PARAMETER RegistrationRaw
        The raw object from Get-SAWRegistration, needed for isSsprEnabled/isSsprRegistered, which
        the roster itself doesn't carry.
    .PARAMETER AuthenticationMethodsPolicy
        The raw object from Get-SAWAuthenticationMethods, for the campaign and FIDO2 configuration.
    .PARAMETER AdminSsprEnabled
        Whether admin SSPR is enabled tenant-wide (authorizationPolicy.allowedToUseSSPR). Defaults
        to $true, matching Microsoft's own default.
    .PARAMETER SecurityInfoRegistrationBlockedByCa
        Whether an enabled Conditional Access policy gates security info registration in a way
        that suppresses nudges entirely.
    .OUTPUTS
        Hashtable with Users (the enriched roster) and Summary (tenant-level counts, suppressors,
        and caveats).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Roster,

        [Parameter(Mandatory)]
        [object]$RegistrationRaw,

        [Parameter(Mandatory)]
        [object]$AuthenticationMethodsPolicy,

        [bool]$AdminSsprEnabled = $true,

        [bool]$SecurityInfoRegistrationBlockedByCa = $false
    )

    $campaign = $AuthenticationMethodsPolicy.registrationEnforcement.authenticationMethodsRegistrationCampaign
    $fido2 = $AuthenticationMethodsPolicy.authenticationMethodConfigurations | Where-Object { $_.id -eq 'Fido2' }

    $campaignState = $campaign.state
    # 'default' is the Microsoft-managed state, which per concept-sms-voice-retirement is exactly
    # what the 2026-09-01 rollout switches tenants into, targeting passkeys. Treat it as active
    # for forecasting rather than as "off".
    $campaignActive = $campaignState -in @('enabled', 'default')

    $includeTargets = @($campaign.includeTargets) | Where-Object { $_ }
    $targetedMethods = @($includeTargets | ForEach-Object { $_.targetedAuthenticationMethod }) | Where-Object { $_ }
    $campaignTargetsPasskey = $targetedMethods -contains 'fido2'
    $campaignTargetsAuthenticator = $targetedMethods -contains 'microsoftAuthenticator'

    # Under Microsoft-managed state the targeted method is set by Microsoft, not readable from the
    # policy - and is documented as moving to passkeys. Forecast that rather than reporting neither.
    if ($campaignActive -and -not $campaignTargetsPasskey -and -not $campaignTargetsAuthenticator -and $campaignState -eq 'default') {
        $campaignTargetsPasskey = $true
    }

    # Scope certainty: all_users is knowable, a specific group is not without a membership call.
    $scopedToAllUsers = @($includeTargets | Where-Object { $_.id -eq 'all_users' }).Count -gt 0
    $scopedToSpecificGroups = @($includeTargets | Where-Object { $_.id -and $_.id -ne 'all_users' }).Count
    $scopeUncertain = ($scopedToSpecificGroups -gt 0) -or ($campaignActive -and -not $scopedToAllUsers -and $scopedToSpecificGroups -eq 0)

    # Documented tenant-wide suppressors of the campaign nudge.
    $suppressors = @()
    if ($fido2 -and $fido2.isAttestationEnforced -eq $true) {
        $suppressors += 'FIDO2 attestation is enforced (PASS001), which Microsoft documents as suppressing the passkey nudge for affected users'
    }
    if ($fido2 -and $fido2.keyRestrictions.isEnforced -eq $true) {
        $suppressors += 'FIDO2 AAGUID key restrictions are enforced (PASS002), which Microsoft documents as suppressing the passkey nudge for affected users'
    }
    if ($fido2 -and $fido2.isSelfServiceRegistrationAllowed -eq $false) {
        $suppressors += 'FIDO2 self-service registration is off, which is a prerequisite for a passkey campaign'
    }
    if ($SecurityInfoRegistrationBlockedByCa) {
        $suppressors += 'A Conditional Access policy gates security info registration, and Microsoft documents that a nudge does not appear for users it blocks'
    }

    $passkeyNudgeSuppressed = $suppressors.Count -gt 0

    # isSsprEnabled / isSsprRegistered live on the raw registration data, not the roster.
    $ssprByUpn = @{}
    foreach ($u in @($RegistrationRaw.value)) {
        if ($u.userPrincipalName) {
            $ssprByUpn[$u.userPrincipalName] = @{
                IsSsprEnabled    = [bool]$u.isSsprEnabled
                IsSsprRegistered = [bool]$u.isSsprRegistered
            }
        }
    }

    $enriched = foreach ($user in $Roster) {
        $methods = @()
        if ($user.MethodsRegistered) {
            $methods = ($user.MethodsRegistered -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        }

        $hasPasskey = @($methods | Where-Object { $_ -in @('fido2', 'passKeyDeviceBound', 'passKeyDeviceBoundAuthenticator', 'passKeyDeviceBoundWindowsHello') }).Count -gt 0
        $hasAuthenticatorPush = @($methods | Where-Object { $_ -in @('microsoftAuthenticatorPush', 'microsoftAuthenticatorPasswordless') }).Count -gt 0
        $hasPhoneMethod = @($methods | Where-Object { $_ -in @('sms', 'voiceMobile', 'voiceAlternateMobile', 'voiceOffice', 'mobilePhone', 'officePhone') }).Count -gt 0

        $sspr = $ssprByUpn[$user.UserPrincipalName]
        $isSsprEnabled = if ($sspr) { $sspr.IsSsprEnabled } else { $false }
        $isSsprRegistered = if ($sspr) { $sspr.IsSsprRegistered } else { $false }

        $reasons = @()

        # 1 + 2: registration campaign. Guests are never nudged for passkeys (documented), but are
        # nudged for Authenticator.
        $nudgePasskey = $false
        if ($campaignActive -and $campaignTargetsPasskey -and -not $passkeyNudgeSuppressed -and -not $user.IsGuest -and -not $hasPasskey) {
            $nudgePasskey = $true
            $reasons += 'Registration campaign targeting passkey, and no passkey registered'
        }

        $nudgeAuthenticator = $false
        if ($campaignActive -and $campaignTargetsAuthenticator -and -not $SecurityInfoRegistrationBlockedByCa -and -not $hasAuthenticatorPush) {
            $nudgeAuthenticator = $true
            $reasons += 'Registration campaign targeting Microsoft Authenticator, and Authenticator push not set up'
        }

        # 3: SSPR registration interrupt.
        $nudgeSspr = $false
        if ($isSsprEnabled -and -not $isSsprRegistered) {
            $nudgeSspr = $true
            $reasons += 'SSPR-enabled but not SSPR-registered, so interrupted to register SSPR methods (skippable indefinitely unless MFA registration is also enforced)'
        }

        # 4: the 2026-09-01 automatic passkey enablement, which does not depend on the tenant's own
        # campaign being configured at all.
        $nudgeAutoSept2026 = $false
        if ($hasPhoneMethod -and -not $user.IsGuest) {
            $nudgeAutoSept2026 = $true
            $reasons += 'Enabled for SMS/Voice, so in scope for the 2026-09-01 automatic passkey enablement and Microsoft-managed campaign'
        }

        # 5: the broken admin SSPR experience.
        $ssprBrokenForAdmin = $false
        if ($user.IsAdmin -and -not $AdminSsprEnabled -and $isSsprEnabled) {
            $ssprBrokenForAdmin = $true
            $reasons += 'BROKEN: admin in scope for the user SSPR policy while admin SSPR is disabled - prompted to register, then told no methods can be registered (SSPR002)'
        }

        $willBeNudged = $nudgePasskey -or $nudgeAuthenticator -or $nudgeSspr -or $nudgeAutoSept2026

        $copy = @{}
        foreach ($key in $user.Keys) { $copy[$key] = $user[$key] }
        $copy['NudgePasskeyCampaign'] = $nudgePasskey
        $copy['NudgeAuthenticatorCampaign'] = $nudgeAuthenticator
        $copy['NudgeSsprRegistration'] = $nudgeSspr
        $copy['NudgeAutoPasskeySept2026'] = $nudgeAutoSept2026
        $copy['NudgeSsprBrokenForAdmin'] = $ssprBrokenForAdmin
        $copy['WillBeNudged'] = $willBeNudged
        $copy['NudgeReasons'] = $reasons
        $copy
    }

    $enriched = @($enriched)

    $caveats = @(
        'The passkey nudge is evaluated per device-and-browser combination, not per account - a user who already has a passkey can still be nudged on a device where they do not. These counts are therefore a floor for passkey nudges, not a ceiling.'
        'Several documented suppressors are not visible through Graph (terms-of-use screens, Conditional Access custom controls, existing SSO sessions, Linux clients, Authenticator campaigns on mobile). The forecast over-estimates rather than under-estimates, which is the safer direction when planning a communication.'
        'This forecasts WHO is eligible, not WHEN they will see it. A nudge is UI shown during an interactive sign-in that completes MFA, and Microsoft defines non-interactive sign-ins as requiring no authentication factor and never interrupting the session - so token refreshes, SSO on a joined device, and opening a second Office app on an already-signed-in device cannot show one. A user who rarely does an interactive browser sign-in may stay eligible for weeks without ever being prompted, which is why slow-moving registration coverage is often a reach problem rather than a user-compliance problem.'
    )
    if ($scopeUncertain) {
        $caveats += "The registration campaign is scoped to specific groups rather than all users. Group membership isn't resolved (it would need an extra Graph call per group), so campaign-driven predictions below apply only to whoever is actually in those groups."
    }

    @{
        Users   = $enriched
        Summary = @{
            CampaignState                = $campaignState
            CampaignActive               = $campaignActive
            CampaignTargetsPasskey       = $campaignTargetsPasskey
            CampaignTargetsAuthenticator = $campaignTargetsAuthenticator
            CampaignScopeUncertain       = $scopeUncertain
            PasskeyNudgeSuppressed       = $passkeyNudgeSuppressed
            Suppressors                  = @($suppressors)
            Caveats                      = @($caveats)
            TotalUsers                   = $enriched.Count
            TotalWillBeNudged            = @($enriched | Where-Object { $_.WillBeNudged }).Count
            PasskeyCampaignCount         = @($enriched | Where-Object { $_.NudgePasskeyCampaign }).Count
            AuthenticatorCampaignCount   = @($enriched | Where-Object { $_.NudgeAuthenticatorCampaign }).Count
            SsprRegistrationCount        = @($enriched | Where-Object { $_.NudgeSsprRegistration }).Count
            AutoPasskeySept2026Count     = @($enriched | Where-Object { $_.NudgeAutoPasskeySept2026 }).Count
            SsprBrokenForAdminCount      = @($enriched | Where-Object { $_.NudgeSsprBrokenForAdmin }).Count
        }
    }
}

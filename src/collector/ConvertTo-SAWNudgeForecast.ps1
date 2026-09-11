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

        CORRECTED 2026-09-09, AAGUID gap closed 2026-09-11. This function previously treated
        attestation enforcement, AAGUID key restrictions, and a device-bound-only or synced-only
        default passkey profile as always suppressing the passkey campaign nudge. Message Center
        MC1469555 and Microsoft's rewritten how-to-mfa-registration-campaign page (ms.date
        2026-09-02) document the opposite for the Microsoft managed campaign state: a user needs
        only ONE eligible passkey profile out of Unrestricted, Synced-only, Device-bound-only,
        AAGUID-restricted (allow-list contains at least one AAGUID for iCloud Keychain, Google
        Password Manager, Microsoft Authenticator passkey, or Microsoft Entra passkey on Windows),
        or Device-bound with attestation enforced (key restrictions aren't evaluated for that last
        one). In practice this means only ONE configuration can still suppress the nudge: an
        AAGUID allow-list restriction, without attestation also enforced, whose list contains none
        of the four qualifying providers' AAGUIDs. All four are now verified in this toolkit's
        AAGUID reference table (see ConvertTo-SAWFido2KeyInventory) - the Windows Hello passkey
        AAGUIDs for "Microsoft Entra passkey on Windows" were the last gap, closed via Microsoft's
        how-to-authentication-entra-passkeys-on-windows page. This is an active Microsoft rollout,
        expected complete end of September 2026 - a tenant may still be on the old behavior.

        Sources: how-to-mfa-registration-campaign (ms.date 2026-09-02, updated 2026-09-04),
        how-to-authentication-entra-passkeys-on-windows (ms.date 2026-07-05, updated 2026-09-03),
        MC1469555, concept-registration-mfa-sspr-combined, concept-sms-voice-retirement,
        concept-sspr-policy. See docs/references.md.
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
    .PARAMETER SignInLogs
        Optional raw output of Get-SAWSignInLogs. When supplied, each eligible user is additionally
        classified as reachable or unreachable by a campaign, based on whether they performed an
        INTERACTIVE sign-in inside the collected window.

        This turns the "eligibility is not the same as being prompted" caveat into actual data. A
        nudge is UI shown during an interactive sign-in; Microsoft's v1.0 /auditLogs/signIns
        endpoint returns interactive sign-ins ("Sign-ins that are interactive in nature... are
        currently included in the sign-in logs"), so a user who is eligible but absent from that
        window did not do the kind of sign-in a campaign can interrupt. Those users need direct
        outreach, not a firmer campaign.

        Hard limit worth stating plainly: Entra retains sign-in logs for seven days on Entra ID
        Free and 30 days on P1/P2. Asking for a longer window silently returns only what is
        retained, so "no interactive sign-in" always means "none within retention", never "none
        ever". A user genuinely dormant for six months and a user who simply didn't sign in
        interactively during a 30-day window are indistinguishable here.
    .PARAMETER SignInWindowDays
        The window the supplied sign-in logs were collected over, used only for labelling the
        result honestly. Capped for display purposes at Entra's own 30-day maximum retention.
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

        [bool]$SecurityInfoRegistrationBlockedByCa = $false,

        [object]$SignInLogs = $null,

        [int]$SignInWindowDays = 0
    )

    # Build the set of users who did at least one interactive sign-in inside the collected window.
    # Absence from this set is the signal that matters: a campaign has no way to reach them.
    $interactiveSignInUpns = $null
    if ($SignInLogs) {
        $interactiveSignInUpns = @{}
        foreach ($s in @($SignInLogs.value)) {
            # isInteractive is the authoritative flag. Treat a missing value as interactive rather
            # than assuming otherwise: v1.0 /auditLogs/signIns is documented as returning
            # interactive sign-ins, so absent-and-present-in-the-log means interactive, and
            # guessing "non-interactive" here would invent unreachable users that don't exist.
            $isInteractive = if ($null -eq $s.isInteractive) { $true } else { [bool]$s.isInteractive }
            if ($isInteractive -and $s.userPrincipalName) {
                $interactiveSignInUpns[$s.userPrincipalName] = $true
            }
        }
    }

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
    # Two genuinely different kinds of "uncertain" exist here, and they need different guidance:
    #   'group'                - includeTargets names specific group(s). Microsoft's docs confirm
    #                             include/exclude targets remain configurable even when
    #                             state is 'default' (Microsoft managed) - only the targeted
    #                             method/snooze settings are locked in that mode, not targeting.
    #                             The fix is: go look up who's in the group(s).
    #   'msft-managed-rollout'  - state is 'default' (Microsoft managed) with NO custom targets
    #                             configured at all. Microsoft documents this as an incremental,
    #                             per-tenant rollout where the effective population moves from
    #                             SMS/Voice users only to all MFA-capable users, and which stage a
    #                             given tenant is in isn't exposed through Graph. There is no group
    #                             to go look up - the uncertainty is about Microsoft's own rollout
    #                             wave, not about tenant configuration.
    $scopedToAllUsers = @($includeTargets | Where-Object { $_.id -eq 'all_users' }).Count -gt 0
    $scopedToSpecificGroups = @($includeTargets | Where-Object { $_.id -and $_.id -ne 'all_users' }).Count
    $scopeUncertainReason = $null
    if ($scopedToSpecificGroups -gt 0) {
        $scopeUncertainReason = 'group'
    }
    elseif ($campaignActive -and -not $scopedToAllUsers -and $campaignState -eq 'default') {
        $scopeUncertainReason = 'msft-managed-rollout'
    }
    elseif ($campaignActive -and -not $scopedToAllUsers) {
        $scopeUncertainReason = 'group'
    }
    $scopeUncertain = $null -ne $scopeUncertainReason

    # Documented tenant-wide suppressors of the campaign nudge.
    # Resolved rather than read directly: isAttestationEnforced/keyRestrictions are deprecated in
    # favour of passkeyProfiles (removal October 2027). Note the asymmetry with PASS001/PASS002 -
    # there, an unknown value must not become "not enforced" because that invents a finding. Here,
    # an unknown value simply means no suppressor is listed, which understates why a campaign may
    # be reaching nobody. That is the safer direction for a forecast, but worth knowing when a
    # campaign looks correctly configured and still isn't landing.
    $fido2Effective = ConvertTo-SAWPasskeyPolicyEffective -RawConfig $fido2

    # CORRECTED 2026-09-09 (MC1469555 / how-to-mfa-registration-campaign, ms.date 2026-09-02): under
    # the Microsoft managed campaign state, attestation enforcement, AAGUID key restrictions, and a
    # device-bound-only or synced-only default profile no longer suppress the nudge by themselves -
    # each is now itself a named ELIGIBLE profile configuration. See the .DESCRIPTION correction
    # note above. The only configuration Microsoft's own eligibility table still excludes is an
    # AAGUID allow-list restriction, without attestation also enforced, whose list contains none of
    # the specific providers Microsoft names as qualifying (iCloud Keychain, Google Password
    # Manager, Microsoft Authenticator passkey, Microsoft Entra passkey on Windows).
    #
    # AAGUID gap closed 2026-09-11: this toolkit's own AAGUID reference table
    # (ConvertTo-SAWFido2KeyInventory) now confirms all four qualifying providers, including
    # "Microsoft Entra passkey on Windows" (the Windows Hello passkey AAGUIDs, per Microsoft's
    # how-to-authentication-entra-passkeys-on-windows page).
    $knownQualifyingPasskeyProviderAaguids = @(
        'de1e552d-db1d-4423-a619-566b625cdc84'  # Microsoft Authenticator (Android)
        '90a3ccdf-635c-4729-a248-9b709135078f'  # Microsoft Authenticator (iOS)
        'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4'  # Google Password Manager
        'dd4ec289-e01d-41c9-bb89-70fa845d4bf2'  # iCloud Keychain (Managed)
        'fbfc3007-154e-4ecc-8c0b-6e020557d7bd'  # Apple Passwords / iCloud Keychain
        '08987058-cadc-4b81-b6e1-30de50dcbe96'  # Windows Hello Hardware Authenticator (Microsoft Entra passkey on Windows)
        '9ddd1817-af5a-4672-a2b9-3e3dd95000a9'  # Windows Hello VBS Hardware Authenticator (Microsoft Entra passkey on Windows)
        '6028b017-b1d4-4c02-b4b3-afcdafc96bb2'  # Windows Hello Software Authenticator (Microsoft Entra passkey on Windows)
    )

    $suppressors = @()
    if ($fido2Effective.IsKnown -and
        $fido2Effective.KeyRestrictionsEnforced -eq $true -and
        $fido2Effective.AttestationEnforced -ne $true) {

        $configuredAaGuids = @($fido2Effective.KeyRestrictions.aaGuids) | Where-Object { $_ }
        $hasQualifyingAaguid = @($configuredAaGuids | Where-Object {
            $knownQualifyingPasskeyProviderAaguids -contains $_.ToString().ToLowerInvariant()
        }).Count -gt 0

        if (-not $hasQualifyingAaguid) {
            $suppressors += 'FIDO2 AAGUID key restrictions are enforced (PASS002) without attestation, and the configured allow-list doesn''t contain an AAGUID for any of Microsoft''s four qualifying passkey providers (iCloud Keychain, Google Password Manager, Microsoft Authenticator, Microsoft Entra passkey on Windows) - NOT eligible for the Microsoft managed campaign nudge per MC1469555.'
        }
    }
    if ($fido2 -and -not $fido2Effective.IsKnown) {
        $suppressors += "FIDO2 attestation and key-restriction state couldn't be read, so eligibility for the Microsoft managed campaign nudge is unknown rather than ruled out"
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

        # Reachability: only meaningful for campaign-driven nudges, which require an interactive
        # sign-in. The SSPR interrupt and the 2026-09-01 enablement ride the same requirement, so
        # the same signal applies, but it's the campaign case where "eligible but never prompted"
        # most often gets misread as user non-compliance.
        if ($null -ne $interactiveSignInUpns) {
            $hasInteractive = $interactiveSignInUpns.ContainsKey($user.UserPrincipalName)
            $copy['HasInteractiveSignInInWindow'] = $hasInteractive
            $copy['NudgeUnreachableInWindow'] = ($willBeNudged -and -not $hasInteractive)
        }
        else {
            $copy['HasInteractiveSignInInWindow'] = $null
            $copy['NudgeUnreachableInWindow'] = $false
        }

        $copy
    }

    $enriched = @($enriched)

    $caveats = @(
        'The passkey nudge is evaluated per device-and-browser combination, not per account - a user who already has a passkey can still be nudged on a device where they do not. These counts are therefore a floor for passkey nudges, not a ceiling.'
        'Several documented suppressors are not visible through Graph (terms-of-use screens, Conditional Access custom controls, existing SSO sessions, Linux clients, Authenticator campaigns on mobile). The forecast over-estimates rather than under-estimates, which is the safer direction when planning a communication.'
        'This forecasts WHO is eligible, not WHEN they will see it. A nudge is UI shown during an interactive sign-in that completes MFA, and Microsoft defines non-interactive sign-ins as requiring no authentication factor and never interrupting the session - so token refreshes, SSO on a joined device, and opening a second Office app on an already-signed-in device cannot show one. A user who rarely does an interactive browser sign-in may stay eligible for weeks without ever being prompted, which is why slow-moving registration coverage is often a reach problem rather than a user-compliance problem.'
    )
    if ($scopeUncertainReason -eq 'msft-managed-rollout') {
        $caveats += "The registration campaign is Microsoft managed (state: default) with no custom include/exclude targets - same rollout uncertainty as the 'Rollout timing not confirmed' badge on the Registration Campaign row in the Policy Inventory tab: this tenant may still be on the prior default, mid-transition, or already on Microsoft's current recommended settings (targeting all MFA-capable users), and timing is Microsoft's batch schedule, not something this toolkit can observe. Campaign-driven predictions below assume the broader population (all MFA-capable users) as the safer upper bound."
    }
    elseif ($scopeUncertainReason -eq 'group') {
        $caveats += "The registration campaign is scoped to specific groups rather than all users. Group membership isn't resolved (it would need an extra Graph call per group), so campaign-driven predictions below apply only to whoever is actually in those groups."
    }

    # Entra's own retention ceiling bounds every reachability claim here. Stating it inline stops
    # "no interactive sign-in" being read as "dormant account".
    $effectiveWindowDays = $SignInWindowDays
    $retentionCapped = $false
    if ($effectiveWindowDays -gt 30) {
        $effectiveWindowDays = 30
        $retentionCapped = $true
    }
    if ($null -ne $interactiveSignInUpns) {
        $windowLabel = if ($effectiveWindowDays -gt 0) { "the last $effectiveWindowDays day(s)" } else { 'the collected sign-in window' }
        $caveats += "Reachability is based on whether a user did an INTERACTIVE sign-in within $windowLabel. Entra retains sign-in logs for seven days on Entra ID Free and 30 days on P1/P2, so this always means 'not within retention', never 'not ever' - a genuinely dormant account and someone who simply didn't sign in interactively during the window look identical here."
        if ($retentionCapped) {
            $caveats += "A sign-in window longer than 30 days was requested, but Entra cannot return more than 30 days (P1/P2) or seven days (Free). The effective window is capped at what was actually retained, regardless of what was asked for."
        }
    }

    @{
        Users   = $enriched
        Summary = @{
            CampaignState                = $campaignState
            CampaignActive               = $campaignActive
            CampaignTargetsPasskey       = $campaignTargetsPasskey
            CampaignTargetsAuthenticator = $campaignTargetsAuthenticator
            CampaignScopeUncertain       = $scopeUncertain
            CampaignScopeUncertainReason = $scopeUncertainReason
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
            ReachabilityAvailable        = ($null -ne $interactiveSignInUpns)
            SignInWindowDays             = $effectiveWindowDays
            SignInWindowRetentionCapped  = $retentionCapped
            UnreachableInWindowCount     = @($enriched | Where-Object { $_.NudgeUnreachableInWindow }).Count
        }
    }
}

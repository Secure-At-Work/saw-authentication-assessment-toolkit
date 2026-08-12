function ConvertTo-SAWRegistrationFlowScenarios {
    <#
    .SYNOPSIS
        Documents four real, Microsoft-sourced authentication/registration user flows and marks
        each step applicable/not-applicable against this tenant's actual current settings.
    .DESCRIPTION
        A rules-engine finding tells you whether one setting matches SOLL. It doesn't tell you
        what an end user actually experiences end-to-end when several settings interact - e.g.
        "TAP is enabled" and "the registration campaign targets passkeys" only becomes a real
        bootstrap path once you trace through what happens step by step. This function builds
        that trace for four scenarios, each grounded in a specific Microsoft Learn article (cited
        per flow), evaluating every step's applicability against already-collected tenant data -
        no extra Graph calls.

        The four flows (fixed scope, matching what this toolkit's dashboard documents):
        - New User Bootstrap: first sign-in with a Temporary Access Pass, through to the
          registration campaign nudge on a later sign-in.
          https://learn.microsoft.com/entra/identity/authentication/howto-authentication-temporary-access-pass
          https://learn.microsoft.com/entra/identity/authentication/how-to-mfa-registration-campaign
        - SSPR Eligibility & Two-Gate: whether/how a user (and separately, an admin) can register
          for and use self-service password reset.
          https://learn.microsoft.com/entra/identity/authentication/concept-registration-mfa-sspr-combined
          https://learn.microsoft.com/entra/identity/authentication/concept-sspr-policy
        - Existing User Re-Registration: managing/refreshing security info after initial setup.
          https://learn.microsoft.com/entra/identity/authentication/concept-registration-mfa-sspr-combined
          https://learn.microsoft.com/entra/identity/authentication/how-to-mfa-registration-campaign
        - CA-Gated Registration: how a Conditional Access policy scoped to "Register security
          information" changes all of the above.
          https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-security-info-registration

        Each step's Applies value is $true/$false when it's genuinely conditioned on a collected
        setting, or $null when it's a fixed Microsoft behavior included for context (e.g. the
        5-minute MFA freshness requirement for passkey registration, which isn't configurable).

        System-Preferred Authentication (systemCredentialPreferences on authenticationMethodsPolicy)
        is woven into Flows 1, 3, and 4 below - it's a distinct tenant-wide setting from
        everything else this function reasons about (it governs what gets PRESENTED at sign-in
        for an already-registered credential, not what gets nudged for registration), but it
        directly changes what a user actually sees, so it belongs in the trace. Per
        https://learn.microsoft.com/entra/identity/authentication/concept-system-preferred-authentication:
        state 'disabled' -> no change; state 'enabled' -> the strongest-registered-method ranking
        applies to the second factor only; state 'default'/absent -> "Microsoft managed", ranking
        applies to BOTH first and second factor (the more far-reaching behavior, gradually
        rolling out through 2026-08, so a tenant reading 'default' may not yet actually be
        experiencing it). Conditional Access is validated only for second-factor authentication
        and does not override this first-factor selection - authentication happens first, then
        Conditional Access evaluates authorization.
    .PARAMETER AuthenticationMethodsPolicyRaw
        The object returned by Get-SAWAuthenticationMethods (has .authenticationMethodConfigurations
        and .registrationEnforcement.authenticationMethodsRegistrationCampaign).
    .PARAMETER AuthorizationPolicyRaw
        The object returned by Get-SAWAuthorizationPolicy (has .allowedToUseSSPR).
    .PARAMETER RegistrationRaw
        The object returned by Get-SAWRegistration (has a .value array of user records).
    .PARAMETER CaPolicyInventory
        Output of ConvertTo-SAWConditionalAccessInventory (for TargetsSecurityInfoRegistration).
    .OUTPUTS
        Hashtable[] - one per flow, each with Steps (Hashtable[]).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$AuthenticationMethodsPolicyRaw,

        [Parameter(Mandatory)]
        [object]$AuthorizationPolicyRaw,

        [Parameter(Mandatory)]
        [object]$RegistrationRaw,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$CaPolicyInventory
    )

    $methodConfigs = @($AuthenticationMethodsPolicyRaw.authenticationMethodConfigurations)
    $tapConfig = $methodConfigs | Where-Object { $_.id -eq 'TemporaryAccessPass' } | Select-Object -First 1
    $fido2Config = $methodConfigs | Where-Object { $_.id -eq 'Fido2' } | Select-Object -First 1
    $authenticatorConfig = $methodConfigs | Where-Object { $_.id -eq 'MicrosoftAuthenticator' } | Select-Object -First 1

    $tapEnabled = ($tapConfig -and $tapConfig.state -eq 'enabled')
    $fido2Enabled = ($fido2Config -and $fido2Config.state -eq 'enabled')
    $fido2SelfService = ($fido2Config -and $fido2Config.isSelfServiceRegistrationAllowed -eq $true)
    $authenticatorEnabled = ($authenticatorConfig -and $authenticatorConfig.state -eq 'enabled')

    # Cross-device bootstrap friction for "Passkey in Microsoft Authenticator" specifically -
    # confirmed against https://learn.microsoft.com/entra/identity/authentication/how-to-register-passkey-authenticator.
    # Registering that specific passkey type FROM a different device than the phone it will live
    # on (e.g. a laptop) is genuinely supported - Microsoft's "Use Security info" flow hands off
    # to the phone via a QR code / app-open prompt - but the phone must independently complete
    # its OWN sign-in and MFA inside the Authenticator app; it does not inherit the laptop's TAP
    # session. A fallback "WebAuthn flow" (Bluetooth-proximity based) skips that second sign-in,
    # but is explicitly documented as unavailable when FIDO2 attestation is enforced. TAP's own
    # isUsableOnce therefore matters here specifically: a one-time-use TAP is consumed reaching
    # Security Info on the laptop and has nothing left for the phone-side step, unlike WHfB
    # (device-bound to the machine the TAP was entered on, no cross-device handoff needed at
    # all) or a multi-use TAP (re-enterable on the phone within its lifetime).
    $tapIsOneTimeUse = ($tapConfig -and $tapConfig.isUsableOnce -eq $true)
    # Resolved via ConvertTo-SAWPasskeyPolicyEffective so this honours passkeyProfiles as well as
    # the deprecated top-level property (removal October 2027). -eq $true keeps an unresolved
    # value from reading as enforced, which would wrongly claim the cross-device bootstrap is
    # blocked and send a reader chasing a problem they don't have.
    $fido2AttestationEnforced = ((ConvertTo-SAWPasskeyPolicyEffective -RawConfig $fido2Config).AttestationEnforced -eq $true)
    $crossDevicePasskeyBootstrapBlocked = ($tapIsOneTimeUse -and $fido2AttestationEnforced)

    $campaign = $AuthenticationMethodsPolicyRaw.registrationEnforcement.authenticationMethodsRegistrationCampaign
    $campaignState = if ($campaign) { $campaign.state } else { $null }
    $campaignActive = ($campaignState -eq 'enabled' -or $campaignState -eq 'default')
    $campaignTargets = @($campaign.includeTargets) | Where-Object { $_ }
    $campaignTargetMethod = ($campaignTargets | Select-Object -First 1).targetedAuthenticationMethod
    $campaignTargetLabel = switch ($campaignTargetMethod) {
        'fido2' { 'passkey (FIDO2)' }
        'microsoftAuthenticator' { 'Microsoft Authenticator' }
        default { 'not explicitly targeted yet (Microsoft managed default may still apply)' }
    }
    $enforceAfterSnoozes = $campaign.enforceRegistrationAfterAllowedSnoozes

    $reconfirmationDays = $AuthenticationMethodsPolicyRaw.reconfirmationInDays
    # reconfirmationInDays lives on the MODERN authenticationMethodsPolicy - it is not the same
    # setting as the legacy SSPR "Password reset > Registration" blade's own "Number of days
    # before users are asked to reconfirm their authentication information" field, which this
    # toolkit does not collect at all (it has no Microsoft Graph v1.0/beta equivalent found so
    # far).
    #
    # An earlier version of this code assumed the legacy field stops mattering once
    # policyMigrationState reaches migrationComplete, inferring that from the property's
    # documented "legacy policies are ignored" wording. A live tenant disproved that: migration
    # status showed Complete in the admin center while the legacy blade still had a real,
    # non-default reconfirmation value (180 days) configured. Microsoft's own migration guidance
    # names exactly two legacy elements that are confirmed to survive migrationComplete - "Number
    # of methods required to reset" and the SSPR administrator policy - and this field was never
    # one of them, which is silence, not a documented "ignored" for THIS specific setting. So
    # there is no migration-state threshold this toolkit can safely use to switch from "unknown"
    # to a confident "no reconfirmation" - it hedges unconditionally instead, and the migration
    # state is surfaced as context, not as the basis for a claim.
    $migrationState = [string]$AuthenticationMethodsPolicyRaw.policyMigrationState

    $sysPrefState = [string]$AuthenticationMethodsPolicyRaw.systemCredentialPreferences.state
    if ([string]::IsNullOrEmpty($sysPrefState)) { $sysPrefState = 'default' }
    $sysPrefDisabled = ($sysPrefState -eq 'disabled')
    $sysPrefScopeLabel = switch ($sysPrefState) {
        'enabled' { 'second-factor sign-in only (first factor is unchanged)' }
        default   { 'BOTH first and second factor - "Microsoft managed", gradually rolling out through 2026-08' }
    }

    $users = @($RegistrationRaw.value)
    $ssprEnabledCount = @($users | Where-Object { $_.isSsprEnabled }).Count
    $ssprEnabledAtAll = $ssprEnabledCount -gt 0
    $adminSsprAllowed = $AuthorizationPolicyRaw.allowedToUseSSPR -ne $false

    $securityInfoRegCaPolicies = @($CaPolicyInventory | Where-Object { $_.TargetsSecurityInfoRegistration -and $_.State -eq 'Enabled' })
    $securityInfoRegGated = $securityInfoRegCaPolicies.Count -gt 0

    $flows = @()

    # --- Flow 1: New User Bootstrap ---
    $flows += @{
        FlowID     = 'BOOTSTRAP'
        Category   = 'New User Bootstrap'
        Title      = 'New user first sign-in with a Temporary Access Pass'
        Applicable = $tapEnabled
        ISTSummary = if ($tapEnabled) { 'A new user can be issued a TAP and use it to bootstrap into passwordless registration without knowing a password first.' } else { 'Temporary Access Pass is not enabled tenant-wide - new users cannot bootstrap this way today; an admin-set temporary password is the only onboarding path.' }
        SOLLSummary = 'TAP enabled and scoped to the users/groups who need self-service onboarding (new hires, recovery cases); registration campaign targeting passkeys so a later sign-in nudges the user toward a portable phishing-resistant method.'
        SourceUrl  = 'https://learn.microsoft.com/entra/identity/authentication/howto-authentication-temporary-access-pass'
        Steps      = @(
            @{ Step = 'Admin issues a Temporary Access Pass to the new user'; Applies = $tapEnabled; Detail = if ($tapEnabled) { 'TAP is enabled in the authentication methods policy.' } else { 'TAP is disabled tenant-wide - this step cannot happen.' } }
            @{ Step = 'User signs in at Security Info with the TAP (no password needed)'; Applies = $tapEnabled; Detail = 'Federated domains: a TAP is preferred over federation, so the user authenticates directly in Entra ID rather than being redirected to the on-prem IdP.' }
            @{ Step = 'If the user is in scope for the SSPR or MFA registration policy, they are redirected into Interrupt mode of combined registration'; Applies = $ssprEnabledAtAll; Detail = 'Documented limitation: this forced Interrupt-mode path does not currently support FIDO2 or phone sign-in registration - only outside that redirect can those methods be registered directly.' }
            @{ Step = 'User registers a passkey (FIDO2) directly via Security Info'; Applies = $fido2SelfService; Detail = if ($fido2SelfService) { 'FIDO2 self-service registration is allowed - a TAP-signed-in user can register a passkey themselves.' } else { 'FIDO2 self-service registration is off (or FIDO2 itself is disabled) - a TAP-signed-in user cannot self-register a passkey; an admin must provision one via a custom client/Graph, or the user is left with weaker methods.' } }
            @{ Step = 'If the target is specifically "Passkey in Microsoft Authenticator" and the user signed in with the TAP on a DIFFERENT device than their phone (e.g. a laptop), Microsoft''s cross-device flow hands off to the phone - but the phone must independently complete its OWN sign-in and MFA inside the Authenticator app, it does not just inherit the laptop''s TAP session'; Applies = $null; Detail = 'Fixed Microsoft mechanic, confirmed against how-to-register-passkey-authenticator: cross-device registration IS supported here (unlike a hardware security key or a device-bound Windows passkey, which are inherently local to the device the user is on) - it is not blocked outright, but it is not a single-session handoff either.' }
            @{ Step = 'Whether a brand-new user can actually complete that phone-side step depends on settings already collected above'; Applies = if (-not $fido2SelfService) { $null } else { (-not $crossDevicePasskeyBootstrapBlocked) }; Detail = if (-not $fido2SelfService) { 'Not reachable yet - FIDO2 self-service registration is off, so this scenario does not arise.' } elseif ($crossDevicePasskeyBootstrapBlocked) { 'TAP is enforced one-time-use (TAP001) AND FIDO2 attestation is enforced (PASS001) - the TAP consumed on the laptop has nothing left for the phone, and Microsoft''s Bluetooth-based fallback ("WebAuthn flow") is explicitly documented as unavailable whenever attestation is enforced. A brand-new user in exactly this situation may have no way to complete Authenticator-passkey bootstrap cross-device at all. WHfB (same-device, no handoff needed) or a short-lived multi-use TAP scoped to onboarding are the practical alternatives - see TAP001''s recommendation.' } elseif ($tapIsOneTimeUse) { 'TAP is enforced one-time-use, so the laptop-side TAP is consumed reaching Security Info - but FIDO2 attestation is NOT enforced, so Microsoft''s Bluetooth-based fallback ("WebAuthn flow") remains available as the phone-side path instead. Confirm Bluetooth and the required network endpoints are actually reachable on both devices before relying on this at scale.' } else { 'TAP is multi-use, so the same TAP can be re-entered on the phone within its lifetime window to complete that second, independent sign-in - this specific friction is avoidable here.' } }
            @{ Step = 'User registers Microsoft Authenticator via TAP'; Applies = $authenticatorEnabled; Detail = if ($authenticatorEnabled) { 'Authenticator is enabled tenant-wide, so this is available as an alternative to passkey registration.' } else { 'Authenticator is disabled tenant-wide.' } }
            @{ Step = "On a LATER sign-in (not the same session), the registration campaign nudges the user toward $campaignTargetLabel if not yet set up"; Applies = $campaignActive; Detail = if ($campaignActive) { "Registration campaign state is '$campaignState'. Users are never nudged in the same session they just registered a method in - the nudge appears on the next MFA attempt after that." } else { 'Registration campaign is disabled - no automatic nudge follows initial TAP-based setup; the user stays on whatever they registered during onboarding unless manually followed up on.' } }
            @{ Step = "Once the user has more than one method registered, System-Preferred Authentication may start presenting the newly-registered method first at their NEXT sign-in, ahead of whatever they used before"; Applies = (-not $sysPrefDisabled); Detail = if ($sysPrefDisabled) { 'System-Preferred Authentication is disabled - the user keeps using whatever method they sign in with by choice; nothing is presented preferentially.' } else { "Applies to $sysPrefScopeLabel. A distinct setting from the registration campaign above - this one changes what's presented for a credential the user ALREADY has, not what gets nudged for registration." } }
        )
    }

    # --- Flow 2: SSPR Eligibility & Two-Gate ---
    $flows += @{
        FlowID     = 'SSPR'
        Category   = 'SSPR Eligibility & Two-Gate'
        Title      = 'Self-service password reset registration and use'
        Applicable = $ssprEnabledAtAll
        ISTSummary = if ($ssprEnabledAtAll) { "$ssprEnabledCount user(s) are currently SSPR-enabled." } else { 'No user in this tenant is currently SSPR-enabled - this whole flow does not apply yet.' }
        SOLLSummary = 'All standard users SSPR-enabled with a two-method policy; admin SSPR deliberately governed separately via allowedToUseSSPR, with admins excluded from the user-facing SSPR policy scope if admin SSPR is turned off (see SSPR002).'
        SourceUrl  = 'https://learn.microsoft.com/entra/identity/authentication/concept-registration-mfa-sspr-combined'
        Steps      = @(
            @{ Step = 'User is placed in scope for the SSPR policy (tenant-wide or group-scoped)'; Applies = $ssprEnabledAtAll; Detail = if ($ssprEnabledAtAll) { "$ssprEnabledCount user(s) currently in scope." } else { 'No user is currently in scope.' } }
            @{ Step = 'If ONLY SSPR registration is enforced (no MFA registration policy also enforced), the user can skip the registration interrupt indefinitely'; Applies = $null; Detail = 'A real governance gap worth checking for: without a separate MFA registration enforcement (Identity Protection, per-user MFA, or a Conditional Access MFA requirement), SSPR-only enforcement never actually forces completion.' }
            @{ Step = "If the SSPR policy requires two methods, the user registers an MFA-capable method first, then a second SSPR-specific method (or another MFA method)"; Applies = $null; Detail = 'Fixed combined-registration behavior once two methods are required - not independently toggleable per this toolkit''s collected settings.' }
            @{ Step = 'Administrator accounts follow a separate, built-in two-gate SSPR policy, independent of the setting above'; Applies = $true; Detail = if ($adminSsprAllowed) { 'allowedToUseSSPR is true/absent - admin SSPR is enabled via the default built-in policy (two methods, no security questions).' } else { 'allowedToUseSSPR is explicitly false - admin SSPR is disabled tenant-wide; see SSPR002 for whether admins are correctly excluded from the user-facing policy as a result.' } }
            @{ Step = 'User completes password reset at the SSPR portal, verified via their registered method(s)'; Applies = $ssprEnabledAtAll; Detail = 'Requires the methods registered in the steps above to actually be usable - cross-check against the Security Info Registration Triage section for stale/disabled registrations.' }
        )
    }

    # --- Flow 3: Existing User Re-Registration ---
    $flows += @{
        FlowID     = 'REREGISTRATION'
        Category   = 'Existing User Re-Registration'
        Title      = 'Existing user manages or refreshes their security info'
        Applicable = $true
        ISTSummary = if ($reconfirmationDays) { "Users are periodically interrupted to confirm/update security info every $reconfirmationDays day(s)." } else { "The modern Authentication Methods policy has no reconfirmation interval configured (policyMigrationState: '$migrationState') - but this toolkit cannot see the legacy SSPR `"Password reset > Registration`" blade's own separate reconfirmation setting, and a live tenant has shown that setting can still be configured even when migration status reads Complete. Check that blade directly before concluding users are never reconfirmed." }
        SOLLSummary = 'A registration campaign actively targeting the strongest available method (passkey), plus periodic reconfirmation so stale registrations surface on their own rather than only being caught by an assessment like this one.'
        SourceUrl  = 'https://learn.microsoft.com/entra/identity/authentication/concept-registration-mfa-sspr-combined'
        Steps      = @(
            @{ Step = 'BEFORE any of the below: at ordinary sign-in (not registration), System-Preferred Authentication may present the user''s strongest registered method first - not necessarily the one they''re used to or set as default'; Applies = (-not $sysPrefDisabled); Detail = if ($sysPrefDisabled) { 'System-Preferred Authentication is disabled - the user''s own default/last-used method continues to be presented, unchanged.' } else { "Applies to $sysPrefScopeLabel. The user can always select `"Sign in another way`" to fall back to a different registered method - this changes what's offered first, not what's available." } }
            @{ Step = 'User visits Security Info (mysignins.microsoft.com/security-info) any time to add, change, or delete a method - "manage mode", no interrupt required'; Applies = $true; Detail = 'Always available regardless of tenant configuration; the only gate is completing MFA first if the user already has a method that can serve as MFA.' }
            @{ Step = 'Adding or modifying a passkey (FIDO2) requires the user to have completed MFA within the last 5 minutes'; Applies = $null; Detail = 'Fixed Microsoft Entra session-freshness requirement, not a tenant-configurable setting - included here since it is a common source of "why am I asked to sign in again" support tickets.' }
            @{ Step = "A registration campaign nudge for $campaignTargetLabel appears on the user's next MFA attempt if the targeted method is not present for their current device/browser"; Applies = $campaignActive; Detail = if ($campaignActive) { if ($enforceAfterSnoozes -eq $true) { 'Limited snoozes: after 3 skips, registration becomes required.' } elseif ($enforceAfterSnoozes -eq $false) { 'Unlimited snoozes: users may indefinitely postpone and never actually register.' } else { 'Snooze-limit behavior not explicitly set; Microsoft managed defaults apply.' } } else { 'Registration campaign is disabled - no proactive nudge occurs; re-registration only happens if the user initiates it themselves.' } }
            @{ Step = 'User deletes an existing (e.g. stale or policy-disabled) method from Security Info'; Applies = $true; Detail = 'Always available in manage mode - no tenant setting gates deletion.' }
            @{ Step = 'If reconfirmation is configured, the user is periodically interrupted at sign-in to confirm or update their registered info'; Applies = if ($reconfirmationDays) { $true } else { 'unknown' }; Detail = if ($reconfirmationDays) { "reconfirmationInDays is set to $reconfirmationDays." } else { "reconfirmationInDays (modern policy) is not set (policyMigrationState: '$migrationState') - the legacy SSPR `"Password reset > Registration`" blade's own reconfirmation setting is a separate field this toolkit does not read, and a live tenant has shown it can still be configured regardless of migration status. Verify directly in the admin center rather than assuming reconfirmation is off." } }
        )
    }

    # --- Flow 4: CA-Gated Registration ---
    $gatingPolicyNames = ($securityInfoRegCaPolicies | ForEach-Object { $_.DisplayName }) -join ', '
    $flows += @{
        FlowID     = 'CAGATED'
        Category   = 'CA-Gated Registration'
        Title      = 'Conditional Access policies scoped to "Register security information"'
        Applicable = $securityInfoRegGated
        ISTSummary = if ($securityInfoRegGated) { "$($securityInfoRegCaPolicies.Count) enabled polic$(if ($securityInfoRegCaPolicies.Count -eq 1) { 'y gates' } else { 'ies gate' }) this flow: $gatingPolicyNames." } else { 'No enabled Conditional Access policy currently targets the "Register security information" user action - every user above can reach the registration page under whatever their normal sign-in Conditional Access requires (or does not require).' }
        SOLLSummary = 'A deliberate policy restricting security info registration to a trusted context (e.g. compliant device, specific network) - configured with an escape hatch (a plain "mfa" control, not a custom strength that excludes Temporary Access Pass) so a brand-new user bootstrapping via TAP is not locked out. See CA004.'
        SourceUrl  = 'https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-security-info-registration'
        Steps      = @(
            @{ Step = 'An enabled Conditional Access policy targets the "Register security information" user action'; Applies = $securityInfoRegGated; Detail = if ($securityInfoRegGated) { $gatingPolicyNames } else { 'None found.' } }
            @{ Step = 'Users outside that policy''s required conditions cannot reach the registration page at all - every flow above (bootstrap, SSPR, re-registration) is gated by it first'; Applies = $securityInfoRegGated; Detail = if ($securityInfoRegGated) { ($securityInfoRegCaPolicies | ForEach-Object { $_.GrantControlsSummary }) -join '; ' } else { 'Not applicable - no such policy is enabled.' } }
            @{ Step = 'The registration campaign nudge (Flows 1 and 3 above) does not appear for a user blocked from the registration page by this policy'; Applies = $securityInfoRegGated -and $campaignActive; Detail = 'Documented Microsoft behavior: the campaign nudge is suppressed entirely, not deferred, for a user who cannot reach the page.' }
            @{ Step = 'A Temporary Access Pass-only user (no phishing-resistant method registered yet) can be fully locked out if the policy demands an authentication strength TAP does not satisfy'; Applies = $securityInfoRegGated; Detail = 'See CA004 (Security Info Registration Reachable With Only A Temporary Access Pass) for whether this tenant''s specific policy configuration triggers that lockout.' }
            @{ Step = 'Starting 2026-07-06, this same policy scope additionally applies during Windows Hello for Business and macOS Platform SSO credential registration, which it did not evaluate before'; Applies = $null; Detail = 'A fixed Microsoft rollout date, not a tenant setting - see the Upcoming Microsoft Deadlines section.' }
            @{ Step = 'Conditional Access does NOT override which method System-Preferred Authentication presents at first-factor sign-in - it is validated only for the second factor'; Applies = $null; Detail = 'Fixed Microsoft behavior: authentication happens first, then Conditional Access evaluates authorization. A CA policy gating registration governs whether the page is reachable at all, not what credential the user is prompted with to get there.' }
        )
    }

    return $flows
}

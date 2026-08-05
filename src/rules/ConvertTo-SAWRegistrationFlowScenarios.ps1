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
            @{ Step = 'User registers Microsoft Authenticator via TAP'; Applies = $authenticatorEnabled; Detail = if ($authenticatorEnabled) { 'Authenticator is enabled tenant-wide, so this is available as an alternative to passkey registration.' } else { 'Authenticator is disabled tenant-wide.' } }
            @{ Step = "On a LATER sign-in (not the same session), the registration campaign nudges the user toward $campaignTargetLabel if not yet set up"; Applies = $campaignActive; Detail = if ($campaignActive) { "Registration campaign state is '$campaignState'. Users are never nudged in the same session they just registered a method in - the nudge appears on the next MFA attempt after that." } else { 'Registration campaign is disabled - no automatic nudge follows initial TAP-based setup; the user stays on whatever they registered during onboarding unless manually followed up on.' } }
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
        ISTSummary = if ($reconfirmationDays) { "Users are periodically interrupted to confirm/update security info every $reconfirmationDays day(s)." } else { 'No periodic reconfirmation interval is configured - users only revisit their security info voluntarily (manage mode) or when a registration campaign nudge fires.' }
        SOLLSummary = 'A registration campaign actively targeting the strongest available method (passkey), plus periodic reconfirmation so stale registrations surface on their own rather than only being caught by an assessment like this one.'
        SourceUrl  = 'https://learn.microsoft.com/entra/identity/authentication/concept-registration-mfa-sspr-combined'
        Steps      = @(
            @{ Step = 'User visits Security Info (mysignins.microsoft.com/security-info) any time to add, change, or delete a method - "manage mode", no interrupt required'; Applies = $true; Detail = 'Always available regardless of tenant configuration; the only gate is completing MFA first if the user already has a method that can serve as MFA.' }
            @{ Step = 'Adding or modifying a passkey (FIDO2) requires the user to have completed MFA within the last 5 minutes'; Applies = $null; Detail = 'Fixed Microsoft Entra session-freshness requirement, not a tenant-configurable setting - included here since it is a common source of "why am I asked to sign in again" support tickets.' }
            @{ Step = "A registration campaign nudge for $campaignTargetLabel appears on the user's next MFA attempt if the targeted method is not present for their current device/browser"; Applies = $campaignActive; Detail = if ($campaignActive) { if ($enforceAfterSnoozes -eq $true) { 'Limited snoozes: after 3 skips, registration becomes required.' } elseif ($enforceAfterSnoozes -eq $false) { 'Unlimited snoozes: users may indefinitely postpone and never actually register.' } else { 'Snooze-limit behavior not explicitly set; Microsoft managed defaults apply.' } } else { 'Registration campaign is disabled - no proactive nudge occurs; re-registration only happens if the user initiates it themselves.' } }
            @{ Step = 'User deletes an existing (e.g. stale or policy-disabled) method from Security Info'; Applies = $true; Detail = 'Always available in manage mode - no tenant setting gates deletion.' }
            @{ Step = 'If reconfirmation is configured, the user is periodically interrupted at sign-in to confirm or update their registered info'; Applies = [bool]$reconfirmationDays; Detail = if ($reconfirmationDays) { "reconfirmationInDays is set to $reconfirmationDays." } else { 'reconfirmationInDays is not set - stale-but-still-valid registrations are never proactively surfaced to the user.' } }
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
        )
    }

    return $flows
}

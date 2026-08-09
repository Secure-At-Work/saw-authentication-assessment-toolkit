function ConvertTo-SAWStagedRolloutInventory {
    <#
    .SYNOPSIS
        Interprets the raw featureRolloutPolicies response into a Staged Rollout inventory,
        plus the caveats an active rollout places on other findings in this assessment.
    .DESCRIPTION
        Inventory, not a rule: this never reaches Invoke-SAWRulesEngine and produces no
        pass/fail. Staged Rollout is a deliberately temporary migration state, so "enabled" is
        neither good nor bad on its own. What it has is consequences, and the consequences are
        the point of collecting it.

        Three caveats are emitted whenever at least one rollout policy is actually enabled, each
        qualifying a recommendation this toolkit makes elsewhere. All three come from
        https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-staged-rollout
        (verified 2026-08-09) and are quoted rather than paraphrased in docs/references.md:

        - SSPR with on-premises writeback "isn't supported when staged rollout is enabled for a
          security group", and Microsoft is explicit that it "can't be guaranteed to work
          consistently" even where it appears to work. That qualifies SSPR001/SSPR002.
        - Windows Hello for Business hybrid CERTIFICATE trust (federation server acting as
          registration authority) and smartcard users aren't supported on Staged Rollout at all,
          which removes a bootstrap route BOOT001 would otherwise count.
        - A newly added user keeps authenticating through the old identity provider until one
          more interactive federated sign-in, unless a TAP is issued - Entra evaluates a TAP
          before it redirects to the federated IdP. That is an argument FOR the TAP configuration
          AUTH005/TAP001/TAP002 already assess, in a scenario those rules don't currently mention.

        A fourth note fires only when a policy has isAppliedToOrganization = true. Microsoft's own
        best-practice list says to "avoid placing all users in staged rollout unless you have a
        clear transition plan to managed authentication" and that the feature is "not designed to
        be a permanent configuration", so org-wide is worth surfacing distinctly from a pilot
        group rather than folding both into one "enabled" state.

        Feature names are mapped to labels a non-specialist reader can follow. Two of them
        (certificateBasedAuthentication, multiFactorAuthentication) only arrive by name at all
        because Get-SAWStagedRollout sends the Prefer: include-unknown-enum-members header; a
        `unknownFutureValue` reaching this function therefore means Microsoft has shipped a
        rollout feature newer than this mapping, which is reported as exactly that rather than
        silently relabelled.
    .PARAMETER RawResponse
        The object returned by Get-SAWStagedRollout (has .value and .sawCollectionStatus).
    .OUTPUTS
        Hashtable with IsAvailable, UnavailableReason, IsActive, AppliesToOrganization,
        Policies (array of hashtables), Summary, and Caveats (array of hashtables with
        Heading, Detail, AffectsRules).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$RawResponse
    )

    begin {
        $featureLabels = @{
            'passthroughAuthentication'      = 'Pass-through authentication'
            'seamlessSso'                    = 'Seamless single sign-on'
            'passwordHashSync'               = 'Password hash sync'
            'emailAsAlternateId'             = 'Email as alternate sign-in ID'
            'certificateBasedAuthentication' = 'Certificate-based authentication'
            'multiFactorAuthentication'      = 'Microsoft Entra multifactor authentication'
        }
    }

    process {
        $status = $RawResponse.sawCollectionStatus
        if ($status -eq 'Unavailable') {
            Write-Verbose 'ConvertTo-SAWStagedRolloutInventory: collection reported Unavailable'
            return @{
                IsAvailable           = $false
                UnavailableReason     = $RawResponse.sawUnavailableReason
                IsActive              = $false
                AppliesToOrganization = $false
                Policies              = @()
                Summary               = 'Staged Rollout could not be read.'
                Caveats               = @()
            }
        }

        $policies = @()
        foreach ($p in @($RawResponse.value)) {
            if (-not $p) { continue }

            $feature = [string]$p.feature
            $label = $featureLabels[$feature]
            $recognized = $true
            if (-not $label) {
                $recognized = $false
                $label = if ($feature) {
                    "Unrecognized feature '$feature'"
                }
                else {
                    'Unrecognized feature (no value returned)'
                }
            }

            # appliesTo is only populated because the collector asked for it with $expand.
            # Groups are the only supported target type, so a non-group here would be a Graph
            # surprise rather than something to model.
            $groupNames = @(
                foreach ($g in @($p.appliesTo)) {
                    if ($g -and $g.displayName) { [string]$g.displayName }
                    elseif ($g -and $g.id) { [string]$g.id }
                }
            )

            $appliesToOrg = [bool]$p.isAppliedToOrganization
            $scopeText = if ($appliesToOrg) {
                'Entire organization'
            }
            elseif ($groupNames.Count -gt 0) {
                "$($groupNames.Count) group$(if ($groupNames.Count -ne 1) { 's' })"
            }
            else {
                'No groups targeted'
            }

            $policies += @{
                Id                    = [string]$p.id
                DisplayName           = [string]$p.displayName
                Description           = [string]$p.description
                Feature               = $feature
                FeatureLabel          = $label
                FeatureRecognized     = $recognized
                IsEnabled             = [bool]$p.isEnabled
                AppliesToOrganization = $appliesToOrg
                GroupNames            = $groupNames
                GroupCount            = $groupNames.Count
                ScopeText             = $scopeText
            }
        }

        $enabledPolicies = @($policies | Where-Object { $_.IsEnabled })
        $isActive = $enabledPolicies.Count -gt 0
        $appliesToOrganization = @($enabledPolicies | Where-Object { $_.AppliesToOrganization }).Count -gt 0

        Write-Verbose "ConvertTo-SAWStagedRolloutInventory: $($policies.Count) policy/policies, $($enabledPolicies.Count) enabled, org-wide=$appliesToOrganization"

        if ($policies.Count -eq 0) {
            $summary = 'No Staged Rollout policies are configured. Either this tenant was never federated, or the move to managed cloud authentication is already complete.'
        }
        elseif (-not $isActive) {
            $summary = "$($policies.Count) Staged Rollout policy/policies exist but none are enabled, so no user is currently being moved from federated to managed authentication by this mechanism. Leftover disabled policies are worth tidying up, but change nothing today."
        }
        else {
            $enabledLabels = @($enabledPolicies | ForEach-Object { $_.FeatureLabel }) -join ', '
            $summary = "$($enabledPolicies.Count) of $($policies.Count) Staged Rollout policy/policies are enabled ($enabledLabels). Users in scope authenticate against Microsoft Entra rather than the federated identity provider, which changes several recommendations elsewhere in this report."
        }

        $caveats = @()
        if ($isActive) {
            $caveats += @{
                Heading      = 'SSPR with on-premises password writeback is not supported while this is on'
                Detail       = "Microsoft states that self-service password reset with writeback to an on-premises domain isn't supported when staged rollout is enabled for a security group, and that although it works in some cases, it can't be guaranteed to work consistently. Treat SSPR coverage targets as still worth reaching, but don't rely on the writeback path until the domain cutover to managed authentication is finished."
                AffectsRules = 'SSPR001, SSPR002'
            }
            $caveats += @{
                Heading      = 'A Temporary Access Pass skips the last federated sign-in'
                Detail       = "Adding a user to a rollout group doesn't take effect until they complete one more interactive sign-in through the existing federated login, sending someone you're moving towards passwordless back to a password one final time. Entra evaluates a TAP before it redirects to the federated identity provider, so issuing a TAP straight after adding the user makes their first sign-in managed, with no trip through AD FS, and they can register a passkey or Authenticator from there. Removing a user from a rollout group behaves the same way in reverse."
                AffectsRules = 'AUTH005, TAP001, TAP002, BOOT001'
            }
            $caveats += @{
                Heading      = 'Windows Hello for Business certificate trust and smartcards are unsupported here'
                Detail       = "If Windows Hello for Business runs on hybrid CERTIFICATE trust with certificates issued via the federation server acting as registration authority, or the population uses smartcards, Microsoft does not support those scenarios on Staged Rollout at all. That removes the WHfB-shaped bootstrap route for exactly the users most likely to have it, so plan a different first credential for them. Hybrid KEY trust and cloud Kerberos trust are not named in this limitation."
                AffectsRules = 'BOOT001, AUTH004'
            }
            if ($appliesToOrganization) {
                $caveats += @{
                    Heading      = 'At least one rollout is applied to the entire organization'
                    Detail       = "Microsoft's guidance is to use staged rollout only for pilot groups, to keep a federated identity provider available as a fallback while testing, and to 'avoid placing all users in staged rollout unless you have a clear transition plan to managed authentication'. The feature is explicitly not designed to be a permanent configuration, and staged rollout never converts the domain by itself, so an org-wide rollout that has been sitting in place is a migration to finish rather than a steady state."
                    AffectsRules = 'None directly - a hybrid identity question to raise with the customer'
                }
            }
        }

        @{
            IsAvailable           = $true
            UnavailableReason     = $null
            IsActive              = $isActive
            AppliesToOrganization = $appliesToOrganization
            Policies              = $policies
            Summary               = $summary
            Caveats               = $caveats
        }
    }
}

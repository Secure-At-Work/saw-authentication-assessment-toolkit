function ConvertTo-SAWPasskeyPolicyEffective {
    <#
    .SYNOPSIS
        Resolves the tenant's effective passkey (FIDO2) attestation and key-restriction settings
        from either the new passkey profiles or the deprecated top-level properties.
    .DESCRIPTION
        One resolver, so the "which source is authoritative?" decision is made once instead of at
        each of the five call sites that need it (ConvertTo-SAWNormalizedPasskeys,
        ConvertTo-SAWFido2KeyInventory, ConvertTo-SAWNudgeForecast,
        ConvertTo-SAWRegistrationFlowScenarios, ConvertTo-SAWAuthenticationMethodsInventory).

        WHY THIS EXISTS. Microsoft's v1.0 reference for fido2AuthenticationMethodConfiguration
        marks both properties this toolkit originally read as deprecated:

            isAttestationEnforced - "This property is deprecated and will be removed in
            October 2027. Use passkeyProfiles property."
            keyRestrictions       - same wording.

        The replacement is a passkeyProfiles collection (see
        https://learn.microsoft.com/graph/api/resources/passkeyprofile), where each profile
        carries attestationEnforcement ('disabled' | 'registrationOnly' | 'unknownFutureValue'),
        its own keyRestrictions, and passkeyTypes ('deviceBound' | 'synced' |
        'unknownFutureValue') for group-based control. defaultPasskeyProfile names the
        non-deletable baseline profile, which per Microsoft "is automatically created when
        migrating to passkey profiles and initially mirrors the tenant's legacy global passkey
        (FIDO2) authentication methods policy settings."

        The failure mode being fixed is worse than "stops working in 2027". Every original call
        site coerced the value with [bool], so an absent property became $false, which renders as
        "attestation NOT enforced" - a false negative on a security control, presented as a real
        finding. A tenant already migrated to profiles whose profile has since diverged from the
        mirrored legacy values can read wrong today, not only after removal. Hence the third state
        below: when neither source is present, this reports Unknown rather than guessing $false.

        RESOLUTION ORDER.
          1. passkeyProfiles, when present and non-empty. Authoritative.
          2. The deprecated top-level properties, when profiles are absent. Still correct for a
             tenant that hasn't migrated.
          3. Neither - Unknown. Callers must render "couldn't determine", never "not enforced".

        AGGREGATING ACROSS PROFILES. Profiles are per-group, so a tenant can enforce attestation
        for one population and not another, and there is no single tenant-wide truth to report.
        This returns the conservative reading for a security check: attestation counts as enforced
        only when EVERY profile enforces it, and key restrictions likewise. A tenant with a strict
        admin profile and a permissive everyone-else profile is not a tenant with attestation
        enforced, and reporting it as such would be the same false-negative-with-extra-steps this
        function exists to prevent. ProfileCount and MixedEnforcement are returned so callers can
        say "3 of 4 profiles" rather than flattening the nuance away entirely.

        PasskeyTypeRestriction deliberately does NOT use that same "every profile agrees" rule.
        Unlike attestation/key restrictions (booleans with a safe "not enforced" default),
        passkeyTypes is a required field on every profile - there is no unrestricted value to fall
        back to, so the "all profiles must agree" aggregation used above would either be
        meaningless (profiles nearly always differ) or silently produce the wrong caveat. Instead
        this reads the DEFAULT profile's value specifically, the same simplification already used
        for KeyRestrictions above - the best available single answer for a fundamentally per-group
        setting, not a tenant-wide guarantee. Callers using this to flag a nudge-suppression
        caveat should treat it as "worth checking," not as confirmed for every user.

        NOT CONFIRMED AGAINST A LIVE MIGRATED TENANT. The shape here follows Microsoft's published
        v1.0 reference (ms.date 2026-03-04). No tenant in this project's reach has migrated to
        passkey profiles yet, so the fallback path is the exercised one and the profiles path is
        built from the schema. Re-check against a real migrated tenant before relying on the
        profile branch for a customer finding - in particular whether attestationEnforcement
        carries values beyond the three documented, and whether Graph returns passkeyProfiles
        without an explicit $expand.
    .PARAMETER RawConfig
        The object returned by Get-SAWPasskeys (the Fido2 authentication method configuration).
    .OUTPUTS
        Hashtable with AttestationEnforced, KeyRestrictionsEnforced (each $true/$false/$null where
        $null means unknown), IsKnown, Source, ProfileCount, MixedEnforcement, KeyRestrictions
        (the effective fido2KeyRestrictions-shaped object), SyncedPasskeysAllowed, and
        PasskeyTypeRestriction (the default profile's passkeyTypes value - 'deviceBound', 'synced',
        or $null when unrestricted/unknown/not on the profiles path - see the note below on why
        this is read from the default profile rather than aggregated like AttestationEnforced).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowNull()]
        [object]$RawConfig
    )

    process {
        $unknown = @{
            AttestationEnforced    = $null
            KeyRestrictionsEnforced = $null
            IsKnown                = $false
            Source                 = 'Unknown'
            ProfileCount           = 0
            MixedEnforcement       = $false
            KeyRestrictions        = $null
            SyncedPasskeysAllowed  = $null
            PasskeyTypeRestriction = $null
            Summary                = 'Passkey policy could not be determined: neither passkey profiles nor the legacy attestation/key-restriction properties were present in the Graph response.'
        }

        if (-not $RawConfig) {
            Write-Verbose 'ConvertTo-SAWPasskeyPolicyEffective: no config supplied - reporting Unknown'
            return $unknown
        }

        # Outer @(...) wraps the WHOLE pipeline, not just its input. Without it, a tenant with
        # exactly one passkey profile makes Where-Object emit a single object, which PowerShell
        # then assigns to $profiles as a bare Hashtable rather than a 1-element array - and
        # Hashtable.Count returns its KEY count (4, for a typical profile), not "how many
        # profiles". Every "-eq $profiles.Count" check below silently breaks for exactly the
        # single-profile case a freshly-migrated tenant (one auto-created default profile) is
        # most likely to have, misreporting attestation/key-restriction enforcement as $false.
        $profiles = @(@($RawConfig.passkeyProfiles) | Where-Object { $_ })

        if ($profiles.Count -gt 0) {
            # attestationEnforcement is an enum, not a boolean. 'registrationOnly' is the only
            # documented value that actually enforces; 'disabled' does not; 'unknownFutureValue'
            # (or anything newer than this mapping) is deliberately NOT treated as enforcing,
            # because assuming a control is on when the value isn't recognized is the optimistic
            # direction, and this check exists to avoid exactly that.
            $enforcingProfiles = @($profiles | Where-Object { $_.attestationEnforcement -eq 'registrationOnly' })
            $attestationEnforced = $enforcingProfiles.Count -eq $profiles.Count

            $keyRestrictedProfiles = @($profiles | Where-Object { $_.keyRestrictions.isEnforced -eq $true })
            $keyRestrictionsEnforced = $keyRestrictedProfiles.Count -eq $profiles.Count

            $mixed = ($enforcingProfiles.Count -gt 0 -and -not $attestationEnforced) -or
                     ($keyRestrictedProfiles.Count -gt 0 -and -not $keyRestrictionsEnforced)

            # The default profile's restrictions are the closest thing to a tenant-wide answer for
            # the AAGUID inventory, which lists specific allowed keys. Falls back to the first
            # profile when defaultPasskeyProfile doesn't resolve.
            $defaultProfile = $profiles | Where-Object { $_.id -and $_.id -eq $RawConfig.defaultPasskeyProfile } | Select-Object -First 1
            if (-not $defaultProfile) { $defaultProfile = $profiles | Select-Object -First 1 }

            # passkeyTypes is the explicit control for device-bound versus synced, which is a far
            # better signal than inferring it from registered AAGUIDs. Synced is allowed if any
            # profile targets it.
            $syncedAllowed = @($profiles | Where-Object { $_.passkeyTypes -and ([string]$_.passkeyTypes) -match 'synced' }).Count -gt 0

            # See the AGGREGATING ACROSS PROFILES note above: read from the default profile only,
            # not aggregated the way attestation/key restrictions are. $null covers 'unrecognized
            # value' the same conservative way $unrecognized already treats attestationEnforcement.
            $passkeyTypeRestriction = $null
            if ($defaultProfile -and $defaultProfile.passkeyTypes -in @('deviceBound', 'synced')) {
                $passkeyTypeRestriction = [string]$defaultProfile.passkeyTypes
            }

            $unrecognized = @($profiles | Where-Object {
                $_.attestationEnforcement -and $_.attestationEnforcement -notin @('disabled', 'registrationOnly')
            })

            $summary = "Resolved from $($profiles.Count) passkey profile$(if ($profiles.Count -ne 1) { 's' })."
            if ($mixed) {
                $summary += " Settings differ between profiles: attestation enforced in $($enforcingProfiles.Count) of $($profiles.Count), key restrictions in $($keyRestrictedProfiles.Count) of $($profiles.Count). Reported as enforced only when every profile enforces it."
            }
            if ($unrecognized.Count -gt 0) {
                $summary += " $($unrecognized.Count) profile(s) report an attestationEnforcement value this toolkit doesn't recognize; those are treated as NOT enforcing rather than assumed safe."
            }

            Write-Verbose "ConvertTo-SAWPasskeyPolicyEffective: $($profiles.Count) profile(s), attestation=$attestationEnforced, keyRestrictions=$keyRestrictionsEnforced, mixed=$mixed"

            return @{
                AttestationEnforced     = $attestationEnforced
                KeyRestrictionsEnforced = $keyRestrictionsEnforced
                IsKnown                 = $true
                Source                  = 'PasskeyProfiles'
                ProfileCount            = $profiles.Count
                MixedEnforcement        = $mixed
                KeyRestrictions         = $defaultProfile.keyRestrictions
                SyncedPasskeysAllowed   = $syncedAllowed
                PasskeyTypeRestriction  = $passkeyTypeRestriction
                Summary                 = $summary
            }
        }

        # No profiles. Fall back to the deprecated properties, but only when they're actually
        # present - PSObject.Properties rather than a null test, so an explicit $false is honoured
        # and distinguished from an absent property, which is the whole point of this function.
        $hasLegacyAttestation = $false
        $hasLegacyRestrictions = $false
        # IDictionary MUST be checked first. Every object - Hashtable included - has a non-null
        # .PSObject and .PSObject.Properties, but for a Hashtable that collection exposes the
        # dictionary's own .NET members (Keys, Values, Count...), not its key-value entries, so
        # .PSObject.Properties['isAttestationEnforced'] silently returns nothing even when the key
        # is genuinely present. Checking PSObject.Properties first (as an earlier version of this
        # function did) made the IDictionary branch below unreachable dead code - live Graph
        # responses shaped as a Hashtable would always fall through to $unknown regardless of what
        # they actually contained, exactly the false-negative-as-Unknown failure mode this whole
        # function exists to prevent, just reintroduced in the fallback path.
        if ($RawConfig -is [System.Collections.IDictionary]) {
            # Live Graph returns a Hashtable, sample data a PSCustomObject; handle both.
            $hasLegacyAttestation = $RawConfig.Contains('isAttestationEnforced')
            $hasLegacyRestrictions = $RawConfig.Contains('keyRestrictions')
        }
        elseif ($RawConfig.PSObject -and $RawConfig.PSObject.Properties) {
            $hasLegacyAttestation = [bool]($RawConfig.PSObject.Properties['isAttestationEnforced'])
            $hasLegacyRestrictions = [bool]($RawConfig.PSObject.Properties['keyRestrictions'])
        }

        if (-not $hasLegacyAttestation -and -not $hasLegacyRestrictions) {
            Write-Verbose 'ConvertTo-SAWPasskeyPolicyEffective: no profiles and no legacy properties - reporting Unknown'
            return $unknown
        }

        Write-Verbose 'ConvertTo-SAWPasskeyPolicyEffective: resolved from deprecated top-level properties'

        return @{
            AttestationEnforced     = if ($hasLegacyAttestation) { [bool]$RawConfig.isAttestationEnforced } else { $null }
            KeyRestrictionsEnforced = if ($hasLegacyRestrictions) { [bool]$RawConfig.keyRestrictions.isEnforced } else { $null }
            IsKnown                 = $true
            Source                  = 'LegacyProperties'
            ProfileCount            = 0
            MixedEnforcement        = $false
            KeyRestrictions         = $RawConfig.keyRestrictions
            SyncedPasskeysAllowed   = $null
            PasskeyTypeRestriction  = $null
            Summary                 = "Resolved from the tenant-wide isAttestationEnforced/keyRestrictions properties. Microsoft has deprecated both, with removal scheduled for October 2027 in favour of passkey profiles; this tenant hasn't migrated yet, so these are still the live settings. passkeyTypes has no legacy equivalent - a per-type restriction is only possible via passkey profiles, so PasskeyTypeRestriction is always null on this path."
        }
    }
}

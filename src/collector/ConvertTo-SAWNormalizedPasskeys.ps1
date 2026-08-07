function ConvertTo-SAWNormalizedPasskeys {
    <#
    .SYNOPSIS
        Normalizes the raw FIDO2 configuration into Secure At Work passkey hygiene checks.
    .DESCRIPTION
        Derives three facts from the raw FIDO2 configuration object: whether attestation is
        enforced, whether key restrictions (an AAGUID allow/block-list) are enforced, and
        whether synced (cloud-backed) passkeys are currently allowed through. All three only
        make sense once FIDO2 is actually enabled tenant-wide (see Get-SAWAuthenticationMethods
        / AUTH004) - if it is disabled, this normalizer emits no facts at all, so the rules
        engine correctly marks PASS001-003 as Grey ("not applicable"), per spec section 10,
        rather than a misleading Red/Green.

        Synced passkeys (Google Password Manager, iCloud Keychain, 1Password, Bitwarden, ...)
        are still phishing-resistant WebAuthn credentials - the security concern isn't
        "weaker crypto", it's custody: the private key material leaves the original device and
        is held by a third-party cloud provider, which some customers (e.g. regulated
        industries) don't want. Whether that's acceptable is a customer policy choice, not a
        universal right answer, so unlike PASS001/002 the toolkit ships a permissive default
        (Expected Enabled, Low severity - see PASS003.json) and expects a customer baseline to
        override it if stricter, device-bound-only registration is required (see
        config/baselines/cloud-native-passwordless.json for an example).

        Detection is AAGUID-based against a small, maintained-by-hand reference list of known
        synced-passkey providers (see $syncedPasskeyProviderAaguids below), sourced from the
        community passkeydeveloper/passkey-authenticator-aaguids project
        (https://github.com/passkeydeveloper/passkey-authenticator-aaguids/blob/main/aaguid.json,
        confirmed to be its full, current contents as of this writing - every entry from that
        list is included here except the one deliberate exclusion below) - it is a strong
        signal, not exhaustive proof: new providers appear over time, and this list needs
        periodic upkeep. Includes both dedicated password manager apps (Google Password Manager,
        iCloud Keychain, 1Password, Bitwarden, Dashlane, NordPass, Keeper, Sesame, Enpass,
        Samsung Pass, AliasVault, IDmelon) and browser-level platform credential stores (Chrome
        on Mac, Chromium Browser, Edge on Mac) - the latter aren't password manager apps, but
        the same custody concern applies: a passkey saved there syncs via the user's Google/
        Microsoft account rather than staying device-bound. Windows Hello AAGUIDs are
        deliberately NOT included, the one exclusion from that source list - whether a given
        Windows Hello AAGUID represents a per-device TPM-bound credential or a newer
        cloud-synced Windows passkey varies, and treating it as "synced" risks false-flagging
        a legitimately device-bound credential.
    .PARAMETER RawConfig
        The object returned by Get-SAWPasskeys.
    .OUTPUTS
        Hashtable[]
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$RawConfig
    )

    begin {
        function ConvertTo-SAWStateLabel {
            param([bool]$Value)
            if ($Value) { return 'Enabled' }
            return 'Disabled'
        }

        # Known cloud-synced passkey provider AAGUIDs (community-maintained reference,
        # https://github.com/passkeydeveloper/passkey-authenticator-aaguids). Not exhaustive -
        # see the function-level notes above on Windows Hello's deliberate exclusion.
        $syncedPasskeyProviderAaguids = @{
            'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4' = 'Google Password Manager'
            'dd4ec289-e01d-41c9-bb89-70fa845d4bf2' = 'iCloud Keychain (Managed)'
            'fbfc3007-154e-4ecc-8c0b-6e020557d7bd' = 'Apple Passwords (iCloud Keychain)'
            '531126d6-e717-415c-9320-3d9aa6981239' = 'Dashlane'
            'bada5566-a7aa-401f-bd96-45619a55120d' = '1Password'
            'b84e4048-15dc-4dd0-8640-f4f60813c8af' = 'NordPass'
            '0ea242b4-43c4-4a1b-8b17-dd6d0b6baec6' = 'Keeper'
            '891494da-2c90-4d31-a9cd-4eab0aed1309' = 'Sesame'
            'f3809540-7f14-49c1-a8b3-8f813b225541' = 'Enpass'
            'd548826e-79b4-db40-a3d8-11116f7e8349' = 'Bitwarden'
            '53414d53-554e-4700-0000-000000000000' = 'Samsung Pass'
            'a11a5faa-9f32-4b8c-8c5d-2f7d13e8c942' = 'AliasVault'
            '39a5647e-1853-446c-a1f6-a79bae9f5bc7' = 'IDmelon'
            # Browser-level platform credential stores - not password manager apps, but the same
            # custody concern applies: a passkey saved here syncs via the user's Google/Microsoft
            # account rather than staying device-bound, so they belong in this list too.
            'adce0002-35bc-c60a-648b-0b25f1f05503' = 'Chrome on Mac'
            'b5397666-4885-aa6b-cebf-e52262a439a2' = 'Chromium Browser'
            '771b48fd-d3d4-4f74-9232-fc157ab0507a' = 'Edge on Mac'
        }
    }

    process {
        if ($RawConfig.state -ne 'enabled') {
            Write-Verbose "ConvertTo-SAWNormalizedPasskeys: FIDO2 is not enabled tenant-wide (state: $($RawConfig.state)); attestation/key-restriction/synced-passkey checks are not applicable"
            return
        }

        $attestationEnforced = [bool]$RawConfig.isAttestationEnforced
        $keyRestrictionsEnforced = [bool]$RawConfig.keyRestrictions.isEnforced

        @{
            Category = 'Passkeys'
            Setting  = 'FIDO2 Attestation Enforced'
            State    = ConvertTo-SAWStateLabel $attestationEnforced
        }
        @{
            Category = 'Passkeys'
            Setting  = 'FIDO2 Key Restrictions Enforced'
            State    = ConvertTo-SAWStateLabel $keyRestrictionsEnforced
        }

        # --- Synced passkeys currently allowed? ---
        # Default assumption: allowed, unless key restrictions are configured in a way that
        # provably excludes every known synced-passkey provider.
        $syncedPasskeysAllowed = $true
        $configuredAaGuids = @($RawConfig.keyRestrictions.aaGuids) | Where-Object { $_ }

        if ($keyRestrictionsEnforced -and $RawConfig.keyRestrictions.enforcementType -eq 'allow') {
            # Allow-list: only the listed AAGUIDs may register. Synced passkeys are allowed
            # only if at least one known synced provider appears in that allow-list.
            $syncedPasskeysAllowed = $false
            foreach ($aaguid in $configuredAaGuids) {
                if ($syncedPasskeyProviderAaguids.ContainsKey($aaguid)) {
                    $syncedPasskeysAllowed = $true
                    break
                }
            }
        }
        elseif ($keyRestrictionsEnforced -and $RawConfig.keyRestrictions.enforcementType -eq 'block') {
            # Block-list: everything EXCEPT the listed AAGUIDs may register. Synced passkeys
            # are allowed unless every known synced provider is explicitly blocked.
            $syncedPasskeysAllowed = $false
            foreach ($knownAaguid in $syncedPasskeyProviderAaguids.Keys) {
                if ($configuredAaGuids -notcontains $knownAaguid) {
                    $syncedPasskeysAllowed = $true
                    break
                }
            }
        }

        Write-Verbose "ConvertTo-SAWNormalizedPasskeys: synced passkeys currently allowed = $syncedPasskeysAllowed (keyRestrictions enforced=$keyRestrictionsEnforced, enforcementType=$($RawConfig.keyRestrictions.enforcementType))"

        @{
            Category = 'Passkeys'
            Setting  = 'Synced Passkeys Currently Allowed'
            State    = ConvertTo-SAWStateLabel $syncedPasskeysAllowed
        }
    }
}

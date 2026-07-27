function ConvertTo-SAWNormalizedPasskeys {
    <#
    .SYNOPSIS
        Normalizes the raw FIDO2 configuration into Secure At Work passkey hygiene checks.
    .DESCRIPTION
        Derives two facts from the raw FIDO2 configuration object: whether attestation is
        enforced, and whether key restrictions (an AAGUID allow-list) are enforced. Both
        checks only make sense once FIDO2 is actually enabled tenant-wide (see
        Get-SAWAuthenticationMethods / AUTH004) - if it is disabled, this normalizer emits no
        facts at all, so the rules engine correctly marks PASS001/PASS002 as Grey
        ("not applicable"), per spec section 10, rather than a misleading Red/Green.
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
    }

    process {
        if ($RawConfig.state -ne 'enabled') {
            Write-Verbose "ConvertTo-SAWNormalizedPasskeys: FIDO2 is not enabled tenant-wide (state: $($RawConfig.state)); attestation/key-restriction checks are not applicable"
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
    }
}

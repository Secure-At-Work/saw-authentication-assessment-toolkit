function ConvertTo-SAWNormalizedTemporaryAccessPass {
    <#
    .SYNOPSIS
        Normalizes the raw Temporary Access Pass configuration into Secure At Work checks.
    .DESCRIPTION
        Derives two facts from the raw TAP configuration object: whether one-time-use is
        enforced (isUsableOnce), and whether the maximum allowed lifetime is capped at 8 hours
        (480 minutes) or less, to limit the exposure window if a pass is intercepted or leaked.
    .PARAMETER RawConfig
        The object returned by Get-SAWTemporaryAccessPass.
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
        $isUsableOnce = [bool]$RawConfig.isUsableOnce

        $withinEightHours = $false
        $maxLifetime = $RawConfig.maximumLifetimeInMinutes
        if ($null -ne $maxLifetime) {
            $withinEightHours = $maxLifetime -le 480
        }

        Write-Verbose "ConvertTo-SAWNormalizedTemporaryAccessPass: isUsableOnce=$isUsableOnce, maximumLifetimeInMinutes=$maxLifetime"

        @{
            Category = 'Temporary Access Pass'
            Setting  = 'One-Time Use Enforced'
            State    = ConvertTo-SAWStateLabel $isUsableOnce
        }
        @{
            Category = 'Temporary Access Pass'
            Setting  = 'Maximum Lifetime Within 8 Hours'
            State    = ConvertTo-SAWStateLabel $withinEightHours
        }
    }
}

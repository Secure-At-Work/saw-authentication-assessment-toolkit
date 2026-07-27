function ConvertTo-SAWNormalizedAuthenticationStrengths {
    <#
    .SYNOPSIS
        Normalizes raw authentication strength policies into Secure At Work capability checks.
    .DESCRIPTION
        Scans every built-in and custom authentication strength policy and checks whether at
        least one is restricted to phishing-resistant methods only (FIDO2, Windows Hello for
        Business, certificate-based MFA) - i.e. its allowedCombinations contains nothing weaker.
        A policy that also allows e.g. password+SMS does not count, even if it also allows
        FIDO2, since it would not force phishing-resistant auth when actually assigned.
    .PARAMETER RawResponse
        The object returned by Get-SAWAuthenticationStrengths (has a .value array of policies).
    .OUTPUTS
        Hashtable[]
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$RawResponse
    )

    begin {
        $phishingResistantMethods = @('fido2', 'windowsHelloForBusiness', 'x509CertificateMultiFactor')

        function ConvertTo-SAWStateLabel {
            param([bool]$Value)
            if ($Value) { return 'Enabled' }
            return 'Disabled'
        }
    }

    process {
        $policies = $RawResponse.value
        if (-not $policies) { $policies = @() }

        $phishingResistantAvailable = $false

        foreach ($policy in $policies) {
            $combinations = $policy.allowedCombinations
            if (-not $combinations -or $combinations.Count -eq 0) {
                continue
            }

            $onlyPhishingResistant = $true
            foreach ($combination in $combinations) {
                if ($phishingResistantMethods -notcontains $combination) {
                    $onlyPhishingResistant = $false
                    break
                }
            }

            if ($onlyPhishingResistant) {
                Write-Verbose "ConvertTo-SAWNormalizedAuthenticationStrengths: '$($policy.displayName)' is phishing-resistant only"
                $phishingResistantAvailable = $true
                break
            }
        }

        @{
            Category = 'Authentication Strengths'
            Setting  = 'Phishing-Resistant MFA Strength Available'
            State    = ConvertTo-SAWStateLabel $phishingResistantAvailable
        }
    }
}

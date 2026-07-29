function ConvertTo-SAWTenantProfile {
    <#
    .SYNOPSIS
        Interprets the raw /organization response into a hybrid-vs-cloud-native tenant
        profile, used to auto-select a customer SOLL baseline.
    .DESCRIPTION
        organization.onPremisesSyncEnabled is a nullable boolean with three real states:
          - true  - actively synced from an on-premises directory right now (Hybrid).
          - false - was synced at some point but sync is no longer active (FormerlyHybrid).
                    Treated the same as Hybrid for baseline purposes: AD-era artifacts
                    (passwords, legacy MFA methods) may well still be in play during/after
                    a decommission, so the more permissive hybrid baseline is the safer
                    default until an assessor confirms otherwise.
          - null  - never synced from on-premises AD (CloudNative).
        This is not a pass/fail rules-engine fact (like the CA policy inventory or the user
        registration roster, it's a separate data product) - it feeds
        Invoke-SAWAssessment's baseline auto-detection, not Invoke-SAWRulesEngine.
    .PARAMETER RawResponse
        The object returned by Get-SAWTenantProfile (has a .value array; only the first
        entry is used - a tenant has exactly one organization object).
    .OUTPUTS
        Hashtable with DisplayName, OnPremisesSyncEnabled, HybridState, RecommendedBaseline,
        OnPremisesLastSyncDateTime.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$RawResponse
    )

    process {
        $org = $null
        if ($RawResponse.value) {
            $org = @($RawResponse.value) | Select-Object -First 1
        }

        $syncEnabled = $null
        if ($org) { $syncEnabled = $org.onPremisesSyncEnabled }

        if ($syncEnabled -eq $true) {
            $hybridState = 'Hybrid'
            $recommendedBaseline = 'hybrid-ad-passwords-required'
        }
        elseif ($syncEnabled -eq $false) {
            $hybridState = 'FormerlyHybrid'
            $recommendedBaseline = 'hybrid-ad-passwords-required'
        }
        else {
            $hybridState = 'CloudNative'
            $recommendedBaseline = 'cloud-native-passwordless'
        }

        Write-Verbose "ConvertTo-SAWTenantProfile: onPremisesSyncEnabled=$syncEnabled -> HybridState=$hybridState, RecommendedBaseline=$recommendedBaseline"

        @{
            DisplayName                = if ($org) { $org.displayName } else { $null }
            OnPremisesSyncEnabled       = $syncEnabled
            OnPremisesLastSyncDateTime  = if ($org) { $org.onPremisesLastSyncDateTime } else { $null }
            HybridState                 = $hybridState
            RecommendedBaseline         = $recommendedBaseline
        }
    }
}

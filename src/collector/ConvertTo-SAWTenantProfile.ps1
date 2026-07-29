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
        Invoke-SAWAssessment's baseline auto-detection, not Invoke-SAWRulesEngine. Slug (derived
        from TenantId, falling back to DisplayName) drives multi-tenant output namespacing and
        history snapshot storage (see Invoke-SAWAssessment.ps1 and Invoke-SAWDriftReport.ps1) -
        it exists so every run for the same tenant lands in the same folder without assuming
        TenantId is always present (e.g. hand-edited sample data).
    .PARAMETER RawResponse
        The object returned by Get-SAWTenantProfile (has a .value array; only the first
        entry is used - a tenant has exactly one organization object).
    .OUTPUTS
        Hashtable with TenantId, DisplayName, Slug, OnPremisesSyncEnabled, HybridState,
        RecommendedBaseline, OnPremisesLastSyncDateTime.
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

        $tenantId = if ($org) { $org.id } else { $null }
        $displayName = if ($org) { $org.displayName } else { $null }

        # Filesystem-safe identifier used to namespace report/dashboard/history output per
        # tenant. Prefer TenantId (a GUID - already filesystem-safe, stable even if the tenant
        # is renamed); fall back to a sanitized DisplayName, then a fixed placeholder so runs
        # against incomplete sample data still land somewhere predictable rather than erroring.
        $slugSource = if ($tenantId) { $tenantId } elseif ($displayName) { $displayName } else { 'unknown-tenant' }
        $slug = ($slugSource -replace '[^a-zA-Z0-9\-]+', '-').Trim('-').ToLowerInvariant()
        if (-not $slug) { $slug = 'unknown-tenant' }

        @{
            TenantId                    = $tenantId
            DisplayName                = $displayName
            Slug                        = $slug
            OnPremisesSyncEnabled       = $syncEnabled
            OnPremisesLastSyncDateTime  = if ($org) { $org.onPremisesLastSyncDateTime } else { $null }
            HybridState                 = $hybridState
            RecommendedBaseline         = $recommendedBaseline
        }
    }
}

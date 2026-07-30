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

        DomainServicesDetected is a proxy signal, not an authoritative check: it's true when
        Get-SAWTenantProfile finds a group named "AAD DC Administrators" in the tenant, which
        Microsoft's setup wizard automatically creates when Microsoft Entra Domain Services is
        enabled (the actual service lives in Azure Resource Manager, out of reach for a
        Graph-only, delegated-scopes toolkit like this one - see Get-SAWTenantProfile.ps1's
        .DESCRIPTION). The group's presence means Domain Services was provisioned at some
        point; it does not confirm the managed domain is still active today, and the group
        could in principle have been renamed or removed. Treat this as "worth following up on
        with the customer", not a hard finding - it never feeds Invoke-SAWRulesEngine.
    .PARAMETER RawResponse
        The object returned by Get-SAWTenantProfile (has a .value array; only the first
        entry is used - a tenant has exactly one organization object; and an
        .aadDcAdministratorsGroups array merged on from the second /groups call).
    .OUTPUTS
        Hashtable with TenantId, DisplayName, Slug, OnPremisesSyncEnabled, HybridState,
        RecommendedBaseline, OnPremisesLastSyncDateTime, DomainServicesDetected.
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

        $domainServicesDetected = (@($RawResponse.aadDcAdministratorsGroups) | Where-Object { $_ }).Count -gt 0
        Write-Verbose "ConvertTo-SAWTenantProfile: 'AAD DC Administrators' group found=$domainServicesDetected (proxy signal for Entra Domain Services)"

        @{
            TenantId                    = $tenantId
            DisplayName                = $displayName
            Slug                        = $slug
            OnPremisesSyncEnabled       = $syncEnabled
            OnPremisesLastSyncDateTime  = if ($org) { $org.onPremisesLastSyncDateTime } else { $null }
            HybridState                 = $hybridState
            RecommendedBaseline         = $recommendedBaseline
            DomainServicesDetected      = $domainServicesDetected
        }
    }
}

function Get-SAWTenantProfile {
    <#
    .SYNOPSIS
        Collects tenant-level metadata via Microsoft Graph, used to auto-detect whether the
        tenant is hybrid (synced with on-premises Active Directory) or cloud-native.
    .DESCRIPTION
        Read-only collector. Issues a GET against /organization (a singleton-ish collection -
        Graph returns it as a list, but a tenant only ever has one organization object, so this
        returns just that first entry). Requires Directory.Read.All (already in the toolkit's
        default scope set - no additional permission needed).

        This is a different kind of data product from the Category/Setting/State facts the
        rules engine evaluates: it's not a pass/fail check, it's context used to pick which
        customer SOLL baseline applies (see ConvertTo-SAWTenantProfile.ps1 and
        Invoke-SAWAssessment.ps1's baseline auto-detection).

        Also issues a second GET against /groups, filtered to displayName 'AAD DC
        Administrators' - a group Microsoft's setup wizard automatically creates when Microsoft
        Entra Domain Services is enabled for a tenant (see
        https://learn.microsoft.com/entra/identity/domain-services/tutorial-create-instance).
        Entra Domain Services itself is an Azure Resource Manager resource
        (Microsoft.AAD/domainServices under management.azure.com) - a different API, token
        audience, and permission model (Azure RBAC on a subscription) than everything else this
        toolkit does, so it's out of reach without a second auth flow. The group's presence in
        the tenant's directory is a proxy signal reachable via ordinary Graph data instead: it
        means Domain Services was provisioned at some point, not that it's still active/healthy
        today, and the group could in principle have been renamed or removed. Treat it as a
        strong hint worth following up on, not an authoritative yes/no.
    .PARAMETER UseSampleData
        Read from a local sample JSON file instead of calling Microsoft Graph. Used for
        offline development and testing.
    .PARAMETER SampleDataPath
        Path to the sample raw /organization response used when -UseSampleData is set.
    .PARAMETER DomainServicesGroupSampleDataPath
        Path to the sample raw /groups (AAD DC Administrators) response used when
        -UseSampleData is set.
    .OUTPUTS
        PSCustomObject or Hashtable with a .value array (Graph's shape) plus an
        .aadDcAdministratorsGroups array merged on from the second call; this collector only
        ever needs the first .value entry for the rest of its fields.
    #>
    [CmdletBinding()]
    param(
        [switch]$UseSampleData,

        [string]$SampleDataPath = (Join-Path $PSScriptRoot '..\..\sampledata\raw\organization.raw.json'),

        [string]$DomainServicesGroupSampleDataPath = (Join-Path $PSScriptRoot '..\..\sampledata\raw\aadDcAdministratorsGroup.raw.json')
    )

    if ($UseSampleData) {
        Write-Verbose "Get-SAWTenantProfile: reading sample data from $SampleDataPath"
        if (-not (Test-Path -Path $SampleDataPath)) {
            throw "Sample data file not found: $SampleDataPath"
        }
        $org = Get-Content -Path $SampleDataPath -Raw | ConvertFrom-Json

        Write-Verbose "Get-SAWTenantProfile: reading Domain Services group sample data from $DomainServicesGroupSampleDataPath"
        if (-not (Test-Path -Path $DomainServicesGroupSampleDataPath)) {
            throw "Sample data file not found: $DomainServicesGroupSampleDataPath"
        }
        $groups = Get-Content -Path $DomainServicesGroupSampleDataPath -Raw | ConvertFrom-Json
        # Add-Member (not dot-assignment) because $org here is a PSCustomObject from
        # ConvertFrom-Json - dot-assigning a property that doesn't already exist throws on a
        # PSCustomObject ("cannot be found on this object"), unlike a hashtable, where
        # dot-assignment adds a new key cleanly. Add-Member -Force works safely for both
        # shapes, which matters below where $org is a live Hashtable from Invoke-MgGraphRequest.
        $org | Add-Member -NotePropertyName 'aadDcAdministratorsGroups' -NotePropertyValue @($groups.value) -Force

        return $org
    }

    if (-not (Get-Command -Name Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
        throw 'Invoke-MgGraphRequest is not available. Install/import Microsoft.Graph.Authentication first.'
    }
    if (-not (Get-MgContext)) {
        throw 'Not connected to Microsoft Graph. Run Connect-MgGraph with read-only scopes first (e.g. Directory.Read.All).'
    }

    Write-Verbose 'Get-SAWTenantProfile: GET https://graph.microsoft.com/v1.0/organization'
    $org = Invoke-SAWGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization'

    Write-Verbose "Get-SAWTenantProfile: GET https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq 'AAD DC Administrators'"
    $groups = Invoke-SAWGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq 'AAD DC Administrators'"
    $org | Add-Member -NotePropertyName 'aadDcAdministratorsGroups' -NotePropertyValue @($groups.value) -Force

    return $org
}

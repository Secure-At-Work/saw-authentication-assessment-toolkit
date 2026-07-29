function Get-SAWTenantProfile {
    <#
    .SYNOPSIS
        Collects tenant-level metadata via Microsoft Graph, used to auto-detect whether the
        tenant is hybrid (synced with on-premises Active Directory) or cloud-native.
    .DESCRIPTION
        Read-only collector. Issues a single GET against /organization (a singleton-ish
        collection - Graph returns it as a list, but a tenant only ever has one organization
        object, so this returns just that first entry). Requires Directory.Read.All
        (already in the toolkit's default scope set - no additional permission needed).

        This is a different kind of data product from the Category/Setting/State facts the
        rules engine evaluates: it's not a pass/fail check, it's context used to pick which
        customer SOLL baseline applies (see ConvertTo-SAWTenantProfile.ps1 and
        Invoke-SAWAssessment.ps1's baseline auto-detection).
    .PARAMETER UseSampleData
        Read from a local sample JSON file instead of calling Microsoft Graph. Used for
        offline development and testing.
    .PARAMETER SampleDataPath
        Path to the sample raw response used when -UseSampleData is set.
    .OUTPUTS
        PSCustomObject or Hashtable with a .value array (Graph's shape); this collector
        only ever needs the first entry.
    #>
    [CmdletBinding()]
    param(
        [switch]$UseSampleData,

        [string]$SampleDataPath = (Join-Path $PSScriptRoot '..\..\sampledata\raw\organization.raw.json')
    )

    if ($UseSampleData) {
        Write-Verbose "Get-SAWTenantProfile: reading sample data from $SampleDataPath"
        if (-not (Test-Path -Path $SampleDataPath)) {
            throw "Sample data file not found: $SampleDataPath"
        }
        return Get-Content -Path $SampleDataPath -Raw | ConvertFrom-Json
    }

    if (-not (Get-Command -Name Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
        throw 'Invoke-MgGraphRequest is not available. Install/import Microsoft.Graph.Authentication first.'
    }
    if (-not (Get-MgContext)) {
        throw 'Not connected to Microsoft Graph. Run Connect-MgGraph with read-only scopes first (e.g. Directory.Read.All).'
    }

    Write-Verbose 'Get-SAWTenantProfile: GET https://graph.microsoft.com/v1.0/organization'
    return Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization'
}

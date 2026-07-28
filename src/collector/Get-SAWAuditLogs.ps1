function Get-SAWAuditLogs {
    <#
    .SYNOPSIS
        Collects directory audit logs via Microsoft Graph relevant to authentication changes.
    .DESCRIPTION
        Read-only collector. Issues GET requests against /auditLogs/directoryAudits, following
        @odata.nextLink to collect every page, and returns a raw object with a .value array -
        the same shape Microsoft Graph itself returns. Requires AuditLog.Read.All (read-only).
        As with Get-SAWSignInLogs, callers running against a live tenant should scope this with
        a $filter (e.g. activityDateTime ge ...) to bound the time range; this vertical slice
        keeps the query unfiltered for simplicity. Must never create, modify, or delete any
        tenant object.
    .PARAMETER UseSampleData
        Read from a local sample JSON file instead of calling Microsoft Graph. Used for
        offline development and testing.
    .PARAMETER SampleDataPath
        Path to the sample raw response used when -UseSampleData is set.
    .OUTPUTS
        PSCustomObject or Hashtable with a .value array of directory audit entries.
    #>
    [CmdletBinding()]
    param(
        [switch]$UseSampleData,

        [string]$SampleDataPath = (Join-Path $PSScriptRoot '..\..\sampledata\raw\directoryAudits.raw.json')
    )

    if ($UseSampleData) {
        Write-Verbose "Get-SAWAuditLogs: reading sample data from $SampleDataPath"
        if (-not (Test-Path -Path $SampleDataPath)) {
            throw "Sample data file not found: $SampleDataPath"
        }
        return Get-Content -Path $SampleDataPath -Raw | ConvertFrom-Json
    }

    if (-not (Get-Command -Name Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
        throw 'Invoke-MgGraphRequest is not available. Install/import Microsoft.Graph.Authentication first.'
    }
    if (-not (Get-MgContext)) {
        throw 'Not connected to Microsoft Graph. Run Connect-MgGraph with read-only scopes first (e.g. AuditLog.Read.All).'
    }

    $allAudits = @()
    $uri = 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits'

    while ($uri) {
        Write-Verbose "Get-SAWAuditLogs: GET $uri"
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri
        $allAudits += $response.value
        $uri = $response.'@odata.nextLink'
    }

    return @{ value = $allAudits }
}

function Get-SAWSignInLogs {
    <#
    .SYNOPSIS
        Collects interactive and non-interactive sign-in logs via Microsoft Graph.
    .DESCRIPTION
        Read-only collector. Issues GET requests against /auditLogs/signIns, following
        @odata.nextLink to collect every page, and returns a raw object with a .value array -
        the same shape Microsoft Graph itself returns. Requires AuditLog.Read.All and
        Directory.Read.All (read-only). Sign-in logs are retained for a limited window
        (Entra ID Free/P1/P2 tiers differ) - callers running against a live tenant should
        scope this with a $filter (e.g. createdDateTime ge ...) and/or $top to bound both
        the time range and result volume; this vertical slice keeps the query unfiltered for
        simplicity. Must never create, modify, or delete any tenant object.
    .PARAMETER UseSampleData
        Read from a local sample JSON file instead of calling Microsoft Graph. Used for
        offline development and testing.
    .PARAMETER SampleDataPath
        Path to the sample raw response used when -UseSampleData is set.
    .OUTPUTS
        PSCustomObject or Hashtable with a .value array of sign-in log entries.
    #>
    [CmdletBinding()]
    param(
        [switch]$UseSampleData,

        [string]$SampleDataPath = (Join-Path $PSScriptRoot '..\..\sampledata\raw\signIns.raw.json')
    )

    if ($UseSampleData) {
        Write-Verbose "Get-SAWSignInLogs: reading sample data from $SampleDataPath"
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

    $allSignIns = @()
    $uri = 'https://graph.microsoft.com/v1.0/auditLogs/signIns'

    while ($uri) {
        Write-Verbose "Get-SAWSignInLogs: GET $uri"
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri
        $allSignIns += $response.value
        $uri = $response.'@odata.nextLink'
    }

    return @{ value = $allSignIns }
}

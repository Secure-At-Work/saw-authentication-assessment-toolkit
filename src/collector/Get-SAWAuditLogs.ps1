function Get-SAWAuditLogs {
    <#
    .SYNOPSIS
        Collects directory audit logs via Microsoft Graph relevant to authentication changes.
    .DESCRIPTION
        Read-only collector. Issues GET requests against /auditLogs/directoryAudits, following
        @odata.nextLink to collect every page, and returns a raw object with a .value array -
        the same shape Microsoft Graph itself returns. Requires AuditLog.Read.All (read-only).

        Scoped with a $filter=activityDateTime ge <DaysBack days ago>, same as
        Get-SAWSignInLogs and for the same reason: unfiltered, this endpoint paginated
        against a live tenant until Invoke-MgGraphRequest's HttpClient.Timeout (300s)
        canceled the request. -MaxPages is a second safety net in case the date-bounded
        query is still very large.
    .PARAMETER UseSampleData
        Read from a local sample JSON file instead of calling Microsoft Graph. Used for
        offline development and testing.
    .PARAMETER SampleDataPath
        Path to the sample raw response used when -UseSampleData is set.
    .PARAMETER DaysBack
        How many days of audit history to request. Defaults to 7 - enough for the
        break-glass-credential-change and app-initiated-CA-change checks this collector's
        normalizer runs, without risking an unbounded pull on a busy tenant.
    .PARAMETER MaxPages
        Safety cap on the number of pages to follow via @odata.nextLink. Defaults to 50.
        If reached, a verbose warning is emitted and whatever was collected so far is
        returned.
    .OUTPUTS
        PSCustomObject or Hashtable with a .value array of directory audit entries.
    #>
    [CmdletBinding()]
    param(
        [switch]$UseSampleData,

        [string]$SampleDataPath = (Join-Path $PSScriptRoot '..\..\sampledata\raw\directoryAudits.raw.json'),

        [int]$DaysBack = 7,

        [int]$MaxPages = 50
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

    $startDateTime = Get-Date -Date ((Get-Date).ToUniversalTime().AddDays(-$DaysBack)) -Format 'yyyy-MM-ddTHH:mm:ssZ'
    $filter = "activityDateTime ge $startDateTime" -replace ' ', '%20'

    $allAudits = @()
    $uri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=$filter"
    $pageCount = 0

    while ($uri) {
        $pageCount++
        if ($pageCount -gt $MaxPages) {
            Write-Verbose "Get-SAWAuditLogs: reached -MaxPages ($MaxPages), stopping early with $($allAudits.Count) entry/entries collected so far"
            break
        }

        Write-Verbose "Get-SAWAuditLogs: GET $uri (page $pageCount)"
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri
        $allAudits += $response.value
        $uri = $response.'@odata.nextLink'
    }

    return @{ value = $allAudits }
}

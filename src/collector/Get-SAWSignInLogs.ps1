function Get-SAWSignInLogs {
    <#
    .SYNOPSIS
        Collects interactive and non-interactive sign-in logs via Microsoft Graph.
    .DESCRIPTION
        Read-only collector. Issues GET requests against /auditLogs/signIns, following
        @odata.nextLink to collect every page, and returns a raw object with a .value array -
        the same shape Microsoft Graph itself returns. Requires AuditLog.Read.All and
        Directory.Read.All (read-only).

        Scoped with a $filter=createdDateTime ge <DaysBack days ago> - on a real tenant this
        endpoint is unbounded without one and will happily paginate for as long as sign-ins
        exist in the retention window, which is exactly what caused
        "The request was canceled due to the configured HttpClient.Timeout of 300 seconds
        elapsing." against a live tenant. -MaxPages is a second safety net in case even the
        date-bounded query is still very large (e.g. a busy tenant): collection stops early
        and returns whatever was gathered rather than hanging indefinitely.
    .PARAMETER UseSampleData
        Read from a local sample JSON file instead of calling Microsoft Graph. Used for
        offline development and testing.
    .PARAMETER SampleDataPath
        Path to the sample raw response used when -UseSampleData is set.
    .PARAMETER DaysBack
        How many days of sign-in history to request. Defaults to 7 - enough for the
        legacy-auth and device-code-flow checks this collector's normalizer runs, without
        risking an unbounded pull on a busy tenant.
    .PARAMETER MaxPages
        Safety cap on the number of pages to follow via @odata.nextLink. Defaults to 50
        (at Graph's default page size, tens of thousands of sign-ins). If reached, a verbose
        warning is emitted and whatever was collected so far is returned.
    .OUTPUTS
        PSCustomObject or Hashtable with a .value array of sign-in log entries.
    #>
    [CmdletBinding()]
    param(
        [switch]$UseSampleData,

        [string]$SampleDataPath = (Join-Path $PSScriptRoot '..\..\sampledata\raw\signIns.raw.json'),

        [int]$DaysBack = 7,

        [int]$MaxPages = 50
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

    $startDateTime = Get-Date -Date ((Get-Date).ToUniversalTime().AddDays(-$DaysBack)) -Format 'yyyy-MM-ddTHH:mm:ssZ'
    $filter = "createdDateTime ge $startDateTime" -replace ' ', '%20'

    $allSignIns = @()
    $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$filter"
    $pageCount = 0

    while ($uri) {
        $pageCount++
        if ($pageCount -gt $MaxPages) {
            Write-Verbose "Get-SAWSignInLogs: reached -MaxPages ($MaxPages), stopping early with $($allSignIns.Count) sign-in(s) collected so far"
            break
        }

        Write-Verbose "Get-SAWSignInLogs: GET $uri (page $pageCount)"
        $response = Invoke-SAWGraphRequest -Method GET -Uri $uri
        $allSignIns += $response.value
        $uri = $response.'@odata.nextLink'
    }

    return @{ value = $allSignIns }
}

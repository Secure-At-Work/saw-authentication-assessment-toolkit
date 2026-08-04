function Get-SAWRegistration {
    <#
    .SYNOPSIS
        Collects per-user authentication method registration details via Microsoft Graph.
    .DESCRIPTION
        Read-only collector. Issues GET requests against
        /reports/authenticationMethods/userRegistrationDetails, following @odata.nextLink to
        collect every page, and returns a raw object with a .value array - the same shape
        Microsoft Graph itself returns. Requires Reports.Read.All or AuditLog.Read.All (read-only).
        Must never create, modify, or delete any tenant object.
    .PARAMETER UseSampleData
        Read from a local sample JSON file instead of calling Microsoft Graph. Used for
        offline development and testing.
    .PARAMETER SampleDataPath
        Path to the sample raw response used when -UseSampleData is set.
    .OUTPUTS
        PSCustomObject or Hashtable with a .value array of user registration details.
    #>
    [CmdletBinding()]
    param(
        [switch]$UseSampleData,

        [string]$SampleDataPath = (Join-Path $PSScriptRoot '..\..\sampledata\raw\userRegistrationDetails.raw.json')
    )

    if ($UseSampleData) {
        Write-Verbose "Get-SAWRegistration: reading sample data from $SampleDataPath"
        if (-not (Test-Path -Path $SampleDataPath)) {
            throw "Sample data file not found: $SampleDataPath"
        }
        return Get-Content -Path $SampleDataPath -Raw | ConvertFrom-Json
    }

    if (-not (Get-Command -Name Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
        throw 'Invoke-MgGraphRequest is not available. Install/import Microsoft.Graph.Authentication first.'
    }
    if (-not (Get-MgContext)) {
        throw 'Not connected to Microsoft Graph. Run Connect-MgGraph with read-only scopes first (e.g. Reports.Read.All).'
    }

    $allUsers = @()
    $uri = 'https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails'

    while ($uri) {
        Write-Verbose "Get-SAWRegistration: GET $uri"
        $response = Invoke-SAWGraphRequest -Method GET -Uri $uri
        $allUsers += $response.value
        $uri = $response.'@odata.nextLink'
    }

    return @{ value = $allUsers }
}

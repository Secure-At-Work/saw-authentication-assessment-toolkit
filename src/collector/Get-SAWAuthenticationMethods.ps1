function Get-SAWAuthenticationMethods {
    <#
    .SYNOPSIS
        Collects the tenant's authentication methods policy configuration via Microsoft Graph.
    .DESCRIPTION
        Read-only collector. Issues a single GET against
        /policies/authenticationMethodsPolicy and returns the raw Graph response
        as a PowerShell object. Must never create, modify, or delete any tenant object.
    .PARAMETER UseSampleData
        Read from a local sample JSON file instead of calling Microsoft Graph. Used for
        offline development and testing.
    .PARAMETER SampleDataPath
        Path to the sample raw response used when -UseSampleData is set.
    .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    param(
        [switch]$UseSampleData,

        [string]$SampleDataPath = (Join-Path $PSScriptRoot '..\..\sampledata\raw\authenticationMethodsPolicy.raw.json')
    )

    if ($UseSampleData) {
        Write-Verbose "Get-SAWAuthenticationMethods: reading sample data from $SampleDataPath"
        if (-not (Test-Path -Path $SampleDataPath)) {
            throw "Sample data file not found: $SampleDataPath"
        }
        return Get-Content -Path $SampleDataPath -Raw | ConvertFrom-Json
    }

    if (-not (Get-Command -Name Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
        throw 'Invoke-MgGraphRequest is not available. Install/import Microsoft.Graph.Authentication first.'
    }
    if (-not (Get-MgContext)) {
        throw 'Not connected to Microsoft Graph. Run Connect-MgGraph with read-only scopes first (e.g. Policy.Read.All).'
    }

    Write-Verbose 'Get-SAWAuthenticationMethods: GET https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy'
    return Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy'
}

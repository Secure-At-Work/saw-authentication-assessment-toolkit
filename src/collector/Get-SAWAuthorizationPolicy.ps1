function Get-SAWAuthorizationPolicy {
    <#
    .SYNOPSIS
        Collects the tenant's authorization policy via Microsoft Graph, for its
        allowedToUseSSPR field - the tenant-wide toggle controlling whether administrator
        accounts can use self-service password reset at all.
    .DESCRIPTION
        Read-only collector. Issues a GET against /policies/authorizationPolicy (v1.0) and
        returns the raw Graph response. Must never create, modify, or delete any tenant object.

        allowedToUseSSPR is a separate, easy-to-miss control from the regular SSPR/registration
        settings this toolkit already reads: by default, administrator accounts get SSPR through
        their own built-in "two-gate" policy (two methods required, no security questions),
        independent of the tenant's general SSPR configuration for end users - confirmed against
        https://learn.microsoft.com/entra/identity/authentication/concept-sspr-howitworks
        ("SSPR for Administrators isn't enabled on the tenant by default as SSPR is only for the
        end users"). allowedToUseSSPR is the switch that turns admin SSPR off entirely -
        confirmed against
        https://learn.microsoft.com/entra/identity/authentication/concept-sspr-policy
        ("Administrator reset policy differences"), which also documents a real, easy-to-hit
        trap this toolkit checks for (see ConvertTo-SAWNormalizedAuthorizationPolicy.ps1):
        disabling admin SSPR without also excluding admins from the user-facing SSPR policy
        leaves admins stuck with a broken registration prompt they can never complete.

        Uses Policy.Read.All, already part of this toolkit's default scope set - no new
        permission needed.
    .PARAMETER UseSampleData
        Read from a local sample JSON file instead of calling Microsoft Graph. Used for
        offline development and testing.
    .PARAMETER SampleDataPath
        Path to the sample raw response used when -UseSampleData is set.
    .OUTPUTS
        PSCustomObject (sample data) or Hashtable (live Graph).
    #>
    [CmdletBinding()]
    param(
        [switch]$UseSampleData,

        [string]$SampleDataPath = (Join-Path $PSScriptRoot '..\..\sampledata\raw\authorizationPolicy.raw.json')
    )

    if ($UseSampleData) {
        Write-Verbose "Get-SAWAuthorizationPolicy: reading sample data from $SampleDataPath"
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

    Write-Verbose 'Get-SAWAuthorizationPolicy: GET https://graph.microsoft.com/v1.0/policies/authorizationPolicy'
    return Invoke-SAWGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'
}

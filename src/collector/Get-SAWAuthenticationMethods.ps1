function Get-SAWAuthenticationMethods {
    <#
    .SYNOPSIS
        Collects the tenant's authentication methods policy configuration via Microsoft Graph.
    .DESCRIPTION
        Read-only collector. Issues a GET against /policies/authenticationMethodsPolicy (v1.0)
        and returns the raw Graph response as a PowerShell object. Must never create, modify,
        or delete any tenant object.

        Also issues a second GET against the beta endpoint for exactly one additional field:
        optOutSettings.passkeyDynamicMigration (see
        https://learn.microsoft.com/entra/identity/authentication/concept-sms-voice-retirement).
        This is deliberately the toolkit's only /beta call - everything else stays on v1.0 -
        kept narrow specifically because this field does not exist on v1.0 yet and there is no
        v1.0 substitute: Microsoft auto-enables passkeys for SMS/Voice users and flips the
        registration campaign to "Microsoft managed" starting 2026-09-01, and this opt-out is
        the only tenant-level control over the timing of that (opting out does not exempt the
        tenant from the 2027-02-01 SMS/Voice retirement, which has no opt-out at all). The
        result is merged onto the v1.0 response as .optOutSettings before returning, so callers
        (see ConvertTo-SAWNormalizedAuthenticationMethods.ps1) see one object regardless of
        which endpoint each field actually came from.

        Note: this endpoint rejects $select entirely ("Query option 'Select' is not allowed"
        per a live-tenant 400 response, confirmed 2026-07-30) - unlike most Graph resources, it
        does not support OData query options, so the beta call fetches the whole object.
    .PARAMETER UseSampleData
        Read from a local sample JSON file instead of calling Microsoft Graph. Used for
        offline development and testing. The sample fixture already includes an optOutSettings
        block, so no second file/call is needed in this mode.
    .PARAMETER SampleDataPath
        Path to the sample raw response used when -UseSampleData is set.
    .OUTPUTS
        PSCustomObject (sample data) or Hashtable (live Graph), both carrying .optOutSettings.
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
    $policy = Invoke-SAWGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy'

    Write-Verbose 'Get-SAWAuthenticationMethods: GET https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy'
    $betaPolicy = Invoke-SAWGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy'
    $policy.optOutSettings = $betaPolicy.optOutSettings

    return $policy
}

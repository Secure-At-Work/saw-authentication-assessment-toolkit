function Get-SAWAuthenticationMethods {
    <#
    .SYNOPSIS
        Collects the tenant's authentication methods policy configuration via Microsoft Graph.
    .DESCRIPTION
        Read-only collector. Issues a GET against /policies/authenticationMethodsPolicy (v1.0)
        and returns the raw Graph response as a PowerShell object. Must never create, modify,
        or delete any tenant object.

        Also issues a second GET against the beta endpoint, because three properties this toolkit
        reads are absent from Microsoft's own v1.0 resource reference for
        authenticationMethodsPolicy and appear only on the beta one:

        - optOutSettings.passkeyDynamicMigration - the tenant-level control over the timing of the
          2026-09-01 automatic passkey enablement (see AUTH006 and
          https://learn.microsoft.com/entra/identity/authentication/concept-sms-voice-retirement).
          Opting out does not exempt the tenant from the 2027-02-01 retirement, which has no
          opt-out at all.
        - systemCredentialPreferences - System-preferred multifactor authentication, i.e. what gets
          presented at sign-in for a credential the user already has. Feeds the inventory row and
          the flow scenarios.
        - reconfirmationInDays - how often users are asked to reconfirm their methods. Feeds the
          re-registration flow.

        Compare the two published property tables to see why this matters:
        https://learn.microsoft.com/graph/api/resources/authenticationmethodspolicy (v1.0) lists
        neither systemCredentialPreferences nor reconfirmationInDays; the ?view=graph-rest-beta
        version of the same page lists both. Reading them off the v1.0 response alone therefore
        risks them silently coming back empty, which would render as "not configured" rather than
        as an error - a wrong answer that looks like a real one. The merge below is deliberately
        one-directional and null-guarded: beta wins only when it actually returned something, so
        nothing breaks if/when these graduate to v1.0.

        NOT YET CONFIRMED AGAINST A LIVE TENANT: the v1.0 reference page is dated considerably
        older (ms.date 2024-07-22) than the beta one, and Microsoft's reference docs do lag the
        API, so v1.0 may well return these in practice despite not documenting them. The merge is
        safe either way, but if you want to know which is true for a real tenant, compare the two
        endpoints directly on a live run.

        Everything else stays on v1.0. The merged result is returned as one object, so callers
        (see ConvertTo-SAWNormalizedAuthenticationMethods.ps1) don't need to care which endpoint
        each property actually came from.

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

    # Merge across every property this toolkit reads that Microsoft's v1.0 resource reference does
    # not list. Only overwrite when beta actually returned a value, so a v1.0 value is never
    # clobbered by a beta null if/when these graduate to v1.0.
    foreach ($betaOnlyProperty in 'optOutSettings', 'systemCredentialPreferences', 'reconfirmationInDays') {
        if ($null -ne $betaPolicy.$betaOnlyProperty) {
            $policy.$betaOnlyProperty = $betaPolicy.$betaOnlyProperty
        }
        elseif ($null -eq $policy.$betaOnlyProperty) {
            Write-Verbose "Get-SAWAuthenticationMethods: '$betaOnlyProperty' came back empty from both v1.0 and beta - anything derived from it will read as unset"
        }
    }

    return $policy
}

function Get-SAWPasskeys {
    <#
    .SYNOPSIS
        Collects the FIDO2 (passkey) authentication method configuration via Microsoft Graph.
    .DESCRIPTION
        Read-only collector. Issues a single GET against
        /policies/authenticationMethodsPolicy/authenticationMethodConfigurations/Fido2 - a more
        targeted call than pulling the whole authentication methods policy, since this module
        cares about FIDO2-specific hygiene (attestation, key restrictions) rather than the
        tenant-wide enabled/disabled flag already covered by Get-SAWAuthenticationMethods.
        Must never create, modify, or delete any tenant object.
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

        [string]$SampleDataPath = (Join-Path $PSScriptRoot '..\..\sampledata\raw\fido2Configuration.raw.json')
    )

    if ($UseSampleData) {
        Write-Verbose "Get-SAWPasskeys: reading sample data from $SampleDataPath"
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

    # $expand=passkeyProfiles because passkeyProfiles is a RELATIONSHIP, not a property, so it is
    # absent from the default response. Microsoft has deprecated the top-level
    # isAttestationEnforced and keyRestrictions properties this toolkit used to read, with removal
    # scheduled for October 2027, in favour of these profiles - see
    # ConvertTo-SAWPasskeyPolicyEffective.ps1 for how the two sources are reconciled, and why
    # "absent" must never be read as "not enforced".
    $uri = 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/Fido2?$expand=passkeyProfiles'
    Write-Verbose "Get-SAWPasskeys: GET $uri"

    try {
        return Invoke-SAWGraphRequest -Method GET -Uri $uri
    }
    catch {
        # A tenant that hasn't been moved to passkey profiles may reject the expand outright. That
        # is not a reason to fail the assessment: retry without it and let the resolver fall back
        # to the deprecated properties, which are still live for exactly those tenants.
        Write-Verbose "Get-SAWPasskeys: expand on passkeyProfiles failed ($($_.Exception.Message.Split([char]10)[0])) - retrying without it"
        return Invoke-SAWGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/Fido2'
    }
}

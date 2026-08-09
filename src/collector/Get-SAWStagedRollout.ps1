function Get-SAWStagedRollout {
    <#
    .SYNOPSIS
        Collects the tenant's Staged Rollout (feature rollout) policies via Microsoft Graph.
    .DESCRIPTION
        Read-only collector. Issues a GET against /policies/featureRolloutPolicies (v1.0) and
        returns the raw Graph response. Must never create, modify, or delete any tenant object.

        Staged Rollout is the mechanism that moves a pilot group of users from federated
        authentication (AD FS or a third-party IdP) to managed cloud authentication, one group at
        a time, before converting the whole domain. It matters to an authentication assessment
        for three reasons, all documented at
        https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-staged-rollout:

        - Self-service password reset with writeback to on-premises AD "isn't supported when
          staged rollout is enabled for a security group". A tenant in this state has SSPR advice
          (SSPR001/SSPR002) that is qualified rather than simply actionable.
        - Windows Hello for Business hybrid CERTIFICATE trust, where the federation server acts
          as registration authority, and smartcard users, "isn't supported on a Staged Rollout" -
          which removes a bootstrap route (BOOT001) for exactly the population most likely to
          have it.
        - A user newly added to a rollout group still authenticates through the old identity
          provider until they complete "one more interactive sign-in using their existing
          federated login" - unless a Temporary Access Pass is issued, because Entra evaluates a
          TAP BEFORE it redirects to the federated IdP. That makes TAP (AUTH005/TAP001/TAP002) do
          double duty as a migration tool, not only as a passwordless bootstrap.

        This is inventory, not a pass/fail rule. It never reaches Invoke-SAWRulesEngine. Staged
        Rollout is a deliberately temporary migration state ("not designed to be a permanent
        configuration", per the same article), so "is it on?" has no correct answer that applies
        to every tenant - what it has is consequences, which the inventory reports.

        Three things about this endpoint differ from every other collector here, and each one is
        a wrong answer waiting to happen if missed:

        1. PERMISSION. The least-privileged delegated scope is Policy.Read.HybridAuthentication.
           Policy.Read.All does NOT cover it (confirmed against
           https://learn.microsoft.com/graph/api/featurerolloutpolicies-list, which lists only
           Policy.Read.HybridAuthentication, Directory.ReadWrite.All and
           Policy.ReadWrite.HybridAuthentication - the latter two being write scopes this
           read-only toolkit will not ask for). Because this is an optional inventory row rather
           than a rule, a missing scope must not take the whole assessment down with it: an
           authorization failure here is caught and reported as "couldn't read this", so the run
           continues and every other finding still lands.

        2. EVOLVABLE ENUM. The `feature` property is an evolvable enum. Without the
           `Prefer: include-unknown-enum-members` request header, the two newest members -
           `certificateBasedAuthentication` and `multiFactorAuthentication` - come back as
           `unknownFutureValue` instead of by name. Those two are precisely the ones an
           authentication assessment cares about most (a tenant staging its move off an
           on-premises MFA Server onto Entra MFA is squarely this toolkit's subject matter), so
           the header is sent. Without it the data would still parse, and would still be wrong.

        3. EXPANSION. `appliesTo` is a relationship, not a property, so the targeted groups are
           absent unless the request asks for them with $expand. "Enabled" without knowing who it
           applies to is not usable inventory, so the expansion is not optional here.

        Group targeting has documented limits worth knowing when reading the output: a maximum of
        10 groups per feature, groups only (no other directory object types), and neither nested
        nor dynamic groups are supported.
    .PARAMETER UseSampleData
        Read from a local sample JSON file instead of calling Microsoft Graph. Used for offline
        development and testing.
    .PARAMETER SampleDataPath
        Path to the sample raw response used when -UseSampleData is set.
    .OUTPUTS
        Hashtable. On success: the raw Graph response (carrying .value) plus an added
        .sawCollectionStatus = 'Collected'. On an authorization failure: a stand-in object with
        .sawCollectionStatus = 'Unavailable', .sawUnavailableReason, and an empty .value, so
        callers can render "not read" distinctly from "read, and there are none" - two states
        that look identical if a failure is quietly turned into an empty list.
    #>
    [CmdletBinding()]
    param(
        [switch]$UseSampleData,

        [string]$SampleDataPath = (Join-Path $PSScriptRoot '..\..\sampledata\raw\featureRolloutPolicies.raw.json')
    )

    if ($UseSampleData) {
        Write-Verbose "Get-SAWStagedRollout: reading sample data from $SampleDataPath"
        if (-not (Test-Path -Path $SampleDataPath)) {
            throw "Sample data file not found: $SampleDataPath"
        }
        $sample = Get-Content -Path $SampleDataPath -Raw | ConvertFrom-Json
        return @{
            value               = @($sample.value)
            sawCollectionStatus = 'Collected'
        }
    }

    if (-not (Get-Command -Name Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
        throw 'Invoke-MgGraphRequest is not available. Install/import Microsoft.Graph.Authentication first.'
    }
    $context = Get-MgContext
    if (-not $context) {
        throw 'Not connected to Microsoft Graph. Run Connect-MgGraph with read-only scopes first (e.g. Policy.Read.All).'
    }

    # Checked up front rather than left to the 403, because the remedy is specific and worth
    # stating plainly: this endpoint needs its own scope. A caller who passed a custom -Scopes
    # list to Connect-SAWGraph is the likely way to end up here.
    $requiredScope = 'Policy.Read.HybridAuthentication'
    if ($context.Scopes -and ($requiredScope -notin $context.Scopes)) {
        Write-Verbose "Get-SAWStagedRollout: '$requiredScope' is not in the current token's scopes - skipping the call"
        return @{
            value                = @()
            sawCollectionStatus  = 'Unavailable'
            sawUnavailableReason = "The connected session doesn't carry the $requiredScope scope, which this endpoint requires (Policy.Read.All does not cover it). Reconnect with that scope included to inventory Staged Rollout."
        }
    }

    $uri = 'https://graph.microsoft.com/v1.0/policies/featureRolloutPolicies?$expand=appliesTo'
    Write-Verbose "Get-SAWStagedRollout: GET $uri"

    try {
        $response = Invoke-SAWGraphRequest -Method GET -Uri $uri -Headers @{ Prefer = 'include-unknown-enum-members' }
        return @{
            value               = @($response.value)
            sawCollectionStatus = 'Collected'
        }
    }
    catch {
        # Only authorization failures are absorbed. Anything else (a malformed response, a
        # network failure, a Graph outage) is a real problem the operator should see, and is
        # rethrown so it can't hide behind an empty inventory section.
        $message = $_.Exception.Message
        if ($message -notmatch 'denied|Forbidden|AccessDenied|Authorization_RequestDenied|\b401\b|\b403\b') {
            throw
        }

        Write-Verbose 'Get-SAWStagedRollout: authorization failure - continuing without Staged Rollout inventory'
        return @{
            value                = @()
            sawCollectionStatus  = 'Unavailable'
            sawUnavailableReason = "Microsoft Graph denied the request. This endpoint needs the $requiredScope scope, which Policy.Read.All does not include; the account may also need a qualifying directory role (Global Reader or Hybrid Identity Administrator). Every other part of the assessment completed normally."
        }
    }
}

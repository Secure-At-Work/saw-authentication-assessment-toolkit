function ConvertTo-SAWNormalizedAuditLogs {
    <#
    .SYNOPSIS
        Normalizes raw directory audit log entries into Secure At Work governance checks.
    .DESCRIPTION
        Scans every directory audit entry and derives two facts:
        - whether any password/credential-related change targeted the known break-glass
          account (an unexpected change to an emergency-access account outside a planned,
          documented rotation is a red flag worth investigating);
        - whether any Conditional Access policy change was initiated by an application/service
          principal rather than a named administrator (unattributed automation touching
          security policy is a governance risk worth confirming is expected).
    .PARAMETER RawResponse
        The object returned by Get-SAWAuditLogs (has a .value array of audit entries).
    .OUTPUTS
        Hashtable[]
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$RawResponse
    )

    begin {
        # Same placeholder break-glass account id used in the Conditional Access sample data
        # (excluded from every CA policy) - kept consistent across sample fixtures.
        $breakGlassUserId = '99999999-9999-9999-9999-999999999999'

        function ConvertTo-SAWStateLabel {
            param([bool]$Value)
            if ($Value) { return 'Enabled' }
            return 'Disabled'
        }
    }

    process {
        $auditEntries = $RawResponse.value
        if (-not $auditEntries) { $auditEntries = @() }

        $breakGlassCredentialChangeFound = $false
        $conditionalAccessChangeByAppFound = $false

        foreach ($entry in $auditEntries) {
            $targets = $entry.targetResources
            if (-not $targets) { $targets = @() }

            foreach ($target in $targets) {
                if (-not $breakGlassCredentialChangeFound -and
                    $target.id -eq $breakGlassUserId -and
                    $entry.activityDisplayName -match 'password') {
                    $breakGlassCredentialChangeFound = $true
                    Write-Verbose "ConvertTo-SAWNormalizedAuditLogs: break-glass credential change '$($entry.activityDisplayName)' by '$($entry.initiatedBy.user.userPrincipalName)' on $($entry.activityDateTime)"
                }
            }

            if (-not $conditionalAccessChangeByAppFound -and
                $entry.activityDisplayName -match 'conditional access' -and
                $entry.initiatedBy.app) {
                $conditionalAccessChangeByAppFound = $true
                Write-Verbose "ConvertTo-SAWNormalizedAuditLogs: Conditional Access change by app '$($entry.initiatedBy.app.displayName)' on $($entry.activityDateTime)"
            }
        }

        @{
            Category = 'Audit Logs'
            Setting  = 'No Unexpected Break Glass Credential Changes'
            State    = ConvertTo-SAWStateLabel (-not $breakGlassCredentialChangeFound)
        }
        @{
            Category = 'Audit Logs'
            Setting  = 'Conditional Access Changes Not Made By Applications'
            State    = ConvertTo-SAWStateLabel (-not $conditionalAccessChangeByAppFound)
        }
    }
}

function Get-SAWRegistration {
    <#
    .SYNOPSIS
        Collects authentication method registration details per user via Microsoft Graph.
    .DESCRIPTION
        Read-only collector. Returns the raw Graph response as a PowerShell object.
        Must never create, modify, or delete any tenant object.
    .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    param()

    Write-Verbose 'Get-SAWRegistration: not yet implemented'
    throw [System.NotImplementedException]::new('Get-SAWRegistration is a scaffold placeholder.')
}

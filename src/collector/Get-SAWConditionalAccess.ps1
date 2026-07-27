function Get-SAWConditionalAccess {
    <#
    .SYNOPSIS
        Collects Conditional Access policies via Microsoft Graph.
    .DESCRIPTION
        Read-only collector. Returns the raw Graph response as a PowerShell object.
        Must never create, modify, or delete any tenant object.
    .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    param()

    Write-Verbose 'Get-SAWConditionalAccess: not yet implemented'
    throw [System.NotImplementedException]::new('Get-SAWConditionalAccess is a scaffold placeholder.')
}

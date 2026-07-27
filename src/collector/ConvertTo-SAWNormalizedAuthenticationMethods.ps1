function ConvertTo-SAWNormalizedAuthenticationMethods {
    <#
    .SYNOPSIS
        Normalizes a raw authenticationMethodsPolicy Graph response into the
        Secure At Work normalized schema consumed by the rules engine.
    .DESCRIPTION
        Maps each entry in authenticationMethodConfigurations to a
        { Category, Setting, State } object, using the same Category/Setting
        naming the rule JSON files key off of.
    .PARAMETER RawPolicy
        The object returned by Get-SAWAuthenticationMethods.
    .OUTPUTS
        Hashtable[]
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$RawPolicy
    )

    begin {
        $displayNameByMethodId = @{
            Fido2                  = 'FIDO2'
            MicrosoftAuthenticator = 'Microsoft Authenticator'
            Sms                    = 'SMS'
            Voice                  = 'Voice'
            Email                  = 'Email OTP'
            TemporaryAccessPass    = 'Temporary Access Pass'
            SoftwareOath           = 'Software OATH'
            X509Certificate        = 'Certificate Authentication'
        }
    }

    process {
        foreach ($config in $RawPolicy.authenticationMethodConfigurations) {
            $setting = $displayNameByMethodId[$config.id]
            if (-not $setting) {
                Write-Verbose "ConvertTo-SAWNormalizedAuthenticationMethods: no display name mapping for method id '$($config.id)', using raw id"
                $setting = $config.id
            }

            $state = [string]$config.state
            if ($state.Length -gt 0) {
                $state = $state.Substring(0, 1).ToUpper() + $state.Substring(1).ToLower()
            }

            @{
                Category = 'Authentication Methods'
                Setting  = $setting
                State    = $state
                RawId    = $config.id
            }
        }
    }
}

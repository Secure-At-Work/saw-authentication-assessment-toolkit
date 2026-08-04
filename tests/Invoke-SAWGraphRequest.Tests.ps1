BeforeAll {
    . "$PSScriptRoot/../src/Invoke-SAWGraphRequest.ps1"
}

Describe 'Invoke-SAWGraphRequest' {
    It 'passes through a successful response unchanged' {
        function Invoke-MgGraphRequest { param($Method, $Uri) @{ value = @('ok') } }

        $result = Invoke-SAWGraphRequest -Method GET -Uri 'https://example.com/success'

        $result.value | Should -Be 'ok'
    }

    It 'adds PIM and required-role guidance for a 403 AccessDenied error, preserving the original error text' {
        function Invoke-MgGraphRequest {
            param($Method, $Uri)
            throw 'GET https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies HTTP/1.1 403 Forbidden {"error":{"code":"AccessDenied","message":"Your account does not have access to this report or data. One of the following roles is required: Security Reader, Company Administrator, Security Administrator, Conditional Access Administrator, Global Reader, Devices Admin, Entra Network Access Administrator."}}'
        }

        { Invoke-SAWGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' } | Should -Throw

        try {
            Invoke-SAWGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
        }
        catch {
            $_.Exception.Message | Should -Match 'PIM'
            $_.Exception.Message | Should -Match 'Global Reader'
            $_.Exception.Message | Should -Match 'Disconnect-MgGraph'
            $_.Exception.Message | Should -Match 'AccessDenied'
            $_.Exception.Message | Should -Match 'Security Reader, Company Administrator'
        }
    }

    It 'adds guidance for a bare 401 error too (text-matched, not just AccessDenied)' {
        function Invoke-MgGraphRequest {
            param($Method, $Uri)
            throw 'GET https://graph.microsoft.com/v1.0/foo HTTP/1.1 401 Unauthorized {"error":{"code":"InvalidAuthenticationToken","message":"Access token is empty."}}'
        }

        try {
            Invoke-SAWGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/foo'
            throw 'expected an exception'
        }
        catch {
            $_.Exception.Message | Should -Match 'PIM'
        }
    }

    It 'captures request-id/client-request-id from response headers when present' {
        function Invoke-MgGraphRequest {
            param($Method, $Uri)
            $headers = [System.Net.Http.Headers.HttpResponseHeaders]::new
            $ex = [System.Exception]::new('Response status code does not indicate success: Forbidden (Forbidden).')
            $response = [PSCustomObject]@{
                StatusCode = [System.Net.HttpStatusCode]::Forbidden
                Headers    = [PSCustomObject]@{
                    TryGetValues = {
                        param($name, [ref]$values)
                        switch ($name) {
                            'request-id' { $values.Value = @('11111111-2222-3333-4444-555555555555'); return $true }
                            'client-request-id' { $values.Value = @('66666666-7777-8888-9999-aaaaaaaaaaaa'); return $true }
                            default { return $false }
                        }
                    }
                }
            }
            $ex | Add-Member -MemberType NoteProperty -Name Response -Value $response -Force
            throw $ex
        }

        try {
            Invoke-SAWGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
            throw 'expected an exception'
        }
        catch {
            $_.Exception.Message | Should -Match '11111111-2222-3333-4444-555555555555'
            $_.Exception.Message | Should -Match '66666666-7777-8888-9999-aaaaaaaaaaaa'
            $_.Exception.Message | Should -Match 'Microsoft support'
        }
    }

    It 'falls back to the JSON error body for request-id/client-request-id when headers are unavailable' {
        function Invoke-MgGraphRequest {
            param($Method, $Uri)
            $ex = [System.Exception]::new('Response status code does not indicate success: Forbidden (Forbidden).')
            $errorDetails = [System.Management.Automation.ErrorDetails]::new('{"error":{"code":"AccessDenied","message":"denied","innerError":{"request-id":"aaaa1111-bbbb-2222-cccc-3333dddd4444","client-request-id":"bbbb2222-cccc-3333-dddd-4444eeee5555"}}}')
            $PSCmdlet = $null
            $record = [System.Management.Automation.ErrorRecord]::new($ex, 'Forbidden', [System.Management.Automation.ErrorCategory]::PermissionDenied, $null)
            $record.ErrorDetails = $errorDetails
            throw $record
        }

        try {
            Invoke-SAWGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
            throw 'expected an exception'
        }
        catch {
            $_.Exception.Message | Should -Match 'aaaa1111-bbbb-2222-cccc-3333dddd4444'
            $_.Exception.Message | Should -Match 'bbbb2222-cccc-3333-dddd-4444eeee5555'
        }
    }

    It 'omits the Microsoft-support block entirely when no request-id is recoverable' {
        function Invoke-MgGraphRequest {
            param($Method, $Uri)
            throw 'GET https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies HTTP/1.1 403 Forbidden {"error":{"code":"AccessDenied","message":"denied"}}'
        }

        try {
            Invoke-SAWGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
            throw 'expected an exception'
        }
        catch {
            $_.Exception.Message | Should -Not -Match 'Microsoft support'
        }
    }

    It 'does not add authorization guidance for an unrelated error (e.g. 404)' {
        function Invoke-MgGraphRequest {
            param($Method, $Uri)
            throw 'GET https://graph.microsoft.com/v1.0/some/bad/path HTTP/1.1 404 Not Found {"error":{"code":"ResourceNotFound","message":"The requested resource does not exist."}}'
        }

        try {
            Invoke-SAWGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/some/bad/path'
            throw 'expected an exception'
        }
        catch {
            $_.Exception.Message | Should -Not -Match 'PIM'
            $_.Exception.Message | Should -Match 'ResourceNotFound'
        }
    }
}

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

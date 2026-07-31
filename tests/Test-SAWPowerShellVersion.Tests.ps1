BeforeAll {
    . "$PSScriptRoot/../src/Test-SAWPowerShellVersion.ps1"
}

Describe 'Test-SAWPowerShellVersion' {
    It 'is satisfied when the version exactly matches the minimum and the edition is Core' {
        $result = Test-SAWPowerShellVersion -CurrentVersion ([version]'7.4.0') -CurrentEdition 'Core' -MinimumVersion ([version]'7.4') -PwshAvailable $true -ScriptPath 'C:\foo\bar.ps1'

        $result.Satisfied | Should -BeTrue
        $result.Message | Should -BeNullOrEmpty
    }

    It 'is satisfied when the version is newer than the minimum and the edition is Core' {
        $result = Test-SAWPowerShellVersion -CurrentVersion ([version]'7.6.3') -CurrentEdition 'Core' -MinimumVersion ([version]'7.4') -PwshAvailable $true -ScriptPath 'C:\foo\bar.ps1'

        $result.Satisfied | Should -BeTrue
    }

    It 'is not satisfied when the edition is Desktop, even if the version number alone would be high enough' {
        $result = Test-SAWPowerShellVersion -CurrentVersion ([version]'7.4.0') -CurrentEdition 'Desktop' -MinimumVersion ([version]'7.4') -PwshAvailable $true -ScriptPath 'C:\foo\bar.ps1'

        $result.Satisfied | Should -BeFalse
    }

    Context 'Windows PowerShell (Desktop edition), pwsh already installed' {
        It 'is not satisfied and suggests relaunching with pwsh' {
            $result = Test-SAWPowerShellVersion -CurrentVersion ([version]'5.1.19041.0') -CurrentEdition 'Desktop' -MinimumVersion ([version]'7.4') -PwshAvailable $true -ScriptPath 'C:\foo\bar.ps1'

            $result.Satisfied | Should -BeFalse
            $result.Message | Should -Match 'already appears to be installed'
            $result.Message | Should -Match 'pwsh -File "C:\\foo\\bar\.ps1"'
        }
    }

    Context 'Windows PowerShell (Desktop edition), pwsh not installed' {
        It 'is not satisfied and gives install instructions with the winget command and docs link' {
            $result = Test-SAWPowerShellVersion -CurrentVersion ([version]'5.1.19041.0') -CurrentEdition 'Desktop' -MinimumVersion ([version]'7.4') -PwshAvailable $false -ScriptPath 'C:\foo\bar.ps1'

            $result.Satisfied | Should -BeFalse
            $result.Message | Should -Match 'does not appear to be installed'
            $result.Message | Should -Match 'winget install --id Microsoft\.PowerShell'
            $result.Message | Should -Match 'learn\.microsoft\.com/powershell/scripting/install'
        }
    }

    Context 'Already running pwsh (Core), just outdated' {
        It 'is not satisfied and suggests upgrading, not relaunching (relaunching would be circular)' {
            $result = Test-SAWPowerShellVersion -CurrentVersion ([version]'7.2.5') -CurrentEdition 'Core' -MinimumVersion ([version]'7.4') -PwshAvailable $true -ScriptPath 'C:\foo\bar.ps1'

            $result.Satisfied | Should -BeFalse
            $result.Message | Should -Match 'already running PowerShell 7'
            $result.Message | Should -Match 'winget upgrade --id Microsoft\.PowerShell'
            $result.Message | Should -Not -Match 'relaunch'
        }
    }

    It 'falls back to a placeholder script path when ScriptPath is not supplied' {
        $result = Test-SAWPowerShellVersion -CurrentVersion ([version]'5.1.19041.0') -CurrentEdition 'Desktop' -MinimumVersion ([version]'7.4') -PwshAvailable $true -ScriptPath ''

        $result.Message | Should -Match '<this script>'
    }
}

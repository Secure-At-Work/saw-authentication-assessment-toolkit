# Tests

Pester tests for each collector module, mirroring `src/collector/`:

```
tests/
  Get-SAWAuthenticationMethods.Tests.ps1
  Get-SAWAuthenticationStrengths.Tests.ps1
  Get-SAWConditionalAccess.Tests.ps1
  Get-SAWRegistration.Tests.ps1
  Get-SAWTemporaryAccessPass.Tests.ps1
  Get-SAWPasskeys.Tests.ps1
  Get-SAWSignInLogs.Tests.ps1
  Get-SAWAuditLogs.Tests.ps1
  mocks/            Mock Microsoft Graph responses used by the tests above
```

No tests implemented yet — this is scaffold only. Target: >80% code coverage (spec section 18), using mocked Graph responses so tests never call a real tenant.

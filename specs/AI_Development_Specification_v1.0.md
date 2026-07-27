# AI Development Specification
# Secure At Work Authentication Assessment Toolkit

Version: 1.0
Status: Draft
Author: Kenneth van Surksum
Target AI: Claude Code, Codex, Cursor, GitHub Copilot

---

## 1. Project Goal

Develop an Authentication Assessment Toolkit for Secure At Work that can assess the current Microsoft Entra authentication configuration of a customer tenant and compare it with the Secure At Work recommended configuration.

The toolkit must provide:

- Current state (IST)
- Target state (SOLL)
- Gap analysis
- Risk assessment
- Recommended remediation
- Migration guidance

The toolkit must be completely read-only.

It may NEVER change tenant configuration.

---

## 2. Primary Objectives

The toolkit shall

- Inventory
- Analyze
- Compare
- Score
- Generate recommendations
- Generate reports
- Export raw data

It shall NOT

- Modify tenant settings
- Create objects
- Delete objects
- Enable or disable policies
- Register authentication methods

---

## 3. High Level Architecture

```
                    Microsoft Graph
                           |
                    PowerShell Collector
                           |
                 -----------------------
                 |                     |
            Raw JSON              Normalized JSON
                 |                     |
                 +----------+----------+
                            |
                     Rules Engine
                            |
          +----------+------+-------+
          |          |              |
     Dashboard   HTML Report   Excel Report
          |
     Markdown Report
```

---

## 4. Repository Structure

```
AuthenticationAssessmentToolkit/
  docs/
  specs/
  src/
    collector/
    rules/
    dashboard/
  tests/
  sampledata/
  schemas/
  reports/
```

---

## 5. Technology Stack

- PowerShell 7.4+
- Microsoft Graph SDK
  - Microsoft.Graph.Authentication
  - Microsoft.Graph.Identity.SignIns
  - Microsoft.Graph.Users
  - Microsoft.Graph.Identity.DirectoryManagement
  - Microsoft.Graph.Beta (only when unavoidable)
- HTML
- JavaScript
- CSS
- Bootstrap
- Chart.js

No Azure resources.
No SQL Server.
No Azure Functions.
Everything runs locally.

---

## 6. Collector

The collector must consist of independent modules.

Example:

```
Get-SAWAuthenticationMethods.ps1
Get-SAWAuthenticationStrengths.ps1
Get-SAWConditionalAccess.ps1
Get-SAWRegistration.ps1
Get-SAWTemporaryAccessPass.ps1
Get-SAWPasskeys.ps1
Get-SAWSignInLogs.ps1
Get-SAWAuditLogs.ps1
```

Each module returns a PowerShell object.
Never formatted text.

---

## 7. JSON Output

Every collector writes:

```
raw/
normalized/
```

Raw contains original Graph responses.
Normalized contains Secure At Work schema.

---

## 8. Secure At Work Rules Engine

The Rules Engine must NOT contain PowerShell logic.

Rules shall be JSON files.

Example:

```json
{
    "RuleID": "AUTH001",
    "Category": "Authentication Methods",
    "Setting": "Microsoft Authenticator",
    "Expected": "Enabled",
    "Severity": "High",
    "Recommendation": "Enable Microsoft Authenticator"
}
```

The PowerShell collector loads these rules dynamically.

---

## 9. Dashboard

The dashboard shall contain:

- Overview
- Authentication Methods
- Authentication Strengths
- Conditional Access
- Registration
- Temporary Access Pass
- Passkeys
- FIDO2
- SMS
- Voice
- OATH
- Certificate Authentication
- Guests
- Break Glass
- Risk Findings
- Recommendations
- Exports

---

## 10. Dashboard Principles

- Green: Configured according to Secure At Work.
- Yellow: Configured but differs.
- Red: Security issue.
- Grey: Not applicable.

Every recommendation must link to:

- Recommendation
- Reason
- Microsoft Documentation
- Secure At Work guidance

---

## 11. Conditional Access Integration

Integrate Kenneth van Surksum's Conditional Access Baseline.

Each policy must contain:

- Policy ID
- Purpose
- Category
- Dependencies
- Migration Ring
- Required Before
- Required After
- Validation
- Rollback

---

## 12. Authentication Methods

Collect:

- Migration State
- Authenticator
- SMS
- Voice
- Email OTP
- TAP
- Passkeys
- FIDO2
- Software OATH
- Hardware OATH
- Certificate Authentication
- QR Code

---

## 13. Sign-in Analysis

Analyze:

- Authentication Method Usage
- Registration
- Failed MFA
- Legacy Authentication
- Password + SMS
- Device Code Flow
- Authentication Transfer
- Guest Authentication
- Break Glass Usage

---

## 14. Reports

Generate:

- HTML
- Markdown
- Excel
- JSON

---

## 15. Testing

Every collector module shall contain:

- Pester Tests
- Mock Graph Responses
- Unit Tests

---

## 16. AI Coding Standards

Claude Code shall:

- Never hardcode Tenant IDs.
- Never hardcode Group IDs.
- Never hardcode Policy IDs.
- Never hardcode GUIDs.
- Use configuration files.

Every function:

- Single Responsibility
- Comment Based Help
- Supports -Verbose
- Supports -WhatIf when applicable
- Supports pipeline where logical.

---

## 17. Future Modules

- Authentication
- Identity Lifecycle
- Conditional Access
- Privileged Identity Management
- Devices
- Intune
- Defender
- Exchange
- Purview
- Teams
- SharePoint

---

## 18. Acceptance Criteria

The project is complete when:

- A tenant can be inventoried
- Dashboard loads
- Reports generate
- Recommendations generated
- Rules loaded dynamically
- No tenant changes occur
- Code coverage exceeds 80%
- PSScriptAnalyzer passes
- Documentation updated

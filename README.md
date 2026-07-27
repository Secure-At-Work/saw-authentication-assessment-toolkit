# Secure At Work Authentication Assessment Toolkit

Read-only assessment toolkit for Microsoft Entra ID authentication configuration. Inventories the current (IST) state of a tenant via Microsoft Graph, compares it against the Secure At Work recommended (SOLL) configuration, and produces gap analysis, risk scoring, and remediation guidance.

See [specs/AI_Development_Specification_v1.0.md](specs/AI_Development_Specification_v1.0.md) for the full specification.

## Hard constraint

This toolkit is **read-only**. It must never create, modify, enable/disable, or delete any tenant object, policy, or authentication method registration.

## Repository structure

```
docs/               Project documentation
specs/              Specifications driving development
src/
  collector/         PowerShell modules that read data from Microsoft Graph
  rules/             Secure At Work rule definitions (JSON, no logic)
  dashboard/         HTML/JS/CSS dashboard
tests/              Pester tests + mock Graph responses
sampledata/         Sample raw/normalized JSON for offline dashboard development
schemas/            JSON schemas for normalized data and rules
reports/            Generated report output (gitignored)
```

## Status

Scaffold only — no collector logic implemented yet. See the spec for module list and acceptance criteria.

## Requirements

- PowerShell 7.4+
- Microsoft Graph PowerShell SDK modules:
  - Microsoft.Graph.Authentication
  - Microsoft.Graph.Identity.SignIns
  - Microsoft.Graph.Users
  - Microsoft.Graph.Identity.DirectoryManagement
- Delegated or app-only Graph permissions with **read-only** scopes (e.g. `Policy.Read.All`, `UserAuthenticationMethod.Read.All`, `AuditLog.Read.All`) — no write scopes should ever be requested.

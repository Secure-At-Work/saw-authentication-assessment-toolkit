# Changelog

All notable changes to this repository are documented in this file.

## [Unreleased]

### Added
- Added a customer-facing transition runbook in [docs/ist-to-soll-summary.md](docs/ist-to-soll-summary.md) under "Smooth Transition Playbook (including temporary exceptions)".
- Added explicit repository-level changelog discoverability links in [README.md](README.md) and [docs/README.md](docs/README.md).
- Added Microsoft Authenticator's per-target `authenticationMode` (Any/Push/Passwordless) to the Authentication Methods Policy inventory, with a matching caveat on [REG003](src/rules/REG003.json)'s passwordless-capability check ([src/collector/ConvertTo-SAWAuthenticationMethodsInventory.ps1](src/collector/ConvertTo-SAWAuthenticationMethodsInventory.ps1)).
- Added a caveat to [CA005](src/rules/CA005.json) on the password-only registration risk once passkeys can be registered as a user's first MFA method (Message Center MC1450133).
- Added a caveat to [REG001/REG002](src/rules/REG001.json) noting Identity Protection's Multifactor authentication registration policy as a stronger, Graph-invisible enforcement lever alongside the registration campaign.

### Changed
- Expanded the "New User Bootstrap" guidance in [docs/reading-the-report.md](docs/reading-the-report.md) to document a controlled, time-boxed temporary PASS001 exception path for onboarding continuity.
- Updated [src/rules/PASS001.json](src/rules/PASS001.json) recommendation text to include preferred mitigations and controlled temporary attestation exception guardrails.
- Updated [src/rules/TAP001.json](src/rules/TAP001.json) recommendation text to align with PASS001 on transition options and exception safeguards.
- Corrected the System-Preferred Authentication Microsoft-managed rollout completion date in [config/timeline-milestones.json](config/timeline-milestones.json) from "through August 2026" to "late September 2026", per Message Center MC1411574 (the public docs page had not yet caught up as of this correction).
- Corrected the passkey-profile auto-migration assumption in [docs/design-notes.md](docs/design-notes.md) - Worldwide/GCC tenants have very likely already auto-migrated (Message Center MC1221452), superseding the earlier "no tenant has migrated yet" caveat.
- Corrected [RCAMP001](src/rules/RCAMP001.json), [PASS001](src/rules/PASS001.json), and [PASS002](src/rules/PASS002.json) recommendation text: under the Microsoft managed registration campaign state, attestation enforcement, AAGUID key restrictions (with a qualifying provider AAGUID), and synced-only/device-bound-only default passkey profiles are now themselves eligible profile configurations rather than nudge suppressors (Message Center MC1469555, reversing the previously documented and previously described behavior).

### Fixed
- Fixed [ConvertTo-SAWNudgeForecast.ps1](src/collector/ConvertTo-SAWNudgeForecast.ps1)'s suppressor logic, which incorrectly reported the passkey registration campaign nudge as suppressed for attestation-enforced, AAGUID-restricted, and synced-only/device-bound-only passkey profiles under the now-reversed Microsoft managed eligibility rules (MC1469555). Updated tests in [tests/collector/ConvertTo-SAWNudgeForecast.Tests.ps1](tests/collector/ConvertTo-SAWNudgeForecast.Tests.ps1).

### Notes
- A fresh sample dashboard was regenerated after these updates to verify the new guidance appears in rendered report output.
- The public blog post ([docs/blog-ist-to-soll-authentication.md](docs/blog-ist-to-soll-authentication.md)) and the SAW Internal Runbook received dated "Update" sections and in-place strikethrough corrections matching the changes above, keeping already-published claims that remain accurate untouched.

# Changelog

All notable changes to this repository are documented in this file.

## [Unreleased]

### Added
- Added a customer-facing transition runbook in [docs/ist-to-soll-summary.md](docs/ist-to-soll-summary.md) under "Smooth Transition Playbook (including temporary exceptions)".
- Added explicit repository-level changelog discoverability links in [README.md](README.md) and [docs/README.md](docs/README.md).

### Changed
- Expanded the "New User Bootstrap" guidance in [docs/reading-the-report.md](docs/reading-the-report.md) to document a controlled, time-boxed temporary PASS001 exception path for onboarding continuity.
- Updated [src/rules/PASS001.json](src/rules/PASS001.json) recommendation text to include preferred mitigations and controlled temporary attestation exception guardrails.
- Updated [src/rules/TAP001.json](src/rules/TAP001.json) recommendation text to align with PASS001 on transition options and exception safeguards.

### Notes
- A fresh sample dashboard was regenerated after these updates to verify the new guidance appears in rendered report output.

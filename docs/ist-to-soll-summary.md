# From IST to SOLL: Authentication Hardening Roadmap

**IST** = what's actually configured today. **SOLL** = the target state for this tenant
specifically — a hybrid, on-premises-AD-connected tenant and a fully cloud-native, passwordless
tenant don't share the same target, and this assessment is measured against the one that
actually applies here.

## The five-phase path

Order matters: enforcing MFA for everyone before enough users are registered risks lockouts;
retiring SMS/Voice before coverage is high enough removes someone's only working method. Work
each phase to completion before starting the next.

| Phase | Goal | Typical actions |
|---|---|---|
| **1. Foundation & Visibility** | Safe to do immediately, nothing blocks it | Block legacy authentication; enable Authenticator, FIDO2, and Temporary Access Pass; clean up audit log / break-glass hygiene |
| **2. Enable Phishing-Resistant Capability** | Give users something strong to register | Turn on FIDO2 (attestation, key restrictions); enable a phishing-resistant Conditional Access authentication strength |
| **3. Drive Registration Coverage** | Get people actually registered | Run the registration campaign; close admin and overall MFA registration gaps; raise SSPR registration coverage |
| **4. Retire Weak Fallback Methods** | Remove the downgrade path | Turn off SMS/Voice — only once coverage from Phase 3 is high enough |
| **5. Enforce via Conditional Access** | Make the target state mandatory | Require MFA for all users; require compliant device or phishing-resistant auth for admins |

## How to work it

1. **Run the assessment.** Read-only; produces a dashboard scoring every check Green (meets
   SOLL), Yellow (partial gap), Red (fails SOLL), or Grey (not applicable here).
2. **Follow the Remediation Roadmap**, not just the findings list — it's phase-ordered, and a
   `Blocked` item is waiting on an earlier phase, even if it looks easy to switch on now.
3. **Work the User Triage list** for the people-side of phases 2–4: who to nudge toward a
   stronger method, who has a weak fallback to remove, plus flags for anything worth a second
   look (an admin relying only on a device-bound method, a registered method never actually
   used, an account that looks internal but originated externally).
4. **Check Upcoming Microsoft Deadlines** — some of this work happens on Microsoft's own
   timeline regardless (e.g. automatic passkey enablement for SMS/Voice users), which changes
   what's worth prioritizing manually versus what's coming either way.
5. **Re-run periodically.** A trend chart shows whether Green is actually increasing over time;
   comparing any two runs shows exactly what changed — useful for a project check-in.

## Done, for now

Every phase-5 item Green (or intentionally Grey) means this tenant matches its SOLL target
today. Microsoft's own rollouts and new checks shift what SOLL means over time, so periodic
re-assessment stays worthwhile even after reaching Green.

---
*Secure At Work Authentication Assessment — see the full dashboard report for tenant-specific
detail behind every item above.*

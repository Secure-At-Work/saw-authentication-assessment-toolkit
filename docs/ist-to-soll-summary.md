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

## Smooth Transition Playbook (including temporary exceptions)

Use this when the customer wants passkey rollout to stay smooth for first-time registration,
especially for scenarios where TAP is entered on one device and the passkey is saved on another.

1. **Preferred path (no temporary security reduction):** keep PASS001 (attestation) enabled,
   keep TAP001 one-time-use as the default, and steer first-time users to same-device onboarding
   (Windows Hello for Business) or issue a short-lived, onboarding-only multi-use TAP for the
   small group that truly needs cross-device bootstrap.
2. **Temporary exception path (if needed):** permit a short, explicitly approved PASS001
   exception (attestation disabled) only for onboarding, then revert to enforced attestation.

Guardrails for the temporary exception path:

1. **Time-box it** (for example, a defined cutover week) with a named owner and rollback date.
2. **Scope it narrowly** to onboarding cohorts, not all users and not admin/high-value accounts.
3. **Keep TAP constrained** (short lifetime, minimum scope, one-time everywhere except the
   onboarding cohort that needs cross-device).
4. **Keep PASS002 in place as guidance** during the exception window (AAGUID restrictions are not
   a hard control without attestation, but still reduce accidental registrations).
5. **Log and review registrations created during the exception window** and schedule cleanup for
   any method that does not meet the customer's long-term key model.
6. **Re-enable PASS001 on schedule** and communicate the date up front so help desk and users know
   when cross-device bootstrap behavior changes back.

Decision rule:

1. If onboarding can be made smooth with same-device WHfB or onboarding-scoped multi-use TAP,
   prefer that over disabling attestation.
2. If temporary attestation disablement is required for business continuity, treat it as a
   controlled exception with a fixed end date, explicit owner, and post-window review.

## Done, for now

Every phase-5 item Green (or intentionally Grey) means this tenant matches its SOLL target
today. Microsoft's own rollouts and new checks shift what SOLL means over time, so periodic
re-assessment stays worthwhile even after reaching Green.

---
*Secure At Work Authentication Assessment — see the full dashboard report for tenant-specific
detail behind every item above.*

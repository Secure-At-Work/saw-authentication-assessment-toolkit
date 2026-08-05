# Reading the Assessment Report: IST, SOLL, and What to Do Next

This document explains what a Secure At Work Authentication Assessment actually is, how to read
its output, and how to work from the current state (**IST**) toward the recommended state
(**SOLL**). It assumes no prior familiarity with the toolkit - if you're on the receiving end of
a report rather than the one who ran it, start here.

## The situation, in short

Microsoft Entra ID (the identity platform behind Microsoft 365 and Azure) has dozens of
authentication-related settings spread across several different areas: which sign-in methods are
allowed, which Conditional Access policies enforce MFA, how many users have actually registered a
strong method, whether legacy/weak fallback methods are still reachable, and so on. Individually
each setting is simple; together, whether they add up to "this tenant is well protected" is not
something you can eyeball from the admin center.

This toolkit connects to a tenant read-only via Microsoft Graph, inventories the **current**
configuration (IST - German/Dutch for "is", i.e. "as-is"), compares it against a **recommended**
configuration (SOLL - "should be", i.e. "target state"), and produces a gap analysis: what's
already good, what's missing, how severe each gap is, and what order to fix things in.

**It is read-only.** It never creates, changes, enables, disables, or deletes anything in the
tenant - see the "Hard constraint" section of the main [README](../README.md). Running an
assessment carries no risk to the tenant itself.

**SOLL is not one-size-fits-all.** A tenant still tied to on-premises Active Directory
legitimately needs different things than a fully cloud-native, passwordless tenant - e.g. the
former may still need passwords and SSPR for longer. The toolkit auto-detects which profile a
tenant matches and picks the matching baseline; every report states which baseline was used, so
you always know what "target" a given assessment was measured against.

## The two report files

Every run produces two files, in `reports/<tenant>/<run-timestamp>/`:

- **`assessment-report.html`** - a flat table: every check, its result, and its severity. Quick
  to scan, easy to export/print, no interactivity.
- **`dashboard/index.html`** - the full picture: the same results, plus context, trends, a
  prioritized work plan, and supporting detail. This is the one worth spending time in. It's
  self-contained (its own `vendor/` folder ships with it), so the whole `dashboard/` folder can
  be zipped and shared without needing internet access to view it.

The rest of this document walks through the dashboard, top to bottom.

## Reading the dashboard

### 1. The baseline banner

Right at the top: which SOLL baseline this run was measured against (e.g. *"hybrid-ad-passwords-
required"*), and whether it was auto-detected from the tenant's own configuration or set
explicitly. If the tenant profile looks off, this is the first thing to check.

### 2. Upcoming Microsoft Deadlines

Microsoft is retiring/changing several authentication behaviors on fixed dates (e.g. SMS/Voice
retirement, SSPR no longer accepting directory-sourced contact info). This section is not a
finding about the tenant - it's a heads-up about the calendar, independent of anything found
below. Each card shows:

- A live **"N days left"** countdown, color-coded by urgency (red inside 14 days, yellow inside
  45, grey once the date has passed).
- Where computable, **"N user(s) impacted"** - e.g. how many users currently have a phone-based
  method registered and will be affected by the SMS/Voice changes, or how many SSPR-enabled
  users aren't SSPR-registered yet. The label under the number always states exactly what's
  being counted, since some of these are necessarily proxies (Graph doesn't expose every
  distinction the deadline itself cares about) - read the label, not just the number.
- A link to Microsoft's own source for the date, since dates like these have moved before.

Treat this section as "things to plan around," not "things this tenant is doing wrong."

### 3. Overview

The headline numbers: how many checks are Green (meets SOLL), Yellow (partial/lower-severity
gap), Red (fails SOLL, the priority list), and Grey (not applicable to this tenant/baseline -
e.g. a passkey-attestation check when passkeys aren't in use at all). Grey is not a failure; it
means the check doesn't apply here.

### 4. Trend Over Time

If this tenant has been assessed more than once, a chart plots Green/Yellow/Red/Grey counts
across every past run. This is the "are we actually making progress" view - useful for check-ins
during a remediation project, not just the point-in-time snapshot.

### 5. Remediation Roadmap - the IST-to-SOLL work plan

This is the most actionable section, and the answer to "what do we actually do about this." See
[From IST to SOLL](#from-ist-to-soll-the-work-plan-itself) below for how to use it.

### 6. Conditional Access Policy Inventory

Every Conditional Access policy in the tenant, in plain language: name, state (on/off/report-
only), who it targets, what it requires. This is independent of the pass/fail checks above - it's
the full picture, useful for understanding *why* a check passed or failed, or for a general
CA hygiene review that isn't captured by any single rule.

### 7. Security Info Registration Triage

A per-user list, bucketed:

- **Hunt** - no phishing-resistant method (passkey/FIDO2/Windows Hello for Business) registered
  yet. These are the users to nudge toward registering one.
- **Remove** - already has a phishing-resistant method, but *also* still has a phone-based
  fallback (SMS/voice) registered. The fallback should be removed: leaving it in place is
  exactly what enables a downgrade attack, where an attacker forces the weaker fallback method
  even though a stronger one exists.
- **Guest (FIDO2 Not Supported)** - guest/external users, called out separately because
  Microsoft doesn't yet support passkey registration for guest accounts - nudging them the same
  way as regular users would be asking them to do something they currently can't.
- **OK** - already in the target state for this check.

Admin accounts are always listed first within each bucket, since they're the highest-priority
targets either way.

A user may also carry a **"Possible External Member"** badge alongside their bucket. This flags
a UPN with the `#EXT#` shape Microsoft auto-generates for B2B guest invitations (e.g.
`name_partnerdomain.com#EXT#@yourtenant.onmicrosoft.com`) whose account type is Member rather
than Guest - most likely a guest that was converted to Member at some point, or an account
provisioned as Member via cross-tenant synchronization. Either way it's still an externally-
sourced identity, just not one the Guest bucket above catches. It's a heuristic based on the
UPN's shape, not a confirmed fact - worth a quick check with the customer if it shows up.

### 8. Flat findings table

Every individual check, its result, and its severity - the same data as the flat report, kept
here too so you don't need to cross-reference two files while reading.

## From IST to SOLL: the work plan itself

A list of findings tells you *what's* wrong. It doesn't tell you *what order* to fix things in -
and order matters here, because doing things out of sequence can create real problems:

- Enforcing "MFA required for everyone" via Conditional Access *before* enough users have
  registered a strong method risks locking people out entirely.
- Pushing users to register a passkey *before* a bootstrap method (self-service FIDO2
  registration, or a Temporary Access Pass) exists gives them no way to actually act on the ask.
- Removing a phone-based fallback *before* a stronger method is registered removes someone's
  only working factor.

To avoid this, every check belongs to one of five ordered phases:

| Phase | Name | What it covers |
|---|---|---|
| 1 | Foundation & Visibility | Safe immediately, nothing depends on anything else: block legacy authentication, enable Authenticator/FIDO2/TAP, audit log hygiene, TAP hardening. |
| 2 | Enable Phishing-Resistant Capability | Needs FIDO2 enabled first: attestation, key restrictions, synced-passkey policy, phishing-resistant authentication strength. |
| 3 | Drive Registration Coverage | Needs a bootstrap path first: the registration campaign, admin/overall MFA coverage, SSPR coverage. |
| 4 | Retire Weak Fallback Methods | Don't remove SMS/Voice until registration coverage is actually high enough. |
| 5 | Enforce via Conditional Access | Enforcing MFA-for-everyone or privileged-access protection before coverage is up risks lockouts. |

The **Remediation Roadmap** dashboard section groups every outstanding finding into its phase,
with a completion count per phase, and flags any item that's `Blocked - waiting on <check>` when
a prerequisite from an earlier phase isn't resolved yet. Anything not flagged as blocked is safe
to work on right now.

**The practical workflow:**

1. Run the assessment (or receive the report). Read the baseline banner first, so you know what
   target this was measured against.
2. Open the **Remediation Roadmap**. Work phase 1 to completion (or as close as practical) before
   moving to phase 2, and so on - a `Blocked` item is a signal to finish its dependency first,
   even if the blocked item itself looks technically easy to just switch on.
3. Use the **Security Info Registration Triage** list to drive the actual user-facing work in
   phases 2-4: who to nudge, who to clean up.
4. Check **Upcoming Microsoft Deadlines** against your own timeline - some of Microsoft's own
   changes will do part of phase 3/4's job automatically (e.g. the automatic passkey enablement
   for SMS/Voice users), which can shift what's worth prioritizing manually versus what's coming
   either way.
5. Re-run periodically. The **Trend Over Time** chart shows whether the Green count is actually
   moving in the right direction, and a [drift report](../README.md#multiple-tenants-and-drift-over-time)
   between any two runs shows exactly what changed between them - useful for a project check-in
   or a "what happened since last quarter" conversation.
6. Once every phase-5 item is Green (or intentionally Grey - not applicable to this tenant's
   baseline), the tenant matches its SOLL target. New Microsoft rollouts and new rule checks may
   still shift what SOLL means over time, which is exactly why periodic re-assessment matters
   even after reaching Green.

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
- Where computable, **"N user(s) impacted"**. The label under the number always states exactly
  what's being counted, since some of these are necessarily proxies (Graph doesn't expose every
  distinction the deadline itself cares about) - read the label, not just the number. The two
  SMS/Voice-related dates deliberately use two *different* counts, because Microsoft's own
  eligibility criteria for them are different:
  - **2026-09-01** (auto-enablement, not blocking) counts everyone with a phone-based method
    (SMS/Voice) currently **registered at all** - even someone who already has a passkey too.
    Microsoft's own docs confirm a user with a stronger method isn't automatically exempt from
    this date: they can still be nudged on a device/browser where they don't yet have a local
    passkey.
  - **2027-02-01** (mandatory, blocking, no opt-out) counts only users whose phone-based method
    is their **only** registered MFA method - nobody else. This is a narrower, usually smaller
    number than the one above, and it's the one that actually matters for "who gets fully
    blocked on this date." If the two numbers ever come out equal, that's worth a second look -
    either every phone-based user genuinely has nothing else registered, or something's off.
  - Or, for the SSPR-related deadlines, how many SSPR-enabled users aren't SSPR-registered yet.
- For the SSPR-related deadlines specifically, a card can instead say **"Not applicable"** - this
  means no user in the tenant has SSPR enabled at all, so those deadlines genuinely don't apply
  here. Shown deliberately differently from "0 users impacted," which would otherwise look the
  same whether it means "nobody's affected because everyone's already compliant" or "SSPR isn't
  even in use" - two very different things worth being able to tell apart at a glance.
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

### 6. What Users Can Expect (IST vs. SOLL)

Four real, Microsoft-documented end-to-end flows, each traced step by step against this
tenant's actual settings - not another single-setting check, but "what does a user actually go
through." Each flow shows an **IST** line (what's true today) and a **SOLL** line (the
recommended target), followed by a numbered list of steps. Each step carries one of three
badges:

- **IST: happens today** (green) - this step currently occurs in this tenant, given its
  collected settings.
- **IST: does not happen today** (grey) - this step is currently blocked or unavailable, and why
  is explained underneath.
- **Fixed Microsoft behavior** (neutral) - not conditioned on any tenant setting; included for
  context (e.g. a passkey registration requiring MFA within the last 5 minutes is true
  everywhere, not something this tenant chose).

The four flows:

- **New User Bootstrap** - a new user's first sign-in with a Temporary Access Pass, through to a
  later registration-campaign nudge (deliberately on a *different* sign-in, since Microsoft
  never nudges someone in the same session they just registered a method in). Surfaces a real,
  easy-to-miss limitation: if that same user is also in scope for the SSPR or MFA registration
  policy, they can be redirected into a forced registration wizard that currently doesn't support
  registering a passkey or phone sign-in directly - only outside that redirect can those be set
  up. Last step: once the user has more than one method registered, System-Preferred
  Authentication can start presenting the newest one first on a *later* sign-in.
- **SSPR Eligibility & Two-Gate** - whether a standard user, and separately an administrator, can
  actually register for and use self-service password reset. Admin accounts follow their own
  built-in policy, independent of the general SSPR setting - see the SSPR002 explanation above
  for the trap this can create.
- **Existing User Re-Registration** - what happens after initial setup: managing security info
  any time, the fixed 5-minute MFA-freshness rule for passkey changes, how the registration
  campaign's snooze limit behaves, and whether periodic reconfirmation is configured. First
  step: at *ordinary* sign-in (not registration), System-Preferred Authentication may already be
  presenting this user's strongest registered method first - not necessarily the one they're
  used to - which is worth knowing before assuming a "why did my sign-in screen change" question
  is a problem rather than this setting working as configured.
- **CA-Gated Registration** - how an enabled Conditional Access policy scoped to "Register
  security information" reshapes every flow above: registration-campaign nudges are suppressed
  entirely (not just delayed) for a blocked user, and a Temporary Access Pass-only user can be
  fully locked out if that policy's authentication strength doesn't accept a TAP. Also notes a
  fixed Microsoft behavior worth knowing: Conditional Access is validated only for the second
  factor and never overrides what System-Preferred Authentication presents at the first factor -
  the two settings don't interact the way they might seem to.

Each flow links to the specific Microsoft Learn article it's grounded in - worth opening if a
step's applicability looks surprising.

### 7. Security Info Registration Triage

A per-user list, grouped into one expandable/collapsible section per bucket - click a section's
header to open or close it. Remove/Hunt/Guest start open (there's something to act on); OK
starts closed, since there's nothing to do there and it's usually the longest list. The buckets:

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

A user may also carry a **"WHfB-Only (Not Portable)"** badge. Windows Hello for Business is
bound to the specific Windows device it was set up on - unlike a FIDO2 security key or a
passkey, it can't be carried to a different machine. A user flagged here has a phishing-
resistant method registered (so they still land in OK/Remove normally, same as anyone else with
one), but WHfB is the *only* kind they have - meaning off that one device, they effectively have
no working phishing-resistant credential at all. This matters most for admin accounts: many
admins don't do routine interactive sign-in on a managed Windows device with their admin account
(PIM activation from elsewhere, a jump box, browser-only workflows), so WHfB alone may not
actually be usable when it counts.

A user may also carry a **"SMS/Voice-Only MFA"** badge - always inside the Hunt bucket, since
having a phishing-resistant method already would put them in OK or Remove instead. This badge is
narrower than it might look: it only appears when SMS/Voice is the user's **only** registered
MFA method, nothing else at all. It's the precise population Microsoft's 2027-02-01 SMS/Voice
retirement blocks with a mandatory, no-opt-out passkey registration prompt (see Upcoming
Microsoft Deadlines above) - a user with SMS registered alongside, say, Authenticator push is
not in this population, even though they'd still count toward the broader 2026-09-01 milestone's
impact number. Highest-priority group to reach out to before that date, since they have no
fallback at all once it lands.

A registered method may also carry a **"Disabled by policy"** badge - a stronger claim than "not
recently used" below: the tenant's own authentication methods policy currently has that method
type turned off entirely, so the registration structurally cannot be used to sign in anymore,
not just "probably abandoned." Safe to clean up. Windows Hello for Business is never flagged
here specifically because there's no tenant-level on/off toggle for it to check against (it's
governed by a different, device-level policy) - its absence from this badge doesn't mean it's
fine, just that this particular check can't see it.

Finally, a registered method itself may carry a **"Not recently used"** badge. Being registered
only means a method is available - it says nothing about whether anyone has actually used it.
This badge means no successful sign-in in the last N days (shown in the section note, 90 by
default) used that method: it could mean the device it lived on is gone, the user relies on
something else day to day, or the registration is simply stale - not a confirmed problem on its
own, but worth a quick check rather than assuming either way. Only a well-established subset of
method types is checked for this (FIDO2, Windows Hello for Business, Temporary Access Pass,
SMS/voice, Microsoft Authenticator push/OTP, email, certificate) - a registered method type with
no badge here wasn't necessarily used recently, it just wasn't evaluated, since Microsoft Graph's
registration data and sign-in log data use two different naming schemes with no documented
one-to-one mapping between them.

### 8. Authentication Methods Policy Inventory

Every authentication method's tenant-wide policy configuration, in plain language: enabled/
disabled state, who's included/excluded (counts only - no group/user names shown, to avoid an
extra Graph call this toolkit doesn't otherwise need), and key settings (e.g. FIDO2's attestation
and self-service registration, Temporary Access Pass's default lifetime and one-time-use). This
is independent of the pass/fail checks above - the full picture, useful for understanding *why*
a check passed or failed, or for a general "what's actually configured" review.

The last row, **System-Preferred Authentication**, is a different kind of setting from everything
above it: it controls what gets *presented* at sign-in for a credential the user already has -
not what gets nudged for registration. It genuinely has three distinct behaviors, not a simple
on/off: **Disabled** (no change to sign-in order), **Enabled** (the strongest registered method
is presented first, but only for the second factor - first-factor sign-in is unchanged), and
**Microsoft managed** (the same ranking applied to *both* first and second factor - counterintuitively
the behavior behind the *unset/default* state rather than something an admin has to opt into).
Microsoft is gradually rolling the Microsoft-managed behavior out through August 2026, so a
tenant showing "Microsoft managed" here may not yet actually be experiencing it - see the matching
card in Upcoming Microsoft Deadlines. Because this changes what a specific user sees at sign-in,
its influence is also woven directly into the "What Users Can Expect (IST vs. SOLL)" flows above,
rather than only appearing here as a policy setting.

### 9. Conditional Access Policy Inventory

Every Conditional Access policy in the tenant, in plain language: name, state (on/off/report-
only), who it targets, what it requires. This is independent of the pass/fail checks above - it's
the full picture, useful for understanding *why* a check passed or failed, or for a general
CA hygiene review that isn't captured by any single rule.

### 10. Flat findings table

Every individual check, its result, and its severity - the same data as the flat report, kept
here too so you don't need to cross-reference two files while reading.

One entry worth calling out specifically: **"Admins Excluded From User SSPR Policy When Admin
SSPR Is Disabled"**. Administrator accounts get self-service password reset through their own
built-in policy, entirely separate from the general SSPR configuration end users are subject to
- so an admin showing as SSPR-enabled while the tenant's general SSPR setting looks "off" is
normal, not a bug. This check only fires when admin SSPR has been *explicitly disabled*
tenant-wide (a deliberate, admin-only lockdown) but at least one admin is still in scope of the
regular user-facing SSPR policy. Left that way, Microsoft's own documentation confirms that admin
gets stuck: still prompted to register for SSPR, but shown a message that they can't actually
register any method, since admin SSPR is off regardless of what the user policy says. The fix is
to explicitly exclude administrators from the user-facing SSPR policy once admin SSPR is turned
off. This check shows Grey whenever admin SSPR is enabled (the default) - there's nothing to
exclude admins from in that case.

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

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

## The report file

Every run produces one report, at `reports/<tenant>/<run-timestamp>/dashboard/index.html`:
the results, plus context, trends, a prioritized work plan, and supporting detail. It ships with
its own `vendor/` folder, so zip the whole `dashboard/` directory to share it - the page needs
those files alongside it and won't render correctly on its own. No internet access required to
view it.

Earlier versions also wrote a flat `assessment-report.html` next to it. That's gone. It dated
from before this dashboard existed, and every section added since landed in the dashboard only,
so it had started to disagree with the dashboard about the same tenant rather than just repeat
it. One file, one answer.

The rest of this document walks through the dashboard, tab by tab.

## Reading the dashboard

The dashboard is organized into five tabs across the top. Nothing is hidden - every tab is just a
grouping of the same run's results, split so no single page becomes an unreadable scroll:

| Tab | What's on it | Use it when |
|---|---|---|
| **Overview** | Baseline banner, Microsoft deadlines, the Green/Yellow/Red/Grey headline numbers, charts, trend over time | You want the summary, or you're presenting to someone who won't read further |
| **Findings & Roadmap** | The prioritized work plan, and every individual finding with its recommendation | You're deciding what to actually do, and in what order |
| **User Journeys** | The four end-to-end user flows, and the per-user registration triage list | You're working out what real people will experience, or who to contact |
| **Policy Inventory** | Authentication methods policy, FIDO2 key restrictions, Conditional Access policies, per-category detail | You're checking *why* something passed or failed, or doing a config review |
| **Reading This Report** | This document, embedded in the dashboard itself | You're handing the file to someone who hasn't seen one before |

Charts live on Overview because a chart drawn inside a hidden tab renders at zero size - so
Overview is always the tab that opens first.

## Overview tab

### The baseline banner

Right at the top: which SOLL baseline this run was measured against (e.g. *"hybrid-ad-passwords-
required"*), and whether it was auto-detected from the tenant's own configuration or set
explicitly. If the tenant profile looks off, this is the first thing to check.

### Upcoming Microsoft Deadlines

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

### The headline numbers

The counts: how many checks are Green (meets SOLL), Yellow (partial/lower-severity
gap), Red (fails SOLL, the priority list), and Grey (not applicable to this tenant/baseline -
e.g. a passkey-attestation check when passkeys aren't in use at all). Grey is not a failure; it
means the check doesn't apply here.

### Trend Over Time

If this tenant has been assessed more than once, a chart plots Green/Yellow/Red/Grey counts
across every past run. This is the "are we actually making progress" view - useful for check-ins
during a remediation project, not just the point-in-time snapshot.

## Findings & Roadmap tab

### Remediation Roadmap - the IST-to-SOLL work plan

This is the most actionable section, and the answer to "what do we actually do about this." See
[From IST to SOLL](#from-ist-to-soll-the-work-plan-itself) below for how to use it.

### Risk Findings & Recommendations

Every individual check that isn't already Green, with its severity and the specific recommendation
attached to it. Two entries are worth calling out because they surprise people; both are described
in full under [Findings worth explaining](#findings-worth-explaining) below.

## User Journeys tab

### Who Will Be Nudged (Communication Planning)

The section to read *before* changing anything. It answers "which of our people are going to get
interrupted at sign-in, and can we tell them first" - because an unannounced registration prompt
is a help-desk call and a dent in trust, not a technical failure.

Four different interrupts are forecast separately, because they have different triggers, different
populations, and different escape hatches:

- **Automatic passkey enablement (2026-09-01)** - the one to plan around first, because the date
  isn't yours. Users enabled for SMS or Voice get auto-enabled for passkeys and nudged on their
  next MFA sign-in, whether or not you've configured a campaign yourself. Unlimited snoozes by
  default, so it's a recurring prompt rather than a wall.
- **Registration campaign - passkey** and **- Microsoft Authenticator** - your own campaign, if
  one is active. Fires after a successful MFA for in-scope users who don't already have the
  targeted method.
- **SSPR registration interrupt** - users who are SSPR-enabled but not registered. Worth knowing:
  if only SSPR registration is enforced (no MFA registration policy alongside it), users can skip
  this **indefinitely**, so it's a nag that never resolves itself rather than something that
  completes on its own.
- **Broken: admin prompted but cannot register** - not a nudge so much as a defect to fix before
  anyone reports it. These admins get interrupted to register and are then shown a message saying
  they can't register anything. See the SSPR002 explanation below.

Each card expands to the **named users** behind the count, so the list can go straight into a
comms tool rather than being re-derived by hand.

**If a warning appears saying the campaign "currently reaches nobody,"** take it seriously: it
means the tenant has attestation enforced, AAGUID key restrictions, blocked self-service
registration, or a blocking Conditional Access policy - all of which Microsoft documents as
suppressing the nudge. The campaign will look correctly configured in the admin center and quietly
prompt no one. Note this does *not* stop the 2026-09-01 automatic enablement, which Microsoft
drives independently of your campaign.

**Treat the counts as a planning estimate, not a guarantee.** Two limits are stated on the section
itself and are worth repeating: the passkey nudge is evaluated per *device and browser*, not per
account (so someone who already has a passkey can still be prompted on a different machine), and
several documented suppressors are invisible to this toolkit (terms-of-use screens, Conditional
Access custom controls, existing SSO sessions, Linux clients). The forecast deliberately
over-estimates, since over-communicating is the cheaper mistake.

**If the passkey or Authenticator campaign card says "Scope uncertain" and shows "up to N users,"**
the reason shown depends on how your campaign is configured - there are two different causes, and
they call for different follow-up:

- **Targets specific group(s).** Your campaign has custom include/exclude targets pointing at
  group(s) rather than everyone, and this toolkit doesn't resolve group membership from Graph (it
  would need an extra call per group). The N is every user tenant-wide who lacks the target method
  - not filtered down to who's actually in your campaign's group(s) - so it's a ceiling, and the
  real number nudged is very likely smaller. Check **Authentication methods > Registration
  campaign** in the admin center to see which group(s) the campaign actually targets, and
  cross-reference against that group's real membership for an accurate count. Note that Microsoft
  managed mode does **not** prevent this - Microsoft's own documentation confirms include/exclude
  targets remain configurable even when the campaign is Microsoft managed, only the target
  authentication method and snooze settings are locked in that mode.
- **Microsoft managed, no custom targets configured.** Your campaign is Microsoft managed (state:
  `default`) and you haven't set any include/exclude targets at all - there is no group to look up.
  This is the same fact as the **"Rollout timing not confirmed"** badge on the Registration
  Campaign row in the **Policy Inventory** tab: Microsoft documents Microsoft-managed settings as
  rolling out incrementally per tenant, on Microsoft's own batch schedule, not something this
  toolkit can observe. For this specific setting, the effective population moves from SMS/Voice
  users only to all MFA-capable users, and which stage your tenant is currently in isn't exposed
  through Graph. The N assumes the broader population (all MFA-capable users) as the safer upper
  bound; if your tenant hasn't reached that rollout stage yet, the true number currently nudged may
  be smaller. The same principle applies to any other setting marked Microsoft managed in this
  report (e.g. System-Preferred Authentication) - Microsoft managed generally means "on Microsoft's
  stated default, not customized by this tenant, with rollout timing this toolkit cannot confirm,"
  not "locked to a specific configuration you can rely on today."

**"Eligible, but a campaign cannot reach them"** is the card to act on differently from the rest.
These users are forecast to be nudged but did no *interactive* sign-in during the collected window,
so a campaign has no opportunity to prompt them at all. This is the population most often misread
as "users ignoring the prompt" when they're simply never shown one, and it needs direct outreach
(email, service desk, their manager) rather than a firmer campaign. Two limits on reading it: the
window is bounded by Entra's own log retention (seven days on Entra ID Free, 30 days on P1/P2), so
it means "not within retention" rather than "never"; and a genuinely dormant account looks identical
to someone who just didn't sign in interactively that month.

**This tells you who is eligible, not when they'll see it.** A nudge is a piece of UI shown during
an interactive sign-in that completes MFA. Microsoft defines non-interactive sign-ins as ones that
require no authentication factor and never interrupt the session, so they structurally cannot carry
a nudge: a token refresh, single sign-on to an app on a joined device, or opening a second Office
app on a machine that already has a session. In practice that means someone who leaves their laptop
signed in and works out of Outlook and Teams all day may be eligible for weeks without ever being
prompted. It also means slow-moving registration coverage often isn't users ignoring the prompt,
it's users never being shown it - and those two problems need different fixes, since no amount of
campaign tuning reaches someone the campaign can't interrupt. Broadly: browser sign-ins are where
nudges land reliably, native apps sometimes (Microsoft says "certain applications", and excludes
Windows out-of-box experiences), mobile depends on both the platform and which method the campaign
targets, and Linux is never nudged.

### What Users Can Expect (IST vs. SOLL)

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
- **Unknown - verify directly** (amber) - the opposite case: this step genuinely IS conditioned
  on a tenant setting, but this toolkit has no way to read that setting from Graph. Don't read
  this the same as "Fixed Microsoft behavior" - it means "go check the admin center," not "this
  is the same everywhere."

The four flows:

- **New User Bootstrap** - a new user's first sign-in with a Temporary Access Pass, through to a
  later registration-campaign nudge (deliberately on a *different* sign-in, since Microsoft
  never nudges someone in the same session they just registered a method in). Surfaces a real,
  easy-to-miss limitation: if that same user is also in scope for the SSPR or MFA registration
  policy, they can be redirected into a forced registration wizard that currently doesn't support
  registering a passkey or phone sign-in directly - only outside that redirect can those be set
  up. Also traces a second, separate limitation: registering "Passkey in Microsoft Authenticator"
  on a different device than the phone it will live on (e.g. TAP entered on a laptop) is
  genuinely supported cross-device, Microsoft hands off to the phone via a QR code / app-open
  prompt, but the phone must independently complete its own sign-in and MFA inside the
  Authenticator app rather than inheriting the laptop's TAP session. Whether a brand-new user can
  actually get through that phone-side step depends on two settings already collected elsewhere
  in the report: a one-time-use TAP (TAP001) is consumed reaching Security Info on the laptop and
  leaves nothing for the phone, and the fallback Bluetooth-based path Microsoft documents for this
  case is unavailable whenever FIDO2 attestation is enforced (PASS001). With both settings at
  their recommended values at once, a brand-new user can be left with no way to complete this
  specific bootstrap path, Windows Hello for Business (same device, no handoff) or a short-lived
  multi-use TAP for onboarding are the practical ways around it. Last step: once the user has
  more than one method registered, System-Preferred Authentication can start presenting the
  newest one first on a *later* sign-in.
- **SSPR Eligibility & Two-Gate** - whether a standard user, and separately an administrator, can
  actually register for and use self-service password reset. Admin accounts follow their own
  built-in policy, independent of the general SSPR setting - see the SSPR002 explanation below
  for the trap this can create.
- **Existing User Re-Registration** - what happens after initial setup: managing security info
  any time, the fixed 5-minute MFA-freshness rule for passkey changes, how the registration
  campaign's snooze limit behaves, and whether periodic reconfirmation is configured. First
  step: at *ordinary* sign-in (not registration), System-Preferred Authentication may already be
  presenting this user's strongest registered method first - not necessarily the one they're
  used to - which is worth knowing before assuming a "why did my sign-in screen change" question
  is a problem rather than this setting working as configured. **The reconfirmation step can show
  "Unknown - verify directly" instead of a yes/no answer** when this tenant hasn't finished
  migrating off the legacy MFA/SSPR policies (`policyMigrationState` isn't `migrationComplete`)
  and the modern policy has no reconfirmation interval set. That's not indecision - it means the
  classic **Password reset > Registration** admin blade has its own separate "Number of days
  before users are asked to reconfirm their authentication information" setting, which this
  toolkit has no way to read from Graph, and Microsoft documents legacy policy settings as still
  actively respected until migration completes. Check that blade directly rather than assuming
  reconfirmation is off - a tenant can have this configured (180 days is Microsoft's own tutorial
  example) while the modern policy shows nothing.
- **CA-Gated Registration** - how an enabled Conditional Access policy scoped to "Register
  security information" reshapes every flow above: registration-campaign nudges are suppressed
  entirely (not just delayed) for a blocked user, and a Temporary Access Pass-only user can be
  fully locked out if that policy's authentication strength doesn't accept a TAP. Also notes a
  fixed Microsoft behavior worth knowing: Conditional Access is validated only for the second
  factor and never overrides what System-Preferred Authentication presents at the first factor -
  the two settings don't interact the way they might seem to.

Each flow links to the specific Microsoft Learn article it's grounded in - worth opening if a
step's applicability looks surprising.

### Security Info Registration Triage

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

**This badge gets more important, not less, in late 2026.** Microsoft is making Windows Hello for
Business and macOS Platform SSO count as standalone MFA factors (Message Center MC1450134, rolling
out roughly October to November 2026). That's a genuine usability win, but it carries a side effect
stated in Microsoft's own post: users holding only these device-bound credentials will no longer be
automatically prompted to register additional MFA methods. Today this population slowly
self-corrects, because Entra keeps nudging them toward a second method. After that change it stops
self-correcting, while the underlying exposure (no way to complete MFA from any device that doesn't
carry the credential) stays exactly the same. The mitigation is to get these users a *portable*
backup method deliberately - a synced passkey, or a passkey in Microsoft Authenticator - rather
than assuming the prompts will handle it. The Upcoming Microsoft Deadlines section carries this
date along with the affected count for this tenant.

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

## Policy Inventory tab

### Authentication Methods Policy Inventory

Every authentication method's tenant-wide policy configuration, in plain language: enabled/
disabled state, who's included/excluded (counts only - no group/user names shown, to avoid an
extra Graph call this toolkit doesn't otherwise need), and key settings (e.g. FIDO2's attestation
and self-service registration, Temporary Access Pass's default lifetime and one-time-use). This
is independent of the pass/fail checks above - the full picture, useful for understanding *why*
a check passed or failed, or for a general "what's actually configured" review.

The last two rows, **Registration Campaign** and **System-Preferred Authentication**, are a
different kind of setting from the 8 method rows above them - and easy to confuse with each
other. Registration Campaign controls what gets *nudged for registration*; System-Preferred
Authentication controls what gets *presented at sign-in* for a credential the user already has.
Both genuinely have three distinct behaviors, not a simple on/off:

- **Disabled** - no campaign nudge / no change to sign-in order.
- **Enabled** - the admin's own configured settings apply exactly as configured (target method,
  snooze duration and limit for the campaign; second-factor-only ranking for System-Preferred
  Authentication).
- **Microsoft managed** - Microsoft's own recommended defaults apply instead, incrementally
  rolled out on Microsoft's own schedule. Counterintuitively, this sits behind the *unset/default*
  state rather than something an admin explicitly opts into.

**When either row shows "Microsoft managed," it carries two badges, not one** - a blue state
badge naming the setting, and a separate amber **"Rollout timing not confirmed"** badge next to
it. They mean different things on purpose: the blue badge is what's *configured*; the amber one
is a warning that Microsoft communicating a start date for a Microsoft-managed change (e.g.
"gradually deployed... through August 2026") does **not** mean every tenant already has the new
behavior by that date. Tenants are migrated in batches on a schedule this toolkit has no way to
observe - a tenant could be on the old defaults, the new ones, or partway through the transition,
regardless of what today's date is relative to Microsoft's announcement. The Settings column's
description for a Microsoft-managed row is Microsoft's stated *intent*, not a confirmed fact for
this specific tenant right now - hover the amber badge for the full explanation, and check the
admin center directly if the exact current behavior matters in the moment. Neither row is a
rules-engine pass/fail finding, for the same reason. Because System-Preferred Authentication
changes what a specific user sees at sign-in, its influence is also woven directly into the "What
Users Can Expect (IST vs. SOLL)" flows above, rather than only appearing here as a policy
setting.

### FIDO2 Key Restrictions

Only shown when the tenant actually enforces key restrictions (and FIDO2 is enabled at all) -
otherwise there's nothing to list and the section is omitted entirely.

Microsoft Graph returns the tenant's allow-list or block-list as bare AAGUIDs: 128-bit identifiers
like `cb69481e-8ff7-4039-93ec-0a2729a154a8`, which tell you nothing on their own. This section
resolves each one to a readable name ("YubiKey 5 NFC", "Microsoft Authenticator (iOS)", "1Password")
where it can, so the question "we restrict keys, but to *what*?" has a visible answer.

Two things to read carefully here:

- The header line states whether this is an **allow-list** (only these may register, everything
  else is rejected) or a **block-list** (everything except these may register). Same list of
  AAGUIDs, opposite meaning.
- An entry marked **Unrecognized** is not a problem in itself. It means a real key or provider
  whose AAGUID isn't in this toolkit's reference table - the table covers Yubico, Feitian,
  SoloKeys, Microsoft Authenticator, and common passkey providers, which is not everything on the
  market. Look it up with the vendor or the FIDO Alliance Metadata Service. The toolkit
  deliberately says "unrecognized" rather than guessing at a name, and flags one entry (Thales)
  as community-sourced rather than vendor-confirmed. See [references.md](references.md) for
  exactly where each name came from.

### Conditional Access Policy Inventory

Every Conditional Access policy in the tenant, in plain language: name, state (on/off/report-
only), who it targets, what it requires. This is independent of the pass/fail checks above - it's
the full picture, useful for understanding *why* a check passed or failed, or for a general
CA hygiene review that isn't captured by any single rule.

### Detail by Category

The same checks as the Findings tab, but grouped by category (Authentication Methods, Conditional
Access, Passkeys, and so on) behind a row of sub-tabs, including the ones already Green. Use this
when you want "show me everything about Passkeys" rather than "show me what's broken."

## Findings worth explaining

These two findings come up in almost every assessment and are the ones most often misread as bugs.

The first: **"Admins Excluded From User SSPR Policy When Admin
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

The second: **"Legacy MFA/SSPR Policy Migration Complete"**. Entra ID has
had two ways to manage authentication methods: the old, tenant-wide legacy per-user MFA policy
and legacy SSPR policy (found under **Multifactor authentication** and **Password reset** in the
admin center), and the modern Authentication Methods Policy this report otherwise focuses on
entirely. Microsoft announced retiring the legacy ones back in March 2023, and since September
30, 2025 they can no longer be *edited* at all - but that's not the same as being *ignored*.
Per Microsoft's own documentation, a tenant that hasn't explicitly completed migration (shown as
**"Migration status: Not started"** or **"In progress"** under **Manage migration** in the
Authentication methods blade) still has those frozen legacy settings actively governing who can
register and use which method, layered on top of whatever the modern policy says. That's a real
blind spot for everything else in this report: a method this dashboard shows as Disabled in the
Authentication Methods Policy Inventory can still be usable in practice via the legacy policy,
which this toolkit has no way to see into (it lives on a separate, older API). The fix is to
finish the migration - Microsoft's own automated guide ( **Authentication methods > Policies >
Manage migration > Begin automated guide**) does most of the work, and the whole process is
documented as fully reversible, so there's no rollout-risk reason to leave it half-done.

## Sources and credits

Nothing in this report is this toolkit's opinion about how Entra behaves. Every behavioral claim
traces to a published source, and the full rule-by-rule mapping (with the date each was last
verified against the live page) is in [references.md](references.md). If a finding is ever
challenged, start there.

**Microsoft documentation** is the primary source throughout: the authentication methods policy,
registration campaign, combined registration, authentication strengths, Temporary Access Pass,
passkey/FIDO2, Conditional Access, SSPR policy, sign-in log and data-retention articles on
Microsoft Learn, plus the Microsoft Graph API reference. Individual articles are linked from the
findings and deadlines they support.

**Microsoft 365 Message Center** posts cover changes announced but not yet in the product
documentation. Because Message Center posts can't be linked publicly, this report cites
[mc.merill.net](https://mc.merill.net), the community mirror maintained by Merill Fernando, so the
reference is checkable by anyone. Verify against your own tenant's Message Center before treating
one as final.

**Community and vendor sources** that contributed material findings, credited because they surfaced
things worth knowing that weren't obvious from the product documentation alone:

- [ourcloudnetwork.com](https://ourcloudnetwork.com/microsoft-entra-just-made-passwordless-mfa-registration-easier/)
  for surfacing the passwordless-registration changes (MC1450133 and MC1450134). The dates recorded
  here come from the Message Center posts themselves.
- [Threatscape](https://www.youtube.com/watch?v=3MC0Hoc8GuA), specifically Ru Campbell's
  walkthrough of passkey deployment pitfalls, which prompted the checks around MFA downgrade,
  device compatibility, and the limits of what "phishing-resistant" covers.
- [passkeydeveloper/passkey-authenticator-aaguids](https://github.com/passkeydeveloper/passkey-authenticator-aaguids),
  a community-maintained AAGUID list used for passkey provider identification.
- Vendor AAGUID references from [Yubico](https://support.yubico.com/hc/en-us/articles/360016648959-YubiKey-hardware-FIDO2-AAGUIDs),
  [Feitian](https://fido.ftsafe.com/products/) and [SoloKeys](https://docs.solokeys.dev/metadata-statements/).

**Software** used to build this dashboard: [Bootstrap](https://getbootstrap.com/) and
[Chart.js](https://www.chartjs.org/), both bundled locally so the report opens without internet
access.

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

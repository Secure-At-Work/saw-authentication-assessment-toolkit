# From IST to SOLL: A Field Guide to Modernizing Entra ID Authentication

Microsoft has set a hard timeline for retiring SMS and voice call as sign-in methods in
Microsoft Entra ID, and passkeys become the default authentication experience along the way.
That announcement is what usually starts this conversation, but SMS/Voice retirement is really
just one deadline sitting inside a much bigger picture: what your tenant's authentication
configuration actually *is* today (**IST**), how all of its moving parts actually interact with
each other, and what a deliberately chosen target state (**SOLL**) looks like for your specific
tenant, plus the order you need to move through to get there safely. This post covers all of
that. (We use the Secure At Work Authentication Assessment Toolkit to run this kind of
assessment against real tenants; it's mentioned where relevant, but the guidance below applies
whether or not you're using it.)

## Why this is harder than it looks

Microsoft Entra ID's authentication behavior is the sum of at least eight separately configured
surfaces, each with its own admin blade and its own Graph endpoint:

- The **Authentication Methods Policy** (which methods are enabled, for whom, with what settings)
- **Conditional Access** policies (who's required to do what, under which conditions)
- **Authentication Strengths** (custom combinations of methods that satisfy "strong" sign-in)
- **Registration data** (who's actually registered what, per user)
- The **Temporary Access Pass** policy (a sub-setting of the methods policy, but with its own
  lifetime/one-time-use rules)
- **SSPR policy**, and this one is actually *two* policies: a general one for end users, and a
  completely separate, easy-to-miss one for administrators
- **Sign-in and audit logs** (what's actually happening, versus what's configured to happen)
- **Tenant profile** (hybrid vs. cloud-native, which changes what "good" even means)

None of these individually tells you whether the tenant is well protected. A Conditional Access
policy requiring MFA means nothing if the users it targets have never registered a method
stronger than SMS. A registration campaign targeting passkeys does nothing if FIDO2 self-service
registration is switched off. An admin SSPR policy that's deliberately disabled can silently
strand admins with a broken registration prompt if nobody remembered to exclude them from the
general user policy. Understanding the tenant means reading all eight surfaces together.

## Part 1: Inventorying IST: what to collect, and why each piece matters

"IST" (German/Dutch for "as-is") is simply the tenant's actual current configuration, collected
without judgment before any comparison against a target happens. Here's what a complete
inventory requires, and why each piece earns its place.

### Authentication Methods Policy

For every method type (Microsoft Authenticator, FIDO2/passkey, SMS, Voice, Email, Temporary
Access Pass, Software OATH, X.509 Certificate), the policy carries: state (enabled/disabled), who
it's scoped to (`includeTargets`/`excludeTargets`, down to the `all_users` well-known target or
specific groups), and method-specific settings that change what the method actually *does*:

- **FIDO2**: `isAttestationEnforced` (are only vetted hardware keys accepted, or anything
  claiming to be a passkey), `isSelfServiceRegistrationAllowed` (can a user register one
  themselves, or does an admin have to provision it)
- **Temporary Access Pass**: default/minimum/maximum lifetime, and `isUsableOnce` (single-use vs.
  multi-use)
- **Microsoft Authenticator**: number matching required, location shown in the approval prompt
- **The registration campaign** (`registrationEnforcement.authenticationMethodsRegistrationCampaign`):
  state (a genuine three-way Disabled/Enabled/Microsoft-managed, not on/off), which method it
  targets (`microsoftAuthenticator` or `fido2`), snooze duration, and whether snoozes are limited
  (forced registration after three skips) or unlimited. See Part 2 for why "Microsoft managed"
  specifically deserves its own paragraph.
- **System-Preferred Authentication** (`systemCredentialPreferences`): a genuinely separate
  setting, easy to conflate with the registration campaign but controlling something different:
  not what gets *nudged for registration*, but what gets *presented at sign-in* for a credential
  the user already has. Covered in full in Part 2.
- **`policyMigrationState`**: whether the tenant has actually finished migrating off the legacy
  per-user MFA policy and legacy SSPR policy onto this one. Deceptively easy to assume is a
  solved problem simply because those legacy policies can no longer be *edited*. See Part 3 for
  why that's a real, checkable gap, not just historical housekeeping.

Target scoping matters here more than it looks: `excludeTargets` lives on the base
`authenticationMethodConfiguration` type common to every method, while each method has its own
typed `includeTargets`. Get the two confused and you'll misread who a policy actually covers.

### Conditional Access policies

Every policy's state, who it targets (all users, specific roles, specific groups), what it
requires (MFA, compliant device, a custom authentication strength), and specifically whether it
targets the **"Register security information" user action** (`urn:user:registersecurityinfo`).
That last one deserves its own callout, because Conditional Access's targeting modes are
mutually exclusive: a policy scoped to "All resources" does **not** also apply to security-info
registration. Only a policy explicitly scoped via user actions reaches that flow. Missing this
distinction is how organizations end up believing registration is protected when it isn't, or,
in the opposite and more dangerous failure, believing a policy that targets registration also
covers ordinary sign-in, when it doesn't.

### Authentication Strengths

Whether a phishing-resistant custom authentication strength exists at all, and, more
importantly, whether anything actually *requires* it. Defining the strength and enforcing it
are two different rules; a tenant can have a perfectly good phishing-resistant strength sitting
unused.

### Per-user registration data

The single richest data source in the whole inventory: for every user,
`userRegistrationDetails` reports `isAdmin`, `isMfaRegistered`, `isSsprEnabled`,
`isSsprRegistered`, and, crucially, `methodsRegistered`, the actual list of methods that
specific person has set up. This is what tells you, per user, whether they:

- Have **no phishing-resistant method at all** and need active nudging toward one.
- Have a phishing-resistant method **and** still have a phone-based fallback registered
  alongside it, a live downgrade-attack surface: an attacker can force the weaker fallback even
  though a stronger method exists, so the fallback should be removed once it's no longer needed.
- Are a guest/external user, worth tracking separately since Microsoft doesn't yet support
  passkey registration for guest accounts, so nudging them toward one isn't actionable advice.
- Have their *only* phishing-resistant method be Windows Hello for Business, which is bound to
  one device: a real problem for admins who don't do routine interactive sign-in from a managed
  machine.
- Have a registered method that the tenant's own policy has since disabled (structurally can't
  be used anymore, safe to clean up), or one that hasn't been used in a successful sign-in in a
  long time (a proxy for staleness, worth a second look).
- Have SMS/Voice as their *only* registered method: the precise population Microsoft's February
  2027 blocking enforcement targets, and worth prioritizing ahead of everyone else relying on
  SMS/Voice alongside something stronger.

### The authorization policy: the admin SSPR trap

One field, easy to miss entirely: `allowedToUseSSPR` on `/policies/authorizationPolicy`. By
default, administrator accounts get self-service password reset through their own **built-in
two-gate policy** (two methods required, security questions prohibited), completely independent
of whatever the general SSPR configuration says for end users. `allowedToUseSSPR` is the actual
switch that turns *admin* SSPR off. Microsoft's own documentation flags a specific, real trap
here: disable admin SSPR without also excluding admins from the general user-facing SSPR policy,
and those admins get stuck, still prompted to register, but shown a message that they can't
register any method, because admin SSPR is off at the tenant level regardless of what the user
policy says.

### Sign-in and audit logs

Two separate windows serve two separate purposes. A short window (7 days is a reasonable
default) checks for successful legacy authentication or device-code-flow sign-ins, both of which
bypass modern Conditional Access controls entirely and are a red flag wherever they still
succeed. A second, deliberately wider window (90 days is a reasonable default) checks whether
*registered* methods are actually being *used*: registration alone doesn't mean a method still
works, the device it lived on might be gone. Audit logs separately catch unexpected credential
changes on break-glass accounts and CA policy modifications made by applications rather than
people, both classic incident indicators.

### Tenant profile

`organization.onPremisesSyncEnabled` determines whether this tenant is hybrid (synced with
on-premises Active Directory, current or former) or cloud-native. This single fact changes what
"good" means for the rest of the inventory: a hybrid tenant may legitimately still need
passwords and SSPR for longer than a cloud-native, passwordless-first one.

## Part 2: How it all actually works together

Individual settings are necessary but not sufficient. The interesting failures happen at the
seams between them, where one setting's behavior depends entirely on another one you weren't
looking at.

### The registration campaign

A registration campaign nudges users to set up either Microsoft Authenticator or a passkey.
Never both at once: it's one target method per tenant. Users complete their normal sign-in and
MFA first; only then are they prompted. If they decline ("Skip for now"), the snooze duration
(0–14 days, configurable) determines when they're asked again; if "limited snoozes" is enabled,
they're forced to register after three skips, otherwise they can defer indefinitely. For a
passkey campaign specifically, the nudge is evaluated **per device-and-browser combination**, not
per user account. A user with a Windows Hello for Business credential is skipped on Windows +
Chrome, but still nudged the moment they sign in from a Mac, because that credential doesn't
transfer. A user is never nudged in the same session they just registered a method in. And the
nudge is silently suppressed for anyone blocked from reaching the registration page by a
Conditional Access policy, which is exactly why the CA trap below matters: a lockout there isn't
loud, it's just an absence of a prompt nobody notices.

The campaign's own state is itself three-valued, not on/off: `disabled`, `enabled` (your own
configured target/snooze settings apply exactly as set), or `default` (which the admin center
labels "Microsoft managed": Microsoft's own recommended defaults apply instead, currently
documented as targeting passkeys over Authenticator, a 1-day snooze, unlimited snoozes, and
targeting every MFA-capable user). Worth flagging explicitly: **Microsoft's own reference docs
for this exact field contradict each other**. The resource reference page states the default
value is `disabled`, while the how-to article describes "Microsoft managed" as an
actively-rolling-out set of new defaults. And even taking the how-to article at face value, a
start date Microsoft announces isn't a guarantee: tenants are migrated onto the new defaults in
batches on Microsoft's own schedule, invisible from the tenant side. A tenant reading "Microsoft
managed" today could be on the old behavior, the new one, or partway through, regardless of how
long ago Microsoft's announced date has passed. If you need certainty about what a specific user
is actually being shown, check that tenant directly rather than trusting the stated default.

### The Temporary Access Pass as bootstrap mechanism

A TAP is how a user with nothing registered yet gets into the system at all: created by an
admin, entered at Security Info instead of a password, and good for either one sign-in or
multiple within its lifetime window. Once signed in with a TAP, the user can register a stronger
method: a passkey (if FIDO2 self-service registration is allowed), Microsoft Authenticator, or,
on Windows, join the device and set up Windows Hello for Business in the same flow. There's a
real operational nuance here: registering a passwordless method with a one-time-use TAP must
happen within 10 minutes of the TAP sign-in, which is why organizations doing device enrollment
plus WHfB setup in one sitting often either issue two single-use TAPs, or enable a multi-use TAP
so the same code covers both steps without a hard clock running underneath.

### The SSPR "two-gate" and its trap

Combined registration serves both MFA and SSPR from the same wizard, but the two policies that
govern it are genuinely separate. For ordinary users, if only SSPR is enforced (no MFA
registration policy alongside it), the registration interrupt can be skipped indefinitely. That's
a real, quiet governance gap: SSPR enforcement without MFA enforcement never actually forces
completion. For administrators, the picture changes entirely: they run on their own built-in
two-gate policy, independent of the general SSPR setting. That's exactly why `allowedToUseSSPR`
being explicitly `false` combined with admins still being in-scope for the *user* policy produces
the broken, confusing prompt described above.

### System-Preferred Authentication: a different mechanic from everything above

Every mechanism so far governs *registration*: what gets set up, and when a user is nudged to set
something up. System-Preferred Authentication (`systemCredentialPreferences`) is something else
entirely: it governs what gets **presented at sign-in** for a credential the user *already has*.
Easy to conflate with the registration campaign, and genuinely a distinct setting with distinct
user-experience impact, confirmed against Microsoft's own concept article
(`concept-system-preferred-authentication`):

- **Disabled**: no change to sign-in order; the user's own default/last-used method keeps
  showing up.
- **Enabled**: the strongest registered method is presented first, but only for the **second**
  factor. First-factor sign-in (e.g. the password prompt) is unchanged.
- **Default / unset** ("Microsoft managed"): the counterintuitive part is that the *unset* state
  is the more far-reaching one, applying the ranking to **both** first and second factor. A user
  with a password and a passkey registered gets prompted with the passkey first, at *first*-factor
  sign-in, ahead of the password screen entirely.

The ranking itself is fixed and documented: Temporary Access Pass outranks everything (recovery
takes priority), then passkey, then certificate-based authentication, then Microsoft Authenticator
notifications, then weaker MFA methods, then telephony (SMS/voice), then password last. The user
can always back out via "Sign in another way," but the *default* screen they see changes, which is
exactly the kind of thing that generates a wave of "why does my sign-in look different" tickets if
nobody was told to expect it. The Microsoft-managed behavior is being **gradually rolled out
through August 2026**, so two tenants that have both left this setting untouched may currently be
experiencing different things, purely based on where they are in that rollout.

One structural nuance worth carrying into the next section: Conditional Access is validated only
for the **second** factor. It doesn't see, and can't override, what System-Preferred Authentication
decides to show at the first factor: authentication happens first, and only afterward does
Conditional Access evaluate authorization.

### Conditional Access on the registration page itself

A policy scoped to `urn:user:registersecurityinfo` governs *how* and *where* users are allowed to
register or update their security info, often used to confine that to a trusted network or
compliant device during onboarding. The trap: if that policy's grant control is a **custom
authentication strength** whose `allowedCombinations` doesn't include
`temporaryAccessPassOneTime` or `temporaryAccessPassMultiUse`, a user relying on a TAP as their
only way in (precisely the population being pushed toward passkey registration by every
mechanism above) can never reach the page that would let them register one. A plain `mfa`
built-in control doesn't cause this; a TAP generically satisfies that. Only a custom strength
without a TAP escape hatch does. And as of **2026-07-06**, this same policy scope additionally
governs Windows Hello for Business and macOS Platform SSO credential registration too, which it
previously didn't evaluate at all. That widens the blast radius of any policy that already has this
gap. This CA policy governs whether the registration page is *reachable*: it still has no say over
what System-Preferred Authentication presents on the way there.

### Tracing it end to end

Individually, every mechanism above is documented somewhere in Microsoft's own docs. What's
harder to find anywhere is the *combined* trace: what does a specific user, in your specific
tenant, with your specific settings, actually experience? Four scenarios are worth deliberately
tracing through, step by step, against your own tenant's real settings:

1. **New User Bootstrap**: first sign-in with a TAP, through to a registration campaign nudge on
   a *later* sign-in (never the same session), and then to System-Preferred Authentication
   potentially promoting that new credential to the front on a *subsequent* sign-in.
2. **SSPR Eligibility & Two-Gate**: whether a standard user, and separately an admin, can
   register for and use SSPR at all.
3. **Existing User Re-Registration**: what managing or refreshing security info looks like after
   initial setup, including the fixed 5-minute MFA-freshness requirement for passkey changes, and,
   before any of that, what System-Preferred Authentication already presented at that user's
   ordinary sign-in.
4. **CA-Gated Registration**: how an enabled "Register security information" policy reshapes
   every flow above, including whether it suppresses campaign nudges or locks out TAP-only users,
   plus the fixed reminder that this CA scope never overrides System-Preferred Authentication's
   first-factor choice.

Each step is either happening today, given your tenant's real settings, or it isn't: this is not
a generic description of how Entra works in the abstract, it's a trace specific to your
configuration.

## Part 3: SOLL: what "good" looks like, and why it isn't one-size-fits-all

SOLL ("should be") is the target state, but there is deliberately no single hard-coded "correct"
answer. A hybrid tenant still tied to on-premises AD may legitimately need passwords and SSPR
for longer than a fully cloud-native, passwordless tenant, and a severity that's appropriate for
one isn't necessarily appropriate for the other. What "good" should mean for your tenant is
worth deciding deliberately, ideally auto-detected as a starting point from a signal like
`organization.onPremisesSyncEnabled` (hybrid vs. cloud-native) and then adjusted for your
specific risk appetite, rather than assumed.

A representative checklist of what "good" actually requires, to make SOLL concrete rather than
abstract:

- **Block legacy authentication tenant-wide** and **require MFA for all users** via Conditional
  Access, the foundational pair almost everything else assumes is already in place.
- **Privileged access protection for admins**, as a composite rather than one hard-coded
  control: a compliant device requirement *or* a phishing-resistant authentication strength
  requirement for admin roles, either one satisfies the intent.
- **Admin and overall MFA registration coverage** at or above a defined threshold, since a
  Conditional Access requirement is meaningless if the people it targets never actually
  registered a method to satisfy it.
- **FIDO2 attestation and key restrictions enforced**, and a defined policy on whether
  cloud-synced passkeys (Google Password Manager, iCloud Keychain, and similar) are acceptable or
  whether only device-bound credentials are, a real, defensible choice either way depending on
  your risk appetite.
- **SSPR registration coverage** among SSPR-enabled users, and, the narrower and easier-to-miss
  check, **admins correctly excluded from the user-facing SSPR policy whenever admin SSPR has
  been deliberately disabled**, closing exactly the trap described above.
- **A phishing-resistant registration bootstrap actually available** (self-service FIDO2, or
  TAP), without which every downstream registration push has nowhere for a brand-new user to
  start.
- **Legacy MFA/SSPR policy migration actually completed**, the one item on this list that isn't
  ambiguous or judgment-dependent at all. Microsoft announced deprecating the legacy per-user MFA
  policy and legacy SSPR policy back in March 2023, and since September 30, 2025 they can no
  longer be *edited*. That's easy to mistake for "solved." It isn't. Per Microsoft's own
  migration-states table, a tenant sitting at `premigration` or `migrationInProgress` still has
  those now-frozen legacy settings *actively respected* for who can register and use which
  method, layered invisibly on top of whatever the modern Authentication Methods Policy says.
  That's a real blind spot: a method that looks Disabled in the modern policy can still be usable
  in practice via the legacy one. The fix (Microsoft's own automated migration guide) is
  documented as fully reversible, so there's no reason to delay it once you know to look for it.

## Part 4: The path from IST to SOLL: five phases, and why the order matters

A list of findings tells you *what's* wrong. It doesn't tell you *what order* to fix things in,
and sequencing genuinely matters here, because doing this out of order creates real incidents,
not just theoretical risk:

| Phase | Goal | Typical actions |
|---|---|---|
| **1. Foundation & Visibility** | Safe immediately, nothing depends on anything else | Block legacy authentication; enable Authenticator, FIDO2, and TAP; audit log and break-glass hygiene; TAP hardening (one-time-use, shorter lifetime) |
| **2. Enable Phishing-Resistant Capability** | Give users something strong to actually register | Turn on FIDO2 self-service registration, attestation, key restrictions; define and be ready to enforce a phishing-resistant authentication strength |
| **3. Drive Registration Coverage** | Get people actually registered, using the bootstrap from Phase 2 | Run the registration campaign; close admin and overall MFA registration gaps; raise SSPR registration coverage |
| **4. Retire Weak Fallback Methods** | Remove the downgrade path, only once it's safe to | Turn off SMS/Voice, but only after Phase 3's coverage is genuinely high enough |
| **5. Enforce via Conditional Access** | Make the target state mandatory, last | Require MFA for all users; require compliant device or phishing-resistant auth for admins |

Concretely: enforcing "MFA required for everyone" (Phase 5) before enough users have a registered
method (Phase 3) risks locking people out entirely. Pushing users to register a passkey before a
bootstrap method exists (Phase 2 not yet done) gives them nothing to act on. Removing SMS/Voice
(Phase 4) before a stronger method is actually registered removes someone's only working factor.
Track which phase each open item belongs to and work through them in order; don't let an
easy-to-fix Phase 4 item jump ahead of an unresolved Phase 2 dependency just because it looks
simpler.

## Part 5: The SMS/Voice retirement, worked through the whole framework

This is where the calendar deadline that usually starts the conversation fits into everything
above, not as a special case but as Phase 1 through 4 applied to one specific, Microsoft-driven
timeline.

Two dates, with genuinely different eligibility criteria, and conflating them is the single most
common way this gets mis-scoped:

**September 1, 2026: passkeys become the default, automatically.** Microsoft auto-enables
passkeys and flips the registration campaign to "Microsoft managed" (targeting passkeys) for
**every user currently enabled for SMS or Voice** in the authentication methods policy: policy
*scope*, not registration state. A user who already has a passkey or WHfB registered is not
automatically exempt: Microsoft's own documentation states plainly that such users "may still
receive prompts to register passkeys on eligible devices," because the nudge-suppression logic
only skips a specific device/browser combination once a qualifying local passkey exists *there*,
not tenant-wide. Unlimited snoozes by default; not blocking.

**February 1, 2027: Microsoft-provided SMS/Voice retires outright, no opt-out.** Narrower
population: only users **whose only available MFA method is SMS or voice** get a mandatory,
blocking passkey registration prompt they cannot skip. A user with SMS *and* Authenticator
registered sails through this date unaffected, even though they were still in scope for the
broader September rollout.

**The opt-out covers only the first date.** Setting
`authenticationMethodsPolicy.optOutSettings.passkeyDynamicMigration` to `true` (via the **beta**
Graph endpoint, the one field on this policy that doesn't exist on `v1.0`) excludes the tenant
from the automatic enablement and registration-campaign rollout for a defined runway. It does
**not** touch the February 1 enforcement in any way; that date applies to every tenant regardless.
Organizations with a genuine regulatory or operational need to keep an SMS/Voice channel have a
documented exception path instead: customer-managed telecom providers become reviewable in the
Microsoft Security Store from September 18, 2026, and configurable from October 30, 2026.

**The trap, again, in this specific context.** If the tenant has a Conditional Access policy
scoped to "Register security information" that demands a custom authentication strength without
a TAP escape, a user with no phishing-resistant method yet (exactly the population this whole
rollout is trying to move) can be locked out of the very page that would let them register one.
This is the same mechanism described in Part 2, just now colliding with a live Microsoft rollout
instead of a hypothetical.

**The migration order is Phases 1 through 4, applied here specifically:**

1. Find out who's actually relying on SMS/Voice today, and specifically who has *nothing else*
   registered: the real February 1 exposure, not everyone with a phone number on file (Phase 1
   visibility work).
2. Confirm a bootstrap path exists: FIDO2 self-service registration allowed, and TAP not
   accidentally walled off by the Conditional Access trap above (Phase 1/2).
3. Turn on the registration campaign deliberately, targeting passkeys, before Microsoft does it
   automatically. This gives you control over snooze limits and targeting instead of inheriting
   Microsoft-managed defaults (Phase 3).
4. Prioritize the highest-risk group first: SMS/Voice-only users, admins especially. Everyone
   else has a fallback and can follow at normal pace.
5. Only then retire SMS/Voice, once coverage is genuinely high enough (Phase 4).
6. Communicate on Microsoft's own recommended cadence (awareness, then action, then a reminder
   for stragglers), scoped to the group identified in step one, not a blanket announcement.

## One known limitation worth naming

Per-user legacy MFA state, the classic Disabled/Enabled/Enforced flag from the old "per-user
MFA" admin experience (`perUserMfaState`, readable via
`GET /beta/users/{id}/authentication/requirements`), is easy to overlook in this whole exercise.
Unlike the report-style endpoints most of the above is built on, there's no bulk way to read it:
one Graph call per user. It doesn't matter equally everywhere. For a Conditional-Access-based
tenant (the default assumption throughout this piece), Microsoft's own guidance is that this
should sit at `Disabled` and be left alone once CA is in place; a stray `Enabled`/`Enforced` user
left over from before CA adoption is mostly a cleanup item. But for a tenant with no Conditional
Access at all (Entra ID Free, no P1/P2), per-user MFA is the *only* enforcement mechanism that
exists, and it's worth checking explicitly rather than assuming it's covered by everything above.

## The practical workflow, in short

1. Inventory IST first, in full, before deciding anything. Know your baseline (hybrid vs.
   cloud-native) so you're measuring against the right target.
2. Work Phase 1 through 5 in order. A Phase 4 or 5 item that looks easy to switch on is still
   blocked if its Phase 1–3 prerequisite isn't resolved yet; fix the dependency first, even when
   the later item looks simpler.
3. Drive the people-side work (who needs nudging toward a phishing-resistant method, who has a
   fallback to remove, who's at risk from an upcoming Microsoft deadline) off the per-user data
   from Part 1, and trace the four end-to-end flows from Part 2 whenever a specific mechanism's
   behavior is in question rather than assumed.
4. Check upcoming Microsoft-driven deadlines against your own timeline. Some of this work happens
   on Microsoft's schedule regardless, which changes what's worth prioritizing manually versus
   what's coming either way.
5. Re-assess periodically rather than once. New Microsoft rollouts and new gaps discovered shift
   what SOLL means over time, so periodic re-assessment stays worthwhile even after reaching a
   clean state. (This is the part a repeatable, read-only assessment like the Secure At Work
   Authentication Assessment Toolkit is built to make easy: a phased work plan of exactly what's
   still open and in what order, a per-user triage list, and a trend view across repeat runs, so
   the sequencing above doesn't have to be re-derived by hand every time.)
6. Once every Phase 5 item is genuinely satisfied, the tenant matches its SOLL target, for now.
   New Microsoft rollouts and new checks shift what SOLL means over time, which is why periodic
   re-assessment stays worthwhile even after reaching that point.

---
*Secure At Work, Microsoft 365 &amp; Entra ID security assessments.*

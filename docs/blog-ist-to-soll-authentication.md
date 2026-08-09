# From IST to SOLL: A Field Guide to Modernizing Entra ID Authentication

Microsoft is retiring SMS and voice call as sign-in methods in Entra ID, and making passkeys the
default. That announcement is what usually starts this conversation, and it gets read as a
compliance deadline: something to be done by a date, on Microsoft's schedule.

It is worth understanding why the deadline exists. Microsoft is not retiring SMS because it is
old. It is retiring SMS because attackers stopped bothering with passwords years ago and went
after the second factor instead, and adversary-in-the-middle phishing kits now defeat one-time
codes and push approvals as a matter of routine. The deadline is the defender's side of an arms
race, and it is already several moves in.

Which is also why "turn on passkeys" is not the end of the story. Through 2026, security
researchers have been taking the passkey layer apart in public, with working tools. Some of what
they found is patched. Some of it is not. And several of their recommendations are configuration
choices, in your tenant, that no deadline will make for you.

So this post is about three questions, in order:

1. **What is actually at risk**, and what the current attack research does and doesn't change.
2. **What your tenant looks like today** (**IST**), how to inventory it, and why each piece
   matters. This is the part most people skip, and it is the part that determines whether
   anything you do next is safe.
3. **What "good" looks like for your tenant specifically** (**SOLL**), the five phases to get
   there, and why the order is not negotiable.

We use the Secure At Work Authentication Assessment Toolkit to run this kind of assessment
against real tenants. It's mentioned where relevant, but everything below applies whether or not
you use it.

## The short version

If you read nothing else:

- **Inventory before you change anything.** Entra's authentication behaviour is the sum of eight
  separately configured surfaces. Any one of them read alone will mislead you. A Conditional
  Access policy requiring MFA means nothing if the users it targets only have SMS registered.
- **Sequence matters more than speed.** Enforcing MFA before people have registered a method
  locks them out. Removing SMS before a stronger method is registered removes someone's only
  working factor. There is a correct order: capability, then registration, then removal, then
  enforcement.
- **Tell people before Microsoft does.** Several of these changes now arrive on Microsoft's
  schedule whether or not you have communicated them. You can find out in advance exactly who
  will be interrupted.
- **Phishing-resistant is a direction, not a finish line.** Requiring a phishing-resistant
  authentication strength in Conditional Access is the right move and you should still do it. It
  is not, on its own, sufficient for your highest-value accounts, and the research below is
  specific about why.
- **For admins, prefer device-bound passkeys and enforce attestation.** This is the single
  clearest configuration recommendation to come out of the 2026 attack research, and it is two
  toggles in the same blade.

## Why now: the attacker's side of this

The uncomfortable framing is that this is a cat-and-mouse game, and announcing a migration to
passkeys does not end it. It moves it. Two pieces of published research from 2026 are worth
knowing about before you decide what your target state is, because both of them change specific
configuration decisions rather than just adding background anxiety.

### Passkeys are being attacked as an implementation, not as a cryptosystem

At Black Hat USA 2026, Michael Grafnetter of SpecterOps presented the
[Pass-the-Passkey family of attacks](https://specterops.io/wp-content/uploads/sites/3/2026/08/Pass-the-Passkey_A4_v2.pdf):
three exploitable zero-day vulnerabilities in Windows 11 and Entra ID, more than twenty attack
techniques, and open-source tooling to reproduce them.

The important thing to understand is *where* the weaknesses were. WebAuthn's phishing resistance
comes from two properties: the browser records the true origin of the page (so a phishing site
cannot obtain a usable assertion), and each ceremony uses a fresh single-use challenge with a
signature counter (so an old assertion cannot be replayed). The cryptography holds. What
Grafnetter found is that the surrounding implementation did not:

- **Windows wrote complete WebAuthn assertions into an event log** readable by authenticated
  unprivileged users, including remote ones. Patched on 14 July 2026 (CVE-2026-34348); fully
  updated systems now truncate the signature so the logged event is still useful for
  troubleshooting but no longer replayable. Microsoft rated it 6.5 Medium; the researcher filed
  it at 8.6 High.
- **Entra ID did not enforce replay protection** on WebAuthn assertions. Microsoft silently
  deployed signature-counter tracking in May 2026, which fixes this for FIDO2 security keys that
  maintain a counter. It is a partial fix: per the paper, "Windows Hello passkeys on Entra ID
  registered devices remain vulnerable to replay, because Windows Hello always sends a counter
  value of 0." Some synced-passkey implementations don't maintain counters either.
- **A Credential UI window handle spoofing issue** lets malware raise Windows authentication
  dialogs that look trustworthy, and flood the user with them until one is approved. Microsoft
  assessed this as Low severity in the Defense in Depth category, which in practice means it is
  not being fixed.

Two findings from that work deserve to be read twice by anyone who has just finished rolling out
a phishing-resistant Conditional Access policy. First: the exploit "satisfies the
phishing-resistant multi-factor authentication requirement enforced by conditional access
policies." Second: during testing against users licensed for Microsoft 365 E5, with Entra
Identity Protection and Defender for Identity active, "no alerts or other security signals were
generated."

The paper's own recommendation to administrators is correspondingly blunt: *do not rely solely on
the phishing-resistant MFA requirement in Conditional Access for high-value identities and
applications*, keep Windows 11 current, enforce passkey attestation for high-value users, and
prefer device-bound passkeys over synced ones for those accounts.

### Windows Hello keys can be borrowed without the PIN

Separately, Dirk-jan Mollema published
[Borrowing Windows Hello Keys for Authentication and Persistence](https://dirkjanm.io/borrowing-windows-hello-keys/).
The preconditions are modest: a compromised user session on a device with Windows Hello for
Business enrolled, and ordinary user privileges. No local administrator required.

Because Windows Hello has to support Remote Desktop scenarios, the key can be used to sign
assertions through the CNG interface without prompting for a PIN or biometric at all, working
instead from cached state. From there an attacker can sign the assertion needed to request a
Primary Refresh Token, valid for 90 days and renewable. The persistence step is the one that
matters most for how you read your own registration data: using the Windows Hello key counts as
performing fresh MFA, so an attacker can use it to *enrol additional passkeys*. A user who shows
as healthily registered for a phishing-resistant method can be healthily registered for the
attacker's method too.

Mollema is explicit that this is largely a consequence of how Windows Hello is designed rather
than a bug with a clean fix, so the practical response is detection. His suggested signal is
sign-ins where Windows Hello authenticated but no device ID is present, which is unusual outside
of incognito sessions:

```kusto
SigninLogs
| where AuthenticationDetails has '"authenticationMethod":"Windows Hello for Business"'
| where DeviceDetail.deviceId == ""
```

Worth pairing with generic monitoring for unexpected new Windows devices being registered by
users, since device registration is the pivot in the chain.

### The other persistence path: passkeys registered *for* a user

One more technique is worth naming because it is invisible in exactly the reports most people
use to measure progress. Entra supports administrative passkey registration: an admin can enrol a
passkey on behalf of another user. This exists for a good reason, such as mailing pre-registered
security keys to remote hires.

An attacker holding `UserAuthenticationMethod.ReadWrite.All` or
`UserAuthMethod-Passkey.ReadWrite.All` can call the same API to plant what the paper calls a
**shadow passkey**: a persistent credential on a high-value account that keeps working after the
legitimate user changes their password, because a passkey is an independent factor. It shows up
in a registration report as an *increase* in phishing-resistant coverage.

This is the reason the assessment described below treats a per-user registration inventory and an
audit-log review as two different things, and why "coverage went up" is not automatically good
news. Registration counts answer "can this user authenticate strongly." They do not answer "did
this user register that themselves."

### None of this is an argument against passkeys

It would be easy to read the above and conclude that the whole migration is theatre. That is not
what the researchers say, and it is not what the data says. Grafnetter's own conclusion is that
passkeys "are still a significant improvement over passwords," and that organizations should
"adopt them as soon as possible."

The correct reading is narrower and more useful: passkeys decisively win the fight they were
designed for, which is credential phishing at scale. The residual attacks above almost all
require code execution on the user's device or an already-privileged foothold in the tenant. That
is a real risk and a much smaller and more expensive one than "an employee typed their password
into a lookalike page." You are trading a cheap, high-volume, remote attack for an expensive,
targeted, local one. That is what winning a round looks like in this game. It is not the same as
the game ending, which is why the target state below distinguishes between what is good enough for
the workforce and what is good enough for a Global Administrator.

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
  (forced registration after three skips) or unlimited. Part 2, on how these mechanisms actually
  interact, covers why "Microsoft managed" specifically deserves its own paragraph.
- **System-preferred multifactor authentication**, found in the portal under Authentication
  methods > Settings, and called `systemCredentialPreferences` if you're reading the policy through
  Graph: a genuinely separate
  setting, easy to conflate with the registration campaign but controlling something different:
  not what gets *nudged for registration*, but what gets *presented at sign-in* for a credential
  the user already has. Covered in full in Part 2, on how the pieces interact.
- **`policyMigrationState`**: not a setting you tune but a status value, reporting whether the
  tenant has actually finished migrating off the legacy
  per-user MFA policy and legacy SSPR policy onto this one. Deceptively easy to assume is a
  solved problem simply because those legacy policies can no longer be *edited*. Part 3, on what a
  defensible target state looks like, covers why that's a real, checkable gap rather than
  historical housekeeping.

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

Worth being precise about what "phishing-resistant" actually promises here, since it's easy to
over-claim. It specifically means resistant to adversary-in-the-middle relay at the moment a
token is issued: the credential can't be captured by a fake sign-in page and replayed, the way a
password or an OTP code can. It says nothing about a token that's already been issued and then
gets stolen off the endpoint afterward, for example by infostealer malware harvesting session
tokens and shipping them to a command-and-control server for replay. That's a different problem,
closed by endpoint controls (EDR, application control, next-gen antivirus), not by which
authentication method was used to sign in. Rolling out passkeys is not a substitute for that
endpoint security work; the two address different stages of the same token's lifecycle.

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

One setting, easy to miss entirely, and one you won't stumble across in the portal because it has
no switch there: `allowedToUseSSPR` on `/policies/authorizationPolicy`, readable only via Graph. By
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
succeed. A second, deliberately wider window checks whether *registered* methods are actually
being *used*: registration alone doesn't mean a method still works, the device it lived on might
be gone. Be careful what you ask for on that second one, though, because Entra caps how far back
you can look: sign-in logs are retained for **seven days on Entra ID Free and 30 days on P1 or
P2**, full stop. Request 90 days and you get back whatever was retained, with nothing in the
response telling you the window was truncated. So 30 days is the real ceiling for most tenants,
and any "not used recently" conclusion means "not within retention," never "not ever." If you
genuinely need a longer history, that's an argument for routing sign-in logs to Azure Monitor or
a storage account, not for asking Graph for a window it cannot serve. Audit logs separately catch unexpected credential
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
targeting every MFA-capable user). Worth flagging explicitly: **at the time of writing, Microsoft's
own reference docs for this exact setting contradict each other**. The resource reference page
states the default value is `disabled`, while the how-to article describes "Microsoft managed" as
an actively-rolling-out set of new defaults. That's a documentation bug rather than a product one,
so it may well be tidied up by the time you read this. Check both pages rather than assuming this
observation still holds. And even taking the how-to article at face value, a
start date Microsoft announces isn't a guarantee: tenants are migrated onto the new defaults in
batches on Microsoft's own schedule, invisible from the tenant side. A tenant reading "Microsoft
managed" today could be on the old behavior, the new one, or partway through, regardless of how
long ago Microsoft's announced date has passed. If you need certainty about what a specific user
is actually being shown, check that tenant directly rather than trusting the stated default.

There's one more way a campaign can quietly do nothing, and it's the one most likely to catch out
someone who has otherwise done everything right. Microsoft documents that users are not nudged at
all if their passkey profile carries any of these restrictions: synced-only, device-bound-only,
attestation enforced, or AAGUID key restrictions. Read that list again with a hardening mindset,
because two of those items are things a security-conscious admin actively wants. Enforce
attestation so only vetted authenticators can register, add an AAGUID allow-list so only approved
key models are accepted, then switch on a registration campaign to drive adoption, and the
campaign reaches nobody. Nothing errors. The admin center shows the campaign as configured and
enabled. Registration coverage simply doesn't move, and the obvious conclusion ("users are
ignoring the prompt") is wrong, because there was no prompt. The same restriction also blocks the
automatic switch to passkey targeting under Microsoft-managed state. If you're going to run a
campaign and enforce attestation, sequence them: drive registration first, tighten afterwards.

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

There's a second nuance worth knowing before rolling out passkeys specifically, and it only shows
up when the device the TAP is entered on isn't the device the passkey will live on. Registering
"Passkey in Microsoft Authenticator" from a laptop, with the phone as the target for the actual
credential, is genuinely supported: Microsoft's Security Info flow hands off to the phone through
a QR code or an app-open prompt. What it doesn't do is carry the laptop's TAP session over. The
phone has to independently sign in and complete MFA inside the Authenticator app itself, as its
own separate step. For a brand-new user whose only credential is a single one-time-use TAP, that's
a problem: the TAP is already spent reaching Security Info on the laptop, so there's nothing left
to authenticate the phone with. Microsoft does document a fallback for exactly this gap, a
Bluetooth-proximity "WebAuthn flow" that skips the second sign-in, but it's explicitly unavailable
whenever FIDO2 attestation is enforced. Push both settings toward their generally-recommended
values (a one-time-use TAP, and attestation enforced) at the same time, and a brand-new user can
end up with no route through this specific bootstrap path at all. Windows Hello for Business
doesn't have this problem, since it's bound to the same device the TAP was entered on and never
needs a handoff, which is the real reason WHfB rollout can look further along than passkey
rollout even when both are technically "enabled." The practical fix, if cross-device passkey
bootstrap actually matters for a given tenant, is a short-lived multi-use TAP scoped to
onboarding rather than a strict one-time-use TAP.

### If the tenant is still federated, TAP does one more thing

Everything above assumes users authenticate against Entra. Plenty of hybrid tenants don't yet:
they're federated to AD FS or a third-party identity provider, and they're partway through moving
to managed cloud authentication using Staged Rollout, the feature that flips a pilot group from
federated to managed so you can test before converting the whole domain.

The relevant mechanic is that moving a user into Staged Rollout doesn't take effect immediately.
Microsoft's own description: the switch to managed authentication lands "after the user completes
one more interactive sign-in using their existing federated login." So the very users you're moving
*towards* passwordless get sent back to the old identity provider, with a password, one last time.
Removing a user from Staged Rollout works the same way in reverse.

TAP short-circuits that, and this is the part worth knowing, because Entra evaluates a TAP *before*
it decides to redirect the user to their federated identity provider. Issue a TAP right after adding
someone to the Staged Rollout group and their first sign-in is already managed: no final trip
through AD FS, no password, and from there they can register Authenticator or a passkey exactly as
any cloud-native user would. It is the same bootstrap pattern described above, doing double duty as
a migration step.

Two related constraints matter if the tenant is in this state, because they quietly contradict
advice given elsewhere in this post. Self-service password reset with writeback to on-premises AD
is **not supported** while Staged Rollout is enabled for a security group; Microsoft says it works
in some cases but can't be guaranteed. So the SSPR coverage targets discussed later are worth
pursuing, but the writeback path specifically is unreliable until the domain conversion finishes.
And Windows Hello for Business hybrid *certificate* trust, where the federation server acts as the
registration authority, along with smartcard users, isn't supported on Staged Rollout at all, which
takes the WHfB-shaped bootstrap route off the table for exactly the population most likely to have
it.

The overall framing Microsoft now uses is worth repeating to anyone treating this as a steady state:
Staged Rollout "is **not** designed to be a permanent configuration," a federated identity provider
should stay in place as a fallback while testing, and the domain cutover to managed authentication
is a separate step that Staged Rollout never performs on its own. A tenant that has been "halfway
migrated" for two years is carrying the constraints above the whole time.

The assessment reads this directly for hybrid tenants and reports it as inventory rather than as a
pass or fail, precisely because there's no value of "enabled" that's correct for everyone. What it
does flag are the three caveats above, against the specific findings each one qualifies, so a
reader working through the SSPR or TAP recommendations sees why they don't fully apply yet.

### Three announced changes that shift this ground in late 2026

All three of the following are announced but not yet shipped at the time of writing, and each
changes the bootstrap picture enough to be worth designing around now rather than reacting to
later.

**A passkey becomes registerable as a first MFA method.** Today the awkwardness is circular: you
want people on passkeys, but the registration path often assumes they already have some other MFA
method to authenticate the registration with. Microsoft is removing that assumption, so a
password-only user can go straight to a passkey rather than setting up something weaker first.
Rolling out in two phases: synced passkeys, Entra passkeys on Windows and FIDO2 keys around
mid-October to mid-November 2026, then Windows Hello for Business, macOS Platform SSO and
Authenticator passwordless around January to February 2027.

This narrows the bootstrap problem without closing it, and the distinction is worth being precise
about because it determines whether you still need Temporary Access Pass. It helps a user who
*already has a password* and needs to add a strong method. It does nothing for a genuinely new
user holding no credential at all, who still needs a TAP or admin provisioning to get far enough
in to register anything. Day-one onboarding and lost-credential recovery are unchanged. Note too
that the second phase lands *after* the February 2027 SMS/Voice retirement, so if you're planning
phone-based migration, plan it on the first phase and on TAP, not on that date.

**Windows Hello for Business and macOS Platform SSO become standalone MFA factors.** These already
satisfied MFA at primary sign-in, but users could still be asked for a separate passkey during a
step-up prompt or an Authentication Strength check. That gap closes around October to November
2026, which is a real usability improvement for anyone who lives on one managed device.

It also carries a consequence that deserves more attention than it usually gets, because it is
stated plainly in Microsoft's own announcement and is easy to skim past: users holding *only* these
device-bound credentials will no longer be automatically prompted to register additional MFA
methods. Consider what that means. Right now, someone whose sole strong credential is Windows Hello
on one laptop keeps getting nudged toward a second method, and some fraction of them act on it, so
the population slowly self-corrects. After this change the nudging stops, while the underlying
exposure is completely unchanged: they still cannot complete MFA from any device that doesn't carry
that credential. Lose or replace the laptop and they're at the service desk.

So a group that was previously shrinking on its own quietly becomes static. That's worth finding
deliberately, because it is exactly the sort of risk that produces no signal until someone needs
help and can't get it. The fix is unglamorous: identify who has only a device-bound credential and
get them a portable backup (a synced passkey, or a passkey in Microsoft Authenticator) as a
deliberate act, rather than assuming the prompts will keep handling it. They won't.

**Passwordless users get a way to change a password they've never used.** This one closes a gap
that sounds like a footnote and isn't. Onboard someone the modern way, TAP into a passkey on day
one, and they may go their entire time at the company without ever typing their password. The
password still exists in the directory, though. It is still an authentication factor. And the day
something actually needs it, a legacy app, a break-glass procedure, a support process that hasn't
caught up, they cannot change it: changing a password today means either knowing the current one
(they don't) or going through SSPR (which they may never have registered for, particularly since
the SSPR registration interrupt can be skipped indefinitely when no MFA registration policy sits
alongside it, as covered just below). A stale password nobody knows and nobody can rotate is not a
great thing to have quietly accumulating across a passwordless population.

From late October 2026, users can change their Entra password from My Sign-Ins by authenticating
with a passkey, FIDO2 key or Windows Hello for Business, with no knowledge of the current password
and no SSPR registration required. Two details decide whether you actually get this, and both are
easy to skim past: it is **off by default** and needs an administrator to switch it on, and it is
**tenant-wide with no per-user or per-group scoping** at release, so it's on for everyone or for
nobody. Nothing happens to you here. This is one you have to go and choose, which in practice makes
it exactly the sort of change that gets read in a Message Center post, nodded along with, and then
never actioned.

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
something up. System-preferred multifactor authentication (`systemCredentialPreferences` in Graph,
and under Authentication methods > Settings in the portal) is something else
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

The ranking is published, and worth reading in full rather than assuming, because it is explicitly
**not fixed**. Microsoft's own words: "The method order is dynamic and updates as the security
landscape changes." As published today:

| Rank | Credential | Satisfies |
|---|---|---|
| 1 | Temporary Access Pass | First factor + MFA |
| 2 | Passkey (security keys, passkeys in Authenticator, synced passkeys, WHfB, macOS Platform SSO) | First factor + MFA |
| 3 | Certificate-based authentication | First factor, or first factor + MFA |
| 4 | Microsoft Authenticator notifications | First factor + MFA |
| 5 | External MFA | MFA |
| 6 | TOTP (hardware or software) | MFA |
| 7 | Telephony (SMS and voice) | MFA |
| 8 | QR code | First factor |
| 9 | Password | First factor |

That "dynamic" caveat is not theoretical: certificate-based authentication used to sit **last** in
this order because of known issues, and moved to **third** on March 18, 2026 once they were
resolved. If you have CBA deployed, that reordering has a sharp edge Microsoft flags directly:
under the Microsoft-managed state, users on a device that has no certificate will **fail
immediately** during CBA and have to select "Sign in another way" manually to get anywhere. A
method jumping from ninth to third is exactly the kind of change nobody re-reads the ranking for.

Two more behaviors worth knowing. Windows Hello for Business and macOS Platform SSO only work as a
first factor, so at first-factor sign-in they're offered **only when the user most recently signed
in with a passkey**; if their only registered passkey is one of those two and their last sign-in
wasn't a passkey, the system skips it and offers the next method down instead. And federated users
are exempt at the first factor entirely: they keep going to their own identity provider, with
system-preferred applying only to their second factor.

The user can always back out via "Sign in another way," but the *default* screen they see changes,
which is exactly the kind of thing that generates a wave of "why does my sign-in look different"
tickets if nobody was told to expect it. The Microsoft-managed behavior is being **gradually rolled
out through August 2026**, so two tenants that have both left this setting untouched may currently
be experiencing different things, purely based on where they are in that rollout. Microsoft is
explicit about how to tell: if first-factor sign-in doesn't reflect the ranking while the state
reads Microsoft managed, the rollout simply hasn't reached that tenant yet.

One practical constraint that catches people staging this: you can include or exclude exactly
**one group**, not several. Piloting to three departments means one group containing all three,
not three include targets.

One nuance worth carrying into the next section, with a caveat about its shelf life: Conditional
Access is validated only for the **second** factor. It doesn't see, and can't override, what
system-preferred authentication decides to show at the first factor, because authentication happens
first and only afterward does Conditional Access evaluate authorization. The caveat is that
Microsoft files this under "Known limitations" rather than describing it as designed behavior, and
a known limitation is a candidate for being fixed. Treat it as true today rather than as
architecture, and re-check it before building a control that depends on it staying true.

### Conditional Access on the registration page itself

There are two separate failure modes here, and it's worth naming both before getting into the
mechanics of either. The first: no policy targets `urn:user:registersecurityinfo` at all, so the
page where users register a new authentication method has no Conditional Access protection of
its own, no matter how solid the rest of the baseline looks. A tenant can have legacy auth
blocked, MFA required for all users, and admin roles protected, and still have zero control over
this specific page, because none of those policies extend to it (targeting resources and
targeting user actions are mutually exclusive choices within one policy, so a baseline "All
resources" policy simply never reaches it). Anyone who's completed first-factor sign-in, whether
or not they have MFA registered yet, can reach that page unchallenged. The fix is a policy that
explicitly targets the user action and requires at least a plain `mfa` grant control.

The second failure mode is the opposite: such a policy exists, but overshoots. A policy scoped to
`urn:user:registersecurityinfo` governs *how* and *where* users are allowed to
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

### Who actually gets interrupted, and why you owe them a heads-up

Everything above describes mechanisms. Put them together and a practical question falls out that
rarely gets asked until it's too late: on Monday morning, which of your people are going to be
stopped mid-sign-in and asked to do something, and do they know it's coming?

This matters more than it sounds. A registration prompt that arrives unannounced isn't a technical
failure, it's a support call, and at scale it's a wave of them. Worse, it teaches users that
unexpected credential prompts are normal, which is precisely the instinct you spend the rest of
your security programme trying to build out of them. The mechanics are all documented; what's
usually missing is that somebody worked out the affected population in advance and sent an email.

Four different interrupts can fire, and they're worth separating because they hit different people
and behave differently once they arrive:

**The automatic passkey enablement on September 1, 2026.** Anyone still enabled for SMS or Voice
gets auto-enabled for passkeys and nudged on their next MFA sign-in. This is the one to plan around
first, because the timing isn't yours: it happens whether or not you've configured a campaign, and
whether or not you're ready. Snoozes are unlimited by default, so it's a recurring prompt rather
than a hard stop, which is its own kind of problem: a nag nobody is required to resolve tends to
get trained out rather than acted on.

**A passkey registration campaign,** if you're running one. Fires after a successful MFA for
in-scope users without a passkey on that particular device and browser.

**A Microsoft Authenticator campaign,** same mechanic, different target. Note you can't run both
at once.

**The SSPR registration interrupt,** for users who are SSPR-enabled but haven't registered. This
one has a sting worth knowing: per Microsoft's own combined-registration documentation, if only an
SSPR policy is enforced and no MFA registration policy sits alongside it, users can skip the
interruption *indefinitely*. So it's not a rollout that completes. It's a prompt that appears
forever, gets dismissed forever, and quietly never improves your SSPR coverage.

There's also a fifth case that isn't a nudge so much as a defect, and it's specific enough to be
worth checking for by name: an administrator who is in scope for the user-facing SSPR policy while
admin SSPR is disabled tenant-wide gets interrupted to register, and is then shown a message saying
they can't register anything. Microsoft documents both the behavior and the fix (explicitly exclude
administrators from the user SSPR policy when admin SSPR is off). It's the kind of thing that gets
reported as a bug by a frustrated admin months after someone turned off admin SSPR for good
reasons.

### Where the prompt actually lands, and where it never will

Knowing *who* is eligible is only half of it. The other half is *where*, and this is where a lot of
rollout plans quietly mis-forecast, because a nudge is a piece of UI shown during a sign-in, and a
large share of real-world sign-ins have no UI at all.

Microsoft splits sign-ins into interactive and non-interactive, and the definition of the latter
does the work here: non-interactive sign-ins are "performed by a client app or OS components on
behalf of a user and don't require the user to provide an authentication factor," with Entra
refreshing the token "behind the scenes, without interrupting the user's session." No
authentication factor is requested and the session is never interrupted, so there is no MFA
completion to nudge after and no surface to nudge on. Microsoft's own examples of non-interactive
sign-ins include a client app using a refresh token to get an access token, single sign-on to a
Windows app on an Entra-joined PC, and signing in to a second Office app while a session already
exists on the device.

That last one is the Outlook case exactly. A user who is already signed in on their laptop and
opens Outlook in the morning is usually generating a token refresh or an SSO event, not an
interactive authentication. They will not see a nudge, no matter how correctly the campaign is
configured, because nothing interrupted them.

Roughly where things land:

- **Browser sign-in that actually completes MFA.** This is the main event, and effectively the only
  reliable one.
- **Native and desktop apps.** Sometimes. Microsoft says registration campaigns "support embedded
  browser views in certain applications," which is deliberately non-committal, and explicitly
  excludes out-of-box experiences and browser views embedded in Windows settings.
- **Anything non-interactive.** Never, structurally. Token refresh, SSO on a joined device, opening
  a second Office app on a device that already has a session.
- **Mobile.** Depends on the campaign: passkey campaigns work on mobile browsers and native iOS
  apps, but not native Android; Authenticator campaigns aren't supported on mobile at all.
- **Linux.** Not nudged.
- **An existing SSO session.** Not nudged, which is the same rule stated from the other direction.

The practical consequence is worth sitting with, because it changes what a flat registration
number means. A user whose whole working pattern is "laptop stays signed in, open Outlook and
Teams, tokens refresh silently" can go weeks without a single interactive browser sign-in, and
therefore weeks without ever seeing a prompt you switched on a month ago. When coverage moves
slower than expected, the intuitive read is that users are ignoring the nudge. Often they are
genuinely never being shown it. Those two situations call for completely different responses: one
needs a firmer campaign, the other needs an email, because no amount of campaign tuning will reach
someone the campaign structurally cannot interrupt.

### You can measure this, not just reason about it

The useful part is that reachability isn't guesswork. Microsoft's `/auditLogs/signIns` endpoint on
`v1.0` returns, in its own words, "sign-ins that are interactive in nature (where a username or
password is passed as part of auth token) and successful federated sign-ins." That is precisely the
population a campaign can interrupt. So cross-reference two lists you can both pull today:

- Everyone eligible for a nudge (no passkey registered, still on SMS or Voice, SSPR-enabled but
  unregistered, and so on).
- Everyone who appears in the interactive sign-in log over the retention window.

Eligible and present in that log means a campaign will get its chance. Eligible and absent means it
won't, no matter how the campaign is configured, and those people need an email or a service-desk
call instead. Two lists, one comparison, and the answer changes what you do next.

Two limits to apply honestly, though, because it's easy to over-read the result. Entra keeps
sign-in logs for **seven days on Entra ID Free and 30 days on P1 or P2**, and that ceiling is hard:
ask for 90 days and you silently get back only what was retained, with no warning that your window
was truncated. So "no interactive sign-in" always means "none within retention," never "none ever."
And within that window, a genuinely dormant account and a perfectly active person who simply works
out of desktop apps all month look identical. Both need reaching directly; the reasons differ
entirely.

What this buys you is a real diagnosis rather than a guess. Coverage barely moving while most
eligible users *are* signing in interactively is a messaging problem: they see the prompt and skip
it, so the fix is better communication, or limited snoozes, or eventually enforcement. Coverage
barely moving while a large share of eligible users *never* sign in interactively is a reach
problem, and no campaign setting solves it, because the campaign was never in the room. Those two
situations look identical on a coverage chart and call for opposite responses, which is exactly why
it's worth spending ten minutes separating them before concluding that users are ignoring you.

Working out who lands in each group is therefore mostly derivable from data you already have:
registration state per user, the campaign's target method and scope, which users still have a
phone-based method registered, who is SSPR-enabled but not SSPR-registered, and who shows up in the
interactive sign-in log. Two further limits are worth carrying into that exercise, because they
push in opposite directions. The passkey nudge is
evaluated per device-and-browser rather than per account, so "this user has a passkey" does not
mean "this user won't be prompted." And several suppressors (terms-of-use screens, Conditional
Access custom controls, an existing SSO session, Linux clients) are invisible from the outside.
Any list you build is therefore an estimate. Build it as an over-estimate and communicate to the
wider group: telling fifty people about a prompt that forty of them see is a much cheaper error
than the reverse.

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
   plus the reminder that, as things currently stand, this CA scope doesn't override
   system-preferred authentication's first-factor choice.

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
  Access, the foundational pair almost everything else assumes is already in place. Treat that
  requirement as a floor, not the finish line: a plain "require MFA" grant control accepts
  whichever method a user has registered, including a weaker one, and that gap is exactly what
  an MFA downgrade attack targets. An adversary-in-the-middle proxy can tell Entra the current
  browser doesn't support a passkey and fall back to something weaker the user also has
  registered, and a plain MFA requirement has no way to object, because it was satisfied.
  Requiring a specific authentication strength instead of "any MFA" closes that fallback, since
  the strength itself defines which methods are acceptable. Rolling that out tenant-wide, not
  just for admins, only makes sense once phishing-resistant methods are broadly registered
  (Phase 3 below); until then, plain MFA is a legitimate interim state, not a failure.
- **Privileged access protection for admins**, as a composite rather than one hard-coded
  control: a compliant device requirement *or* a phishing-resistant authentication strength
  requirement for admin roles, either one satisfies the intent.
- **Admin and overall MFA registration coverage** at or above a defined threshold, since a
  Conditional Access requirement is meaningless if the people it targets never actually
  registered a method to satisfy it.
- **FIDO2 attestation and key restrictions enforced**, and a defined policy on whether
  cloud-synced passkeys (Google Password Manager, iCloud Keychain, and similar) are acceptable or
  whether only device-bound credentials are. For the general workforce this is a genuine
  either-way judgment call. For high-value accounts it is no longer especially balanced: the 2026
  attack research recommends device-bound over synced, and attestation enforced, specifically for
  those users. The reasoning is that a synced passkey's private key exists in more than one place
  and rests in a cloud vault, so a phishing-resistant credential ends up only as strong as the
  password guarding that vault. Researchers have demonstrated exporting usable private keys from
  password-manager vaults in cleartext, at which point the credential can be replayed from
  anywhere with no access to the original device.
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

### Two tiers, not one: the workforce and the accounts worth attacking individually

The single most useful structural change to come out of the 2026 research is that a target state
with one tier is now clearly wrong. The economics differ too much between an ordinary employee
and a Global Administrator to justify one answer.

For the **general workforce**, the goal is to make bulk remote phishing stop working. Passkeys in
Microsoft Authenticator, Windows Hello for Business, or synced passkeys from a reputable provider
all achieve that. Synced passkeys are a legitimate choice here, and often the pragmatic one:
recovery after a lost phone is signing back into a vault rather than a helpdesk ticket and a
re-enrolment, and they reach further back on old Android hardware than Authenticator does. The
residual attacks described earlier need code execution on the user's device, which is a different
and much more expensive problem than a lookalike login page.

For **high-value accounts**, treat the residual attacks as in scope, because for these accounts
an attacker will pay that cost. Concretely:

- **Device-bound passkeys, not synced ones.** No copy of the private key in a cloud vault.
- **Attestation enforced**, so only authenticator models you approve can be registered at all.
  Note the interaction flagged elsewhere in this post: attestation and key restrictions suppress
  the registration-campaign nudge and disable the Bluetooth-proximity cross-device bootstrap, so
  scope this to the admin population rather than switching it on tenant-wide by reflex.
- **Do not treat a phishing-resistant Conditional Access policy as the whole control.** It is
  necessary and you should have it. But the published exploit satisfied exactly that requirement,
  so pair it with a compliant-device requirement, Privileged Identity Management so the role isn't
  standing, and privileged access workstations where the risk justifies it. Defence in depth here
  is not a platitude; it is the specific researcher recommendation.
- **Monitor registration events, not just registration counts.** A shadow passkey planted on an
  admin account raises your phishing-resistant coverage percentage. Coverage metrics cannot
  distinguish it from good news. The audit log can.
- **Watch for Windows Hello sign-ins with no device ID**, using the KQL query quoted earlier, plus
  unexpected new device registrations.

Neither tier is "done." Both are positions you hold and re-check, which is the argument for
running this as a repeatable assessment rather than a one-off project.

### If Windows Hello for Business is part of your answer

For most hybrid SMB tenants it should be, because it turns the laptop the user already has into a
phishing-resistant authenticator with no hardware to buy, and it avoids the cross-device bootstrap
problem entirely: the credential lives on the same machine where the Temporary Access Pass was
entered, so there is no handoff to a phone that needs its own separate sign-in.

The deployment decision that matters is the trust model, and the practical guidance from the field
is to use **cloud Kerberos trust** where you can. Marco Wohler's
[write-up of WHfB in practice for SMBs](https://medium.com/@kmuitspice/windows-hello-for-business-whfb-in-practice-smb-it-spice-93800f834725)
calls it "the newest and by far the simplest way to enable secure WHfB": it creates a virtual
read-only domain controller object in on-premises AD and needs no certificate connector, no PKI
management, and no extra servers. Key trust remains reasonable where certificate infrastructure
already exists. Certificate trust is the legacy path, needs a dedicated Intune Certificate
Connector, and is worth actively avoiding in a small environment.

That choice is not only an operational preference. As noted in the Staged Rollout section, WHfB
hybrid *certificate* trust with the federation server acting as registration authority is one of
the scenarios Microsoft does not support during a federated-to-managed migration, so picking
certificate trust can strand exactly the users you are trying to move.

One field-tested gotcha worth carrying across from that article, because it produces a support
ticket that looks like an authentication failure and isn't: when Kerberos authentication fails,
Windows waits ten minutes before retrying, which makes mapped network drives appear disconnected
after boot or when roaming. Reducing `FarKdcTimeout` to one minute resolves it without weakening
anything.

### Platform and browser gaps that turn "enabled" into "broken" for someone

None of the checklist above is worth enforcing before checking it against the actual devices,
browsers, and apps your users are on. Microsoft publishes an explicit compatibility matrix for
passkey (FIDO2) authentication, and it's worth reading before rollout rather than after the
support tickets start ([full matrix reference](passkey-platform-compatibility.md)). A few gaps
from that matrix are easy to miss and expensive to discover late:

- **Firefox on Android doesn't support passkey sign-in at all**, full stop, while Chrome and Edge
  on the same device do. Firefox on Linux specifically can't use a passkey stored in Microsoft
  Authenticator either, though other passkey types there are fine.
- **New security key registration doesn't work in any browser on macOS or iOS**, because those
  browsers don't prompt for the biometric/PIN setup Entra needs to complete registration.
  Sign-in with an already-registered key works fine; registering a new one has to happen on a
  platform that does prompt for it. ChromeOS goes further and blocks security key registration
  entirely, in any browser.
- **Without an authentication broker installed** (Microsoft Authenticator, Company Portal, or
  Link to Windows), **Outlook, Teams, and OneDrive on Android can't do passkey sign-in at all**.
  The same apps work without a broker on iOS and macOS. If a rollout assumes "the app supports
  passkeys" without checking whether the broker is actually deployed on Android, that's where it
  breaks.
- **Third-party identity provider passkey authentication isn't supported on iOS or macOS at
  all**, broker or no broker. A tenant federating out to a third-party IdP will find passkeys
  silently don't work for that population on Apple platforms; the workaround runs through the
  IdP's own Apple Extensible SSO integration on MDM-managed devices, not anything Entra-side.
- **Version floors gate all of the above**, and they're stricter than "reasonably current
  device": Authenticator passkey support needs Android 14+ or Windows 11 22H2+ specifically (not
  just "Windows 10 or later," which only covers security-key sign-in); iOS native app passkey
  support needs 16.0+ without Microsoft's SSO plug-in, or 17.1+ *with* it; macOS needs 14.0+ and
  MDM enrollment for the same. An unmanaged Mac can't use passkey-via-broker at all, regardless
  of OS version.

Inventorying which of these combinations are actually in use, and deciding whether syncable
passkeys are acceptable specifically because they reach further back (Google Password Manager
supports Android versions well below Authenticator's floor), belongs in Phase 1 alongside
everything else in "Foundation & Visibility," not discovered after enforcement is already live.

## Part 4: The path from IST to SOLL: five phases, and why the order matters

A list of findings tells you *what's* wrong. It doesn't tell you *what order* to fix things in,
and sequencing genuinely matters here, because doing this out of order creates real incidents,
not just theoretical risk:

| Phase | Goal | Typical actions |
|---|---|---|
| **1. Foundation & Visibility** | Safe immediately, nothing depends on anything else | Block legacy authentication; enable Authenticator, FIDO2, and TAP; check platform/browser compatibility against Microsoft's own matrix; audit log and break-glass hygiene; TAP hardening (one-time-use, shorter lifetime) |
| **2. Enable Phishing-Resistant Capability** | Give users something strong to actually register | Turn on FIDO2 self-service registration; decide the Windows Hello trust model (cloud Kerberos trust for most hybrid SMB tenants); scope attestation and key restrictions to high-value accounts rather than tenant-wide, since both suppress the Phase 3 nudge; define and be ready to enforce a phishing-resistant authentication strength |
| **3. Drive Registration Coverage** | Get people actually registered, using the bootstrap from Phase 2 | Work out who will be interrupted and tell them *before* switching anything on; run the registration campaign; close admin and overall MFA registration gaps; raise SSPR registration coverage |
| **4. Retire Weak Fallback Methods** | Remove the downgrade path, only once it's safe to | Turn off SMS/Voice, but only after Phase 3's coverage is genuinely high enough |
| **5. Enforce via Conditional Access** | Make the target state mandatory, last | Require MFA for all users; require compliant device or phishing-resistant auth for admins; once adoption is broad enough, tighten the all-user policy from plain MFA to a phishing-resistant authentication strength to close the MFA downgrade path. For high-value accounts, layer rather than stop here: the published exploit satisfied a phishing-resistant requirement, so add compliant device, PIM, and registration-event monitoring on top |

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
Graph endpoint, since Microsoft's `v1.0` reference for this policy doesn't list this setting,
system-preferred multifactor authentication, or the reconfirmation interval, all three of which
appear only on the beta reference) excludes the tenant
from the automatic enablement and registration-campaign rollout for a defined runway. It does
**not** touch the February 1 enforcement in any way; that date applies to every tenant regardless.
Organizations with a genuine regulatory or operational need to keep an SMS/Voice channel have a
documented exception path instead: customer-managed telecom providers become reviewable in the
Microsoft Security Store from September 18, 2026, and configurable from October 30, 2026.

**The trap, again, in this specific context.** If the tenant has a Conditional Access policy
scoped to "Register security information" that demands a custom authentication strength without
a TAP escape, a user with no phishing-resistant method yet (exactly the population this whole
rollout is trying to move) can be locked out of the very page that would let them register one.
This is the same mechanism described in Part 2, where the registration page's Conditional Access
gate was covered in the abstract, just now colliding with a live Microsoft rollout instead of a
hypothetical.

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
   for stragglers), scoped to the group identified in step one, not a blanket announcement. Do
   this *before* the campaign goes on rather than after, and remember the September 1 nudge
   arrives on Microsoft's schedule regardless: if you haven't sent anything by then, Microsoft
   will have started the conversation with your users on your behalf.

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
   from Part 1's inventory, and trace the four end-to-end user flows from Part 2 whenever a
   specific mechanism's behavior is in question rather than assumed.
4. Check upcoming Microsoft-driven deadlines against your own timeline. Some of this work happens
   on Microsoft's schedule regardless, which changes what's worth prioritizing manually versus
   what's coming either way.
5. Re-assess periodically rather than once, and treat "every Phase 5 item satisfied" as a state
   you hold rather than a finish line you cross. SOLL moves: Microsoft ships rollouts on its own
   schedule, and each one can turn a previously clean tenant into one with a new gap, as most of
   the late-2026 dates above demonstrate. (This is the part a repeatable, read-only assessment
   like the Secure At Work Authentication Assessment Toolkit is built to make easy: a phased work
   plan of exactly what's still open and in what order, a per-user triage list, and a trend view
   across repeat runs, so the sequencing above doesn't have to be re-derived by hand every time.)

## Sources and further reading

Everything above is grounded in published documentation rather than assertion, and some of it came
from other people's work. Both are worth being explicit about, because dates in this area move and
because credit matters.

**Microsoft documentation** is the primary source throughout. The articles doing the most work
here:

- [Passkeys by default and retirement of SMS and voice](https://learn.microsoft.com/entra/identity/authentication/concept-sms-voice-retirement)
  for the September 2026 and February 2027 dates and the opt-out property.
- [Run a registration campaign](https://learn.microsoft.com/entra/identity/authentication/how-to-mfa-registration-campaign)
  for nudge mechanics, the per-device evaluation, and the suppression conditions.
- [Combined registration for SSPR and MFA](https://learn.microsoft.com/entra/identity/authentication/concept-registration-mfa-sspr-combined)
  for interrupt versus manage mode and the indefinitely-skippable SSPR interrupt.
- [Authentication strengths](https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths)
  for what counts as phishing-resistant, and for Temporary Access Pass not satisfying it.
- [Configure a Temporary Access Pass](https://learn.microsoft.com/entra/identity/authentication/howto-authentication-temporary-access-pass)
  for lifetime and one-time-use settings, the 10-minute rule, and the Interrupt-mode limitation.
- [Enable passkeys (FIDO2)](https://learn.microsoft.com/entra/identity/authentication/how-to-authentication-passkeys-fido2)
  and [passkeys in Authenticator](https://learn.microsoft.com/entra/identity/authentication/how-to-enable-authenticator-passkey)
  for attestation, key restrictions, synced versus device-bound, and the Authenticator AAGUIDs.
- [Passkey (FIDO2) authentication matrix](https://learn.microsoft.com/entra/identity/authentication/concept-fido2-compatibility)
  for every platform and browser support claim.
- [Targeting resources in Conditional Access](https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-cloud-apps)
  for resource and user-action targeting being mutually exclusive.
- [Non-interactive sign-in logs](https://learn.microsoft.com/entra/identity/monitoring-health/concept-noninteractive-sign-ins),
  [List signIns](https://learn.microsoft.com/graph/api/signin-list) and
  [data retention](https://learn.microsoft.com/entra/identity/monitoring-health/reference-reports-data-retention)
  for what a nudge can and cannot reach, and how far back you can measure it.
- [Cloud authentication via Staged Rollout](https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-staged-rollout)
  for the one-more-federated-sign-in transition, TAP being evaluated ahead of the federation
  redirect, and the SSPR-writeback and WHfB-certificate-trust scenarios it doesn't support.
- [Authentication flows in Conditional Access](https://learn.microsoft.com/entra/identity/conditional-access/concept-authentication-flows)
  for device code flow being high risk, and for the protocol-tracking and Device Registration
  Service traps that come with blocking it.

**Security research** is where the "why now" in this post comes from, and all of it is worth
reading in full rather than via my summary:

- Michael Grafnetter (SpecterOps), [Pass-the-Passkey Family of
  Attacks](https://specterops.io/wp-content/uploads/sites/3/2026/08/Pass-the-Passkey_A4_v2.pdf),
  17 July 2026, presented at Black Hat USA 2026. Three zero-days, 20+ techniques, open-source
  tooling, and the clearest published statement of what to do differently for high-value accounts.
  Everything quoted here about the event-log assertion leak (CVE-2026-34348, patched 14 July
  2026), the Entra ID replay gap (partially fixed May 2026, still open for Windows Hello because
  it always sends counter 0), the Credential UI spoofing issue (assessed Low, Defense in Depth),
  and shadow passkeys comes from this paper.
- Dirk-jan Mollema, [Borrowing Windows Hello Keys for Authentication and
  Persistence](https://dirkjanm.io/borrowing-windows-hello-keys/), for the no-PIN key use, the
  PRT chain, the "counts as fresh MFA so we can add more passkeys" persistence step, and the
  detection query reproduced above.
- Marco Wohler, [Windows Hello for Business (WHfB) in
  practice](https://medium.com/@kmuitspice/windows-hello-for-business-whfb-in-practice-smb-it-spice-93800f834725),
  for the cloud-Kerberos-trust recommendation and the `FarKdcTimeout` gotcha.

Both attack papers are explicit that passkeys remain a large improvement over passwords and
should still be adopted. If this post has left the opposite impression, that is my error and not
theirs.

**Message Center posts** cover changes announced but not yet in the product documentation. Since
they can't be linked publicly, the references below point at
[mc.merill.net](https://mc.merill.net), Merill Fernando's community mirror, which makes them
checkable by anyone: [MC1450133](https://mc.merill.net/message/MC1450133) (passkey as a first MFA
method), [MC1450134](https://mc.merill.net/message/MC1450134) (Windows Hello for Business and
macOS Platform SSO as standalone MFA factors), and
[MC1437671](https://mc.merill.net/message/MC1437671) (passwordless password change in My Sign-Ins).
Check your own tenant's Message Center before treating any of them as final.

**With thanks to:**

- [ourcloudnetwork.com](https://ourcloudnetwork.com/microsoft-entra-just-made-passwordless-mfa-registration-easier/),
  whose write-up surfaced the passwordless-registration changes covered above.
- [Ru Campbell at Threatscape](https://www.youtube.com/watch?v=3MC0Hoc8GuA), whose walkthrough of
  passkey deployment pitfalls prompted the sections on MFA downgrade, device compatibility, and the
  limits of what "phishing-resistant" actually covers.
- The [passkey-authenticator-aaguids](https://github.com/passkeydeveloper/passkey-authenticator-aaguids)
  project, and the published AAGUID references from
  [Yubico](https://support.yubico.com/hc/en-us/articles/360016648959-YubiKey-hardware-FIDO2-AAGUIDs),
  [Feitian](https://fido.ftsafe.com/products/) and
  [SoloKeys](https://docs.solokeys.dev/metadata-statements/).

One habit worth borrowing regardless of any of the above: check the `ms.date` on a Microsoft Learn
article before relying on a date it states. Two SSPR dates referenced in an earlier version of this
piece had both moved by the time it was rechecked, and their order relative to each other had
reversed. Secondary sources, this one included, go stale faster than the primary ones do.

A subtler version of the same habit, and the one that catches people out more often: watch for
claims of *permanence*, not just claims about dates. Two categories in particular are worth
distrusting. Anything Microsoft publishes under a **"Known limitations"** heading is, by
definition, something they may intend to fix, so building a control that depends on a limitation
persisting is building on sand. And anything presented as a fixed order or a fixed default is
worth re-reading, because Microsoft states outright that the system-preferred credential order "is
dynamic and updates as the security landscape changes," and duly moved certificate-based
authentication from ninth place to third in March 2026. An earlier draft of this post described
that order as fixed. It wasn't, and saying so confidently would have quietly misled anyone who
took it at face value.

---
*Secure At Work, Microsoft 365 &amp; Entra ID security assessments.*

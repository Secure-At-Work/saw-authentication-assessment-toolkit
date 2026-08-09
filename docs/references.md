# Source References

Every substantive claim this toolkit makes, mapped to the primary source that backs it.

The point of this document is that you can hand a customer a finding and, if challenged, point at
Microsoft's own words rather than at this toolkit's opinion. It also makes staleness visible:
Microsoft moves dates and changes behavior, and a claim that was true when a rule was written can
quietly stop being true. Each row carries the date it was last checked against the live page.

**How to verify anything here yourself.** Every Microsoft Learn article carries an `ms.date` and a
last-updated timestamp near the top of its source, and a "Feedback" / "Edit" link to its GitHub
source file. If a claim in a report looks wrong, open the linked article and check its date first:
if the page changed after the "Last verified" date below, treat this toolkit's wording as suspect
and the article as authoritative. That is exactly how the SSPR date corrections in this repo were
caught (see "Known corrections" at the bottom).

## Conventions

- **Verified** means someone opened the live page and confirmed that the page *states the specific
  claim*, on the date shown. Confirming the link resolves is not verification: two rows survived
  months that way before the 2026-08-09 pass found the pages never said the thing. It also does not
  mean the page hasn't changed since.
- **Carried over** means the citation predates this review and was not re-opened during it. Treat
  those as good but slightly colder. As of 2026-08-09 no rows are in this state; the definition
  stays because new rules arrive this way.
- Where a rule's claim rests on a *specific sentence*, that sentence is quoted, because paraphrase
  is where accuracy usually goes missing.

---

## Rule-by-rule sources

| Rule | What it claims | Primary source | Last verified |
|---|---|---|---|
| **AUDIT001** | Break-glass credential changes should be deliberate and reviewed | [Manage emergency access accounts](https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access) | **2026-08-09** |
| **AUDIT002** | Conditional Access changes made by applications rather than people warrant review | [Plan a Conditional Access deployment, "Govern and manage policies at scale"](https://learn.microsoft.com/entra/identity/conditional-access/plan-conditional-access#govern-and-manage-policies-at-scale) | **2026-08-09** (citation replaced) |
| **AUTH001** | Microsoft Authenticator should be enabled | [Microsoft Entra authentication overview](https://learn.microsoft.com/entra/identity/authentication/overview-authentication) | **2026-08-09** (URL corrected) |
| **AUTH002 / AUTH003** | SMS and Voice are being retired and should be moved off | [Passkeys by default and retirement of SMS and voice](https://learn.microsoft.com/entra/identity/authentication/concept-sms-voice-retirement) | **2026-08-07** |
| **AUTH004** | FIDO2 / passkeys should be enabled | [How to enable passkeys (FIDO2)](https://learn.microsoft.com/entra/identity/authentication/how-to-authentication-passkeys-fido2) | **2026-08-07** |
| **AUTH005** | Temporary Access Pass should be enabled as a bootstrap method | [Configure a Temporary Access Pass](https://learn.microsoft.com/entra/identity/authentication/howto-authentication-temporary-access-pass) | **2026-08-07** |
| **AUTH006** | `passkeyDynamicMigration = true` opts the tenant **out** of the automatic rollout | [SMS/voice retirement, "Temporarily opt out"](https://learn.microsoft.com/entra/identity/authentication/concept-sms-voice-retirement) | **2026-08-07** |
| **AUTH007** | Unmigrated legacy MFA/SSPR policy is still actively respected | [Migration between policies](https://learn.microsoft.com/entra/identity/authentication/concept-authentication-methods-manage#migration-between-policies) | **2026-08-09** |
| **BOOT001** | A bootstrap path (self-service FIDO2 or TAP) must exist before registration can be driven | [TAP article](https://learn.microsoft.com/entra/identity/authentication/howto-authentication-temporary-access-pass) + [passkey self-service toggle](https://learn.microsoft.com/entra/identity/authentication/how-to-authentication-passkeys-fido2) | **2026-08-07** |
| **CA001** | Legacy authentication should be blocked via CA, targeting Exchange ActiveSync + Other clients | [Block legacy authentication with Conditional Access](https://learn.microsoft.com/entra/identity/conditional-access/policy-block-legacy-authentication) | **2026-08-07** |
| **CA002** | MFA should be required for all users | [Require MFA for all users](https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-mfa-strength) | **2026-08-09** |
| **CA003** | Admin protection via compliant device *or* phishing-resistant strength | [Authentication strengths overview](https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths) | **2026-08-07** |
| **CA004** | A phishing-resistant strength gating security-info registration locks out TAP-only users | [Authentication strengths overview](https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths) | **2026-08-07** |
| **CA005** | Resource targeting and user-action targeting are mutually exclusive per policy | [Targeting resources in Conditional Access](https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-cloud-apps) | **2026-08-07** |
| **CA006** | A plain `mfa` control accepts any registered method; a strength does not | [Authentication strengths overview](https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths) | **2026-08-07** |
| **PASS001** | Attestation verifies the authenticator's make/model at registration | [Passkey profiles, "Enforce attestation"](https://learn.microsoft.com/entra/identity/authentication/how-to-authentication-passkeys-fido2) | **2026-08-07** |
| **PASS002** | Key restrictions allow/block specific models by AAGUID | [Passkey profiles, "Key Restriction Policy"](https://learn.microsoft.com/entra/identity/authentication/how-to-authentication-passkeys-fido2) | **2026-08-07** |
| **PASS003** | Synced passkeys are phishing-resistant but have a different custody model | [Synced vs device-bound passkeys](https://learn.microsoft.com/entra/identity/authentication/how-to-authentication-passkeys-fido2) | **2026-08-07** |
| **RCAMP001 / RCAMP002** | The campaign nudges registration and can target Authenticator or passkey | [Run a registration campaign](https://learn.microsoft.com/entra/identity/authentication/how-to-mfa-registration-campaign) | **2026-08-07** |
| **REG001 / REG002** | Per-user registration state is readable and coverage is measurable | [Authentication methods activity report](https://learn.microsoft.com/entra/identity/authentication/howto-authentication-methods-activity) | **2026-08-09** |
| **SIGNIN001** | Successful legacy-auth sign-ins are visible in sign-in logs | [Block legacy auth, "Identify legacy authentication use"](https://learn.microsoft.com/entra/identity/conditional-access/policy-block-legacy-authentication) | **2026-08-07** |
| **SIGNIN002** | Device code flow is a known phishing vector worth monitoring | [Authentication flows as a condition in Conditional Access, "Device code flow"](https://learn.microsoft.com/entra/identity/conditional-access/concept-authentication-flows#device-code-flow) | **2026-08-09** (citation replaced) |
| **SSPR001** | Directory-sourced contact info stops satisfying SSPR on a fixed date | [SSPR authentication data](https://learn.microsoft.com/entra/identity/authentication/howto-sspr-authenticationdata) | 2026-08-06 |
| **SSPR002** | Admins run on their own two-gate SSPR policy | [Administrator reset policy differences](https://learn.microsoft.com/entra/identity/authentication/concept-sspr-policy#administrator-reset-policy-differences) | **2026-08-09** |
| **STR001** | Built-in Phishing-resistant MFA strength = FIDO2, WHfB/platform credential, CBA (multifactor) | [Authentication strengths overview](https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths) | **2026-08-07** |
| **TAP001** | One-time use is a supported TAP policy setting (default `False`) | [TAP policy settings table](https://learn.microsoft.com/entra/identity/authentication/howto-authentication-temporary-access-pass) | **2026-08-07** |
| **TAP002** | 8 hours is Microsoft's own default maximum TAP lifetime (range 10 min to 30 days) | [TAP policy settings table](https://learn.microsoft.com/entra/identity/authentication/howto-authentication-temporary-access-pass) | **2026-08-07** |

---

## Key claims, quoted

These are the specific sentences the more surprising findings rest on. Quoted rather than
paraphrased, because these are the ones customers push back on.

### TAP does not satisfy a phishing-resistant strength (backs CA004)

From the built-in authentication strength table: **Temporary Access Pass (one-time use and
multiple use)** is ticked for **MFA strength** only, and is blank for both **Passwordless MFA
strength** and **Phishing-resistant MFA strength**.

> "**Unsupported combination of grant controls**: You can't use the **Require multifactor
> authentication** and **Require authentication strength** grant controls together in the same
> Conditional Access policy."

Source: [concept-authentication-strengths](https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths)
(ms.date 2025-03-04, updated 2026-06-26). Verified 2026-08-07.

### Conditional Access is evaluated only after first-factor authentication

> "Conditional Access policies are evaluated only after the initial authentication. As a result, an
> authentication strength doesn't restrict a user's initial authentication."

This is what backs the report's statement that a CA authentication strength never overrides what
System-Preferred Authentication presents at the first factor. Same source as above.

### The two SMS/Voice dates count different populations (backs the deadline cards)

> "Starting September 1, 2026, passkeys become the default authentication experience and will be
> automatically enabled for users enabled for SMS or voice."

> "After February 1, 2027 | Users whose **only available MFA method is SMS or voice** will be
> required to register a passkey during sign-in... This prompt will be **blocking**... **There is no
> opt out from this February 1 behavior.**"

And, confirming that a user with a stronger method is not automatically exempt from the September
date:

> "Users who already sign in with passkeys, Windows Hello for Business, or another phishing-resistant
> method can continue using those methods. However, users who remain enabled for SMS or voice may
> still receive prompts to register passkeys on eligible devices."

Source: [concept-sms-voice-retirement](https://learn.microsoft.com/entra/identity/authentication/concept-sms-voice-retirement)
(ms.date 2026-07-29, updated 2026-08-03). Verified 2026-08-07.

### The opt-out is a single Graph property (backs AUTH006)

> "To opt out, update your authentication methods policy using Microsoft Graph and set the
> `passkeyDynamicMigration` property to `true`."

Note the direction: `true` means **excluded from** the rollout. Same source.

### Registration nudges never fire in the same session as a registration (backs the flow scenarios)

> "**If a user just went through MFA registration, are they nudged in the same sign-in session?**
> No. To provide a good user experience, users aren't nudged to set up Authenticator in the same
> session in which they registered other authentication methods."

### A CA policy on security-info registration suppresses nudges entirely (backs CA-Gated flow)

> "A nudge doesn't appear if a user is in scope for a Conditional Access policy that blocks access
> to the **Register security information** page."

Source for both: [how-to-mfa-registration-campaign](https://learn.microsoft.com/entra/identity/authentication/how-to-mfa-registration-campaign)
(ms.date 2026-05-20, updated 2026-07-23). Verified 2026-08-07.

### Who gets interrupted, and whether they can skip (backs the nudge forecast)

On the SSPR interrupt being skippable forever when MFA registration isn't also enforced:

> "Combined registration adheres to both multifactor authentication and SSPR policies, if both are
> enabled for your tenant. These policies control whether a user is interrupted for registration
> during sign-in and which methods are available for registration. **If only an SSPR policy is
> enabled, then users are be able to skip (indefinitely) the registration interruption** and
> complete it at a later time."

On the documented list of scenarios that interrupt a user:

> "*SSPR registration enforced:* Users are asked to register during sign-in. They register only
> SSPR methods."
> "*SSPR refresh enforced:* Users are required to review their security info at an interval set by
> the admin."

Source: [concept-registration-mfa-sspr-combined](https://learn.microsoft.com/entra/identity/authentication/concept-registration-mfa-sspr-combined)
(ms.date 2025-03-04, updated 2026-05-01). Verified 2026-08-07.

On the passkey nudge being evaluated per device rather than per account, which is why the forecast
reports eligibility rather than certainty:

> "The nudge evaluation is based on each device-and-browser combination that you use, rather than
> for your user account."

On the tenant-wide suppressors:

> "Users don't see a nudge when MFA is finished if their passkey profile has any of the following
> restrictions: Synced only / Device-bound only / Attestation enforced / AAGUID restrictions"

Source: [how-to-mfa-registration-campaign](https://learn.microsoft.com/entra/identity/authentication/how-to-mfa-registration-campaign)
(ms.date 2026-05-20, updated 2026-07-23). Verified 2026-08-07.

On the broken admin experience the forecast flags separately:

> "If SSPR registration is enabled and administrators are included in the password reset policy for
> users, they're still prompted to register but see a message indicating they can't register any
> methods. To avoid this experience, explicitly exclude administrators from the password reset
> policy for users when the password reset policy for administrators is disabled."

Source: [concept-sspr-policy](https://learn.microsoft.com/entra/identity/authentication/concept-sspr-policy)
(ms.date 2026-05-26, updated 2026-05-27). Verified 2026-08-07.

### Non-interactive sign-ins cannot show a nudge (backs the "where the prompt lands" guidance)

> "Non-interactive sign-ins are done *on behalf of a* user. These delegated sign-ins were performed
> by a client app or OS components on behalf of a user and **don't require the user to provide an
> authentication factor**. Instead, Microsoft Entra ID recognizes when the user's token needs to be
> refreshed and does so behind the scenes, **without interrupting the user's session**."

Microsoft's own examples of non-interactive sign-ins, which is why opening Outlook on an
already-signed-in device typically produces no prompt:

> - "A client app uses an OAuth 2.0 refresh token to get an access token."
> - "A user performs single sign-on (SSO) to a web or Windows app on a Microsoft Entra joined PC
>   (without providing an authentication factor or interacting with a Microsoft Entra prompt)."
> - "A user signs in to a second Microsoft Office app while they have a session on a mobile device
>   using FOCI (Family of Client IDs)."

Source: [concept-noninteractive-sign-ins](https://learn.microsoft.com/entra/identity/monitoring-health/concept-noninteractive-sign-ins)
(ms.date 2026-02-09, updated 2026-02-26). Verified 2026-08-07.

Note this is an inference chain rather than a single quoted sentence: Microsoft does not say
"non-interactive sign-ins are never nudged" in one place. It says a nudge follows MFA completion
during sign-in, and separately that non-interactive sign-ins request no authentication factor and
never interrupt the session. The conclusion follows, and is corroborated by the campaign article's
own statement that the nudge doesn't trigger inside an existing SSO session, but it is reasoning
across two documents rather than one citation.

On which app contexts can show a nudge:

> "Registration campaigns support embedded browser views in certain applications. The campaign
> doesn't nudge users in out-of-the-box experiences or in browser views embedded in Windows
> settings."

> "Microsoft Authenticator registration campaigns aren't supported on mobile devices. Passkey
> registration campaigns are supported on mobile devices, including: Browser-based experiences on
> mobile devices. Native iOS mobile apps. Native Android mobile app support isn't currently
> available."

> "Linux users aren't nudged. FIDO2 passkeys aren't available on Linux."

Source: [how-to-mfa-registration-campaign](https://learn.microsoft.com/entra/identity/authentication/how-to-mfa-registration-campaign)
(ms.date 2026-05-20, updated 2026-07-23). Verified 2026-08-07.

### Sign-in logs return interactive sign-ins, and retention is capped (backs campaign reachability)

On what the v1.0 endpoint returns, which is what makes "did this user do an interactive sign-in"
answerable at all:

> "Retrieve the Microsoft Entra user sign-ins for your tenant. **Sign-ins that are interactive in
> nature (where a username/password is passed as part of auth token) and successful federated
> sign-ins are currently included in the sign-in logs.**"

Source: [List signIns (Graph v1.0)](https://learn.microsoft.com/graph/api/signin-list)
(ms.date 2024-07-30, updated 2025-11-04). Verified 2026-08-07.

On the retention ceiling, which bounds every claim built on those logs:

| Report | Entra ID Free | Entra ID P1 | Entra ID P2 |
|---|---|---|---|
| Sign-ins | Seven days | 30 days | 30 days |

> "Log retention changes aren't retroactive. When you upgrade from Microsoft Entra ID Free to P1 or
> P2, only data still within the free retention period (up to seven days) is available."

Source: [reference-reports-data-retention](https://learn.microsoft.com/entra/identity/monitoring-health/reference-reports-data-retention)
(ms.date 2026-01-06, updated 2026-03-25). Verified 2026-08-07.

Consequence for this toolkit: any window longer than 30 days silently returns only what was
retained. "No interactive sign-in in the window" therefore always means "none within retention",
never "none ever", and a dormant account is indistinguishable from someone who simply didn't sign
in interactively during the window.

### The system-preferred credential ranking, and that it is not fixed

Verified in full 2026-08-09. The published order is TAP (1), passkey (2), certificate-based
authentication (3), Microsoft Authenticator notifications (4), external MFA (5), TOTP (6),
telephony (7), QR code (8), password (9). Passkey at rank 2 explicitly "includes security keys,
passkeys in Authenticator app, synced passkeys, Windows Hello for Business, and macOS Platform SSO."

The order is explicitly not stable:

> "The method order is dynamic and updates as the security landscape changes."

> "Certificate-based authentication (CBA) was previously placed last in the system-preferred
> authentication order due to known issues... Now that those issues are resolved, starting March
> 18th, 2026, certificate-based authentication moved to the third position."

With a consequence worth carrying, given CBA moved up six places:

> "users on devices without certificates will fail immediately during CBA and must manually select
> **Sign in another way** to continue with an alternate method."

On the three states, which is what the toolkit's inventory row reports:

> "**Enabled** - System-preferred authentication applies to second-factor only... **Microsoft
> managed** - System-preferred authentication applies to both first-factor and second-factor
> authentication."

On the rollout, and how a tenant can tell where it stands:

> "The **Microsoft managed** state behavior affects both first-factor and multifactor
> authentication and is being gradually deployed to tenants through August 2026. If your tenant or
> users don't experience system-preferred authentication as the first factor when the **State** is
> **Microsoft managed**, the rollout isn't deployed yet for your tenant."

Also relevant to the WHfB-only population the report flags: device-bound passkeys are offered at
first factor only conditionally.

> "If the user's only registered passkey is Windows Hello for Business or macOS Platform SSO, and
> the user's most recent sign-in wasn't with a passkey, system-preferred authentication skips it at
> the first factor and prompts the next highest-ranked method."

And a staging constraint: "You can only include one group for system-preferred authentication."

Source: [concept-system-preferred-authentication](https://learn.microsoft.com/entra/identity/authentication/concept-system-preferred-authentication)
(ms.date 2026-04-15, updated 2026-07-17). Verified 2026-08-09.

### Passkey registration is not supported for guest users (backs the Guest triage bucket)

> "Registration of passkey (FIDO2) credentials isn't supported for internal or external guest users,
> including B2B collaboration users in the resource tenant."

Source: [how-to-authentication-passkeys-fido2](https://learn.microsoft.com/entra/identity/authentication/how-to-authentication-passkeys-fido2)
(ms.date 2026-03-08, updated 2026-06-15). Verified 2026-08-07.

### The forced registration wizard can't register FIDO2 or phone sign-in (backs the Bootstrap flow)

> "Users in scope for these policies are redirected to the Interrupt mode of the combined
> registration. This experience doesn't currently support FIDO2 and phone sign-in registration."

### The 10-minute rule is about MFA freshness, not TAP specifically

> "The 10-minute requirement relates to MFA enforcement during credential registration, but not TAP
> specifically."

Source for both: [howto-authentication-temporary-access-pass](https://learn.microsoft.com/entra/identity/authentication/howto-authentication-temporary-access-pass)
(ms.date 2026-03-04, updated 2026-06-15). Verified 2026-08-07.

### Cross-device passkey registration in Authenticator (backs the cross-device caveat)

> "You can't register a passkey in Authenticator this way if attestation is enabled by your
> administrator."

Source: [how-to-register-passkey-authenticator](https://learn.microsoft.com/entra/identity/authentication/how-to-register-passkey-authenticator)
(updated 2026-07-06). Verified 2026-08-07.

### Microsoft Authenticator's own AAGUIDs

> - **Authenticator for Android**: `de1e552d-db1d-4423-a619-566b625cdc84`
> - **Authenticator for iOS**: `90a3ccdf-635c-4729-a248-9b709135078f`

Source: [how-to-enable-authenticator-passkey, "Authenticator AAGUIDs"](https://learn.microsoft.com/entra/identity/authentication/how-to-enable-authenticator-passkey#authenticator-aaguids)
(ms.date 2026-07-05, updated 2026-07-06). Verified 2026-08-07.

---

### Announced changes not yet reflected in the product docs

Two Message Center posts change the bootstrap story materially. Message Center posts aren't
publicly linkable, so these cite Merill Fernando's public mirror, which is the same convention
already used for MC1437671 elsewhere in this repo. Re-verify in your own tenant's Message Center
before quoting either to a customer, and expect the product documentation to catch up later.

**MC1450133 - passkey registerable as a first MFA method.** Users can register a passkey or
passwordless method as their first multifactor method rather than setting up a weaker one first.
Microsoft's framing: password-only users can go straight to a passkey. Phase 1 (synced passkeys,
Entra passkeys on Windows, FIDO2 keys) mid-October to mid-November 2026; Phase 2 (Windows Hello for
Business, macOS Platform SSO, Authenticator passwordless) early January to late February 2027.
Microsoft's own recommended actions include requiring MFA for security info registration, which is
what CA005 checks. Source: [MC1450133](https://mc.merill.net/message/MC1450133). Verified
2026-08-07.

**MC1450134 - WHfB and macOS Platform SSO as standalone MFA factors.** These already satisfied MFA
at primary sign-in; after this change they also satisfy step-up prompts and Authentication Strength
checks without a separate passkey. Early October to late November 2026. The consequence worth
carrying: users holding only these device-bound credentials stop receiving automatic prompts to
register additional MFA methods, so that population stops self-correcting while its exposure is
unchanged. Source: [MC1450134](https://mc.merill.net/message/MC1450134). Verified 2026-08-07.

Note on sourcing: a secondary write-up of these changes gave a less precise Phase 2 window than the
Message Center posts themselves. The dates recorded in this repo come from the MC posts, which is
also why they're worth re-checking directly rather than from any summary, including this one.

### Device code flow is high risk in Microsoft's own words (backs SIGNIN002)

The protocol reference page that SIGNIN002 originally cited is a developer document and contains no
security warning at all. The Conditional Access page for authentication flows does, verbatim:

> "Device code flow is a high-risk authentication method that can be part of a phishing attack or
> used to access corporate resources on unmanaged devices."

> "Allow device code flow only where necessary. Microsoft recommends blocking device code flow
> wherever possible."

The same page names the mechanism for acting on the finding: an **authentication flows** condition in
Conditional Access that explicitly targets device code flow, plus a sign-in-log **authentication
protocol** filter for measuring current usage before blocking. Two operational traps worth knowing
before recommending the block. First, *protocol tracking*: once a session has used device code flow,
that state persists through refreshes, so later non-device-code requests in the same session are also
subject to the policy. Second, since early September 2024 these policies are enforced against the
**Device Registration Service** when the policy targets all resources, which breaks device
registration that relies on device code flow unless that resource (client ID
`01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9`) is excluded. Source:
[concept-authentication-flows](https://learn.microsoft.com/entra/identity/conditional-access/concept-authentication-flows),
ms.date 2026-03-24. Verified 2026-08-09.

### Reviewing who changes Conditional Access policy (backs AUDIT002)

Microsoft's guidance for this sits in the deployment-planning article, not the Conditional Access
overview. Under "Govern and manage policies at scale":

> "**Protect policy changes.** Enable protected actions to require additional verification before
> anyone creates, modifies, or deletes Conditional Access policies."

> "Adopt a policy-as-code workflow with source control and continuous integration so changes are
> reviewable, testable, and reversible."

One benign explanation for an application rather than a person appearing as the actor on a policy
change: the **Conditional Access Optimization Agent** (Security Copilot) can create or update
policies from a suggestion in one click. A tenant running that agent will legitimately show
non-human policy authorship, so AUDIT002 findings should be triaged against whether the agent is
provisioned rather than treated as suspicious by default. Source:
[plan-conditional-access](https://learn.microsoft.com/entra/identity/conditional-access/plan-conditional-access#govern-and-manage-policies-at-scale),
ms.date 2026-06-01. Verified 2026-08-09.

### Break-glass guidance is now passwordless (affects AUDIT001's framing)

The emergency-access article no longer describes break-glass accounts as long-password accounts
excluded from MFA. It now instructs:

> "Choose one of these passwordless authentication methods for your emergency access accounts. These
> methods satisfy the mandatory multifactor authentication requirements" — passkey (FIDO2)
> (recommended), or certificate-based authentication.

The monitoring claim AUDIT001 rests on is unchanged and explicit:

> "Monitor all sign-in and audit log activity for emergency access accounts with alerts to detect
> unnecessary or unauthorized use."

Also newly explicit, and relevant to CA003/CA004 exclusion advice: report-only policies do **not**
need an emergency-account exclusion, and validation drills are expected "at least every 90 days."
Source:
[security-emergency-access](https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access),
ms.date 2026-06-04. Verified 2026-08-09.

### What survives "Migration Complete" (refines AUTH007)

The migration-state table is exact, and confirms the claim:

> Pre-migration — "Legacy policy settings are respected."
> Migration in Progress — "Legacy policy settings are respected."
> Migration Complete — "Legacy policy settings are ignored."

But "ignored" is not "gone." The same page states that after full migration two parts of the legacy
SSPR policy stay live: the **Number of methods required to reset** control, and the **SSPR
administrator policy**. Independently, the SSPR policy article says the admin policy "doesn't depend
upon the Authentication methods policy" — so an admin can register and use a method for SSPR that the
Authentication methods policy disables. Both facts mean a tenant reading `migrationComplete` still has
authentication behaviour that the Authentication methods policy does not describe. Sources:
[concept-authentication-methods-manage](https://learn.microsoft.com/entra/identity/authentication/concept-authentication-methods-manage#migration-between-policies)
(ms.date 2025-03-04) and
[concept-sspr-policy](https://learn.microsoft.com/entra/identity/authentication/concept-sspr-policy#administrator-reset-policy-differences)
(ms.date 2026-05-26). Verified 2026-08-09.

### Authentication strength is incompatible with external authentication methods (caveats CA002/CA006)

CA006 treats a plain `mfa` grant control as weaker than an authentication strength. There is one
legitimate reason a tenant runs the plain control, and Microsoft flags it on the CA002 template page:

> "External authentication methods are currently incompatible with authentication strength. You
> should use the **Require multifactor authentication** grant control."

A tenant using a third-party MFA provider through external authentication methods therefore *has* to
use the plain control. CA006 should be read alongside whether the tenant has an external method
configured, rather than as an unconditional finding. Source:
[policy-all-users-mfa-strength](https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-mfa-strength),
ms.date 2026-03-24. Verified 2026-08-09.

### Registration reporting lags by up to 36 hours and omits disabled users (caveats REG001/REG002)

> "The data in the report is not updated in real-time and may reflect a latency of up to 36 hours."

> "User accounts that were recently deleted, also known as soft-deleted users, are not listed in user
> registration details. Same for disabled users."

Two consequences for the roster this toolkit builds. A registration that happened yesterday may not
appear, so a run immediately after a registration push understates coverage. And because disabled
users are excluded from the source report, roster totals are a count of *enabled, non-deleted* users,
which will not reconcile against a raw user count. Source:
[howto-authentication-methods-activity](https://learn.microsoft.com/entra/identity/authentication/howto-authentication-methods-activity),
ms.date 2025-10-22. Verified 2026-08-09.

### Staged Rollout, and why TAP matters to federated tenants (backs the Staged Rollout inventory)

Not tied to a rule, by design: this is inventory, collected by `Get-SAWStagedRollout` and
interpreted by `ConvertTo-SAWStagedRolloutInventory`, and it never reaches the rules engine.
Staged Rollout is a temporary migration state, so there is no value of "enabled" that is correct
for every tenant. The quotes below are the caveats the inventory raises against other findings.

Three API facts, each verified against Microsoft's Graph reference on 2026-08-09, because each one
produces a plausible-looking wrong answer if missed:

- The endpoint is **v1.0**, not beta: `GET /v1.0/policies/featureRolloutPolicies`.
- The least-privileged delegated scope is **`Policy.Read.HybridAuthentication`**.
  `Policy.Read.All` does *not* cover it; the only alternatives Microsoft lists are
  `Directory.ReadWrite.All` and `Policy.ReadWrite.HybridAuthentication`, both write scopes this
  toolkit will never request.
- `feature` is an **evolvable enum**. Without a `Prefer: include-unknown-enum-members` request
  header, the two newest members (`certificateBasedAuthentication` and
  `multiFactorAuthentication`) return as `unknownFutureValue` rather than by name. Those two are
  the ones an authentication assessment most cares about, so the header is sent. Without it the
  response still parses and is still wrong.

Sources for the three: [featureRolloutPolicy resource
type](https://learn.microsoft.com/graph/api/resources/featurerolloutpolicy) (ms.date 2024-07-08)
and [List featureRolloutPolicies](https://learn.microsoft.com/graph/api/featurerolloutpolicies-list)
(ms.date 2024-03-06). `appliesTo` is a relationship rather than a property, so the targeted groups
are absent unless the request adds `$expand=appliesTo`.

The transition is not instant in either direction:

> "When a user is added to a Staged Rollout (SR) group ... their authentication method will
> transition from federated to managed. This change takes effect after the user completes one more
> interactive sign-in using their existing federated login."

The TAP interaction is stated as a recommended workaround, and the ordering is the whole point:

> "Because Microsoft Entra evaluates a TAP before it redirects a user to the federated identity
> provider, administrators can issue a TAP to the user immediately after adding them to Staged
> Rollout."

Two unsupported-scenario entries contradict advice this repo gives for hybrid tenants:

> "Self-service password reset (SSPR) with writeback to an on-premises domain isn't supported when
> staged rollout is enabled for a security group. Although it works in some cases, SSPR can't be
> guaranteed to work consistently when staged rollout is enabled."

> "If you have a Windows Hello for Business hybrid certificate trust with certs that are issued via
> your federation server acting as Registration Authority or smartcard users, the scenario isn't
> supported on a Staged Rollout."

And Microsoft's framing of the feature itself, which is newer than most practitioners' mental model:

> "Staged rollout is **not** designed to be a permanent configuration."

Group mechanics, for anyone sizing a pilot: max 10 groups per feature, no nested groups, no dynamic
groups, 200 users when a group is first added, and up to 24 hours for membership edits to take
effect. Source:
[how-to-connect-staged-rollout](https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-staged-rollout),
ms.date 2026-07-22. Verified 2026-08-09.

### Attack research behind the "why now" framing (backs the two-tier target state)

Not Microsoft sources, and not backing a pass/fail rule. Recorded because the blog's threat
framing and its high-value-account recommendations rest on them, and because **patch status is
the part most likely to go stale**: two of the three issues below were fixed or partly fixed
between discovery and publication, so anything written from this section needs its status
re-checked before reuse.

**Michael Grafnetter (SpecterOps), *Pass-the-Passkey Family of Attacks*, 17 July 2026**, presented
at Black Hat USA 2026. Read 2026-08-09 from the published PDF (v2). Three vulnerabilities:

| Issue | Status as of the paper |
|---|---|
| Windows wrote complete WebAuthn assertions to an event log readable by unprivileged, including remote, authenticated users | **Fixed 2026-07-14**, CVE-2026-34348. Patched systems truncate the signature to 6 bytes. Microsoft rated 6.5 Medium; researcher filed 8.6 High |
| Entra ID did not enforce WebAuthn assertion replay protection | **Partially fixed**, May 2026, via signature-counter tracking. Still open for Windows Hello: "Windows Hello passkeys on Entra ID registered devices remain vulnerable to replay, because Windows Hello always sends a counter value of 0" |
| Credential UI window handle spoofing, enabling trustworthy-looking prompt flooding | **Not fixed.** MSRC assessed it Low severity, Defense in Depth category, 2026-06-04 |

The two claims that change our advice, quoted:

> "The exploit satisfies the phishing-resistant multi-factor authentication requirement enforced by
> conditional access policies."

> "For high-value accounts, we recommend using device-bound passkeys instead of synced ones, and
> enforcing attestation to ensure that only genuine and approved authenticators are used."

Also relevant: testing against Microsoft 365 E5 users with Entra Identity Protection and Defender
for Identity produced no alerts. The paper's administrator recommendations map almost directly onto
PASS001 (enforce attestation for high-value users), PASS003 (device-bound over synced), and a
caveat on CA003/CA006 ("do not rely solely on the phishing-resistant multi-factor authentication
requirement in conditional access policies for high-value identities and applications").

The **shadow passkey** technique is why registration coverage and audit review are separate
concerns in this toolkit: an actor holding `UserAuthenticationMethod.ReadWrite.All` or
`UserAuthMethod-Passkey.ReadWrite.All` can register a passkey *on behalf of* another user, which
survives a password reset and **raises** the target's phishing-resistant coverage number. A metric
that goes the wrong way when attacked is worth knowing about.

**Dirk-jan Mollema, *Borrowing Windows Hello Keys for Authentication and Persistence***, read
2026-08-09. Preconditions are a compromised user session on a WHfB-enrolled device plus ordinary
user privileges, no local admin. The Windows Hello key signs assertions through CNG without a PIN
or biometric prompt, working from cached state, because Remote Desktop support requires
device-independent key use. Chain: sign assertion, request a Primary Refresh Token valid 90 days,
register further devices. The persistence step that matters for reading registration data is that
using the WHfB key counts as fresh MFA, so the attacker can enrol additional passkeys. Mollema
frames this as a consequence of the design rather than a fixable bug, so the response is detection;
his query filters `SigninLogs` for Windows Hello sign-ins where `DeviceDetail.deviceId` is empty.

**Marco Wohler, *Windows Hello for Business (WHfB) in practice*** (Medium), read 2026-08-09.
Practitioner source, not vendor documentation, and used only for deployment guidance: cloud
Kerberos trust as the default for SMB ("the newest and by far the simplest way to enable secure
WHfB"), certificate trust as the legacy path needing an Intune Certificate Connector, and the
`FarKdcTimeout` ten-minute Kerberos retry causing mapped drives to look disconnected. The
certificate-trust point corroborates, from a different direction, the Staged Rollout limitation
recorded above.

## Platform compatibility claims

Every platform/browser/app support claim in
[passkey-platform-compatibility.md](passkey-platform-compatibility.md) comes from a single source:

[Passkey (FIDO2) authentication matrix with Microsoft Entra ID](https://learn.microsoft.com/entra/identity/authentication/concept-fido2-compatibility)
(updated 2026-05-09). Verified 2026-08-07.

Re-check that page before quoting any of it in a customer deliverable. It is the fastest-moving
reference in this list, because browser and OS support genuinely changes.

---

## AAGUID reference sources (non-Microsoft)

The FIDO2 key-name resolution table in `ConvertTo-SAWFido2KeyInventory.ps1` mixes sources of
genuinely different reliability. That distinction is deliberate and is surfaced in the report
itself, not just here.

| Vendor / provider | Source | Confidence | Last verified |
|---|---|---|---|
| Yubico (all YubiKey and Security Key models) | [YubiKey hardware FIDO2 AAGUIDs](https://support.yubico.com/hc/en-us/articles/360016648959-YubiKey-hardware-FIDO2-AAGUIDs) | Vendor-published | 2026-08-07 |
| Feitian (ePass, BioPass, MultiPass, AllinPass, iePass, cards) | [FEITIAN FIDO products](https://fido.ftsafe.com/products/) | Vendor-published | 2026-08-07 |
| SoloKeys (Solo, Solo Tap, Somu) | [SoloKeys metadata statements](https://docs.solokeys.dev/metadata-statements/) + [solokeys/solo1 repo](https://github.com/solokeys/solo1/tree/master/metadata) | Vendor-published | 2026-08-07 |
| Microsoft Authenticator (Android, iOS) | [Authenticator AAGUIDs](https://learn.microsoft.com/entra/identity/authentication/how-to-enable-authenticator-passkey#authenticator-aaguids) | Vendor-published | 2026-08-07 |
| Synced passkey providers + browser credential stores | [passkeydeveloper/passkey-authenticator-aaguids](https://github.com/passkeydeveloper/passkey-authenticator-aaguids/blob/main/aaguid.json) | Community-maintained | 2026-08-07 |
| Thales (IDPrime FIDO Bio) | Same community list as above | **Community only** - no Thales-published source found | 2026-08-07 |
| Google Titan | **None found** | Not covered - see below | 2026-08-07 |

**Google Titan.** Checked Google's product pages, FIDO Alliance discussion threads, and every
AAGUID list that does cover the vendors above. No Google-published Titan AAGUID was found. It is
deliberately absent rather than guessed at, so a Titan key shows as "Unrecognized" in the report.
If a customer needs Titan resolved, read the AAGUID off a registered key in the Entra admin center
(the user's authentication method details show it) and add it to the table from that observation.

**Feitian correction.** A secondary-source blog post found during research gave different
AAGUID/product-name pairings than Feitian's own page for at least two entries. The toolkit uses
Feitian's values. This is the reason for the vendor-direct-first rule.

---

## Known corrections and source conflicts

Kept deliberately, because "we checked and Microsoft had moved it" is more credible than a
reference list that looks like it was right the first time.

**SSPR dates moved twice (corrected 2026-08-06).** Both the registration-campaign nudge date and
the enforcement date changed on Microsoft's own page after they were first recorded here. The nudge
moved to 2026-11-09 and enforcement to 2026-10-05, which also **reversed their order**: the nudge
now falls *after* enforcement, so the original "nudge ahead of enforcement" framing was removed
rather than re-dated. Source:
[howto-sspr-authenticationdata](https://learn.microsoft.com/entra/identity/authentication/howto-sspr-authenticationdata).

**System-Preferred Authentication's "default" state is described inconsistently by Microsoft.**
Two Microsoft pages describe the unset/"Microsoft managed" state differently. The toolkit reports
the state as observed and attaches a "Rollout timing not confirmed" badge rather than asserting a
behavior, because the tenant's actual behavior depends on where Microsoft is in its own batch
rollout, which is not observable through Graph.

**Two citations did not support their claims (corrected 2026-08-09).** Re-opening the eight
"carried over" rows found two where the page was real, the claim was true, but the page did not say
it. SIGNIN002 cited the OAuth device-authorization-grant protocol reference for "device code flow is
a known phishing vector" — that page is developer documentation and carries no security warning
whatsoever. AUDIT002 cited the Conditional Access overview for "policy changes made by applications
warrant review" — that page describes what Conditional Access is and never discusses change
governance. Both now cite pages that state the claim in Microsoft's own words (see the quoted
sections above). This is the failure mode that a "last verified" date alone does not catch: the date
records that *someone looked*, not that what they found actually said the thing.

**AUTH001's source URL had been retired (corrected 2026-08-09).**
`.../authentication/concept-authentication-methods` now redirects to
`.../authentication/overview-authentication`. The redirect works, so the link was never broken and
nothing looked wrong. Worth noting alongside the URL change: that page's recommendation is
phishing-resistant methods (Windows Hello for Business, passkeys/FIDO2, certificate-based
authentication), and Microsoft Authenticator *push* is not in that list — it appears in the methods
table as MFA- and SSPR-capable but not as phishing-resistant, while "Passkey in Microsoft
Authenticator" is a separate row that is. AUTH001 checks that Authenticator is enabled, which the
page supports as a baseline; it is not an endorsement of push as a target state, and the rule's
Phase 1 placement already reflects that.

**PASS001/PASS002 read two properties Microsoft has deprecated (found and fixed 2026-08-09).**
`fido2AuthenticationMethodConfiguration.isAttestationEnforced` and `.keyRestrictions` are both
marked in Microsoft's v1.0 Graph reference (ms.date 2026-03-04) as "deprecated and will be removed
in October 2027. Use the **passkeyProfiles** property." The replacement is a `passkeyProfile`
collection plus a `defaultPasskeyProfile` that, per the same page, "is automatically created when
migrating to passkey profiles and initially mirrors the tenant's legacy global passkey (FIDO2)
authentication methods policy settings."

Five places read the deprecated properties and nothing read `passkeyProfiles`. All five now go through `ConvertTo-SAWPasskeyPolicyEffective`, which prefers profiles, falls back to the legacy properties, and reports Unknown when neither is present. The affected call sites were:
`ConvertTo-SAWNormalizedPasskeys` (PASS001/PASS002/PASS003), `ConvertTo-SAWFido2KeyInventory`,
`ConvertTo-SAWNudgeForecast` (suppressor detection), `ConvertTo-SAWRegistrationFlowScenarios`, and
`ConvertTo-SAWAuthenticationMethodsInventory`.

Why this is worse than an ordinary deprecation: every one of those call sites coerces the value with
`[bool]`, so a missing property becomes `$false`, which renders as **"attestation not enforced"** and
**"key restrictions not enforced"**. That is a false negative on a security control that looks like a
real finding, the same failure mode as the beta-property bug recorded above. The risk is not only
future-dated either — a tenant already migrated to passkey profiles whose profile has since diverged
from the mirrored legacy values could read wrong today. Verify against a live migrated tenant before
assuming the October 2027 date is the whole exposure. Source:
[fido2AuthenticationMethodConfiguration](https://learn.microsoft.com/graph/api/resources/fido2authenticationmethodconfiguration).

**Two claims in a secondary explainer did not survive checking (2026-08-09).** A thalpius.com post on
passkey cryptography was reviewed for this project. Its dates were accurate and are now recorded in
`config/timeline-milestones.json`. Two other claims were not: it refers to a `passkeyType` setting for
choosing device-bound versus synced, which does not appear on the v1.0 resource (the real mechanism is
`passkeyProfiles`), and it lists Entra Join or Hybrid Join as a Windows Hello prerequisite, where
Microsoft's own supported-join-types table also lists **Microsoft Entra registered**. The post carries
an explicit disclaimer that "several values and behaviors described in this post fall outside
Microsoft's documented ranges and were only confirmed through direct testing in a single tenant,"
which is exactly the case for treating a good secondary source as a pointer to check rather than a
fact to copy.

**Linux passkey support is described inconsistently.** The compatibility matrix lists Chrome, Edge,
and Firefox on Linux as supported for passkey sign-in, while the registration campaign article
states "Linux users aren't nudged. FIDO2 passkeys aren't available on Linux." These are different
scopes (sign-in vs campaign nudge eligibility) but the wording conflicts. Treat Linux as
"supported for sign-in, not covered by the campaign" and verify against both pages if it matters
for a specific customer.

---

## Maintaining this document

When adding or changing a rule, add or update its row here in the same commit. A rule whose
recommendation text makes a factual claim with no row in this table is the thing this document
exists to prevent.

Re-verification is worth doing before any customer-facing deliverable that quotes dates, and at
minimum whenever a Microsoft rollout milestone passes. Checking a page takes under a minute: open
it, compare its last-updated date against the "Last verified" column, and read the specific
paragraph the claim rests on.

Read the paragraph, not just the page. The 2026-08-09 pass re-opened all eight remaining
"carried over" rows and found three problems, none of which a broken link would have revealed: two
citations pointed at real, current, topically-adjacent pages that never made the claim, and one URL
had been silently redirected to a renamed article. The test to apply is "can I quote a sentence from
this page that says this?" — if the answer is a paraphrase, the citation is decoration. Where the
answer is yes, put the sentence in "Key claims, quoted" so the next person doesn't have to re-derive
it.

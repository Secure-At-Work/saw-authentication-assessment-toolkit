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

**2026-08-12 full audit.** Every URL in this document - all 28 rule and quoted-claim citations,
plus the blog post's external sources (a CVE record, the SpecterOps PDF, Dirk-jan Mollema's blog,
a Medium article, two Message Center posts, and the platform compatibility matrix) - was re-fetched
and every quoted sentence re-checked verbatim. Findings: one citation's quoted sentence had been
rewritten by Microsoft since its last check (Staged Rollout, corrected below), two pages had been
edited since their last verification but their quoted content held up unchanged (SMS/voice
retirement; `how-to-register-passkey-authenticator`'s metadata), and one open mystery (the
`Policy.Read.HybridAuthentication` AADSTS70011 conflict) had one hypothesis ruled out. No wrong
claims, no fabricated citations, and no CVE/CVSS misquotes were found anywhere, including in the
blog post, which had not been through this level of check before. See the dated entries throughout
this document and the "Known corrections" section for specifics.

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
| **PASS001** | Attestation verifies the authenticator's make/model at registration; registration-campaign nudge claim corrected 2026-09-09 | [Passkey profiles, "Enforce attestation"](https://learn.microsoft.com/entra/identity/authentication/how-to-authentication-passkeys-fido2) | **2026-08-07**, corrected **2026-09-09** |
| **PASS002** | Key restrictions allow/block specific models by AAGUID; registration-campaign nudge claim corrected 2026-09-09 | [Passkey profiles, "Key Restriction Policy"](https://learn.microsoft.com/entra/identity/authentication/how-to-authentication-passkeys-fido2) | **2026-08-07**, corrected **2026-09-09** |
| **PASS003** | Synced passkeys are phishing-resistant but have a different custody model | [Synced vs device-bound passkeys](https://learn.microsoft.com/entra/identity/authentication/how-to-authentication-passkeys-fido2) | **2026-08-07** |
| **RCAMP001 / RCAMP002** | The campaign nudges registration and can target Authenticator or passkey - passkey-profile eligibility table corrected 2026-09-09 | [Run a registration campaign](https://learn.microsoft.com/entra/identity/authentication/how-to-mfa-registration-campaign) | **2026-08-07**, corrected **2026-09-09** |
| **REG001 / REG002** | MFA coverage must be measured with `isMfaCapable` (policy-aware), not `isMfaRegistered` | [userRegistrationDetails](https://learn.microsoft.com/graph/api/resources/userregistrationdetails) + [activity report](https://learn.microsoft.com/entra/identity/authentication/howto-authentication-methods-activity) | **2026-08-09** (field corrected) |
| **REG003** | `isPasswordlessCapable` measures passwordless capability, which is **not** the same set as phishing-resistant | [userRegistrationDetails](https://learn.microsoft.com/graph/api/resources/userregistrationdetails) + [phishing-resistant methods](https://learn.microsoft.com/entra/identity/authentication/overview-authentication) | **2026-08-09** |
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
(ms.date 2026-08-10, updated 2026-08-10). Verified 2026-08-12 - page was edited after the prior
2026-08-07 check, re-confirmed word for word including the `passkeyDynamicMigration = true` opt-out
direction ("your tenant is **excluded** from the automatic passkey enablement and Registration
Campaign rollout during the opt-out period").

### The SSPR registration campaign nudge (2026-11-09) is conditional, not universal (backs the deadline card)

Prompted by the user's own question: has this toolkit accounted for which of Microsoft's upcoming
automatic actions can actually be turned off? Re-checked every dated milestone in
`config/timeline-milestones.json` against its source page. Three (2027-02-01 SMS/Voice retirement,
2026-11-30 WHfB/macOS Platform SSO becoming standalone MFA factors) confirmed no opt-out exists;
2026-09-01 was already correctly documented as opt-out-able via AUTH006. The 2026-11-09 SSPR
registration campaign nudge, however, was previously described in this file's own milestone data as
"Informational - no admin action required to trigger it" - wrong. The source states it plainly as a
condition:

> "Starting Nov 9, 2026, **If your SSPR settings require users to register during sign-in**, and
> enabled users do not have enough methods to complete SSPR, a registration campaign will prompt
> affected users to register methods ahead of enforcement."

Source: [howto-sspr-authenticationdata](https://learn.microsoft.com/entra/identity/authentication/howto-sspr-authenticationdata)
(ms.date 2025-03-04, updated 2026-08-04). Verified 2026-08-14.

That condition is the classic **Password Reset > Registration** admin blade's "require users to
register when signing in" toggle - the same blade already established elsewhere in this document as
having no readable Graph property (`passwordresetpolicy` is not a real Graph resource, confirmed 404;
see "The Existing User Re-Registration trace read 'no reconfirmation' from the wrong policy" below,
which hit the same blade's reconfirmation-interval setting). So a tenant that never enabled that
toggle would see this nudge never fire at all, and this toolkit has no way to distinguish that tenant
from one where the nudge is live - the milestone's impacted-user count is now documented as an upper
bound assuming the toggle is on, not a confirmed prediction.

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

### The exact decision logic for how many methods a user must register (backs the SSPR two-gate discussion)

Prompted by the user sharing the page's own flowchart image directly. The same page documents the
flowchart's logic in prose, confirming it's current (not a stale/replaced diagram) and giving the
worked example the diagram alone doesn't:

> "When registration is enforced, users are shown the minimum number of methods needed to be
> compliant with both multifactor authentication and SSPR policies, from most to least secure.
> Users going through combined registration where both MFA and SSPR registration are enforced, and
> the SSPR policy requires two methods, are first required to register an MFA method as the first
> method and can select another MFA or SSPR specific method as the second registered method (such
> as email, security questions, and so on)"

> "A user is enabled for SSPR. The SSPR policy requires two methods to reset and is enabled
> Microsoft Authenticator app, email, and phone. When the user chooses to register, two methods
> are required: The user is shown Microsoft Authenticator app and phone by default. The user can
> choose to register email instead of Authenticator app or phone."

The flowchart's left branch ("MFA Registration Enforced") is triggered by any of three named
scenarios: "multifactor authentication registration enforced through Microsoft Entra ID
Protection" (the same Identity Protection MFA registration policy documented above), "through
per-user multifactor authentication" (the legacy mechanism), or "through Conditional Access or
other policies." All three converge on the same registration requirement once triggered - the
diagram doesn't distinguish which one fired.

One more caveat from the same page, unrelated to the flowchart but worth carrying alongside it:
*"Customers attempting to register or manage security info through combined registration or the
My Sign-ins page should use a modern browser such as Microsoft Edge. IE11 isn't officially
supported."* Narrower than the Opera finding above (this is about the registration/manage
experience specifically, not the sign-in challenge), but the same underlying pattern - Microsoft
names specific supported browsers for a given flow rather than "any modern browser."

Source: same page as above. Verified 2026-08-31.

### Microsoft Authenticator's per-target authentication mode gates passwordless capability (backs REG003's caveat and the new inventory field)

Prompted by the user's own admin-center screenshot of Microsoft Authenticator's target settings,
showing "Authentication mode: Passwordless" for the All Users target - a setting this toolkit
didn't read at all before this. Confirmed against the Graph resource type directly, since the
admin center's label doesn't match the API's enum value:

> "authenticationMode ... Determines which types of notifications can be used for sign-in. The
> possible values are: `any`, `deviceBasedPush` (passwordless only), `push`."

Source: [microsoftAuthenticatorAuthenticationMethodTarget](https://learn.microsoft.com/graph/api/resources/microsoftauthenticatorauthenticationmethodtarget)
(ms.date 2024-07-22, updated 2025-12-03). Verified 2026-08-31. The admin center's "Passwordless"
option is Graph's `deviceBasedPush`; "Push" in the UI is Graph's `push`; there's no UI label
mismatch for `any`.

**No new Graph call needed.** This property lives on each Microsoft Authenticator
`includeTargets` entry, part of the same `authenticationMethodConfigurations` array
`Get-SAWAuthenticationMethods.ps1` already fetches wholesale from `/policies/authenticationMethodsPolicy`
- purely a converter-side gap (`ConvertTo-SAWAuthenticationMethodsInventory.ps1` wasn't reading a
field it already had), not a collector one. Added to the Settings column, one label when every
include target agrees, "varies by target" when they don't. Also added as a caveat on REG003
(`isPasswordlessCapable`), since a group locked to `push` can have every user registered for
Authenticator and still never count as passwordless-capable through it - Graph's own
`isPasswordlessCapable` calculation should already account for this correctly, but the setting is
now visible directly rather than only inferable from a coverage number that doesn't explain itself.

On the passkey nudge being evaluated per device rather than per account, which is why the forecast
reports eligibility rather than certainty:

> "The nudge evaluation is based on each device-and-browser combination that you use, rather than
> for your user account."

On the tenant-wide suppressors:

> "Users don't see a nudge when MFA is finished if their passkey profile has any of the following
> restrictions: Synced only / Device-bound only / Attestation enforced / AAGUID restrictions"

Source: [how-to-mfa-registration-campaign](https://learn.microsoft.com/entra/identity/authentication/how-to-mfa-registration-campaign)
(ms.date 2026-05-20, updated 2026-07-23). Verified 2026-08-07.

**CORRECTED 2026-09-09 - the quote directly above is now stale for the Microsoft managed
campaign state.** Message Center [MC1469555](https://mc.merill.net/message/MC1469555)
("Microsoft Entra: Optimized Passkey Registration Campaign Experience", published 2026-09-09)
announces the opposite of what was quoted: most of those same restricted profiles now qualify a
user for the nudge rather than suppressing it. Re-fetched the same Microsoft page directly to
confirm - it has been rewritten (ms.date now 2026-09-02, updated 2026-09-04) and the "tenant-wide
suppressors" framing above is gone, replaced with a full eligibility table:

> "When your registration campaign is in the **Microsoft managed** state and targets passkeys,
> each scoped user's passkey profile is checked when they sign in. A user is nudged if they're in
> **at least one** passkey profile configuration that meets the following criteria... Unrestricted
> ... Synced-only ... Device-bound-only ... AAGUID-restricted: The allow list contains at least one
> AAGUID for the following providers: iCloud Keychain, Google Password Manager (GPM), Microsoft
> Authenticator passkey, Microsoft Entra passkey on Windows ... Device-bound with attestation
> enforced: Key restrictions aren't evaluated."

And explicitly on Exclude/Block lists, which the old suppressor model didn't need to consider:

> "**Exclude** and **Block** lists are ignored when campaign eligibility is determined. An admin
> can have entries in **Exclude** or **Block**, but the targeting logic doesn't evaluate them for
> eligibility."

This is an active rollout, not a settled fact to encode as certain either way - the page itself
carries a rollout notice:

> "We're rolling out this version of the registration campaign. The rollout is expected to finish
> by the end of September 2026. Until then, the registration campaign experience in your tenant
> might differ from what's described in this article."

General availability per MC1469555: early-to-mid September 2026 for Worldwide/GCC, full rollout
expected complete by end of September 2026. **Scope of the correction**: this only applies to the
**Microsoft managed** campaign state. The **Enabled** state (tenant configures targeting itself)
never applied a passkey-profile eligibility check in the first place - "any passkey profile
configuration" was already sufficient there - so nothing changes for tenants running Enabled
state. Also unaffected: the AAGUID-restricted case still requires a *specific* provider on the
allow-list, not any AAGUID - a tenant restricted to, say, only Yubico AAGUIDs remains ineligible
under Microsoft managed, matching neither the old blanket-suppression claim nor a blanket
inclusion.

Practical effect on this toolkit, FIXED 2026-09-09: `ConvertTo-SAWNudgeForecast.ps1`'s suppressor
logic (`src/collector/ConvertTo-SAWNudgeForecast.ps1`, the `$suppressors` block) previously
implemented the now-superseded rule - it treated `PASS001`/`PASS002` enforcement and a
device-bound/synced-only default passkey profile as unconditionally suppressing the passkey nudge.
This was a functional prediction bug, not just a documentation gap. Corrected: attestation
enforcement, AAGUID key restrictions with a recognized qualifying-provider AAGUID on the allow
list, and a device-bound-only or synced-only default profile no longer suppress the nudge. The
only remaining suppressor is an AAGUID allow-list restriction, without attestation also enforced,
whose configured AAGUIDs don't match this toolkit's own AAGUID reference table (three of
Microsoft's four qualifying providers are verified there - iCloud Keychain, Google Password
Manager, Microsoft Authenticator; no verified AAGUID for "Microsoft Entra passkey on Windows" was
found, so that specific suppressor is worded as "likely" rather than certain, and says so in the
forecast output). RCAMP001, PASS001, PASS002's `Recommendation` text, and the nudge-forecast
collector logic are now all consistent with the corrected Microsoft managed eligibility table.
Tests updated in `tests/collector/ConvertTo-SAWNudgeForecast.Tests.ps1`.

Source: [how-to-mfa-registration-campaign](https://learn.microsoft.com/entra/identity/authentication/how-to-mfa-registration-campaign)
(ms.date 2026-09-02, updated 2026-09-04) + [MC1469555](https://mc.merill.net/message/MC1469555).
Verified 2026-09-09.

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

### Microsoft-managed campaigns can still be scoped by group; the real "default" uncertainty is rollout wave, not lock-out (backs `CampaignScopeUncertainReason`)

Prompted by a live-run false-positive question: does selecting "Microsoft managed" for the
registration campaign lock targeting to All users, making a specific-group scope impossible? No -
Microsoft's own docs say the opposite for targeting specifically, while locking something else:

> "Select **Microsoft managed** to enable the registration campaign with Microsoft-recommended
> defaults. When **Microsoft managed** is selected, the target authentication method, snooze
> duration, and limited number of snoozes are set automatically and can't be configured. **You can
> still configure include/exclude targets.**"

So a Microsoft-managed campaign (`state: default`) with an admin-configured `includeTargets`
pointing at specific group(s) is a real, supported configuration - not something the API would
reject or the portal would grey out. `ConvertTo-SAWNudgeForecast.ps1` treats that case
(`CampaignScopeUncertainReason = 'group'`) the same way as a fully admin-managed (`state: enabled`)
group-scoped campaign: the true nudge population needs group-membership lookup this toolkit doesn't
do.

The separate, more common case - `state: default` with *no* `includeTargets` configured at all
(the shape seen in this project's sample fixture and in a live tenant run) - has a different root
cause, documented on the same page under the incremental rollout:

> "**User targeting** changes from voice call or text message users to all MFA capable users."

Read together with the "recommended defaults... automatically... can't be configured" language
above, this describes a Microsoft-controlled, per-tenant rollout stage that isn't itself exposed
through Graph: an untouched Microsoft-managed campaign's actual population is either "SMS/Voice
users only" or "all MFA-capable users" depending on where a given tenant sits in that rollout, and
there is no group to look up to resolve it - unlike the specific-group case above. This is why the
toolkit distinguishes `CampaignScopeUncertainReason = 'msft-managed-rollout'` from `'group'` and
gives different guidance for each (see `docs/reading-the-report.md`).

Source: [how-to-mfa-registration-campaign](https://learn.microsoft.com/entra/identity/authentication/how-to-mfa-registration-campaign)
(ms.date 2026-05-20, updated 2026-07-23). Verified 2026-08-12.

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
(ms.date 2026-04-15, updated 2026-07-17). Verified 2026-08-09, re-confirmed verbatim 2026-08-12.

**Follow-up, 2026-08-31: the date moved, and the public page hasn't caught up.** Message Center
MC1411574 (last updated 2026-08-24) now states the Microsoft-managed first-factor rollout is
"expected to complete by late September 2026 - updated from the original late July deadline." This
public page, last edited 2026-07-17, still reads "through August 2026" - it predates the MC
update and hasn't been revised to match. Treat the Message Center as the more current source for
this specific date until the public page catches up, and re-check both before quoting either. See
also the new dedicated entry below on this same discrepancy.

### Passkey profiles already auto-migrated for most tenants (revises the "not confirmed against a live migrated tenant" caveat)

Also found searching mc.merill.net for this topic. Message Center
[MC1221452](https://mc.merill.net/message/MC1221452) ("General Availability of passkey profiles
and migration for existing Passkeys (FIDO2) tenants") documents an **automatic** migration, not an
opt-in-only one:

> "If you don't opt in, Microsoft automatically migrates your tenant: Existing Passkey (FIDO2)
> authentication method configurations will be moved into a Default passkey profile... If enforce
> attestation is enabled, then device-bound allowed. If enforce attestation is disabled, then
> device-bound and synced allowed." Existing key restrictions and user targeting carry over
> unchanged.

Rollout: passkey profiles GA - Worldwide/GCC March 2026, GCC High/DoD May 2026, USNat/USSec
October 2026. Automatic migration for tenants with existing Passkey (FIDO2) settings - Worldwide/GCC
**May-June 2026**, GCC High/DoD & USNat/USSec **October 2026**.

Source: [MC1221452](https://mc.merill.net/message/MC1221452) (via mc.merill.net). Verified
2026-08-31.

**Directly revises a caveat in `docs/design-notes.md`** written when this toolkit's own passkey
profile collector (`ConvertTo-SAWPasskeyPolicyEffective.ps1`) had "no tenant in reach" that had
migrated, so the deprecated-properties fallback was assumed to be the commonly-exercised path in
practice. For Worldwide/GCC tenants, the automatic migration window has already closed as of this
writing - the profiles branch should now be the normal case for most tenants, not the fallback.
The collector's own logic doesn't need to change (it already handles both branches), but its
live-tenant testing predates this finding and hasn't been redone against a tenant confirmed to
have gone through auto-migration specifically.

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
(ms.date 2026-07-05, updated 2026-07-06). Verified 2026-08-07, re-confirmed verbatim 2026-08-12.

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

### Identity Protection's MFA registration policy is a blind spot for this toolkit (caveats REG001/REG002)

Prompted by the user's own screenshot of **ID Protection > Multifactor authentication registration
policy** and the question "did you take this into account?" - it wasn't, and it's a real, distinct
enforcement mechanism from everything else this toolkit checks around registration:

> "Microsoft Entra ID Protection prompts your users to register the next time they sign in
> interactively, and they have 14 days to complete registration... at the end of the period, they
> must register before they can complete the sign-in process."

Source: [howto-identity-protection-configure-mfa-policy](https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-mfa-policy),
ms.date 2025-08-06, updated 2026-02-10. Verified 2026-08-26. Requires Entra ID P2 or Entra Suite - the
same page names the [Security Administrator](https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference#security-administrator)
role as least-privileged to configure it.

**Genuinely stronger than the registration campaign this toolkit already tracks (RCAMP001/RCAMP002)**:
the campaign's snooze can be unlimited by default, so a user can defer indefinitely; this policy
converts to a hard block after the 14-day window, no snooze escape.

**Confirmed unreadable via Graph.** The only related object found, `authenticationRequirementPolicy`
(beta, attached to `signIn` log entries, not a standalone policy resource), is diagnostic rather than
configuration: it reports *why* a specific past sign-in required MFA, via a `requirementProvider` enum
that includes `mfaRegistrationRequiredByIdentityProtectionPolicy` as one possible value among many
(`v1ConditionalAccess`, `securityDefaults`, `riskBasedPolicy`, etc.) - useful for confirming after the
fact that this policy fired on a specific sign-in, not for reading its current enabled/disabled state
or target scope. Source: [authenticationRequirementPolicy](https://learn.microsoft.com/graph/api/resources/authenticationrequirementpolicy?view=graph-rest-beta),
ms.date 2024-07-22, updated 2026-07-04. Verified 2026-08-26. Same shape of gap as the classic SSPR
"Registration" blade's reconfirmation setting documented above - a real admin-center control with no
clean Graph read, so REG001/REG002 can only recommend checking it directly rather than reading it.

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

  **Documentation versus live behavior conflict, found 2026-08-12, unresolved.** Requesting this
  exact scope from a real tenant produced an outright rejection at the token endpoint:
  `AADSTS70011: The provided value for the input parameter 'scope' is not valid. The scope '...'
  does not exist.` The scope name was re-checked against
  [List featureRolloutPolicies](https://learn.microsoft.com/graph/api/featurerolloutpolicies-list)
  twice after the failure and matches Microsoft's documented permissions table character for
  character - both times the same "Policy.Read.HybridAuthentication" string. So either this specific
  permission isn't consentable through the default Microsoft Graph PowerShell client for this
  tenant/app combination, or something about live availability lags the documentation - not
  determined, and not something re-reading the same page a third time will resolve. AADSTS70011
  fails the *entire* Connect-MgGraph call atomically (every scope requested alongside it, not just
  this one), so `Connect-SAWGraph.ps1` now catches this specific error and retries once without
  this one scope rather than letting one optional inventory row take the whole assessment down -
  see the `.PARAMETER Scopes` docstring there. If you can independently confirm this scope working
  cleanly on a different tenant or a different first-party client ID, that would narrow down which
  half of the contradiction is the real cause - worth updating this entry with whatever's found.

  **One hypothesis ruled out, 2026-08-12.** Independently re-fetched both Graph reference pages
  again as part of a full documentation audit: the permissions table on
  [List featureRolloutPolicies](https://learn.microsoft.com/graph/api/featurerolloutpolicies-list)
  still reads exactly `Policy.Read.HybridAuthentication` - identical spelling, casing, and
  punctuation to what this toolkit requests. So "Microsoft quietly corrected a typo in the docs"
  is not the explanation; whatever is causing the live AADSTS70011 rejection, it isn't documentation
  drift. The mystery stands as a live-tenant/consent-flow question, not a stale-citation one.
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

The transition is not instant in either direction. Microsoft rewrote this section between the
2026-08-09 and 2026-08-12 checks (new heading "Scenarios that require an additional federated or
managed sign-in"); the meaning is unchanged but the sentence below replaces the one previously
quoted here, which no longer exists verbatim:

> "User added to Staged Rollout. When a user is added to a Staged Rollout group, or when a group
> they belong to is enabled for Staged Rollout, the authentication experience doesn't switch from
> federated to managed immediately. The user must complete one additional interactive sign-in using
> their existing federated authentication method. After this sign-in, Microsoft Entra updates the
> user's state and applies managed authentication for subsequent sign-ins."

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
effect - all unchanged by the rewrite. Source:
[how-to-connect-staged-rollout](https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-staged-rollout),
ms.date 2026-08-11, updated 2026-08-12. Verified 2026-08-12.

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

### App Protection Policy / device compliance can silently block passkey registration (backs CA003's caveat)

Found via a secondary blog ([mobile-jon.com, 11 Aug 2026](https://mobile-jon.com/2026/08/11/farewell-sms-passkeys-are-the-new-standard-getting-ready-to-ditch-legacy-authentication-methods/)),
traced to two more authoritative practitioner sources for verification, since the original article
named only one of the three service principals and gave no diagnostic detail. No official Microsoft
documentation found for any of this - checked directly, nothing on learn.microsoft.com names these
service principals or this failure mode.

**Nathan McNulty** (Entra MVP), *Improving passkey registration experiences*, read 2026-08-13:

> "Many companies that are serious about rolling out phishing resistant authentication are also
> serious about requiring device compliance and/or app protection policies, and they have run into
> issues where these policies prevent users from creating passkeys."

Diagnosed via sign-in logs showing "failed attempts to register with Compliance or APP
requirements." McNulty names the app: "this service principal is responsible for the registration
of security information gathered by apps such as Microsoft Authenticator and the My Signins
portal against a user" - and is explicit that it's undocumented: "no public documentation, and thus
no definitive answer."

**Nate Hutchinson**, *Phishing-resistant MFA: planning your passkey rollout in Microsoft 365*, read
2026-08-13, independently names all three service principals needing exclusion from any App
Protection Policy Conditional Access policy:

> "certain CA configurations requiring App Protection Policies can inadvertently block passkey
> registration in the Authenticator app. Specifically, you need to ensure that Microsoft App Access
> Panel, AAD Reporting, and Azure Credential Configuration Endpoint are excluded from any App
> Protection Policy CA policy."

The Azure Credential Configuration Endpoint Service app ID
(`ea890292-c8c8-4433-b5ea-b09d0668e1a6`) was independently confirmed via
[a third-party Graph permissions reference](https://permissions.cengizyilmaz.net/apps/azure-credential-configuration-endpoint-service-ea890292-c8c8-4433-b5ea-b09d0668e1a6.html)
listing it as a real first-party Microsoft enterprise application. Three independent sources naming
the same failure mode, two of them naming the same app by ID, is enough corroboration to act on
despite the lack of official documentation - but re-check learn.microsoft.com periodically in case
Microsoft documents this later, since an undocumented exclusion list is exactly the kind of thing
that changes without notice.

### RADIUS/NPS-authenticated workloads never reach Conditional Access at all (backs CA002/CA006's caveat)

Same secondary article surfaced this; unlike the App Protection Policy trap above, this one has
direct, authoritative Microsoft sourcing - found and confirmed 2026-08-13:

> "Rather than relying on RADIUS and the Microsoft Entra multifactor authentication NPS extension
> to apply Microsoft Entra multifactor authentication to VPN workloads, we recommend that you
> upgrade your VPN's to Security Assertion Markup Language (SAML) and directly federate your VPN
> with Microsoft Entra ID. **This gives your VPN the full breadth of Microsoft Entra ID Protection,
> including Conditional Access, multifactor authentication, device compliance, and Microsoft Entra
> ID Protection.**"

Read by contrast: the RADIUS/NPS path does NOT give a VPN that same breadth of coverage - Microsoft
is recommending SAML federation specifically *to gain* Conditional Access, meaning the RADIUS path
lacks it. Applies to VPN, WiFi, Remote Desktop Gateway, and VDI - anything authenticating through
the NPS extension for Microsoft Entra multifactor authentication rather than a native Entra sign-in.
Source: [RADIUS authentication with Microsoft Entra
ID](https://learn.microsoft.com/entra/architecture/auth-radius) (ms.date 2023-01-10, updated
2026-02-26).

A related, smaller fact found while re-checking System-Preferred Authentication's own rollout status
(still "gradually deployed to tenants through August 2026" as of this check - unchanged, and the
secondary article's claim that this rollout "completed" in August 2026 is not corroborated by
Microsoft's own current page, so not adopted here): the same page's FAQ states plainly, "System-
preferred authentication doesn't affect users who sign in by using the Network Policy Server (NPS)
extension. Those users don't see any change to their sign-in experience." Source:
[concept-system-preferred-authentication](https://learn.microsoft.com/entra/identity/authentication/concept-system-preferred-authentication)
(ms.date 2026-04-15, updated 2026-07-17 - unchanged since the last check, re-verified 2026-08-13).
Superseded on the specific "through August 2026" date by the Message Center finding below -
this public page itself was still unchanged as of 2026-08-13, but MC1411574 (2026-08-24) gives a
later, more current completion estimate.

### The System-Preferred Authentication rollout date moved to late September 2026 (corrects `timeline-milestones.json`)

Prompted by the user asking to search mc.merill.net for anything new on this topic. Message Center
MC1411574 ("Microsoft Entra: System-preferred authentication now applies to first-factor
authentication") gives a later completion estimate than every source already cited above:

> Rollout "beginning late June 2026 and expected to complete by late September 2026" - "updated
> from the original late July deadline."

Source: [MC1411574](https://mc.merill.net/message/MC1411574) (via mc.merill.net - Message Center
posts can't be linked publicly). Published 2026-07-01, last updated 2026-08-24. Verified 2026-08-31.

**Two sources now disagree, and the disagreement is itself worth recording rather than picking a
side silently.** The public `concept-system-preferred-authentication` page (last edited
2026-07-17, cited throughout this document as "through August 2026") predates this Message Center
update by five weeks. The Message Center is the tenant-admin-facing channel and the more likely
one to be current, but neither has been cross-confirmed against the other since 2026-08-24 - the
next verification pass should check whether the public page has been revised to match. Corrected
in `config/timeline-milestones.json` (moved 2026-08-31 -> 2026-09-30), `docs/design-notes.md`,
`docs/reading-the-report.md`, and the live dashboard note in
`ConvertTo-SAWAuthenticationMethodsInventory.ps1` - the "through August 2026" phrasing was baked
into product-facing UI text, not just documentation.

### The per-user "Default sign-in method" is superseded once System-Preferred Authentication is on

Prompted by a customer's own admin-center screenshot: a specific user's **Users > Authentication
methods** page showed a per-user **"Default sign-in method (Preview)"** field set to Microsoft
Authenticator notification, alongside a separate **System preferred multifactor authentication**
panel reading Enabled / Fido2 for that same user - two different answers to "what does this user
sign in with," on the same page. The per-user field is not what actually applies once
system-preferred authentication is on for that user. Microsoft's own page states this directly:

> "After system-preferred authentication is enabled, the authentication system does all the work.
> Users don't need to set any authentication method as their default because the system always
> determines and presents the most secure method they registered."

Source: same page as above. Verified 2026-08-31. This resolves a real "which field is true"
confusion the classic per-user Authentication methods report can create - the per-user default is
a legacy value, effectively inert once system-preferred authentication (Enabled or Microsoft
managed) applies to that user; the "System preferred multifactor authentication" panel on that
same page is the one that reflects what will actually happen.

### Opera isn't in Microsoft's own passkey browser matrix (explains the same customer's actual symptom)

Follow-up on the case above: the affected user was on **Opera**, expected a passkey prompt after
username entry (System-Preferred Authentication was confirmed Microsoft managed, ruling out the
Enabled-vs-managed and rollout-timing explanations considered first), and got a **password**
prompt instead. Checked against Microsoft's own passkey browser matrix, and Opera doesn't appear
in it at all - the table lists exactly four browsers, on every platform:

> "| OS | Chrome | Edge | Firefox | Safari |"

Source: [Passkey (FIDO2) authentication matrix with Microsoft Entra ID](https://learn.microsoft.com/entra/identity/authentication/concept-fido2-compatibility),
ms.date 2026-04-16, updated 2026-05-09. Verified 2026-08-31 - same version already cited in
[passkey-platform-compatibility.md](passkey-platform-compatibility.md).

Opera is Chromium-based, same rendering engine as Chrome and Edge, but sharing an engine isn't the
same as being tested or supported - it's absent from the matrix on every OS row, not just missing
a checkmark. The practical read, not confirmed by any Microsoft text found (no page documents the
client-side decision logic itself): Entra's sign-in page most likely does its own browser
detection before deciding whether to attempt a passkey/WebAuthn challenge at all, and a browser
outside its supported list falls back to password rather than attempting an unvalidated flow -
which matches the observed symptom exactly. Treat any other non-listed browser (Brave, Vivaldi,
and similar Chromium-based browsers included) the same way: not a WebAuthn engine problem, a
"Microsoft hasn't tested or listed this browser" problem.

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

**The passkey nudge-suppressor list only covered 2 of Microsoft's 4 documented conditions, and the
resolver feeding it had two pre-existing bugs (found and fixed 2026-08-12).** Microsoft's
`how-to-mfa-registration-campaign` page documents four conditions under which a user's passkey
profile suppresses the nudge: synced-only, device-bound-only, attestation enforced, AAGUID key
restrictions (quoted in full earlier in this document). `ConvertTo-SAWNudgeForecast.ps1`'s
suppressor list only ever checked the last two. The gap was invisible because nothing surfaced it
as a caveat - `docs/reading-the-report.md` described the same incomplete list to readers as if it
were complete.

Closed by reading `passkeyProfile.passkeyTypes` (`deviceBound` | `synced`, confirmed as a real
Graph beta property - [passkeyProfile resource
type](https://learn.microsoft.com/graph/api/resources/passkeyprofile?view=graph-rest-beta)) from
the **default** profile specifically, the same simplification `ConvertTo-SAWPasskeyPolicyEffective`
already uses for `KeyRestrictions` - passkeyTypes is a required field with no "unrestricted" value
to aggregate toward the way attestation/key-restriction booleans have a safe default, so the
"every profile must agree" rule used for those two doesn't apply here.

Two unrelated, pre-existing bugs in the same resolver surfaced while adding this and were fixed in
the same pass:

1. **Dead-code branch order.** `if ($RawConfig.PSObject -and $RawConfig.PSObject.Properties)` was
   checked before the `elseif ($RawConfig -is [IDictionary])` branch written specifically to
   handle Hashtable-shaped configs. Every object - Hashtable included - has a non-null
   `PSObject.Properties`, so the first branch always ran and the second was unreachable. For a
   Hashtable, `.PSObject.Properties['isAttestationEnforced']` silently returns nothing even when
   the key exists (`.Contains(...)` is the correct test), so any live tenant whose Graph response
   came back as a Hashtable - the documented live shape, versus PSCustomObject for sample data -
   would report "Unknown" regardless of its actual attestation/key-restriction state. Fixed by
   checking `IDictionary` first.
2. **Single-item pipeline collapse.** `$profiles = @($RawConfig.passkeyProfiles) | Where-Object
   { $_ }` - when exactly one profile survives the filter, PowerShell assigns that one object to
   `$profiles` directly as a bare `Hashtable`, not a 1-element array. `Hashtable.Count` then
   returns the number of *keys* in the profile (4, typically), not "how many profiles" - silently
   breaking every `-eq $profiles.Count` comparison used to decide whether attestation/key
   restrictions are enforced tenant-wide. This specifically breaks the single-profile case, which
   is the most likely shape for a freshly-migrated tenant (one auto-created default profile).
   Fixed by wrapping the whole pipeline in an outer `@(...)`.

Neither bug was reachable through this project's own sample data (which exercises the "neither
legacy properties nor profiles present" Unknown path, not the Hashtable-legacy or single-profile
paths) - the same "fixture that never disagrees with itself" failure mode already recorded twice
elsewhere in this document. New Pester coverage in
`tests/collector/ConvertTo-SAWPasskeyPolicyEffective.Tests.ps1` (previously nonexistent for this
function despite five call sites) exercises both.

A broader sweep for the same single-item-pipeline-collapse shape elsewhere in `src/` found roughly
ten more occurrences; whether each is actually exposed to it (i.e., whether `.Count` or similar is
called on the result) hasn't been checked yet - flagged as a separate follow-up, not fixed in this
pass.

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

**REG001/REG002 measured `isMfaRegistered` instead of `isMfaCapable` (found and fixed 2026-08-09).**
The two `userRegistrationDetails` properties differ by one clause in Microsoft's own reference
(ms.date 2024-07-22):

> `isMfaRegistered` — "Indicates whether the user has registered a strong authentication method for
> multifactor authentication. The method **may not necessarily be allowed** by the authentication
> methods policy."

> `isMfaCapable` — "Indicates whether the user has registered a strong authentication method for
> multifactor authentication. The method **must be allowed** by the authentication methods policy."

Coverage on `isMfaRegistered` counts users who cannot complete MFA, because the only method they
registered has since been disabled tenant-wide. The failure is worst at the worst time: a customer
following this toolkit's own Phase 4 advice to retire SMS and Voice pushes exactly those users into
`registered = true, capable = false`, so the coverage number looks healthiest at the moment it
becomes least true.

Both rules now read `isMfaCapable`, and the *gap* between the two fields is surfaced as its own
warning — a registered-but-not-capable user appears on no "not registered" list and is one policy
change away from losing their own MFA. Rules renamed to match what they measure ("MFA Capable",
"MFA Capability Coverage"); RuleIDs are unchanged, so drift history still lines up.

Why it survived: the sample fixture had `isMfaRegistered == isMfaCapable` for all ten users, so the
divergence was never exercised. One fixture user now deliberately diverges. This is the third bug in
this repo caused by synthetic data that never disagrees with itself — the other two being the beta
authentication-policy properties and the passkey-profile deprecation. Source:
[userRegistrationDetails](https://learn.microsoft.com/graph/api/resources/userregistrationdetails).

**`isPasswordlessCapable` is now used (REG003), but deliberately NOT as a phishing-resistance
measure.** Microsoft defines it as covering "FIDO2, Windows Hello for Business, and Microsoft
Authenticator (Passwordless)". Compare that with Microsoft's own phishing-resistant list (WHfB,
Platform Credential for macOS, synced passkeys, FIDO2 security keys, passkeys in Microsoft
Authenticator, and certificate-based authentication) and the two sets diverge in BOTH directions:
Authenticator passwordless phone sign-in is passwordless but push-based, so still phishable and it
counts here; certificate-based authentication is phishing-resistant but is not named in the
passwordless definition at all. REG003 therefore reports passwordless capability as its own measure
alongside the roster's method-based phishing-resistant bucketing, and the assessment counts where
the two disagree in each direction. Treating them as synonyms would have repeated the
isMfaRegistered mistake one paragraph above.

Known gap in our own list, not yet closed: `ConvertTo-SAWUserRegistrationRoster` does not count
certificate-based authentication or Platform Credential for macOS as phishing-resistant, because
the exact `methodsRegistered` strings Graph emits for them have not been observed on a live tenant
and guessing one would under-count silently rather than fail loudly.

**Linux passkey support is described inconsistently.** The compatibility matrix lists Chrome, Edge,
and Firefox on Linux as supported for passkey sign-in, while the registration campaign article
states "Linux users aren't nudged. FIDO2 passkeys aren't available on Linux." These are different
scopes (sign-in vs campaign nudge eligibility) but the wording conflicts. Treat Linux as
"supported for sign-in, not covered by the campaign" and verify against both pages if it matters
for a specific customer.

**CA005's claim has no direct quote to point to (found in the 2026-08-12 full audit).** CA005 rests
on "resource targeting and user-action targeting are mutually exclusive per Conditional Access
policy." Re-checking `concept-conditional-access-cloud-apps` found nothing wrong with the claim -
the admin center's "Select what this policy applies to" control is genuinely single-select between
Cloud apps / User actions / Authentication context / Global Secure Access, and a screenshot on the
page is literally named `conditional-access-cloud-apps-or-actions.png` - but there is no sentence on
the page that states the exclusivity in prose the way this document's other rows quote one. This
document's own rule is "if the answer is a paraphrase, the citation is decoration" - by that
standard this citation is support-by-structure, not a quotable sentence, and is worth knowing before
using it as a direct rebuttal to a customer who asks for the exact words.

**The Existing User Re-Registration trace read "no reconfirmation" from the wrong policy (found on
a live tenant, 2026-08-12).** `ConvertTo-SAWRegistrationFlowScenarios.ps1`'s reconfirmation step
read only `authenticationMethodsPolicy.reconfirmationInDays` (the modern policy, beta) and reported
"no periodic reconfirmation interval is configured" whenever it was empty. A live run against a real
tenant showed the classic **Password reset > Registration** admin blade's own "Number of days before
users are asked to reconfirm their authentication information" set to 180 - a genuinely separate
setting this toolkit has never collected, confirmed against Microsoft's own SSPR tutorial:

> "Set **Number of days before users are asked to reconfirm their authentication information** to
> *180*."

Source: [tutorial-enable-sspr](https://learn.microsoft.com/entra/identity/authentication/tutorial-enable-sspr)
(ms.date 2025-03-04, updated 2026-05-08). Verified 2026-08-12.

That page places this setting under the exact same "legacy MFA and SSPR policy" deprecation framing
already established for AUTH007 - the tutorial's own callout, verbatim: "Beginning September 30,
2025, authentication methods can't be managed in these legacy MFA and SSPR policies." No Graph
v1.0 or beta property for this specific legacy setting has been found; `passwordresetpolicy` is not
a real resource type (confirmed 404 on the Graph reference).

**The classic blade's scope, confirmed 2026-08-12.** A follow-up question worth its own citation:
does the Registration page's reconfirmation setting apply tenant-wide, or only to whoever the
Properties page (`Self service password reset enabled: None/Selected/All`) already scoped SSPR to?
The same tutorial answers this directly, in a Note immediately after the Registration page steps:

> "The interruption to register security information during sign-in only occurs if the conditions
> configured on the settings are met. **This only applies to users and admin accounts that are
> enabled to reset passwords using Microsoft Entra self-service password reset.**"

So the Registration page's settings carry no independent scope of their own - they're bounded by
whatever population Properties already enabled. A Properties page scoped to a 2-user group means
exactly those 2 users are subject to the reconfirmation interval, not the tenant. Same source, same
verification pass.

**First fix was itself wrong, corrected same day.** The initial fix hedged only when
`policyMigrationState` wasn't `migrationComplete`, reasoning from that property's documented values
(`premigration`/`migrationInProgress` - "legacy policies are respected"; `migrationComplete` -
"legacy policies are ignored") that the legacy field must stop mattering once migration finishes.
That inference doesn't hold: this document's own AUTH007 section already establishes that
Microsoft names exactly two legacy elements as confirmed survivors of `migrationComplete` - "Number
of methods required to reset" and the SSPR administrator policy - and this reconfirmation field was
never one of them. That's silence, not a documented "ignored" for this specific setting. The same
live tenant that surfaced the original bug had **Migration status: Complete** in the admin center
while the legacy reconfirmation field still read 180 - direct evidence the migration-state gate was
unsafe. Fixed by hedging **unconditionally** whenever `reconfirmationInDays` is unset, regardless of
`policyMigrationState` - the scenario trace has no migration-state threshold it can safely use to
switch from "unknown" to a confident "no reconfirmation." `policyMigrationState` is still surfaced
in the step detail as context, just no longer as the basis for a claim. See
`docs/reading-the-report.md` for how this renders. Worth revisiting if a Graph-readable property for
the legacy setting, or explicit Microsoft guidance on its post-migration fate, is ever found.

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

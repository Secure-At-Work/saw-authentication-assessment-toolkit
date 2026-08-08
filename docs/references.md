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

- **Verified** means someone opened the live page and confirmed the specific claim, on the date
  shown. It does not mean the page hasn't changed since.
- **Carried over** means the citation predates this review and was not re-opened during it. Treat
  those as good but slightly colder.
- Where a rule's claim rests on a *specific sentence*, that sentence is quoted, because paraphrase
  is where accuracy usually goes missing.

---

## Rule-by-rule sources

| Rule | What it claims | Primary source | Last verified |
|---|---|---|---|
| **AUDIT001** | Break-glass credential changes should be deliberate and reviewed | [Manage emergency access accounts](https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access) | Carried over |
| **AUDIT002** | Conditional Access changes made by applications rather than people warrant review | [Conditional Access overview](https://learn.microsoft.com/entra/identity/conditional-access/overview) | Carried over |
| **AUTH001** | Microsoft Authenticator should be enabled | [What are authentication methods?](https://learn.microsoft.com/entra/identity/authentication/concept-authentication-methods) | Carried over |
| **AUTH002 / AUTH003** | SMS and Voice are being retired and should be moved off | [Passkeys by default and retirement of SMS and voice](https://learn.microsoft.com/entra/identity/authentication/concept-sms-voice-retirement) | **2026-08-07** |
| **AUTH004** | FIDO2 / passkeys should be enabled | [How to enable passkeys (FIDO2)](https://learn.microsoft.com/entra/identity/authentication/how-to-authentication-passkeys-fido2) | **2026-08-07** |
| **AUTH005** | Temporary Access Pass should be enabled as a bootstrap method | [Configure a Temporary Access Pass](https://learn.microsoft.com/entra/identity/authentication/howto-authentication-temporary-access-pass) | **2026-08-07** |
| **AUTH006** | `passkeyDynamicMigration = true` opts the tenant **out** of the automatic rollout | [SMS/voice retirement, "Temporarily opt out"](https://learn.microsoft.com/entra/identity/authentication/concept-sms-voice-retirement) | **2026-08-07** |
| **AUTH007** | Unmigrated legacy MFA/SSPR policy is still actively respected | [Migration between policies](https://learn.microsoft.com/entra/identity/authentication/concept-authentication-methods-manage#migration-between-policies) | Carried over |
| **BOOT001** | A bootstrap path (self-service FIDO2 or TAP) must exist before registration can be driven | [TAP article](https://learn.microsoft.com/entra/identity/authentication/howto-authentication-temporary-access-pass) + [passkey self-service toggle](https://learn.microsoft.com/entra/identity/authentication/how-to-authentication-passkeys-fido2) | **2026-08-07** |
| **CA001** | Legacy authentication should be blocked via CA, targeting Exchange ActiveSync + Other clients | [Block legacy authentication with Conditional Access](https://learn.microsoft.com/entra/identity/conditional-access/policy-block-legacy-authentication) | **2026-08-07** |
| **CA002** | MFA should be required for all users | [Require MFA for all users](https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-mfa-strength) | Carried over |
| **CA003** | Admin protection via compliant device *or* phishing-resistant strength | [Authentication strengths overview](https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths) | **2026-08-07** |
| **CA004** | A phishing-resistant strength gating security-info registration locks out TAP-only users | [Authentication strengths overview](https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths) | **2026-08-07** |
| **CA005** | Resource targeting and user-action targeting are mutually exclusive per policy | [Targeting resources in Conditional Access](https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-cloud-apps) | **2026-08-07** |
| **CA006** | A plain `mfa` control accepts any registered method; a strength does not | [Authentication strengths overview](https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths) | **2026-08-07** |
| **PASS001** | Attestation verifies the authenticator's make/model at registration | [Passkey profiles, "Enforce attestation"](https://learn.microsoft.com/entra/identity/authentication/how-to-authentication-passkeys-fido2) | **2026-08-07** |
| **PASS002** | Key restrictions allow/block specific models by AAGUID | [Passkey profiles, "Key Restriction Policy"](https://learn.microsoft.com/entra/identity/authentication/how-to-authentication-passkeys-fido2) | **2026-08-07** |
| **PASS003** | Synced passkeys are phishing-resistant but have a different custody model | [Synced vs device-bound passkeys](https://learn.microsoft.com/entra/identity/authentication/how-to-authentication-passkeys-fido2) | **2026-08-07** |
| **RCAMP001 / RCAMP002** | The campaign nudges registration and can target Authenticator or passkey | [Run a registration campaign](https://learn.microsoft.com/entra/identity/authentication/how-to-mfa-registration-campaign) | **2026-08-07** |
| **REG001 / REG002** | Per-user registration state is readable and coverage is measurable | [Authentication methods activity report](https://learn.microsoft.com/entra/identity/authentication/howto-authentication-methods-activity) | Carried over |
| **SIGNIN001** | Successful legacy-auth sign-ins are visible in sign-in logs | [Block legacy auth, "Identify legacy authentication use"](https://learn.microsoft.com/entra/identity/conditional-access/policy-block-legacy-authentication) | **2026-08-07** |
| **SIGNIN002** | Device code flow is a known phishing vector worth monitoring | [Device code flow](https://learn.microsoft.com/entra/identity-platform/v2-oauth2-device-code) | Carried over |
| **SSPR001** | Directory-sourced contact info stops satisfying SSPR on a fixed date | [SSPR authentication data](https://learn.microsoft.com/entra/identity/authentication/howto-sspr-authenticationdata) | 2026-08-06 |
| **SSPR002** | Admins run on their own two-gate SSPR policy | [Administrator reset policy differences](https://learn.microsoft.com/entra/identity/authentication/concept-sspr-policy#administrator-reset-policy-differences) | Carried over |
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

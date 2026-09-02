# Passkey (FIDO2) Platform Compatibility Reference

This is a working reference for planning a passkey rollout: which OS/browser/app combinations
support passkey (FIDO2) authentication with Microsoft Entra ID, and which don't. It's static
Microsoft product compatibility - the same for every tenant - not something this toolkit's
collectors query, so it lives here as documentation rather than as a rule or dashboard check. See
the ["Possible future work"](../README.md#possible-future-work) note in the README for the
related, genuinely tenant-specific question this reference doesn't answer: whether *your*
tenant's actual devices meet these floors, which would require an Intune/device-compliance
collector this toolkit doesn't have.

Primary source: Microsoft's own
[Passkey (FIDO2) authentication matrix with Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-fido2-compatibility),
last confirmed against the version updated 2026-05-09. Re-check that page before relying on this
for a live engagement - Microsoft revises this matrix as browser and OS support changes.

## Web browsers

| OS | Chrome | Edge | Firefox | Safari |
| --- | --- | --- | --- | --- |
| **Windows** | Yes | Yes | Yes | N/A |
| **macOS** | Yes | Yes | Yes | Yes |
| **ChromeOS** | Yes | N/A | N/A | N/A |
| **Linux** | Yes | Yes | Yes | N/A |
| **iOS** | Yes | Yes | Yes | Yes |
| **Android** | Yes | Yes | **No** | N/A |

The one explicit "doesn't work at all" cell: **Firefox on Android does not support passkey
sign-in.** Chrome and Edge on the same device do.

**Chrome, Edge, Firefox, and Safari are the entire list - nothing else is covered, and that
includes other Chromium-based browsers.** Opera, Brave, Vivaldi, and similar browsers built on the
same Chromium engine as Chrome/Edge do not appear anywhere in Microsoft's matrix, on any platform.
Confirmed against a real case: a user on Opera got a username prompt, then a **password** prompt
instead of the expected passkey step, even with System-Preferred Authentication set to Microsoft
managed. Sharing Chromium's rendering engine doesn't mean sharing Microsoft's testing or support -
the practical read is that Entra's sign-in page does its own browser detection before deciding
whether to attempt a passkey/WebAuthn challenge, and a browser it doesn't recognize as supported
falls back to password rather than attempting a flow Microsoft hasn't validated. Don't assume an
unlisted Chromium browser will "just work" because the engine matches one that's listed.

### Per-platform considerations

**Windows**
- Security-key sign-in requires Windows 10 version 1903+, and Chromium-based Edge, Chrome 76+, or
  Firefox 66+.

**macOS**
- Passkey sign-in requires macOS Catalina 11.1+ with Safari 14+ (Entra requires user verification
  for MFA).
- NFC and Bluetooth Low Energy (BLE) security keys are not supported on macOS - an Apple platform
  restriction, not an Entra one.
- **New security key registration doesn't work in any browser on macOS** - none of them prompt
  for the biometric/PIN setup Entra needs to complete registration. Sign-in with an
  already-registered key is fine; registration has to happen on a platform that does prompt.

**ChromeOS**
- NFC and BLE security keys are not supported (Google platform restriction).
- **Security key registration is not supported on ChromeOS or in Chrome browser at all**, on any
  platform.

**Linux**
- **Sign-in with a passkey stored in Microsoft Authenticator is not supported in Firefox on
  Linux** specifically. Other passkey types on Linux/Firefox are unaffected.

**iOS**
- Passkey sign-in requires iOS 14.3+ (user verification requirement, same as macOS).
- BLE security keys are not supported (Apple restriction).
- NFC with FIPS 140-3 certified security keys is not supported (Apple restriction).
- **New security key registration doesn't work in any iOS browser**, same root cause as macOS.

**Android**
- Passkey sign-in requires Google Play Services 21+ (user verification requirement).
- BLE security keys are not supported (Google restriction).

## Native apps

### Authentication broker support by OS

| OS | Broker(s) |
| --- | --- |
| **iOS** | Microsoft Authenticator |
| **macOS** | Microsoft Intune Company Portal |
| **Android** | Authenticator, Company Portal, or Link to Windows |

With a broker installed, a user can sign in with a passkey to any app that redirects through it
(e.g. Outlook), broker or third-party.

### Microsoft app support *without* a broker installed

| App | macOS | iOS | Android |
| --- | --- | --- | --- |
| Remote Desktop | Yes | Yes | Yes |
| Windows App | Yes | Yes | Yes |
| Microsoft 365 Copilot (Office) | N/A | Yes | Yes |
| Word / PowerPoint / Excel / OneNote | Yes | Yes | Yes |
| Loop | N/A | Yes | Yes |
| Edge | Yes | Yes | Yes |
| **OneDrive** | Yes | Yes | **No** |
| **Outlook** | Yes | Yes | **No** |
| **Teams** | Yes | Yes | **No** |

**Without a broker installed, OneDrive, Outlook, and Teams on Android cannot do passkey sign-in
at all.** The same three apps work fine without a broker on iOS and macOS - this is an
Android-specific gap. If a rollout plan assumes "the app supports passkeys" without separately
confirming the broker is actually deployed on Android devices, this is where it breaks silently.

### Third-party apps and identity providers

- Third-party MSAL-enabled apps can support passkey sign-in without a broker installed, subject
  to the app's own implementation (see Microsoft's
  [FIDO2 app development guidance](https://learn.microsoft.com/en-us/entra/identity-platform/support-fido2-authentication)).
- **Passkey authentication with a third-party identity provider is not supported on iOS or
  macOS at all**, broker or no broker. A tenant federating out to a third-party IdP will find
  passkeys silently don't work for that population on Apple platforms. The documented workaround
  runs through the IdP's own Apple Extensible Single Sign-On integration on MDM-managed devices,
  not anything Entra-side.

### Version floors for native apps

| Platform | Requirement |
| --- | --- |
| Windows | FIDO2 security key: Windows 10 version 1903+. Passkey in Microsoft Authenticator: **Windows 11 version 22H2+** specifically. |
| iOS | Without Microsoft's SSO plug-in: iOS 16.0+. **With** the plug-in: iOS 17.1+ (stricter, not looser). |
| macOS | Company Portal as broker requires the Microsoft Enterprise SSO plug-in, **macOS 14.0+, and MDM enrollment**. An unmanaged Mac cannot use passkey-via-broker regardless of OS version. |
| Android | FIDO2 security key: Android 13+. Passkey in Microsoft Authenticator: **Android 14+**. |

Windows also has a narrower, easy-to-miss gap: some PowerShell modules that route through
Internet Explorer instead of Edge (SharePoint Online, Teams modules, and any script that requires
admin credentials) can't prompt for FIDO2 at all. Microsoft's own documented workaround is
certificate-based authentication (CBA) on the affected admin accounts as an interim measure, not
a fix to FIDO2 support itself.

## Why syncable passkeys reach further than device-bound ones

Passkey in Microsoft Authenticator's Android 14+ floor is stricter than it needs to be for every
scenario: a syncable passkey via Google Password Manager reaches back to Android 9. If the
device fleet skews older, allowing syncable passkeys (see `PASS003` in this toolkit) broadens who
can actually be onboarded, at the trade-off `PASS003`'s recommendation already describes -
whether device-bound-only is a real requirement for this tenant or not is a policy decision, not
a fixed answer.

## How to use this during a rollout

Treat this matrix as a Phase 1 ("Foundation & Visibility") input, not something discovered after
enforcement is already live: know which OS/browser/app combinations are actually in your
tenant's device fleet before requiring passkeys via Conditional Access, so gaps surface as a
plan, not as a wave of support tickets.

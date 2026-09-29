# SMS/Voice Freeze Pilot Runbook

This runbook is the operational implementation plan for restricting SMS/voice authentication to a controlled Entra security group. It is designed for a pilot first, followed by measured expansion. The assessment remains read-only; the freeze script is the only flow in this repository that can change the authentication method policy, and it requires `-Apply` explicitly.

## Scope and safety model

The pilot freezes the current state. Users who currently have a phone-based authentication method are placed in an allowlist cohort. Users without one are reported as excluded. Optional exception users are placed in a separate review group; the exception group is for membership and governance tracking and is not automatically added to the policy target.

Do not apply the policy until the dry-run output has been reviewed and an approved rollback owner and date have been recorded.

## 1. Confirm prerequisites

Before touching the tenant:

- Confirm the target tenant and the change window.
- Confirm the Microsoft Graph PowerShell authentication module and PowerShell 7.4+ are available.
- Confirm the operator has the required Graph permissions and Entra roles to read users and authentication methods, manage groups, and update the authentication methods policy.
- Confirm a break-glass path that does not depend on SMS/voice.
- Name the business owner, technical operator, service desk contact, pilot start, review date, and rollback deadline.
- Export or record the current `VoiceAndPhone` authentication method policy before applying a change.

The assessment report should be reviewed before this runbook is started. Pay particular attention to SMS/Voice-only users, administrators, guests, and any registration or Conditional Access findings that could cause lockout.

## 2. Configure the group names

Create a local `config/config.json` from the sample and set the names according to the SAW Entra group convention. For example:

```json
{
  "SMSFreezePilot": {
    "GroupName": "AAD_UG_SMS-CurrentUsers-Allowed",
    "ExceptionGroupName": "AAD_UG_SMS-Exceptions"
  }
}
```

Use names that clearly identify the target population and purpose. Do not put tenant names, user names, or other PII in group names. Explicit `-GroupName` and `-ExceptionGroupName` parameters take precedence over the config file.

## 3. Establish the baseline

Run the assessment against the target tenant and save the generated dashboard and history snapshot. Record at least:

- Total users in scope.
- Users with SMS/voice registered.
- SMS/Voice-only users.
- Administrators and high-value accounts in those populations.
- Existing authentication method policy targets and exclusions.
- Existing registration campaign, passkey, TAP, SSPR, and Conditional Access settings.

Do not proceed if the report shows a missing bootstrap method, an unresolved high-risk Conditional Access registration path, or an unapproved account population in the proposed pilot.

## 4. Generate and review the dry-run plan

From the repository root, run:

```powershell
pwsh -File src/Invoke-SAWSmsFreezePilot.ps1 `
  -ConfigPath ./config/config.json `
  -DryRun -Verbose
```

Review and retain the output. Confirm:

- `DryRun` is `True`.
- `GroupName` and `ExceptionGroupName` match the approved names.
- Every intended pilot user appears in `AllowedUsers`.
- `ExceptionUsers` is intentional and separately approved.
- `ExcludedUsers` contains no user who must retain SMS during the pilot.
- No live Graph policy update occurred.

If the population is wrong, stop. Correct the source data, exception list, or group names and rerun the dry-run.

## 5. Approve the pilot wave

Start with a small, representative wave rather than the whole tenant. Record the selected users or departments outside the script's output, including the reason for inclusion and the owner who approved them.

The first wave should normally exclude:

- Break-glass accounts.
- Privileged administrators unless separately tested and approved.
- Users with unresolved device, browser, platform, accessibility, or application compatibility gaps.
- Users whose only usable authentication method is SMS/voice unless the replacement path has been verified.

The current-state allowlist mechanism is tenant-policy scoped. If the pilot must be limited to a subset, prepare the membership and exception approach before applying the policy, and verify how the tenant's policy targeting model handles that scope. Do not assume that creating a group alone limits the change unless the policy target is confirmed.

## 6. Apply the pilot change

Only after approval, run the apply command. Use `-CreateGroupIfMissing` only when group creation has been approved:

```powershell
pwsh -File src/Invoke-SAWSmsFreezePilot.ps1 `
  -ConfigPath ./config/config.json `
  -Apply `
  -CreateGroupIfMissing `
  -CreateExceptionGroupIfMissing `
  -ForceReauth -Verbose
```

If the groups already exist, pass their object IDs where possible and omit the create switches. The command adds the current allowlist users to the main group, adds approved exceptions to the exception group, and patches the `VoiceAndPhone` policy to target the main group.

Keep the command output, request identifiers, policy response, group object IDs, and timestamp with the change record.

## 7. Verify immediately

After apply, verify through Microsoft Graph and the Entra admin center:

- The main group exists and contains the intended members.
- The exception group exists and contains only approved exceptions.
- The `VoiceAndPhone` policy is enabled and its `includeTargets` contains the main group object ID.
- The policy does not contain unexpected targets or exclusions.
- A pilot user with an approved alternative method can authenticate.
- A controlled test account outside the allowlist cannot newly register or use SMS/voice, according to the tenant's expected policy behavior.
- No break-glass or administrative recovery path was changed unintentionally.

Record the verification results. Do not use a real user's account as a negative test account without explicit approval.

## 8. Monitor the pilot

Monitor for the agreed pilot window, with a named owner checking at least daily:

- Authentication failures and help-desk tickets.
- Registration and authentication method changes.
- Sign-in and audit logs for affected users.
- Group membership drift.
- New SMS/voice registrations or unexpected policy target changes.
- Admin and break-glass access.

The pilot is successful only when the replacement method works for the selected population, no critical lockout occurs, and the exception list is stable or shrinking. A warning, unexpected membership change, or unexplained authentication failure pauses expansion.

## 9. Roll back if required

Rollback is an approved change, not an emergency guess. Use the recorded pre-change policy as the source of truth:

1. Stop further pilot expansion.
2. Preserve the failing user's sign-in and audit evidence.
3. Restore the previously recorded `VoiceAndPhone` policy targets and state through the approved Graph change process.
4. Verify the restored policy in Graph and the Entra admin center.
5. Restore or adjust group membership only after the policy is restored.
6. Retest break-glass, admin, pilot, and affected user access.
7. Record the reason, impact, operator, timestamps, and next corrective action.

Do not delete the groups during the first rollback. Retain them for evidence and controlled retry unless the change owner explicitly approves deletion.

## 10. Expand or close the pilot

At the review date, compare the results with the approval criteria:

- Zero unresolved critical lockouts.
- Replacement authentication works for the pilot population.
- No unapproved exceptions remain.
- No unexpected policy or group drift exists.
- Service desk impact is understood and accepted.
- A new rollback date and owner are recorded for the next wave.

If the criteria pass, expand in small waves and repeat the dry-run, approval, apply, verify, and monitor sequence for each wave. If they do not pass, keep the pilot frozen, roll back when necessary, and remediate the underlying registration, platform, or Conditional Access issue before retrying.

## Related files

- [SMS freeze implementation](../src/Invoke-SAWSmsFreezePilot.ps1)
- [Sample configuration](../config/config.sample.json)
- [Assessment and dashboard usage](../README.md)
- [IST-to-SOLL roadmap](ist-to-soll-summary.md)
- [Report interpretation and transition guidance](reading-the-report.md)

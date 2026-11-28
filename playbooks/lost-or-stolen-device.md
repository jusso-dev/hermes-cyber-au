# Lost or stolen device

Playbook id: `lost-or-stolen-device`. Version 0.1.0. Last reviewed 2026-11-28.

Guidance, not legal advice. The assistant proposes. A person acts.

## Scope

Use this playbook when a work laptop, phone, tablet, USB drive or backup disk is lost or stolen, or a personal device with work data on it is. Open [suspected data breach](suspected-data-breach.md) as well when the device held personal information and was not protected.

## Roles

| Role | Who | Notes |
|---|---|---|
| Incident lead | Named person | Owns decisions and the timeline |
| Approver | IT manager or delegate | Approves remote lock or wipe |
| Device administrator | IT or managed service provider | Carries out approved actions |
| Device user | The staff member | Facts about the loss |
| Privacy officer | Named person | Data breach assessment |

## Approval boundaries

The assistant may read device management records, keep the timeline, draft messages and propose actions.

A named person must approve and carry out:

- remote lock, remote wipe or retiring the device. A wipe cannot be undone.
- disabling the user's accounts or resetting credentials
- a police report
- any notification to customers or a regulator

Write each as `Proposal: <action>. Reversible: <yes or no, and how>. Approver: <role>.` and stop.

## Phases

### 1. Detect and triage

Steps:

1. Record when the organisation became aware, in Australia/Sydney with an offset, and when and where the device was last seen.
2. Identify the device: asset tag, serial number, device management record.
3. Check encryption status and screen lock from device management, not from memory.

Decisions:

- Was the device encrypted and locked? If yes, and the key was not with it, the risk is much lower.
- What data and access did it hold: synced mail, files, saved passwords, VPN certificates?

Evidence to collect: device management record, encryption status report, last check-in time.

### 2. Contain

Steps:

1. Propose a remote lock now. Propose a remote wipe once evidence of the last check-in is saved.
2. Propose revoking sessions and tokens for accounts used on the device, and resetting passwords if they were stored on it.
3. Propose revoking device certificates.

Decisions:

- Wipe now or wait in case the device is found? The approver decides. Record why.

Evidence to collect: lock and wipe command results with times.

### 3. Investigate

Steps:

1. Review sign-ins from the device after it was lost.
2. List the data that was on the device, and whether it was synced copies or the only copy.

Decisions:

- Was data accessed after the loss? If yes, treat as a data breach.

Evidence to collect: sign-in logs, data inventory for the device.

### 4. Eradicate and recover

Steps:

1. Issue a replacement device with fresh credentials.
2. Restore the user's data from the organisation's copy.

Decisions:

- Is any data lost for good? Record it.

Evidence to collect: replacement record.

### 5. Notify and report

Steps:

1. If personal information was on an unencrypted or unlocked device, open [suspected data breach](suspected-data-breach.md) and run the [reporting obligations checker](../skills/reporting-obligations/SKILL.md).
2. Propose a police report for a theft, if the approver agrees.

Decisions:

- Is serious harm likely? The privacy officer assesses.

Evidence to collect: police event number, copies of any reports lodged.

### 6. Review

Steps:

1. Check that all devices are enrolled, encrypted and lock automatically.
2. Update this playbook.

## Evidence to collect

- [ ] Awareness time and last-seen time and place, Australia/Sydney
- [ ] Asset tag, serial number and device management record
- [ ] Encryption and screen lock status at the last check-in
- [ ] Data and accounts on the device
- [ ] Lock, wipe and revocation actions: who approved, who did it, when
- [ ] Police event number for a theft

## Who to tell

| Who | When | Why |
|---|---|---|
| Incident lead and IT | Immediately | Lock and revoke |
| Privacy officer | Within the first hour if personal information was on it | Breach assessment |
| Police | After approval, for a theft | Event number for insurance |
| Insurer | As the policy requires | Claim |

## Reporting obligations

Pass these facts to the [reporting obligations checker](../skills/reporting-obligations/SKILL.md): `personal_information_involved`, `serious_harm_ruled_out` (for example a strongly encrypted device whose key was not with it), `eligible_breach_believed`, `cyber_security_incident`. Likely rule: NDB assessment within 30 days, then a statement to the OAIC as soon as practicable if the breach is eligible.

## Timeline record

Record each entry as: time (Australia/Sydney with offset), phase, what happened or was decided, who, evidence reference.

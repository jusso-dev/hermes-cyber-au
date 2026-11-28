# Compromised cloud admin account

Playbook id: `compromised-cloud-admin`. Version 0.1.0. Last reviewed 2026-11-28.

Guidance, not legal advice. The assistant proposes. A person acts.

## Scope

Use this playbook when a privileged account in a cloud platform, identity provider or SaaS admin console shows activity nobody can explain: new admins, new access keys, changed MFA, disabled logging, unusual regions or mass downloads. Switch to [ransomware](ransomware.md) if workloads are encrypted or deleted for extortion.

## Roles

| Role | Who | Notes |
|---|---|---|
| Incident lead | Named person | Owns decisions and the timeline |
| Approver | Executive or platform owner | Approves lockouts and resource changes |
| Cloud administrator | A different, trusted admin | Carries out approved actions from a clean device |
| Legal and privacy | Counsel or privacy officer | Reporting duties |

## Approval boundaries

The assistant may read audit logs and configuration, keep the timeline, draft messages and propose actions.

A named person must approve and carry out:

- disabling the account, revoking sessions, deleting access keys or tokens
- removing admin role assignments, apps or federation trusts
- stopping, deleting or isolating cloud resources
- changing logging or retention
- any external report

Use a break-glass account for containment only with approval, and record its use. Write each action as `Proposal: <action>. Reversible: <yes or no, and how>. Approver: <role>.` and stop.

## Phases

### 1. Detect and triage

Steps:

1. Record when the organisation became aware, in Australia/Sydney with an offset.
2. Record the account, the platform, and the first suspicious event from the audit log.
3. Check that audit logging is still on. If the attacker disabled it, that is an urgent finding.

Decisions:

- Is the activity confirmed unauthorised? Ask the account owner through a separate channel.
- Which tenants, subscriptions or projects can the account reach?

Evidence to collect: audit log export, the account's role assignments, the first suspicious event.

### 2. Contain

Steps:

1. Propose disabling the account and revoking all its sessions, refresh tokens and access keys.
2. Propose removing any admins, keys, apps, federation trusts or MFA methods the attacker added.
3. Propose restricting admin sign-in to known locations or devices.

Decisions:

- Will disabling the account break production automation? The approver decides, with a replacement credential plan.

Evidence to collect: before and after exports of role assignments, keys and apps.

### 3. Investigate

Steps:

1. Review the audit log from before the first suspicious event: how did the attacker get in (phished password, leaked key, token theft, consent grant)?
2. List every action the account took: resources created, data read or exported, policies changed.
3. Check billing for new resources such as crypto mining.

Decisions:

- Was personal or customer data read or copied? If yes, open [suspected data breach](suspected-data-breach.md).
- Are other privileged accounts affected?

Evidence to collect: audit and sign-in logs for at least 90 days where retained, storage access logs, billing records.

### 4. Eradicate and recover

Steps:

1. Propose rotating secrets the account could read: keys, connection strings, certificates.
2. Propose removing attacker-created resources after evidence is saved.
3. Propose phishing-resistant MFA for all admins and fewer standing admin roles.

Decisions:

- Is the environment trustworthy, or should workloads be redeployed from code?

Evidence to collect: change records and rotation records.

### 5. Notify and report

Steps:

1. Run the [reporting obligations checker](../skills/reporting-obligations/SKILL.md).
2. Propose a voluntary report to ASD's ACSC.
3. Check the cloud provider's incident support process and contract terms.

Decisions:

- Which reports apply and who lodges each one?

Evidence to collect: copies of reports lodged.

### 6. Review

Steps:

1. Review admin role design, break-glass accounts and alerting on admin changes.
2. Update this playbook.

## Evidence to collect

- [ ] Awareness time, Australia/Sydney
- [ ] Audit, sign-in and storage access logs, exported with hashes
- [ ] Role assignments, keys, apps and federation settings before and after changes
- [ ] List of attacker actions and resources
- [ ] Billing records for the period
- [ ] Every action: who approved, who did it, when

## Who to tell

| Who | When | Why |
|---|---|---|
| Incident lead and platform owner | Immediately | Decisions |
| Trusted cloud administrator | Immediately | Containment |
| Legal and privacy officer | Within the first hour | Reporting duties |
| Cloud provider support | When provider help is needed | Investigation and recovery |
| ASD's ACSC | As soon as possible | Voluntary report |
| Regulators | By the deadlines from the checker | Mandatory reports |

## Reporting obligations

Pass these facts to the [reporting obligations checker](../skills/reporting-obligations/SKILL.md): `cyber_security_incident: true`, `personal_information_involved`, `soci_part_2b_applies`, `relevant_impact`, `significant_availability_impact`, `apra_material_incident`, `apra_control_weakness`. Likely rules: SOCI other incident (72 hours) for critical infrastructure, APRA CPS 234 (72 hours) for regulated entities, NDB assessment if personal information was read, voluntary ASD report.

## Timeline record

Record each entry as: time (Australia/Sydney with offset), phase, what happened or was decided, who, evidence reference.

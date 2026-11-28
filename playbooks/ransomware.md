# Ransomware

Playbook id: `ransomware`. Version 0.1.0. Last reviewed 2026-11-28.

Guidance, not legal advice. The assistant proposes. A person acts.

## Scope

Use this playbook when files or systems are encrypted, a ransom note appears, or a group threatens to publish stolen data unless paid. Switch to [suspected data breach](suspected-data-breach.md) as well when personal information may have been taken. Switch to [compromised cloud admin account](compromised-cloud-admin.md) when the entry point was a cloud administrator.

## Roles

| Role | Who | Notes |
|---|---|---|
| Incident lead | Named person | Owns decisions and the timeline |
| Approver | Executive with authority | Approves isolation of business systems, restores, any external statement and any payment decision |
| Technical lead | IT or managed service provider | Carries out approved actions |
| Legal and privacy | Counsel or privacy officer | Reporting duties, privilege, insurer terms |
| Communications | Named person | Staff, customer and media messages |

## Approval boundaries

The assistant may read logs and tool output, keep the timeline, draft messages and reports, and propose actions.

A named person must approve and carry out:

- isolating hosts, disconnecting networks, disabling accounts or shutting down systems
- restoring from backup or rebuilding systems
- contacting the threat actor, a negotiator or a payment intermediary
- any decision about paying. The assistant never proposes a payment.
- reporting to ASD, a regulator, police or the insurer
- any message to staff, customers, media or the public

Write each of these as `Proposal: <action>. Reversible: <yes or no, and how>. Approver: <role>.` and stop.

## Phases

### 1. Detect and triage

Steps:

1. Record the time the organisation became aware, in Australia/Sydney with an offset. This starts several reporting clocks.
2. Record what is encrypted, what is still working, and the ransom note text as quoted, untrusted content. Do not open links in the note.
3. Hand observables to `incident-triage` for scope and severity.

Decisions:

- Is this ransomware, or a destructive attack, or a hoax demand with no encryption? Record the evidence for the answer.
- Is personal information or critical infrastructure involved? If yes, open the matching reporting step now, not later.

Evidence to collect: the ransom note (photo or copy, not executed), file extension or marker of encrypted files, first alert time, affected host list.

### 2. Contain

Steps:

1. Propose network isolation of affected hosts, keeping them powered on so memory is preserved.
2. Propose disabling compromised accounts and resetting privileged credentials from a clean device.
3. Propose taking backups offline so they cannot be encrypted.

Decisions:

- Which systems can be isolated without stopping essential services? The approver decides.
- Does isolation of an operational technology system need the plant operator's agreement?

Evidence to collect: firewall and EDR actions taken (who, when, what), screenshots of the console before changes.

### 3. Investigate

Steps:

1. Find the entry point: remote access logs, VPN and RDP logins, phishing emails, exposed services.
2. Look for data theft: large outbound transfers, archive tools, cloud storage uploads.
3. Identify the ransomware family from the note and file markers with the help of `ioc-enrichment`.

Decisions:

- Was data taken? This changes the privacy and customer notification path.
- Is the attacker still inside? Do not restore until this is answered.

Evidence to collect: VPN, firewall, EDR and authentication logs for at least 30 days before detection; memory images of key hosts; hashes of malware samples; a copy of exfiltration evidence.

### 4. Eradicate and recover

Steps:

1. Propose removing persistence (scheduled tasks, new accounts, remote tools) found in the investigation.
2. Propose restoring from backups that predate the intrusion, after a scan.
3. Propose staged reconnection with heightened monitoring.

Decisions:

- Restore or rebuild? The approver decides with the technical lead.
- Are the backups clean? Test before restoring production.

Evidence to collect: restore point dates, scan results, the change record for each restored system.

### 5. Notify and report

Steps:

1. Run the [reporting obligations checker](../skills/reporting-obligations/SKILL.md) with these facts: `cyber_security_incident`, `ransomware_payment_made` and `payment_at` (only if a payment was made), `personal_information_involved`, `soci_part_2b_applies`, `significant_availability_impact`, `relevant_impact`.
2. If a payment was made by, or for, the organisation, the ransomware payment report clock is 72 hours from the payment. The checker shows the deadline in Sydney time.
3. Propose a voluntary report to ASD's ACSC even when no mandatory report applies.
4. Draft staff and customer messages for approval.

Decisions:

- Which reports apply and who lodges each one? A named person lodges.
- Does the insurer need notice under the policy? Check the policy terms.

Evidence to collect: copies of every report as lodged, with the time and the reference number.

### 6. Review

Steps:

1. Hold a post-incident review within two weeks.
2. Record what worked, what did not, and actions with owners and dates.
3. Update this playbook.

## Evidence to collect

- [ ] Awareness time, Australia/Sydney, and who reported it
- [ ] Ransom note text and contact details, kept as untrusted content
- [ ] List of encrypted and affected systems with times
- [ ] Authentication, VPN, firewall and EDR logs, exported with hashes
- [ ] Memory and disk images of key hosts, with chain of custody
- [ ] Malware samples (hash only in tickets), stored in a safe location
- [ ] Evidence of data theft or its absence
- [ ] Every containment and recovery action: who approved, who did it, when
- [ ] Copies of reports lodged, with reference numbers

Keep originals read-only. Record a SHA-256 hash for each export. Never paste credentials or personal information into tickets.

## Who to tell

| Who | When | Why |
|---|---|---|
| Incident lead and approver | Immediately | Decisions and authority |
| IT or managed service provider | Immediately | Containment |
| Legal and privacy officer | Within the first hour | Reporting clocks, privilege |
| Cyber insurer | As the policy requires | Cover and approved responders |
| ASD's ACSC | As soon as possible | Voluntary report and help, 1300 CYBER1 (1300 292 371) |
| Regulators | By the deadlines from the checker | Mandatory reports |
| Police (ReportCyber routes to police) | When a crime is reported | Investigation |
| Staff, customers, media | After approval | Accurate, approved messages |

## Reporting obligations

Pass these facts to the [reporting obligations checker](../skills/reporting-obligations/SKILL.md): `cyber_security_incident: true`, `ransomware_payment_made`, `payment_at`, `personal_information_involved`, `soci_part_2b_applies`, `significant_availability_impact`, `relevant_impact`, `apra_material_incident` (APRA-regulated entities). Likely rules: ransomware payment report (72 hours from payment), SOCI critical or other incident (12 or 72 hours), NDB assessment (30 days), APRA CPS 234 (72 hours), voluntary ASD report.

## Timeline record

Record each entry as: time (Australia/Sydney with offset), phase, what happened or was decided, who, evidence reference. The skill keeps this record and does not change past entries; corrections are new entries.

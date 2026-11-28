# Suspected data breach

Playbook id: `suspected-data-breach`. Version 0.1.0. Last reviewed 2026-11-28.

Guidance, not legal advice. The assistant proposes. A person acts.

## Scope

Use this playbook when personal or confidential information may have been accessed, disclosed or lost: a misdirected email, an exposed storage bucket, a stolen database, an insider, or a breach found through another playbook. Hand the detailed Notifiable Data Breaches assessment to the `ndb-breach-notification` skill.

## Roles

| Role | Who | Notes |
|---|---|---|
| Incident lead | Named person | Owns decisions and the timeline |
| Privacy officer | Named person | Leads the assessment |
| Approver | Executive with authority | Approves notifications and public statements |
| Technical lead | IT or managed service provider | Containment and evidence |
| Legal | Counsel | Privilege and obligations |
| Communications | Named person | Messages to individuals and media |

## Approval boundaries

The assistant may read evidence, keep the timeline, draft the assessment, the OAIC statement and the notice to individuals, and propose actions.

A named person must approve and carry out:

- removing public access, revoking links or taking a system offline
- asking a recipient to delete misdirected information
- lodging a statement with the OAIC or any other regulator
- notifying individuals or publishing a statement
- contacting the media

Write each as `Proposal: <action>. Reversible: <yes or no, and how>. Approver: <role>.` and stop.

## Phases

### 1. Detect and triage

Steps:

1. Record when the organisation became aware of grounds to suspect a breach, in Australia/Sydney with an offset. The 30 day assessment clock starts here.
2. Record what information, whose, how many people, and how it was exposed.
3. Run the [reporting obligations checker](../skills/reporting-obligations/SKILL.md) now to see the clocks.

Decisions:

- Is personal information involved? If no, record why and keep the confidential information path.
- Is the exposure still happening?

Evidence to collect: the first report, the data set description, access logs.

### 2. Contain

Steps:

1. Propose closing the exposure: remove public access, revoke shared links, recall the email, or disable the account.
2. Propose asking any known recipient to delete the information and confirm in writing.

Decisions:

- Does containment remove the likelihood of serious harm? This matters for whether the breach is eligible.

Evidence to collect: the time the exposure was closed, recipient confirmations.

### 3. Investigate

Steps:

1. Establish who accessed the information and when from logs.
2. Classify the information: identity documents, financial, health, contact details.
3. Use `ndb-breach-notification` to assess the likelihood of serious harm.

Decisions:

- Are there reasonable grounds to believe an eligible data breach has happened? If yes, the statement to the OAIC is due as soon as practicable.

Evidence to collect: access logs, the assessment record with reasons.

### 4. Eradicate and recover

Steps:

1. Propose fixing the cause: permissions, configuration, process or training.
2. Propose monitoring for misuse of the information.

Decisions:

- Is the fix verified? Record how.

Evidence to collect: change records.

### 5. Notify and report

Steps:

1. Re-run the [reporting obligations checker](../skills/reporting-obligations/SKILL.md) with `eligible_breach_believed` set once the assessment is done.
2. Draft the OAIC statement and the notice to individuals with `ndb-breach-notification`. A person lodges and sends them.
3. For APRA-regulated entities, a statement to the OAIC is a notification to another regulator, which is a CPS 234 trigger.

Decisions:

- Notify all affected individuals, only those at risk, or publish? The privacy officer and approver decide.

Evidence to collect: copies of the statement and notices as sent, with times.

### 6. Review

Steps:

1. Review data retention: was the information needed at all?
2. Update this playbook.

## Evidence to collect

- [ ] Time of awareness of the suspicion, Australia/Sydney
- [ ] Description of the information, the individuals and how many
- [ ] How and when the exposure happened and was closed
- [ ] Access logs, exported with hashes
- [ ] Assessment record with reasons for the decision
- [ ] Copies of the statement, notices and any public statement, with times

## Who to tell

| Who | When | Why |
|---|---|---|
| Privacy officer and incident lead | Immediately | Assessment clock |
| Legal | Within the first hour | Obligations and privilege |
| Approver | Before any external notice | Authority |
| OAIC | As soon as practicable once eligible | Mandatory statement |
| Affected individuals | As soon as practicable after the statement | Mandatory notice and steps to protect themselves |
| APRA | Within 72 hours, for APRA-regulated entities | CPS 234 |

## Reporting obligations

Pass these facts to the [reporting obligations checker](../skills/reporting-obligations/SKILL.md): `personal_information_involved`, `serious_harm_ruled_out`, `eligible_breach_believed`, `cyber_security_incident`, `apra_material_incident`, `notified_other_regulator`. Likely rules: NDB assessment (30 days), NDB statement and notice (as soon as practicable), APRA CPS 234 (72 hours) for regulated entities.

## Timeline record

Record each entry as: time (Australia/Sydney with offset), phase, what happened or was decided, who, evidence reference.

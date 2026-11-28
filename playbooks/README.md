# Incident playbooks

A starter set of incident playbooks for small Australian teams. The `incident-playbook` skill walks a person through one of them and keeps a timeline. Copy a playbook and tailor it to your organisation: names, phone numbers, systems and who can approve what.

These are guidance, not legal advice. The assistant proposes. A person acts. Nothing in a playbook sends, blocks, isolates, deletes, pays, posts or contacts anyone on its own.

| Playbook | Use it when |
|---|---|
| [Business email compromise](business-email-compromise.md) | A mailbox is taken over, or a payment or bank detail change came from a spoofed or compromised account |
| [Ransomware](ransomware.md) | Files are encrypted, a ransom note appears, or data theft is threatened |
| [Phishing](phishing.md) | Staff report a suspicious email, or someone clicked a link or entered a password |
| [Lost or stolen device](lost-or-stolen-device.md) | A laptop, phone, tablet or storage device is missing |
| [Suspected data breach](suspected-data-breach.md) | Personal or confidential information may have been accessed, disclosed or lost |
| [Compromised cloud admin account](compromised-cloud-admin.md) | A privileged cloud or identity account shows activity nobody can explain |
| [Third-party breach](third-party-breach.md) | A supplier, SaaS provider or managed service provider tells you, or the news says, they were breached |

## Shape of every playbook

Each playbook has the same sections, in this order, so the skill can walk any of them:

1. **Scope**: when to use it and when to switch to another playbook.
2. **Roles**: who leads, who approves, who is told.
3. **Approval boundaries**: what the assistant may do (read, draft, propose) and what needs a named person.
4. **Phases**: Detect and triage, Contain, Investigate, Eradicate and recover, Notify and report, Review. Each phase has steps, decisions and the evidence to collect.
5. **Evidence to collect**: a checklist with where to find it and how to keep it intact.
6. **Who to tell**: internal and external contacts, with when.
7. **Reporting obligations**: the facts to pass to the [reporting obligations checker](../skills/reporting-obligations/SKILL.md).
8. **Timeline record**: the entries the skill keeps.

Every time in a timeline is Australia/Sydney with a UTC offset, for example `2026-10-04T09:00:00+11:00`.

## Reporting obligations

Each playbook has a step that runs the reporting obligations checker (`mcp__aureg__aureg_check`, or `skills/reporting-obligations/scripts/check_obligations.py`). It works out which Australian reports may apply, who receives them and by when, and drafts the fields. It never submits anything. Run it as soon as you know when the organisation became aware, and again when a fact changes.

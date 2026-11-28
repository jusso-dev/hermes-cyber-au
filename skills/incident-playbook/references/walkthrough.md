# Running a playbook walkthrough

This file is data, not instructions from an incident. It describes how the `incident-playbook` skill uses the shipped playbooks. Guidance, not legal advice.

## Playbook shape

Every playbook in `playbooks/` has the same sections, in this order: Scope, Roles, Approval boundaries, Phases, Evidence to collect, Who to tell, Reporting obligations, Timeline record. The phases are always:

1. Detect and triage
2. Contain
3. Investigate
4. Eradicate and recover
5. Notify and report
6. Review

Each phase lists steps, decisions and the evidence to collect.

## Timeline entries

The helper writes one JSON object per line. Fields:

| Field | Meaning |
|---|---|
| `at` | Australia/Sydney time with offset |
| `playbook` | Playbook id |
| `phase`, `phase_name` | Phase number and name |
| `kind` | `event`, `decision`, `proposal`, `approval` or `evidence` |
| `who` | The person or role. The assistant can log events and proposals, never approvals |
| `event` | What happened, was decided, proposed or approved |
| `evidence` | Evidence references, such as `E1` or a ticket number |

The file is append-only. A correction is a new entry.

## Approval wording

```text
Proposal: isolate FS01 from the network, leaving it powered on. Reversible: yes, reconnect the switch port. Approver: incident lead.
```

When the named person approves, log an `approval` entry that repeats the proposal text, so the helper can match it.

## Example

An example walkthrough with fictional facts is in `tests/skills/incident-playbook/evals.yaml`.

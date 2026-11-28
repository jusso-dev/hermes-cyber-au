# Incident playbooks and reporting obligations

Two skills help a small team run an incident: `incident-playbook` walks a playbook and keeps a timeline, and `reporting-obligations` works out which Australian reports may apply, to whom and by when. Both are guidance, not legal advice. Neither sends, blocks, isolates, submits or contacts anyone. The assistant proposes. A person acts.

## Playbooks

The distribution ships seven playbooks in `playbooks/`:

| Playbook | Use it when |
|---|---|
| `business-email-compromise` | A mailbox is taken over, or a payment or bank detail change came from a spoofed account |
| `ransomware` | Files are encrypted, or data theft is threatened for payment |
| `phishing` | Someone reports a suspicious message, or clicked or entered a password |
| `lost-or-stolen-device` | A device with work data is missing |
| `suspected-data-breach` | Personal or confidential information may have been exposed |
| `compromised-cloud-admin` | A privileged cloud or identity account shows unexplained activity |
| `third-party-breach` | A supplier or service provider was breached |

Every playbook has the same sections: scope, roles, approval boundaries, six phases (detect and triage, contain, investigate, eradicate and recover, notify and report, review) with steps, decisions and evidence, an evidence checklist, who to tell, and the facts to give the reporting obligations checker. Copy one and tailor names, numbers and systems for your organisation.

Ask, for example:

```text
Walk me through the ransomware playbook. We became aware at 2026-10-03T20:00:00+10:00 that FS01 is encrypted. Keep the timeline in incidents/2026-10-03/timeline.jsonl.
```

The skill's helper keeps the timeline as one JSON line per entry, in Australia/Sydney time with an offset. It never rewrites an entry. It refuses to record an approval for the assistant, and it lists proposals that nobody has approved yet.

```bash
python skills/incident-playbook/scripts/playbook.py list
python skills/incident-playbook/scripts/playbook.py show ransomware --phase 2
python skills/incident-playbook/scripts/playbook.py timeline incidents/2026-10-03/timeline.jsonl
```

## Reporting obligations checker

The `aureg_check` tool on the `aureg` connector, and the `reporting-obligations` skill that uses it, take an incident summary, the discovery time and `org.yaml`. They return:

- the reports that apply, the ones that may apply (with the questions that would settle them), and the ones that do not apply on these facts (with the reason)
- deadlines in Australia/Sydney, with a countdown timeline
- the recipient and channel for each report
- the citation, source link and last reviewed date for each rule
- a draft of each report's fields, labelled "DRAFT. Not submitted."
- limited use notes for information given to ASD, the Department or the National Cyber Security Coordinator

Rules covered (reviewed 2026-11-28):

| Rule | Deadline | Source |
|---|---|---|
| Ransomware payment report (turnover above AUD 3 million, or a SOCI Part 2B responsible entity) | 72 hours after the payment | Cyber Security Act 2024 s 27; Ransomware Payment Reporting Rules 2025 ss 6, 7 |
| SOCI critical cyber security incident | 12 hours; written record 84 hours after an oral report | SOCI Act 2018 s 30BC |
| SOCI other cyber security incident | 72 hours; written record 48 hours after an oral report | SOCI Act 2018 s 30BD |
| APRA CPS 234 material incident | 72 hours | CPS 234 paragraph 35 |
| APRA CPS 234 material control weakness | 10 business days | CPS 234 paragraph 36 |
| NDB suspected breach assessment | 30 days | Privacy Act 1988 s 26WH(2) |
| NDB statement and notice | As soon as practicable | Privacy Act 1988 ss 26WK, 26WL |
| Voluntary report to ASD (ReportCyber) | As soon as possible | ASD guidance |
| Voluntary information to the National Cyber Security Coordinator | Any time during the response | Cyber Security Act 2024 ss 34, 35, 38, 44 |

Hours are elapsed time across daylight saving changes. Business days skip weekends but not public holidays, so the date shown is never later than the real deadline. The data lives in `mcp/au-regulatory/data/obligations-<date>.json`; see the [au-regulatory connector page](../connectors/au-regulatory.md) for how it is reviewed.

Without the connector, the same engine runs from the command line:

```bash
python skills/reporting-obligations/scripts/check_obligations.py \
  --discovered-at 2026-10-03T20:00:00+10:00 --facts facts.json --org org.yaml
```

## Limits

The checker does not decide judgements such as materiality, significant impact or serious harm. It asks. It does not cover state and territory privacy laws, aviation, maritime or telecommunications security reporting, or contract terms. Get legal advice where the answer turns on a judgement or where turnover is close to AUD 3 million.

---

Owner ticket: #166, #167
Last verified: 28 November 2026
